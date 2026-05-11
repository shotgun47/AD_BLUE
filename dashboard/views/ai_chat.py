"""
AD Lab AI Chat - LiteLLM 버전
Claude / Gemini 모두 지원
"""

import asyncio
import json
import os
from typing import Any, Dict, List

import litellm
import streamlit as st

try:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
except ImportError as exc:
    st.error(f"mcp 패키지 임포트 실패: {exc}. requirements.txt를 확인하세요.")
    st.stop()

# ------------------------------------------------------------------
# 환경변수
# ------------------------------------------------------------------
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY", "")
MCP_URL           = os.getenv("MCP_URL", "http://mcp:9000/mcp")
REQUESTED_BY      = os.getenv("ATTACK_REQUESTED_BY", "dashboard-user")
VICTIM_URL        = os.getenv("VICTIM_URL", "")

# LiteLLM API 키 주입
if ANTHROPIC_API_KEY:
    litellm.anthropic_key = ANTHROPIC_API_KEY
if GEMINI_API_KEY:
    os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY

litellm.drop_params = True   # 지원하지 않는 파라미터 자동 제거

# ------------------------------------------------------------------
# 모델 목록
# ------------------------------------------------------------------
MODELS: Dict[str, Dict[str, str]] = {
    "⚡ Gemini Flash (최신)":        {"id": "gemini/gemini-flash-latest",  "provider": "gemini"},
    "⚡ Gemini 2.5 Flash":           {"id": "gemini/gemini-2.5-flash",     "provider": "gemini"},
    "⚡ Gemini 2.0 Flash":           {"id": "gemini/gemini-2.0-flash",     "provider": "gemini"},
    "🔵 Gemini 2.5 Pro":             {"id": "gemini/gemini-2.5-pro",       "provider": "gemini"},
    "🟠 Claude Haiku 4.5 (빠름)":   {"id": "claude-haiku-4-5",            "provider": "anthropic"},
    "🟡 Claude Sonnet 4.5 (균형)":  {"id": "claude-sonnet-4-5",           "provider": "anthropic"},
}

SYSTEM_PROMPT = (
    "너는 AD(Active Directory) 보안 실험실의 AI 어시스턴트야. "
    "사용자가 보안 로그 조회, 공격 시나리오 탐색, 시나리오 실행을 요청하면 "
    "제공된 도구를 적극 활용해서 답해. "
    "공격을 실제로 실행하기 전에는 반드시 어떤 시나리오를 어떤 파라미터로 "
    "실행할지 사용자에게 한 번 더 확인받아. "
    f"`requested_by` 파라미터가 비어있다면 '{REQUESTED_BY}'를 사용해. "
    f"시나리오 실행 시 `target_ip` 파라미터가 필요하면 반드시 '{VICTIM_URL}'을 사용해. "
    "결과는 한국어로 간결하게 정리해서 보여줘."
)


# ------------------------------------------------------------------
# MCP 헬퍼
# ------------------------------------------------------------------
async def _list_tools_async() -> List[Dict[str, Any]]:
    async with streamablehttp_client(MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            return [
                {
                    "name": t.name,
                    "description": t.description or "",
                    "input_schema": t.inputSchema,
                }
                for t in tools.tools
            ]


async def _call_tool_async(name: str, args: Dict[str, Any]) -> str:
    async with streamablehttp_client(MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(name, args)
            parts: List[str] = []
            for c in result.content:
                if hasattr(c, "text") and c.text is not None:
                    parts.append(c.text)
                else:
                    parts.append(str(c))
            return "\n".join(parts) if parts else "(빈 응답)"


def list_tools() -> List[Dict[str, Any]]:
    return asyncio.run(_list_tools_async())


def call_tool(name: str, args: Dict[str, Any]) -> str:
    return asyncio.run(_call_tool_async(name, args))


# ------------------------------------------------------------------
# 도구 스키마 변환: MCP(Anthropic) → OpenAI/LiteLLM 형식
# ------------------------------------------------------------------
def to_litellm_tools(mcp_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result = []
    for t in mcp_tools:
        result.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            },
        })
    return result


# ------------------------------------------------------------------
# 세션 상태 초기화
# ------------------------------------------------------------------
def _init_ai_chat_state():
    if "ai_chat_history"   not in st.session_state:
        st.session_state.ai_chat_history   = []
    if "api_messages"   not in st.session_state:
        st.session_state.api_messages   = []
    if "ai_tools_cache"    not in st.session_state:
        st.session_state.ai_tools_cache    = None
    if "ai_selected_model" not in st.session_state:
        st.session_state.ai_selected_model = list(MODELS.keys())[0]
    if "ai_processing" not in st.session_state:
        st.session_state.ai_processing = False
    if "ai_pending_input" not in st.session_state:
        st.session_state.ai_pending_input = ""


# ------------------------------------------------------------------
# 에이전트 루프
# ------------------------------------------------------------------
def run_agent_loop(user_text: str, model_id: str) -> str:
    tools = to_litellm_tools(st.session_state.ai_tools_cache or [])

    st.session_state.api_messages.append({"role": "user", "content": user_text})

    final_text_parts: List[str] = []
    safety_counter = 0

    while True:
        safety_counter += 1
        if safety_counter > 10:
            final_text_parts.append("\n\n⚠️ 도구 호출 루프가 너무 길어 중단했습니다.")
            break

        resp = litellm.completion(
            model=model_id,
            messages=[{"role": "system", "content": SYSTEM_PROMPT}] + st.session_state.api_messages,
            tools=tools if tools else None,
            tool_choice="auto" if tools else None,
            max_tokens=4096,
        )

        choice        = resp.choices[0]
        message       = choice.message
        finish_reason = choice.finish_reason

        # assistant 메시지 히스토리 저장
        assistant_msg: Dict[str, Any] = {
            "role": "assistant",
            "content": message.content or "",
        }
        if message.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in message.tool_calls
            ]
        st.session_state.api_messages.append(assistant_msg)

        # 도구 호출 없으면 종료
        if finish_reason != "tool_calls" or not message.tool_calls:
            if message.content:
                final_text_parts.append(message.content)
            break

        # 중간 텍스트 수집
        if message.content:
            final_text_parts.append(message.content)

        # 도구 실행
        for tc in message.tool_calls:
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                args = {}

            with st.status(f"🔧 `{name}` 호출 중...", expanded=False) as status:
                st.code(json.dumps(args, ensure_ascii=False, indent=2), language="json")
                try:
                    output = call_tool(name, args)
                    status.update(label=f"✅ `{name}` 완료", state="complete")
                except Exception as exc:
                    output = f"[tool error] {exc}"
                    status.update(label=f"❌ `{name}` 실패", state="error")

            st.session_state.api_messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": output,
            })

    return "\n\n".join(p for p in final_text_parts if p).strip() or "(응답 없음)"


# ------------------------------------------------------------------
# 페이지 로드 (채팅입력)
# ------------------------------------------------------------------
def render_ai_chat():
    _init_ai_chat_state()

    st.title("🛡️ AD Lab AI Assistant")
    st.divider()

    st.subheader("AI Chat")
    st.caption("MCP 도구를 사용해 보안 로그 조회, 공격 시나리오 탐색, BloodHound 분석을 수행합니다.")

    left, right = st.columns([7, 3])

    with right:
        st.markdown("### 모델 선택")

        if st.session_state.ai_selected_model not in MODELS:
            st.session_state.ai_selected_model = list(MODELS.keys())[0]

        selected_label = st.selectbox(
            "LLM",
            list(MODELS.keys()),
            index=list(MODELS.keys()).index(st.session_state.ai_selected_model),
            key="ai_model_selector",
        )
        st.session_state.ai_selected_model = selected_label

        model_info = MODELS[selected_label]
        model_id = model_info["id"]
        model_provider = model_info["provider"]

        if model_provider == "anthropic" and not ANTHROPIC_API_KEY:
            st.warning("⚠️ ANTHROPIC_API_KEY가 .env에 없습니다.")
        elif model_provider == "gemini" and not GEMINI_API_KEY:
            st.warning("⚠️ GEMINI_API_KEY가 .env에 없습니다.")
        else:
            st.caption(f"✅ `{model_id}`")

        st.divider()
        st.markdown("### MCP 도구 상태")

        if st.button("🔄 도구 다시 불러오기", key="ai_reload_tools"):
            st.session_state.ai_tools_cache = None

        if st.session_state.ai_tools_cache is None:
            try:
                st.session_state.ai_tools_cache = list_tools()
            except Exception as exc:
                st.error(f"MCP 서버 연결 실패: {exc}")
                st.session_state.ai_tools_cache = []

        for t in st.session_state.ai_tools_cache or []:
            with st.expander(f"🔧 {t['name']}"):
                st.caption((t.get("description") or "")[:300])

        st.divider()
        if st.button("🗑 대화 초기화", key="ai_clear_chat"):
            st.session_state.ai_chat_history = []
            st.session_state.ai_api_messages = []
            st.session_state.ai_processing = False
            st.session_state.ai_pending_input = ""
            st.session_state.pop("ai_pending_prompt", None)
            st.rerun()

    with left:
        # 1. 대화 히스토리 (항상 입력창 위)
        for msg in st.session_state.ai_chat_history:
            with st.chat_message(msg["role"]):
                st.markdown(msg["text"])

        # 2. 처리 중이면 여기서 실행 (입력창 위)
        if st.session_state.ai_processing:
            pending_input = st.session_state.ai_pending_input
            st.session_state.ai_processing = False
            st.session_state.ai_pending_input = ""

            with st.chat_message("assistant"):
                with st.spinner(f"{selected_label} 처리 중..."):
                    try:
                        answer = run_agent_loop(pending_input, model_id)
                    except Exception as exc:
                        answer = f"❌ 오류: {exc}"
                st.markdown(answer)
                st.session_state.ai_chat_history.append({"role": "assistant", "text": answer})

            st.rerun()

        # 3. 예시 프롬프트
        with st.expander("💡 예시 프롬프트", expanded=False):
            prompt_categories = {
                "🔍 보안 로그": [
                    "최근 보안 로그 30건 보여줘",
                    "탐지된 이벤트만 필터링해서 보여줘",
                    "Sysmon 이벤트 ID 1(프로세스 생성)만 보여줘",
                ],
                "⚔️ 공격 시나리오": [
                    "사용 가능한 공격 시나리오 목록 보여줘",
                    "AS-REP Roasting 공격 실행해줘",
                    "최근 시나리오 실행 이력 보여줘",
                ],
                "🩸 BloodHound": [
                    "BloodHound 수집 실행해줘",
                    "최근 BloodHound 컬렉션 목록 보여줘",
                    "최근 BloodHound 결과 분석해줘",
                    "BloodHound HTML 그래프 생성해줘",
                ],
                "🕵️ 정찰": [
                    "PingCastle AD 헬스체크 실행해줘",
                    "PowerView로 AD 정찰 실행해줘",
                    "PowerView, PingCastle, BloodHound 통합 정찰 워크플로우 실행해줘",
                ],
            }

            for category, prompts in prompt_categories.items():
                st.markdown(f"**{category}**")
                cols = st.columns(len(prompts))
                for col, prompt in zip(cols, prompts):
                    with col:
                        if st.button(prompt, key=f"ex_{prompt}", use_container_width=True):
                            st.session_state["ai_pending_prompt"] = prompt

        # 4. 채팅 입력 (항상 최하단)
        user_input = st.chat_input(
            "질문을 입력하세요. 예: 최근 보안 로그 20건 보여줘",
            key="ai_chat_user_input",
        )

        pending = st.session_state.pop("ai_pending_prompt", None)
        if pending and not user_input:
            user_input = pending

        if user_input:
            st.session_state.ai_chat_history.append({"role": "user", "text": user_input})
            st.session_state.ai_processing = True
            st.session_state.ai_pending_input = user_input
            st.rerun()





