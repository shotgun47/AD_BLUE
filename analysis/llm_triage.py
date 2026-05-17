# analysis/llm_triage.py

import json
import os
from typing import Any

import litellm


LLM_TRIAGE_ENABLED = os.getenv("LLM_TRIAGE_ENABLED", "false").lower() == "true"
LLM_TRIAGE_MODEL = os.getenv("LLM_TRIAGE_MODEL", "gemini/gemini-2.0-flash")
LLM_TRIAGE_TIMEOUT = int(os.getenv("LLM_TRIAGE_TIMEOUT", "20"))

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

if ANTHROPIC_API_KEY:
    litellm.anthropic_key = ANTHROPIC_API_KEY

if GEMINI_API_KEY:
    os.environ["GEMINI_API_KEY"] = GEMINI_API_KEY

litellm.drop_params = True


LLM_TARGET_RULE_IDS = {
    "RULE-063",
    "RULE-064",
    "RULE-065",

    "RULE-101",
    "RULE-102",
    "RULE-103",
    "RULE-104",
    "RULE-105",
    "RULE-106",
    "RULE-107",
    "RULE-108",
    "RULE-109",
}


def _matched_rule_ids(detection: dict) -> set[str]:
    result = set()

    if detection.get("rule_id"):
        result.add(str(detection.get("rule_id")))

    for rule in detection.get("matched_rules") or []:
        rule_id = rule.get("rule_id")
        if rule_id:
            result.add(str(rule_id))

    return result


def _simplify_scenario_runs(scenario_runs: list[dict] | None, limit: int = 5) -> list[dict]:
    result = []

    for run in (scenario_runs or [])[:limit]:
        result.append({
            "scenario_id": run.get("scenario_id"),
            "scenario_type": run.get("scenario_type"),
            "requested_by": run.get("requested_by"),
            "target_ip": run.get("target_ip"),
            "status": run.get("status"),
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
        })

    return result


def should_run_llm_triage(detection: dict, risk: dict) -> bool:
    if not LLM_TRIAGE_ENABLED:
        return False

    if not detection.get("detected"):
        return False

    matched_rule_ids = _matched_rule_ids(detection)

    # RULE-041 같은 범용 프로세스 생성 룰 단독은 제외
    if not (matched_rule_ids & LLM_TARGET_RULE_IDS):
        return False

    return True


def _compact_text(value: Any, limit: int = 1500) -> str:
    if value is None:
        return ""

    text = str(value)

    if len(text) <= limit:
        return text

    return text[:limit] + "\n...(truncated)"


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _fallback_result(reason: str, called: bool = False) -> dict:
    return {
        "enabled": LLM_TRIAGE_ENABLED,
        "called": called,
        "model": LLM_TRIAGE_MODEL,
        "verdict": "not_available",
        "confidence": 0.0,
        "summary": "LLM 2차 판정을 수행하지 않았습니다.",
        "suspicious_points": [],
        "benign_context": [],
        "recommended_action": "룰 탐지 결과와 이벤트 원문을 기준으로 수동 확인하세요.",
        "error": reason,
    }


def _build_payload(
    event: dict,
    normalized: dict,
    detection: dict,
    risk: dict,
    scenario_runs: list[dict] | None = None,
) -> dict[str, Any]:
    matched_rules = detection.get("matched_rules") or []

    return {
        "event": {
            "event_time": event.get("event_time"),
            "event_id": event.get("event_id"),
            "provider": event.get("provider"),
            "channel": event.get("channel"),
            "computer_name": event.get("computer_name"),
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            "target_user": event.get("target_user"),
            "target_host": event.get("target_host"),
            "service_name": event.get("service_name"),
            "image": event.get("image"),
            "command_line": event.get("command_line"),
            "parent_image": event.get("parent_image"),
            "parent_command_line": event.get("parent_command_line"),
            "message": _compact_text(event.get("message")),
        },
        "normalized": {
            "event_type": normalized.get("event_type"),
            "host_role": normalized.get("host_role"),
            "account_type": normalized.get("account_type"),
            "is_admin_account": normalized.get("is_admin_account"),
            "is_privileged": normalized.get("is_privileged"),
            "is_privileged_account": normalized.get("is_privileged_account"),
            "is_off_hours": normalized.get("is_off_hours"),
            "service_name": normalized.get("service_name"),
            "computer_name": normalized.get("computer_name"),
            "username": normalized.get("username"),
        },
        "detection": {
            "detected": detection.get("detected"),
            "rule_id": detection.get("rule_id"),
            "rule_name": detection.get("rule_name"),
            "matched_rules": [
                {
                    "rule_id": rule.get("rule_id"),
                    "rule_name": rule.get("rule_name"),
                    "reason": rule.get("reason"),
                    "attack_tactic": rule.get("attack_tactic"),
                    "attack_technique": rule.get("attack_technique"),
                    "response_guide": rule.get("response_guide"),
                    "risk": rule.get("risk"),
                }
                for rule in matched_rules
            ],
        },
        "risk": {
            "base_score": risk.get("base_score"),
            "weight": risk.get("weight"),
            "final_score": risk.get("final_score"),
            "severity": risk.get("severity"),
            "base_reasons": risk.get("base_reasons"),
        },
        "scenario_runs": _simplify_scenario_runs(scenario_runs),
    }


def _extract_json_from_text(text: str) -> dict:
    """
    모델이 실수로 ```json ... ``` 또는 앞뒤 설명을 붙여도 JSON만 최대한 추출.
    """
    if not text:
        raise ValueError("empty LLM response")

    cleaned = text.strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`").strip()
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].strip()

    try:
        return json.loads(cleaned)
    except Exception as first_error:
        start = cleaned.find("{")
        end = cleaned.rfind("}")

        if start == -1 or end == -1 or end <= start:
            raise ValueError(
                "JSON object not found in response. "
                f"parse_error={first_error}; "
                f"length={len(cleaned)}; "
                f"preview={cleaned[:1500]}"
            )

        candidate = cleaned[start:end + 1]

        try:
            return json.loads(candidate)
        except Exception as second_error:
            raise ValueError(
                "Invalid JSON object in response. "
                f"parse_error={second_error}; "
                f"preview={candidate[:1500]}"
            )


def run_llm_triage(
    event: dict,
    normalized: dict,
    detection: dict,
    risk: dict,
    scenario_runs: list[dict] | None = None,
) -> dict:
    if not should_run_llm_triage(detection, risk):
        return _fallback_result("not_target", called=False)

    if not GEMINI_API_KEY and not ANTHROPIC_API_KEY:
        return _fallback_result("GEMINI_API_KEY or ANTHROPIC_API_KEY is empty", called=False)

    payload = _build_payload(
        event=event,
        normalized=normalized,
        detection=detection,
        risk=risk,
        scenario_runs=scenario_runs,
    )

    system_prompt = (
        "너는 AD 보안 실습 환경의 SOC 분석가를 보조하는 이벤트 트리아지 시스템이다. "
        "반드시 JSON만 출력한다. 마크다운, 코드블록, 설명 문장은 출력하지 않는다."
    )

    user_prompt = f"""
다음 보안 이벤트를 2차 판단해줘.

판단 기준:
- 이 시스템은 AD 보안 교육용 실습 환경이다.
- matched_rules에 RULE-106, RULE-107, RULE-109가 있으면 WinRM/PowerShell 기반 정찰 흐름 가능성을 고려한다.
- scenario_runs에서 이벤트 시간과 겹치는 실행 이력이 있는지 확인한다.
- 겹치는 실행 이력의 scenario_type이 tools이면 승인된 정찰 도구 실행 가능성이 높다.
- scenario_type이 detection_test이면 탐지 테스트 가능성이 높다.
- real_attack 시나리오는 LLM 오탐 보정 대상에서 제외되므로 입력 scenario_runs에 포함되지 않는다.
- matched_rules에 RULE-063, RULE-064, RULE-065가 있으면 AS-REP Roasting 관련 이벤트로 판단한다.
- RULE-063은 Kerberos Pre-Authentication이 사용되지 않은 AS-REQ 이벤트다.
- RULE-064는 짧은 시간 내 여러 계정에 대한 AS-REP Roasting 스캐닝 가능성이다.
- RULE-065는 특정 계정에 대한 반복 AS-REP Roasting 시도 가능성이다.
- scenario_runs에 관련 tools/detection_test가 없고 AS-REP 룰이 탐지되면 suspicious_unapproved_activity 또는 real_attack_activity로 판단한다.
- 실행 이력이 없는데 도구/정찰 룰이 탐지되면 suspicious_unapproved_activity로 본다.
- 확실하지 않은 내용은 단정하지 말고 needs_review로 둔다.
- 최종 위험도 점수 자체를 바꾸지는 말고, 분석가가 이해할 수 있는 판단 근거와 권고 조치만 작성한다.

출력 규칙:
- 출력은 반드시 아래 JSON 스키마를 따른다.
- 반드시 JSON 객체 하나만 출력한다.
- 코드블록, 마크다운, 설명 문장을 붙이지 않는다.
- summary는 80자 이내로 작성한다.
- suspicious_points는 최대 2개만 작성한다.
- benign_context는 최대 2개만 작성한다.
- recommended_action은 100자 이내로 작성한다.

JSON 스키마:
{{
  "verdict": "authorized_tool_activity | suspicious_unapproved_activity | detection_test_activity | real_attack_activity | needs_review"
  "confidence": 0.0,
  "summary": "80자 이내 요약",
  "suspicious_points": ["최대 2개"],
  "benign_context": ["최대 2개"],
  "recommended_action": "100자 이내 권고"
}}

입력 JSON:
{json.dumps(payload, ensure_ascii=False)}
""".strip()

    try:
        response = litellm.completion(
            model=LLM_TRIAGE_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            temperature=0.2,
            max_tokens=3000,
            timeout=LLM_TRIAGE_TIMEOUT,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content or ""
        parsed = _extract_json_from_text(content)

        suspicious_points = parsed.get("suspicious_points") or []
        benign_context = parsed.get("benign_context") or []

        if not isinstance(suspicious_points, list):
            suspicious_points = [str(suspicious_points)]

        if not isinstance(benign_context, list):
            benign_context = [str(benign_context)]

        return {
            "enabled": True,
            "called": True,
            "model": LLM_TRIAGE_MODEL,
            "verdict": parsed.get("verdict", "needs_review"),
            "confidence": _safe_float(parsed.get("confidence"), 0.0),
            "summary": parsed.get("summary", ""),
            "suspicious_points": suspicious_points,
            "benign_context": benign_context,
            "recommended_action": parsed.get("recommended_action", ""),
            "error": None,
        }

    except Exception as exc:
        return _fallback_result(str(exc), called=True)