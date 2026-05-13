import pandas as pd
import streamlit as st

from config import ATTACK_REQUESTED_BY, VICTIM_URL
from api_client import get_scenarios, get_scenario_runs, get_scenario_log
from components import render_scenario_card
from utils import is_recon_run


def _group_scenarios(scenarios):
    grouped = {
        "real_attack": [],
        "detection_test": [],
        "tools": [],
        "general": [],
    }

    for scenario in scenarios:
        scenario_type = scenario.get("scenario_type", "general")
        if scenario_type not in grouped:
            grouped["general"].append(scenario)
        else:
            grouped[scenario_type].append(scenario)

    return grouped


def _render_run_history():
    st.title("공격")
    st.divider()

    st.subheader("최근 실행 이력")

    if st.button("실행 이력 새로고침", key="refresh_attack_history"):
        st.rerun()

    try:
        history_data = get_scenario_runs(limit=20)
        history_data = [
            item for item in history_data
            if not is_recon_run(item)
        ][:5]
    except Exception as e:
        st.error(f"실행 이력 조회 실패: {e}")
        return

    if isinstance(history_data, dict) and history_data.get("result") == "error":
        st.error(history_data.get("message"))
        return

    if not history_data:
        st.info("최근 실행 이력이 없습니다.")
        return

    history_rows = []
    for item in history_data:
        raw_status = item.get("status", "-")

        if raw_status == "running":
            display_status = "🔵 running"
        elif raw_status == "success":
            display_status = "✅ success"
        elif raw_status == "failed":
            display_status = "❌ failed"
        else:
            display_status = raw_status

        history_rows.append({
            "run_id": item.get("run_id", "-"),
            "실행자": item.get("requested_by", "-"),
            "타입": item.get("scenario_type", "general"),
            "시나리오": item.get("scenario_id", "-"),
            "타겟 IP": item.get("target_ip", "-"),
            "상태": display_status,
            "시작 시간": item.get("started_at", "-"),
        })

    history_df = pd.DataFrame(history_rows)

    def highlight_status(val):
        if "running" in str(val):
            return "background-color: #FFC19E; color: #6F310E; font-weight: bold;"
        elif "success" in str(val):
            return "background-color: #ecfdf5; color: #166534;"
        elif "failed" in str(val):
            return "background-color: #fef2f2; color: #991b1b;"
        return ""

    styled_df = history_df.style.map(
        highlight_status,
        subset=["상태"]
    )

    st.dataframe(styled_df, use_container_width=True)

    st.markdown("### 실행 로그 확인")

    run_options = [
        row["run_id"]
        for row in history_rows
        if row.get("run_id") not in (None, "-")
    ]

    if not run_options:
        st.info("조회 가능한 실행 로그가 없습니다.")
        return

    col_run_log, col_log_lines, col_load_log, col_load_refresh = st.columns([3.5, 3.5, 1.5, 1.5])

    with col_run_log:
        selected_run_id = st.selectbox(
            "로그를 볼 실행 선택",
            options=run_options,
            key="attack_selected_run_id"
        )

    with col_log_lines:
        tail = st.selectbox(
            "불러올 로그 줄 수",
            [50, 100, 200, 500],
            index=2,
            key="attack_selected_log_tail"
        )

    with col_load_log:
        if st.button("로그 불러오기", key="attack_load_selected_log"):
            try:
                st.session_state["attack_selected_run_log"] = get_scenario_log(selected_run_id, tail=tail)
            except Exception as e:
                st.session_state["attack_selected_run_log"] = {
                    "result": "error",
                    "message": str(e),
                }

    with col_load_refresh:
        if st.button("새로고침", key="attack_refresh_selected_log"):
            try:
                st.session_state["attack_selected_run_log"] = get_scenario_log(selected_run_id, tail=tail)
            except Exception as e:
                st.session_state["attack_selected_run_log"] = {
                    "result": "error",
                    "message": str(e),
                }

    cached_log = st.session_state.get("attack_selected_run_log")

    if cached_log:
        if cached_log.get("result") == "error":
            st.error(cached_log.get("message", "로그 조회 실패"))
        else:
            st.caption(
                f"log_path: {cached_log.get('log_path', '-')} | "
                f"encoding: {cached_log.get('encoding', '-')} | "
                f"tail: {cached_log.get('tail', '-')}"
            )
            st.code(cached_log.get("log_text", ""), language="bash")
    else:
        st.info("실행 이력을 선택하고 로그를 불러오세요.")


def render_attack():
    _render_run_history()

    st.divider()
    st.subheader("공격 시나리오 실행")

    col_target, col_user = st.columns([6, 4])
    with col_target:
        target_ip = st.text_input("대상 IP", value=VICTIM_URL, key="attack_target_ip")
    with col_user:
        requested_by = st.text_input("실행자", value=ATTACK_REQUESTED_BY, key="attack_requested_by")

    try:
        scenarios = get_scenarios()
    except Exception as e:
        st.error(f"시나리오 목록 조회 실패: {e}")
        return

    if isinstance(scenarios, dict) and scenarios.get("result") == "error":
        st.error(scenarios.get("message"))
        return

    grouped = _group_scenarios(scenarios)

    # 정찰 도구(tools)는 recon.py에서 따로 보여줄 예정이므로 공격 페이지에서는 제외
    attack_scenarios = (
        grouped["real_attack"]
        + grouped["detection_test"]
        + grouped["general"]
    )

    st.markdown("### 공격 시나리오")

    if not attack_scenarios:
        st.info("표시할 공격 시나리오가 없습니다.")
        return

    tab1, tab2, tab3 = st.tabs(["🧪 탐지 테스트", "⚔️ 공격 시나리오", "📌 기타"])

    with tab1:
        for scenario in grouped["detection_test"]:
            render_scenario_card(scenario, target_ip, requested_by)
    with tab2:
        for scenario in grouped["real_attack"]:
            render_scenario_card(scenario, target_ip, requested_by)

    with tab3:
        for scenario in grouped["general"]:
            render_scenario_card(scenario, target_ip, requested_by)