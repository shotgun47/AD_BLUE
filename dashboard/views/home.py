import json
import pandas as pd
import streamlit as st

from api_client import (
    get_health,
    get_events,
    get_event_save_policy,
    get_scenario_runs,
    get_running_scenario_runs,
    get_latest_recon_summary,
)
from utils import safe_json_loads, normalize_matched_rules


def _count_detected_events(events):
    count = 0
    high_or_more = 0
    rule_counter = {}

    for item in events:
        detection = safe_json_loads(item.get("detection_json"))
        risk = safe_json_loads(item.get("risk_json"))

        if detection.get("detected"):
            count += 1

        severity = str(risk.get("severity", "none")).lower()
        if severity in ("high", "critical"):
            high_or_more += 1

        for rule in normalize_matched_rules(detection):
            label = rule.get("rule_name") or rule.get("rule_id") or "-"
            rule_counter[label] = rule_counter.get(label, 0) + 1

    return count, high_or_more, rule_counter


def _render_recon_tool_card(tool_name, title):
    try:
        summary = get_latest_recon_summary(tool_name)
    except Exception as e:
        with st.container(border=True):
            st.markdown(f"**{title}**")
            st.error(f"조회 실패: {e}")
        return

    with st.container(border=True):
        st.markdown(f"**{title}**")

        if summary.get("result") == "empty":
            st.info("저장된 결과 없음")
            return

        if summary.get("result") == "error":
            st.error(summary.get("message", "조회 실패"))
            return

        # 도구별로 키가 달라도 일단 주요 값만 보여주기
        display_items = list(summary.items())[:6]

        if not display_items:
            st.info("summary 값이 비어 있습니다.")
            return

        for key, value in display_items:
            st.write(f"{key}: **{value}**")


def render_home():
    st.title("AD 공격/방어 시뮬레이션 랩")
    st.divider()

    st.subheader("홈")

    # 1. 데이터 조회
    try:
        health = get_health()
        backend_ok = health.get("status") == "ok"
    except Exception:
        backend_ok = False

    try:
        events = get_events(since_minutes=60)
    except Exception:
        events = []

    try:
        save_policy = get_event_save_policy()
        save_mode = save_policy.get("mode", "-")
    except Exception:
        save_mode = "-"

    try:
        runs = get_scenario_runs(limit=5)
    except Exception:
        runs = []

    try:
        running_runs = get_running_scenario_runs()
    except Exception:
        running_runs = []

    detected_count, high_count, rule_counter = _count_detected_events(events)

    # 2. 상단 상태 카드
    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Backend", "정상" if backend_ok else "오류")
    c2.metric("최근 이벤트", len(events))
    c2.caption(f"최근 1시간 | 수집 모드: `{save_mode}`")
    c3.metric("탐지 이벤트", detected_count)
    c4.metric("High 이상", high_count)
    c5.metric("실행 중", len(running_runs) if isinstance(running_runs, list) else 0)

    st.divider()

    # 3. 최근 공격 실행 이력
    left, right = st.columns([6, 4])

    with left:
        st.markdown("### 최근 공격 실행 이력")

        if not runs:
            st.info("최근 실행 이력이 없습니다.")
        else:
            rows = []
            for item in runs:
                rows.append({
                    "run_id": item.get("run_id", "-"),
                    "타입": item.get("scenario_type", "general"),
                    "시나리오": item.get("scenario_id", "-"),
                    "타겟 IP": item.get("target_ip", "-"),
                    "상태": item.get("status", "-"),
                    "실행자": item.get("requested_by", "-"),
                })

            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    # 4. 실행 중 시나리오
    with right:
        st.markdown("### 실행 중 시나리오")

        if not running_runs:
            st.info("현재 실행 중인 시나리오가 없습니다.")
        else:
            for item in running_runs:
                with st.container(border=True):
                    st.write(f"시나리오: **{item.get('scenario_id', '-')}**")
                    st.write(f"타겟 IP: **{item.get('target_ip', '-')}**")
                    st.write(f"실행자: **{item.get('requested_by', '-')}**")
                    st.write(f"시작 시간: **{item.get('started_at', '-')}**")

    st.divider()

    # 5. 탐지 상위 룰
    col_rule, col_event = st.columns([5, 5])

    with col_rule:
        st.markdown("### 최근 탐지 룰 TOP (최근 1시간 기준)")

        if not rule_counter:
            st.info("최근 탐지된 룰이 없습니다.")
        else:
            top_rules = sorted(rule_counter.items(), key=lambda x: x[1], reverse=True)[:5]
            st.dataframe(
                pd.DataFrame(top_rules, columns=["탐지 룰", "건수"]),
                use_container_width=True,
                hide_index=True,
            )

    with col_event:
        st.markdown("### 이벤트 ID TOP (최근 한시간 기준)")

        if not events:
            st.info("이벤트가 없습니다.")
        else:
            df = pd.DataFrame(events)
            if "event_id" in df.columns:
                event_summary = (
                    df["event_id"]
                    .fillna("-")
                    .astype(str)
                    .value_counts()
                    .head(5)
                    .reset_index()
                )
                event_summary.columns = ["event_id", "count"]
                st.dataframe(event_summary, use_container_width=True, hide_index=True)
            else:
                st.info("event_id 컬럼이 없습니다.")

    st.divider()

    # 6. 정찰 결과 요약
    st.markdown("### 정찰 도구 최신 결과")

    r1, r2, r3 = st.columns(3)
    with r1:
        _render_recon_tool_card("powerview", "PowerView")
    with r2:
        _render_recon_tool_card("pingcastle", "PingCastle")
    with r3:
        _render_recon_tool_card("bloodhound", "BloodHound")