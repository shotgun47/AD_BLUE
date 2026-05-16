import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from api_client import get_scenarios, get_latest_recon_summary, get_latest_recon_result, get_scenario_runs, get_scenario_log
from utils import is_recon_run
from components import render_scenario_card
from config import ATTACK_REQUESTED_BY, VICTIM_URL
from views.recon_bloodhound import render_bloodhound
from metadata import get_recon_recommendation


PINGCASTLE_LATEST_DIR = "/data/recon/pingcastle/latest"
RECON_BASE_DIR = Path("/data/recon")


def _render_recon_run_history():
    col_title, col_refresh = st.columns([8, 2])

    with col_title:
        st.markdown("### 정찰 실행 이력")

    with col_refresh:
        if st.button("새로고침", key="refresh_recon_history"):
            st.rerun()

    try:
        runs = get_scenario_runs(limit=20)
    except Exception as e:
        st.error(f"정찰 실행 이력 조회 실패: {e}")
        return

    if isinstance(runs, dict) and runs.get("result") == "error":
        st.error(runs.get("message", "정찰 실행 이력 조회 실패"))
        return

    recon_runs = [item for item in runs if is_recon_run(item)][:5]

    if not recon_runs:
        st.info("최근 정찰 실행 이력이 없습니다.")
        return

    history_rows = []

    for item in recon_runs:
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
            "도구": item.get("scenario_id", "-"),
            "대상 IP": item.get("target_ip", "-"),
            "상태": display_status,
            "실행자": item.get("requested_by", "-"),
            "시작 시간": item.get("started_at", "-"),
            "종료 시간": item.get("finished_at", "-"),
        })

    history_df = pd.DataFrame(history_rows)

    def highlight_status(val):
        text = str(val)
        if "running" in text:
            return "background-color: #dbeafe; color: #1d4ed8; font-weight: bold;"
        elif "success" in text:
            return "background-color: #ecfdf5; color: #166534; font-weight: bold;"
        elif "failed" in text:
            return "background-color: #fef2f2; color: #991b1b; font-weight: bold;"
        return ""

    styled_df = history_df.style.map(
        highlight_status,
        subset=["상태"]
    )

    st.dataframe(styled_df, use_container_width=True, hide_index=True)

    st.markdown("### 정찰 실행 로그 확인")

    run_options = [
        row["run_id"]
        for row in history_rows
        if row.get("run_id") not in (None, "-")
    ]

    if not run_options:
        st.info("조회 가능한 정찰 실행 로그가 없습니다.")
        return

    col_run_log, col_log_lines, col_load_log, col_load_refresh = st.columns([3.5, 3.5, 1.5, 1.5])

    with col_run_log:
        selected_run_id = st.selectbox(
            "로그를 볼 정찰 실행 선택",
            options=run_options,
            key="recon_selected_run_id"
        )

    with col_log_lines:
        tail = st.selectbox(
            "불러올 로그 줄 수",
            [50, 100, 200, 500],
            index=2,
            key="recon_selected_log_tail"
        )

    with col_load_log:
        if st.button("로그 불러오기", key="recon_load_selected_log"):
            try:
                st.session_state["recon_selected_run_log"] = get_scenario_log(
                    selected_run_id,
                    tail=tail
                )
            except Exception as e:
                st.session_state["recon_selected_run_log"] = {
                    "result": "error",
                    "message": str(e),
                }

    with col_load_refresh:
        if st.button("로그 새로고침", key="recon_refresh_selected_log"):
            try:
                st.session_state["recon_selected_run_log"] = get_scenario_log(
                    selected_run_id,
                    tail=tail
                )
            except Exception as e:
                st.session_state["recon_selected_run_log"] = {
                    "result": "error",
                    "message": str(e),
                }

    cached_log = st.session_state.get("recon_selected_run_log")

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
        st.info("정찰 실행 이력을 선택하고 로그를 불러오세요.")

def _list_recon_runs(tool: str):
    tool_dir = RECON_BASE_DIR / tool

    if not tool_dir.exists():
        return []

    runs = []
    for d in sorted(tool_dir.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        if d.name == "latest":
            continue

        summary_path = d / "summary.json"
        if not summary_path.exists():
            continue

        runs.append(d.name)

    return runs


def _load_recon_summary(tool: str, run_id: str):
    path = RECON_BASE_DIR / tool / run_id / "summary.json"

    if not path.exists():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_latest_recon_summary(tool: str):
    path = RECON_BASE_DIR / tool / "latest" / "summary.json"

    if not path.exists():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _to_int(value, default=0):
    try:
        if value is None or value == "-":
            return default
        return int(value)
    except Exception:
        return default


def _delta_text(before, after, lower_better=True):
    before_num = _to_int(before)
    after_num = _to_int(after)
    diff = after_num - before_num

    if diff == 0:
        return "변화 없음", "same"

    if lower_better:
        if diff < 0:
            return f"{abs(diff)} 감소", "good"
        return f"{diff} 증가", "bad"

    if diff > 0:
        return f"{diff} 증가", "good"
    return f"{abs(diff)} 감소", "bad"


def _status_badge(status: str):
    if status == "good":
        return "✅ 개선"
    if status == "bad":
        return "⚠️ 악화/증가"
    return "➖ 유지"


def _render_compare_cards(title: str, before_run: str, before: dict, latest: dict, fields: list[tuple]):
    st.markdown(f"### {title}")

    left, arrow, right = st.columns([4.5, 0.6, 4.5])

    with left:
        with st.container(border=True):
            st.markdown(f"#### 이전 실행")
            st.caption(before_run)

            for key, label, lower_better in fields:
                st.metric(label, before.get(key, "-"))

    with arrow:
        st.markdown(
            """
            <div style="
                height: 100%;
                min-height: 220px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 2rem;
                font-weight: 800;
                color: #6b7280;
                padding-top: 4.5rem;
            ">
                &gt;&gt;
            </div>
            """,
            unsafe_allow_html=True,
        )

    with right:
        with st.container(border=True):
            st.markdown("#### 최신 실행")
            st.caption("latest")

            for key, label, lower_better in fields:
                value_before = before.get(key, 0)
                value_after = latest.get(key, 0)
                delta_label, status = _delta_text(value_before, value_after, lower_better=lower_better)

                if status == "same":
                    st.metric(label, value_after)
                else:
                    delta = f"-{delta_label.replace(' 감소', '')}" if "감소" in delta_label else delta_label
                    st.metric(label, value_after, delta=delta)
                # delta = f"-{delta_label.replace(' 감소', '')}" if "감소" in delta_label else delta_label
                # st.metric(label, value_after, delta=delta)

    rows = []
    for key, label, lower_better in fields:
        before_value = before.get(key, 0)
        latest_value = latest.get(key, 0)
        delta_label, status = _delta_text(before_value, latest_value, lower_better=lower_better)

        rows.append({
            "항목": label,
            "선택"
            "이전 실행": before_value,
            "최신 실행": latest_value,
            "변화": delta_label,
            "판단": _status_badge(status),
        })

    st.markdown("#### 변화 요약")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _risk_id_set(summary: dict):
    values = summary.get("risk_ids") or []
    return {str(v) for v in values if v}


def _risk_item_map(summary: dict):
    result = {}
    for item in summary.get("risk_items") or []:
        risk_id = item.get("risk_id")
        if risk_id:
            result[str(risk_id)] = item
    return result


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


# ----------------------------------
# PingCastle
# ----------------------------------

def _render_pingcastle_summary():
    try:
        summary = get_latest_recon_summary("pingcastle")
        result = get_latest_recon_result("pingcastle")
    except Exception as e:
        st.error(f"PingCastle 결과 조회 실패: {e}")
        return

    if summary.get("result") == "empty":
        st.info("아직 저장된 PingCastle 결과가 없습니다.")
        return

    if summary.get("result") == "error":
        st.error(summary.get("message", "조회 실패"))
        return

    st.markdown("### PingCastle HealthCheck 결과")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("도메인", summary.get("domain", "-"))
    m2.metric("대상", summary.get("target_ip", "-"))
    m3.metric("상태", summary.get("status", "-"))
    m4.metric("XML 생성", "OK" if summary.get("xml_generated") else "-")

    artifacts = summary.get("artifacts") or result.get("saved_artifacts") or []

    if artifacts:
        st.markdown("#### 보고서 파일")
        for artifact in artifacts:
            filename = artifact.get("filename")
            latest_path = artifact.get("latest_path")
            mime_type = artifact.get("mime_type", "application/octet-stream")

            if not latest_path or not os.path.exists(latest_path):
                continue

            with open(latest_path, "rb") as f:
                st.download_button(
                    label=f"⬇ {filename} 다운로드",
                    data=f,
                    file_name=filename,
                    mime=mime_type,
                    key=f"download_pingcastle_{filename}",
                )

    html_name = summary.get("html_report")
    html_path = None

    if html_name:
        candidate = Path(PINGCASTLE_LATEST_DIR) / html_name
        if candidate.exists():
            html_path = candidate

    if html_path:
        st.markdown("#### HTML 보고서 미리보기")

        height = st.slider(
            "PingCastle 보고서 높이(px)",
            min_value=500,
            max_value=1400,
            value=900,
            step=100,
            key="pingcastle_report_height",
        )

        html_content = html_path.read_text(encoding="utf-8", errors="replace")
        components.html(html_content, height=height, scrolling=True)
    else:
        st.info("HTML 보고서 파일을 찾지 못했습니다. 다운로드 파일 또는 실행 로그를 확인하세요.")

    with st.expander("원본 저장 JSON 보기", expanded=False):
        st.json(result)


def _render_pingcastle_risk_diff(before: dict, latest: dict):
    before_ids = _risk_id_set(before)
    latest_ids = _risk_id_set(latest)

    resolved = sorted(before_ids - latest_ids)
    new = sorted(latest_ids - before_ids)
    remaining = sorted(before_ids & latest_ids)

    before_map = _risk_item_map(before)
    latest_map = _risk_item_map(latest)

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("#### ✅ 해결된 Risk")
        if not resolved:
            st.info("해결된 Risk가 없습니다.")
        else:
            for risk_id in resolved[:20]:
                item = before_map.get(risk_id, {})
                st.write(f"- **{risk_id}** ({item.get('points', '-') }점)")
                if item.get("rationale"):
                    st.caption(item.get("rationale"))

    with c2:
        st.markdown("#### ⚠️ 신규 Risk")
        if not new:
            st.info("신규 Risk가 없습니다.")
        else:
            for risk_id in new[:20]:
                item = latest_map.get(risk_id, {})
                st.write(f"- **{risk_id}** ({item.get('points', '-') }점)")
                if item.get("rationale"):
                    st.caption(item.get("rationale"))

    with c3:
        st.markdown("#### ➖ 잔존 Risk")
        if not remaining:
            st.info("잔존 Risk가 없습니다.")
        else:
            for risk_id in remaining[:20]:
                item = latest_map.get(risk_id) or before_map.get(risk_id, {})
                st.write(f"- **{risk_id}** ({item.get('points', '-') }점)")


def _render_pingcastle_top_risks(summary: dict, title: str):
    risks = summary.get("top_risks") or []

    with st.container(border=True):
        st.markdown(f"#### {title}")

        if not risks:
            st.info("상위 Risk 정보가 없습니다.")
            return

        rows = []
        for item in risks:
            rows.append({
                "Points": item.get("points", "-"),
                "Category": item.get("category", "-"),
                "RiskId": item.get("risk_id", "-"),
                "Rationale": item.get("rationale", "-"),
            })

        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _render_pingcastle_compare():
    runs = _list_recon_runs("pingcastle")
    latest = _load_latest_recon_summary("pingcastle")

    if not runs or not latest:
        st.info("비교할 PingCastle 실행 결과가 부족합니다. 최소 2회 이상 실행 후 비교할 수 있습니다.")
        return

    selected_run = st.selectbox(
        "비교할 이전 PingCastle 실행 선택",
        runs,
        index=min(1, len(runs) - 1) if len(runs) > 1 else 0,
        key="pingcastle_compare_run",
    )

    before = _load_recon_summary("pingcastle", selected_run)
    if not before:
        st.error("선택한 PingCastle summary.json을 읽지 못했습니다.")
        return

    fields = [
        ("global_score", "Global Score", True),
        ("stale_objects_score", "Stale Objects", True),
        ("privileged_group_score", "Privileged Group", True),
        ("trust_score", "Trust", True),
        ("anomaly_score", "Anomaly", True),
        ("risk_rule_total", "전체 Risk Rule", True),
        ("risk_rule_positive_count", "점수 있는 Risk", True),
        ("risk_rule_high_point_count", "10점 이상 Risk", True),
        ("risk_category_privileged_accounts", "PrivilegedAccounts", True),
        ("risk_category_stale_objects", "StaleObjects", True),
        ("risk_category_anomalies", "Anomalies", True),
    ]

    _render_compare_cards(
        title="PingCastle 전후 비교",
        before_run=selected_run,
        before=before,
        latest=latest,
        fields=fields,
    )

    st.markdown("#### RiskId 변화")
    _render_pingcastle_risk_diff(before, latest)

    st.divider()

    left, right = st.columns(2)
    with left:
        _render_pingcastle_top_risks(before, "이전 실행 Top Risks")
    with right:
        _render_pingcastle_top_risks(latest, "최신 실행 Top Risks")

    st.markdown("#### 해석 기준")
    st.caption(
        "PingCastle 점수와 Risk Rule 개수는 일반적으로 낮아질수록 개선입니다. "
        "RiskId 변화는 이전 실행 대비 해결/신규/잔존 항목을 보여줍니다."
    )


# ----------------------------------
# PowerView
# ----------------------------------
def _render_powerview_summary():
    summary = get_latest_recon_summary("powerview")
    result = get_latest_recon_result("powerview")

    if summary.get("result") == "empty":
        st.info("아직 저장된 PowerView 정찰 결과가 없습니다.")
        return

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("총 사용자 수", summary.get("total_users", 0))
    c2.metric("총 그룹 수", summary.get("total_groups", 0))
    c3.metric("총 컴퓨터 수", summary.get("total_computers", 0))
    c4.metric("🎯 SPN 계정 수", summary.get("spn_users_count", 0))
    c5.metric("🔓 NoPreAuth 계정 수", summary.get("no_preauth_users_count", 0))

    c6, c7, c8, c9 = st.columns(4)
    c6.metric("👑 Domain Admins", summary.get("domain_admins_count", 0))
    c7.metric("Enterprise Admins", summary.get("enterprise_admins_count", 0))
    c8.metric("🌐 DnsAdmins", summary.get("dns_admins_count", 0))
    c9.metric("🧩 Interesting ACLs", summary.get("interesting_acls_count", 0))

    recommendations = result.get("recommendations") or []
    
    st.markdown("### 추천 공격/점검 시나리오")

    if not recommendations:
        st.info("현재 PowerView 결과 기준으로 추천 시나리오가 없습니다.")
    else:
        for rec in recommendations:
            rec_info = get_recon_recommendation(str(rec))

            if isinstance(rec_info, dict):
                rec_title = rec_info.get("title", "정찰 결과 기반 주의 항목")
                rec_message = rec_info.get("message", str(rec))
            else:
                rec_title = "정찰 결과 기반 주의 항목"
                rec_message = str(rec_info)

            st.markdown(
                f"""
                <div style="
                    border:1px solid #e5e7eb;
                    border-left:5px solid #f59e0b;
                    border-radius:12px;
                    padding:10px 12px;
                    margin-bottom:8px;
                    background:#fffbeb;
                ">
                    <div style="
                        font-size:0.86rem;
                        color:#92400e;
                        font-weight:800;
                        margin-bottom:4px;
                    ">
                        💡 {rec_title}
                    </div>
                    <div style="
                        font-size:0.95rem;
                        color:#374151;
                        line-height:1.55;
                    ">
                        {rec_message}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def _render_powerview_compare():
    runs = _list_recon_runs("powerview")
    latest = _load_latest_recon_summary("powerview")

    if not runs or not latest:
        st.info("비교할 PowerView 실행 결과가 부족합니다. 최소 2회 이상 실행 후 비교할 수 있습니다.")
        return

    before_options = [r for r in runs if r != "latest"]

    if not before_options:
        st.info("선택 가능한 이전 PowerView 실행 결과가 없습니다.")
        return

    selected_run = st.selectbox(
        "비교할 이전 PowerView 실행 선택",
        before_options,
        index=min(1, len(before_options) - 1) if len(before_options) > 1 else 0,
        key="powerview_compare_run",
    )

    before = _load_recon_summary("powerview", selected_run)
    if not before:
        st.error("선택한 PowerView summary.json을 읽지 못했습니다.")
        return

    fields = [
        ("no_preauth_users_count", "NoPreAuth 계정", True),
        ("spn_users_count", "SPN 계정", True),
        ("domain_admins_count", "Domain Admins", True),
        ("enterprise_admins_count", "Enterprise Admins", True),
        ("dns_admins_count", "DnsAdmins", True),
        ("interesting_acls_count", "Interesting ACLs", True),
        ("total_users", "총 사용자", False),
        ("total_groups", "총 그룹", False),
        ("total_computers", "총 컴퓨터", False),
    ]

    _render_compare_cards(
        title="PowerView 전후 비교",
        before_run=selected_run,
        before=before,
        latest=latest,
        fields=fields,
    )

    st.markdown("#### 해석 기준")
    st.caption(
        "NoPreAuth, SPN, 관리자 그룹, DnsAdmins, Interesting ACLs는 일반적으로 줄어드는 것이 개선입니다. "
        "총 사용자/그룹/컴퓨터 수는 환경 변화 참고용입니다."
    )



# ----------------------------------
# 대시보드 로드
# ----------------------------------

def render_recon():
    st.title("🔍 정찰")
    st.caption("PowerView, PingCastle, BloodHound 등 AD 정찰 결과를 확인합니다.")


    st.divider()
    _render_recon_run_history()


    st.divider()

    st.subheader("🛠️ 도구 실행")

    col_target, col_user = st.columns([6, 4])
    with col_target:
        target_ip = st.text_input("대상 IP", value=VICTIM_URL, key="recon_target_ip")
    with col_user:
        requested_by = st.text_input("실행자", value=ATTACK_REQUESTED_BY, key="recon_requested_by")

    try:
        scenarios = get_scenarios()
    except Exception as e:
        st.error(f"시나리오 목록 조회 실패: {e}")
        return

    grouped = _group_scenarios(scenarios)
    recon_scenarios = grouped["tools"]

    # st.markdown("### 🛠️ 도구 실행")

    if not recon_scenarios:
        st.info("표시할 정찰 도구가 없습니다.")
    else:
        for scenario in recon_scenarios:
            render_scenario_card(scenario, target_ip, requested_by)

    st.divider()

    st.markdown("### 정찰 결과 요약")

    tab1, tab2, tab3 = st.tabs(["PowerView", "PingCastle", "BloodHound"])

    with tab1:
        try:
            _render_powerview_summary()
        except Exception as e:
            st.error(f"PowerView 결과 조회 실패: {e}")

    with tab2:
        _render_pingcastle_summary()

    with tab3:
        render_bloodhound()

    st.divider()

    st.markdown("### 정찰 결과 비교")
    compare_tool = st.radio(
        "비교할 도구",
        ["PowerView", "PingCastle"],
        horizontal=True,
        key="recon_compare_tool",
    )

    if compare_tool == "PowerView":
        _render_powerview_compare()
    else:
        _render_pingcastle_compare()