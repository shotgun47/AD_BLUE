import os
from pathlib import Path
import streamlit as st
import streamlit.components.v1 as components

from api_client import get_scenarios, get_latest_recon_summary, get_latest_recon_result
from components import render_scenario_card
from config import ATTACK_REQUESTED_BY, VICTIM_URL
from views.bloodhound import render_bloodhound


PINGCASTLE_LATEST_DIR = "/data/recon/pingcastle/latest"


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


def _render_powerview_summary():
    summary = get_latest_recon_summary("powerview")

    if summary.get("result") == "empty":
        st.info("아직 저장된 PowerView 정찰 결과가 없습니다.")
        return

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("총 사용자 수", summary.get("total_users", 0))
    c2.metric("총 그룹 수", summary.get("total_groups", 0))
    c3.metric("총 컴퓨터 수", summary.get("total_computers", 0))
    c4.metric("SPN 계정 수", summary.get("spn_users_count", 0))
    c5.metric("NoPreAuth 계정 수", summary.get("no_preauth_users_count", 0))

    c6, c7, c8, c9 = st.columns(4)
    c6.metric("Domain Admins", summary.get("domain_admins_count", 0))
    c7.metric("Enterprise Admins", summary.get("enterprise_admins_count", 0))
    c8.metric("DnsAdmins", summary.get("dns_admins_count", 0))
    c9.metric("Interesting ACLs", summary.get("interesting_acls_count", 0))


def _render_generic_summary(tool: str, title: str):
    try:
        summary = get_latest_recon_summary(tool)
    except Exception as e:
        st.error(f"{title} 조회 실패: {e}")
        return

    with st.container(border=True):
        st.markdown(f"### {title}")

        if summary.get("result") == "empty":
            st.info("저장된 결과가 없습니다.")
            return
        
        if summary.get("result") == "error":
            st.error(summary.get("message", "조회 실패"))
            return

        for key, value in list(summary.items())[:10]:
            st.write(f"{key}: **{value}**")


def render_recon():
    st.title("정찰")
    st.caption("PowerView, PingCastle, BloodHound 등 AD 정찰 결과를 확인합니다.")
    st.divider()

    st.subheader("정찰 / 도구")

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

    st.markdown("### 도구 실행")

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