"""
정찰 종합 리포트 페이지

PowerView, PingCastle, BloodHound 의 최신 결과를 하나의 HTML 리포트로 통합한다.

- 백엔드의 /recon-results/latest/{tool} 와 /recon-results/latest/{tool}/summary 를 사용
- BloodHound 는 /data/bloodhound/<컬렉션>/graph.html 직접 임베드
- 브라우저 인쇄(Ctrl+P) → PDF 저장 가능하도록 인쇄용 CSS 포함
"""

import json
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from api_client import get_latest_recon_summary, get_latest_recon_result
from components import severity_badge, SEVERITY_ORDER


PINGCASTLE_LATEST_DIR = "/data/recon/pingcastle/latest"
BLOODHOUND_ROOT = "/data/bloodhound"


# ------------------------------------------------------------------
# 위험도 평가 임계값
# ------------------------------------------------------------------
RISK_THRESHOLDS = [
    # (key, label, medium_threshold, high_threshold, description)
    ("spn_users_count", "SPN 계정 수", 1, 5,
     "SPN이 설정된 사용자 계정은 Kerberoasting 공격 대상이 됩니다."),
    ("no_preauth_users_count", "Kerberos PreAuth 비활성 계정", 1, 3,
     "Pre-authentication 이 꺼진 계정은 AS-REP Roasting 공격 대상이 됩니다."),
    ("interesting_acls_count", "Interesting ACL", 1, 5,
     "민감한 ACL 권한이 설정된 객체는 권한 상승 경로가 될 수 있습니다."),
    ("domain_admins_count", "Domain Admins 수", 5, 10,
     "도메인 관리자 계정 수가 많을수록 침해 시 영향 범위가 커집니다."),
    ("enterprise_admins_count", "Enterprise Admins 수", 1, 3,
     "Enterprise Admins 는 포레스트 전역에 영향을 미치므로 최소화해야 합니다."),
    ("dns_admins_count", "DnsAdmins 수", 1, 3,
     "DnsAdmins 는 DC 권한 상승에 악용될 수 있는 경로입니다."),
]


# README 방어 시나리오 매핑
RECOMMENDATION_MAP = {
    "spn_users_count": [
        "서비스 계정 비밀번호 복잡도 강화 및 주기적 변경",
        "AES 암호화만 허용하도록 GPO 설정",
        "Kerberos 티켓 요청 급증 탐지 룰 적용",
    ],
    "no_preauth_users_count": [
        "사용자 계정의 'Do not require Kerberos preauthentication' 옵션 해제",
        "AS-REP 로깅 활성화 및 비정상 요청 알림",
    ],
    "interesting_acls_count": [
        "민감 객체에 대한 ACL 정기 감사",
        "GPO 기반 감사 정책 강화",
        "특권 계정 사용시 알림",
    ],
    "domain_admins_count": [
        "관리자 계정 사용 제한 및 분리",
        "관리자 그룹 변경 감시",
        "Tier 0 자산 접근 통제",
    ],
    "enterprise_admins_count": [
        "Enterprise Admins 그룹은 비워두고 필요시에만 임시 부여",
        "특권 계정 사용 이벤트 알림",
    ],
    "dns_admins_count": [
        "DnsAdmins 멤버 최소화",
        "비정상 시간대 로그인 탐지",
    ],
}


# ------------------------------------------------------------------
# 유틸
# ------------------------------------------------------------------


def _evaluate_severity(value: int, medium_th: int, high_th: int) -> str:
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        value = 0

    if value >= high_th:
        return "high"
    if value >= medium_th:
        return "medium"
    if value > 0:
        return "low"
    return "none"


def _safe_get_summary(tool: str) -> dict:
    try:
        summary = get_latest_recon_summary(tool)
    except Exception as e:
        return {"result": "error", "message": str(e), "tool": tool}

    if not isinstance(summary, dict):
        return {"result": "error", "message": "summary 형식 오류", "tool": tool}

    return summary


def _safe_get_result(tool: str) -> dict:
    try:
        result = get_latest_recon_result(tool)
    except Exception as e:
        return {"result": "error", "message": str(e), "tool": tool}

    if not isinstance(result, dict):
        return {"result": "error", "message": "result 형식 오류", "tool": tool}

    return result


def _summary_available(summary: dict) -> bool:
    return summary.get("result") not in ("empty", "error") and summary


def _list_bloodhound_collections():
    if not os.path.isdir(BLOODHOUND_ROOT):
        return []
    dirs = sorted(
        [d for d in Path(BLOODHOUND_ROOT).iterdir() if d.is_dir()],
        reverse=True,
    )
    return [(d.name, d / "graph.html") for d in dirs if (d / "graph.html").exists()]

def _extract_report_defaults(pv_summary: dict, pv_result: dict, pc_summary: dict) -> dict:
    """
    최신 정찰 결과에서 리포트 표지용 기본값을 추출한다.
    사용자가 직접 수정할 수 있도록 text_input의 기본값으로만 사용한다.
    """

    pv_data = pv_result if isinstance(pv_result, dict) else {}
    pc_data = pc_summary if isinstance(pc_summary, dict) else {}

    # PowerView result.json 우선, 없으면 PingCastle summary 사용
    domain = (
        pv_data.get("domain")
        or pc_data.get("domain")
        or st.session_state.get("report_domain")
        or "lab.local"
    )

    target_ip = (
        pv_data.get("target_host")
        or pc_data.get("target_ip")
        or st.session_state.get("last_target_ip")
        or st.session_state.get("report_target_ip")
        or ""
    )

    requested_by = (
        pv_data.get("requested_by")
        or st.session_state.get("last_requested_by")
        or st.session_state.get("report_requested_by")
        or ""
    )

    return {
        "domain": str(domain or ""),
        "target_ip": str(target_ip or ""),
        "requested_by": str(requested_by or ""),
    }


# ------------------------------------------------------------------
# 인쇄용 CSS / 표지
# ------------------------------------------------------------------
def _inject_print_css():
    st.markdown(
        """
        <style>
        @media print {
            /* 사이드바, 헤더 등 인쇄 시 숨김 */
            section[data-testid="stSidebar"],
            header[data-testid="stHeader"],
            div[data-testid="stToolbar"] {
                display: none !important;
            }
            .stApp {
                background: #ffffff !important;
            }
            .recon-report-cover {
                page-break-after: always;
            }
            .report-section {
                page-break-inside: avoid;
            }
        }
        .recon-report-cover {
            border: 1px solid #e5e7eb;
            border-radius: 12px;
            padding: 32px 28px;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #f8fafc 0%, #eef2ff 100%);
        }
        .recon-report-cover h1 {
            margin: 0 0 12px 0;
            font-size: 1.8rem;
        }
        .recon-report-cover .meta {
            color: #374151;
            font-size: 0.95rem;
            line-height: 1.7;
        }
        .report-section h3 {
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 6px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_cover(domain: str, target_ip: str, requested_by: str):
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(
        f"""
        <div class="recon-report-cover">
            <h1>AD 정찰 종합 리포트</h1>
            <div class="meta">
                <div>도메인 : <b>{domain or '-'}</b></div>
                <div>대상 IP : <b>{target_ip or '-'}</b></div>
                <div>생성 일시 : <b>{generated_at}</b></div>
                <div>실행자 : <b>{requested_by or '-'}</b></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------------
# Executive Summary
# ------------------------------------------------------------------
def _render_executive_summary(pv_summary, pc_summary, bh_collections):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 1. Executive Summary")

    # 도구 수집 상태
    s1, s2, s3 = st.columns(3)
    s1.metric("PowerView", "수집됨" if _summary_available(pv_summary) else "없음")
    s2.metric("PingCastle", "수집됨" if _summary_available(pc_summary) else "없음")
    s3.metric("BloodHound", f"{len(bh_collections)} 컬렉션" if bh_collections else "없음")

    # PowerView 핵심 메트릭
    if _summary_available(pv_summary):
        st.markdown("**핵심 자산 현황 (PowerView 기준)**")
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("사용자", pv_summary.get("total_users", 0))
        m2.metric("그룹", pv_summary.get("total_groups", 0))
        m3.metric("컴퓨터", pv_summary.get("total_computers", 0))
        m4.metric("Domain Admins", pv_summary.get("domain_admins_count", 0))
        m5.metric("Enterprise Admins", pv_summary.get("enterprise_admins_count", 0))

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# 위험 평가
# ------------------------------------------------------------------
def _compute_risks(pv_summary: dict):
    """위험 항목 평가 결과 리스트와 전체 등급 반환"""
    rows = []
    overall = "none"

    if not _summary_available(pv_summary):
        return rows, overall

    for key, label, mid, high, desc in RISK_THRESHOLDS:
        value = pv_summary.get(key, 0)
        try:
            value_int = int(value or 0)
        except (TypeError, ValueError):
            value_int = 0

        severity = _evaluate_severity(value_int, mid, high)
        rows.append({
            "key": key,
            "항목": label,
            "값": value_int,
            "등급": severity,
            "설명": desc,
        })

        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[overall]:
            overall = severity

    return rows, overall


def _render_risk_assessment(pv_summary: dict):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 2. 위험 항목 평가")

    rows, overall = _compute_risks(pv_summary)

    if not rows:
        st.info("PowerView 결과가 없어 위험도를 평가할 수 없습니다.")
        st.markdown('</div>', unsafe_allow_html=True)
        return overall

    st.markdown(
        f"전체 위험 등급 : {severity_badge(overall)}",
        unsafe_allow_html=True,
    )

    # 표로 출력
    table_html = """
    <table style="width:100%; border-collapse:collapse; margin-top:10px;">
        <thead>
            <tr style="background:#f9fafb;">
                <th style="padding:8px; border:1px solid #e5e7eb; text-align:left;">항목</th>
                <th style="padding:8px; border:1px solid #e5e7eb; text-align:right;">값</th>
                <th style="padding:8px; border:1px solid #e5e7eb; text-align:center;">등급</th>
                <th style="padding:8px; border:1px solid #e5e7eb; text-align:left;">설명</th>
            </tr>
        </thead>
        <tbody>
    """
    for r in rows:
        table_html += (
            "<tr>"
            f"<td style='padding:8px; border:1px solid #e5e7eb;'>{r['항목']}</td>"
            f"<td style='padding:8px; border:1px solid #e5e7eb; text-align:right;'>{r['값']}</td>"
            f"<td style='padding:8px; border:1px solid #e5e7eb; text-align:center;'>{severity_badge(r['등급'])}</td>"
            f"<td style='padding:8px; border:1px solid #e5e7eb; color:#374151;'>{r['설명']}</td>"
            "</tr>"
        )
    table_html += "</tbody></table>"

    st.markdown(table_html, unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")
    return overall


# ------------------------------------------------------------------
# PowerView 상세
# ------------------------------------------------------------------
def _render_powerview_section(pv_summary, pv_result):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 3. PowerView 상세")

    if not _summary_available(pv_summary):
        st.info("PowerView 결과가 없습니다.")
        st.markdown('</div>', unsafe_allow_html=True)
        return

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("총 사용자", pv_summary.get("total_users", 0))
    c2.metric("총 그룹", pv_summary.get("total_groups", 0))
    c3.metric("총 컴퓨터", pv_summary.get("total_computers", 0))
    c4.metric("SPN 계정", pv_summary.get("spn_users_count", 0))
    c5.metric("NoPreAuth 계정", pv_summary.get("no_preauth_users_count", 0))

    c6, c7, c8, c9 = st.columns(4)
    c6.metric("Domain Admins", pv_summary.get("domain_admins_count", 0))
    c7.metric("Enterprise Admins", pv_summary.get("enterprise_admins_count", 0))
    c8.metric("DnsAdmins", pv_summary.get("dns_admins_count", 0))
    c9.metric("Interesting ACLs", pv_summary.get("interesting_acls_count", 0))

    # 상세 리스트 (result.json 안에 사용자/그룹 목록이 있으면 표시)
    detail_keys = [
        ("domain_admins", "Domain Admins 목록"),
        ("enterprise_admins", "Enterprise Admins 목록"),
        ("dns_admins", "DnsAdmins 목록"),
        ("spn_users", "SPN 계정 목록"),
        ("no_preauth_users", "NoPreAuth 계정 목록"),
        ("interesting_acls", "Interesting ACLs 목록"),
    ]

    for key, title in detail_keys:
        items = pv_result.get(key) if isinstance(pv_result, dict) else None
        if not items:
            continue

        with st.expander(f"{title} ({len(items)})", expanded=False):
            try:
                if isinstance(items[0], dict):
                    st.dataframe(pd.DataFrame(items), use_container_width=True, hide_index=True)
                else:
                    st.write(items)
            except Exception:
                st.json(items)

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# PingCastle 상세
# ------------------------------------------------------------------
def _render_pingcastle_section(pc_summary, pc_result):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 4. PingCastle 상세")

    if not _summary_available(pc_summary):
        st.info("PingCastle 결과가 없습니다.")
        st.markdown('</div>', unsafe_allow_html=True)
        return

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("도메인", pc_summary.get("domain", "-"))
    m2.metric("대상", pc_summary.get("target_ip", "-"))
    m3.metric("상태", pc_summary.get("status", "-"))
    m4.metric("XML 생성", "OK" if pc_summary.get("xml_generated") else "-")

    # HTML 보고서 임베드
    html_name = pc_summary.get("html_report")
    html_path = None
    if html_name:
        candidate = Path(PINGCASTLE_LATEST_DIR) / html_name
        if candidate.exists():
            html_path = candidate

    if html_path:
        st.markdown("#### HealthCheck HTML 보고서")
        height = st.slider(
            "PingCastle 보고서 높이 (px)",
            min_value=500, max_value=1400, value=900, step=100,
            key="report_pingcastle_height",
        )
        try:
            html_content = html_path.read_text(encoding="utf-8", errors="replace")
            components.html(html_content, height=height, scrolling=True)
        except Exception as e:
            st.error(f"PingCastle HTML 로드 실패: {e}")
    else:
        st.info("HTML 보고서 파일을 찾을 수 없습니다.")

    # 다운로드 버튼
    artifacts = []
    if isinstance(pc_summary.get("artifacts"), list):
        artifacts = pc_summary["artifacts"]
    elif isinstance(pc_result, dict) and isinstance(pc_result.get("saved_artifacts"), list):
        artifacts = pc_result["saved_artifacts"]

    if artifacts:
        st.markdown("#### 보고서 원본 파일")
        for artifact in artifacts:
            filename = artifact.get("filename")
            latest_path = artifact.get("latest_path")
            mime_type = artifact.get("mime_type", "application/octet-stream")
            if not latest_path or not os.path.exists(latest_path):
                continue
            try:
                with open(latest_path, "rb") as f:
                    st.download_button(
                        label=f"⬇ {filename} 다운로드",
                        data=f,
                        file_name=filename,
                        mime=mime_type,
                        key=f"report_pc_dl_{filename}",
                    )
            except Exception as e:
                st.error(f"{filename} 다운로드 준비 실패: {e}")

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# BloodHound 상세
# ------------------------------------------------------------------
def _render_bloodhound_section(collections):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 5. BloodHound 그래프")

    if not collections:
        st.info(f"`{BLOODHOUND_ROOT}` 에 graph.html 이 포함된 컬렉션이 없습니다.")
        st.markdown('</div>', unsafe_allow_html=True)
        return

    names = [name for name, _ in collections]
    selected = st.selectbox(
        "리포트에 포함할 컬렉션",
        names,
        index=0,
        key="report_bh_collection",
    )
    selected_path = next(path for name, path in collections if name == selected)

    height = st.slider(
        "BloodHound 그래프 높이 (px)",
        min_value=400, max_value=1200, value=700, step=50,
        key="report_bh_height",
    )

    try:
        html_content = selected_path.read_text(encoding="utf-8")
        components.html(html_content, height=height, scrolling=True)
    except Exception as e:
        st.error(f"BloodHound 그래프 로드 실패: {e}")

    try:
        with open(selected_path, "rb") as f:
            st.download_button(
                label="⬇ BloodHound graph.html 다운로드",
                data=f,
                file_name=f"{selected}_graph.html",
                mime="text/html",
                key=f"report_bh_dl_{selected}",
            )
    except Exception:
        pass

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# 권고사항
# ------------------------------------------------------------------
def _render_recommendations(risk_rows):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 6. 권고사항")

    # 위험도 medium 이상인 항목에 대한 권고만 추림
    triggered = [r for r in risk_rows if SEVERITY_ORDER.get(r["등급"], 0) >= SEVERITY_ORDER["medium"]]

    if not triggered:
        st.success("주요 위험 항목이 감지되지 않았습니다. 정기적인 정찰 결과 모니터링을 유지하세요.")
        # 그래도 기본 권고는 안내
        st.markdown(
            "- LLMNR, NetBIOS 비활성화  \n"
            "- 관리자 계정 사용 제한  \n"
            "- GPO를 통한 감사 정책 강화  \n"
            "- 특권 계정 이벤트 알림"
        )
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown("")
        return

    for r in triggered:
        with st.container(border=True):
            st.markdown(
                f"**{r['항목']}** &nbsp; "
                f"(값: {r['값']}) &nbsp; {severity_badge(r['등급'])}",
                unsafe_allow_html=True,
            )
            recs = RECOMMENDATION_MAP.get(r["key"], [])
            if recs:
                for rec in recs:
                    st.markdown(f"- {rec}")
            else:
                st.markdown("- 관련 항목 모니터링 강화")

    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")


# ------------------------------------------------------------------
# 부록 (원본 데이터)
# ------------------------------------------------------------------
def _render_appendix(pv_result, pc_result):
    st.markdown('<div class="report-section">', unsafe_allow_html=True)
    st.markdown("### 7. 부록 - 원본 데이터")

    with st.expander("PowerView result.json", expanded=False):
        if _summary_available(pv_result):
            st.json(pv_result)
        else:
            st.info("데이터 없음")

    with st.expander("PingCastle result.json", expanded=False):
        if _summary_available(pc_result):
            st.json(pc_result)
        else:
            st.info("데이터 없음")

    st.markdown('</div>', unsafe_allow_html=True)


# ------------------------------------------------------------------
# 메인 엔트리
# ------------------------------------------------------------------
def render_report():
    st.title("정찰 리포트")
    st.caption("PowerView, PingCastle, BloodHound 의 최신 결과를 하나의 리포트로 통합합니다.")

    # 인쇄용 CSS
    _inject_print_css()

    # 데이터 수집
    pv_summary = _safe_get_summary("powerview")
    pv_result = _safe_get_result("powerview")
    pc_summary = _safe_get_summary("pingcastle")
    pc_result = _safe_get_result("pingcastle")
    bh_collections = _list_bloodhound_collections()

    defaults = _extract_report_defaults(
        pv_summary=pv_summary,
        pv_result=pv_result,
        pc_summary=pc_summary,
    )

    # 2. text_input은 key가 있으면 session_state 값이 우선 적용되므로,
    #    최초 진입 또는 새로고침 시 기본값을 명시적으로 채워준다.
    if "report_domain" not in st.session_state:
        st.session_state["report_domain"] = defaults["domain"]

    if "report_target_ip" not in st.session_state:
        st.session_state["report_target_ip"] = defaults["target_ip"]

    if "report_requested_by" not in st.session_state:
        st.session_state["report_requested_by"] = defaults["requested_by"]


    # 상단 입력 / 액션
    with st.container(border=True):
        c1, c2, c3 = st.columns([3, 3, 2])
        with c1:
            domain = st.text_input(
                "도메인",
                value=st.session_state.get("report_domain", "lab.local"),
                key="report_domain",
            )
        with c2:
            target_ip = st.text_input(
                "대상 IP",
                value=st.session_state.get("last_target_ip") or "",
                key="report_target_ip",
            )
        with c3:
            requested_by = st.text_input(
                "실행자",
                value=st.session_state.get("last_requested_by") or "",
                key="report_requested_by",
            )

        c_refresh, c_print = st.columns([1, 1])
        with c_refresh:
            if st.button("최신 결과 다시 불러오기", key="report_refresh"):
                st.rerun()
        with c_print:
            st.caption("PDF 저장이 필요하면 브라우저 인쇄(Ctrl+P) → 'PDF로 저장' 을 사용하세요.")


    # 표지
    _render_cover(domain, target_ip, requested_by)

    # 1. Executive Summary
    _render_executive_summary(pv_summary, pc_summary, bh_collections)

    # 2. 위험 평가
    risk_rows, _ = _compute_risks(pv_summary)
    _render_risk_assessment(pv_summary)

    # 3. PowerView
    _render_powerview_section(pv_summary, pv_result)

    # 4. PingCastle
    _render_pingcastle_section(pc_summary, pc_result)

    # 5. BloodHound
    _render_bloodhound_section(bh_collections)

    # 6. 권고사항
    _render_recommendations(risk_rows)

    # 7. 부록
    _render_appendix(pv_result, pc_result)
