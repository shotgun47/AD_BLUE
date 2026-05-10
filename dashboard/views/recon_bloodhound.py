"""
BloodHound 그래프 뷰어
- /data/bloodhound/ 에 저장된 컬렉션 목록을 나열하고
- 선택한 컬렉션의 graph.html 을 인라인 iframe으로 렌더링한다.
"""

import json
import os
import re
import zipfile
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

BLOODHOUND_ROOT = "/data/bloodhound"



# ------------------------------------------------------------------
# 위험 지표 / 관계 후보 렌더링
# ------------------------------------------------------------------
def _load_bloodhound_jsons(coll_dir: Path):
    """
    BloodHound 수집 결과 폴더에서 zip을 풀고,
    *_users.json, *_groups.json, *_computers.json 등을 읽어온다.
    """
    for z in coll_dir.glob("*.zip"):
        try:
            with zipfile.ZipFile(z) as zf:
                zf.extractall(coll_dir)
        except Exception:
            pass

    data = {
        "users": [],
        "groups": [],
        "computers": [],
        "domains": [],
        "gpos": [],
        "ous": [],
        "containers": [],
    }

    for j in coll_dir.glob("*.json"):
        for key in data.keys():
            if j.name.endswith(f"_{key}.json"):
                try:
                    payload = json.loads(j.read_text(encoding="utf-8"))
                    data[key] = payload.get("data", [])
                except Exception:
                    pass
                break

    return data


def _build_sid_map(data):
    sid2name = {}

    for arr in data.values():
        for obj in arr:
            sid = obj.get("ObjectIdentifier")
            name = obj.get("Properties", {}).get("name", sid)
            if sid:
                sid2name[sid] = name

    return sid2name


def _short_name(name):
    if not name:
        return "-"
    return str(name).split("@")[0]


def _analyze_bloodhound_data(coll_dir: Path):
    data = _load_bloodhound_jsons(coll_dir)
    sid2name = _build_sid_map(data)

    kerberoastable = []
    asreproastable = []
    unconstrained_users = []
    unconstrained_computers = []
    admin_count_users = []
    high_value_groups = {}

    high_value_names = {
        "DOMAIN ADMINS",
        "ENTERPRISE ADMINS",
        "SCHEMA ADMINS",
        "ADMINISTRATORS",
        "ACCOUNT OPERATORS",
        "BACKUP OPERATORS",
        "SERVER OPERATORS",
        "PRINT OPERATORS",
        "DNSADMINS",
        "GROUP POLICY CREATOR OWNERS",
        "DOMAIN CONTROLLERS",
        "REMOTE DESKTOP USERS",
    }

    for user in data["users"]:
        props = user.get("Properties", {})
        name = props.get("name", "-")
        spns = props.get("serviceprincipalnames", [])

        if spns and "KRBTGT" not in str(name).upper():
            kerberoastable.append({
                "name": name,
                "short_name": _short_name(name),
                "enabled": props.get("enabled"),
                "spn_count": len(spns),
                "spns": spns,
            })

        if props.get("dontreqpreauth"):
            asreproastable.append({
                "name": name,
                "short_name": _short_name(name),
                "enabled": props.get("enabled"),
            })

        if props.get("unconstraineddelegation"):
            unconstrained_users.append({
                "name": name,
                "short_name": _short_name(name),
                "enabled": props.get("enabled"),
            })

        if props.get("admincount"):
            admin_count_users.append({
                "name": name,
                "short_name": _short_name(name),
                "enabled": props.get("enabled"),
            })

    for computer in data["computers"]:
        props = computer.get("Properties", {})
        if props.get("unconstraineddelegation"):
            name = props.get("name", "-")
            unconstrained_computers.append({
                "name": name,
                "short_name": _short_name(name),
                "enabled": props.get("enabled"),
            })

    for group in data["groups"]:
        props = group.get("Properties", {})
        group_name = props.get("name", "")
        short_group_name = group_name.split("@")[0].upper()

        if short_group_name not in high_value_names:
            continue

        members = []
        for member in group.get("Members", []):
            member_sid = member.get("ObjectIdentifier")
            member_name = sid2name.get(member_sid, member_sid)
            members.append({
                "group": group_name,
                "group_short": _short_name(group_name),
                "member_type": member.get("ObjectType"),
                "member_name": member_name,
                "member_short": _short_name(member_name),
            })

        if members:
            high_value_groups[group_name] = members

    domain_info = {}
    if data["domains"]:
        props = data["domains"][0].get("Properties", {})
        domain_info = {
            "name": props.get("name"),
            "functional_level": props.get("functionallevel"),
        }

    domain_name = domain_info.get("name", "")
    da_members = set()

    for key in [
        f"DOMAIN ADMINS@{domain_name}",
        "DOMAIN ADMINS",
    ]:
        for member in high_value_groups.get(key, []):
            da_members.add(member.get("member_name"))

    for item in kerberoastable:
        item["is_domain_admin"] = item.get("name") in da_members

    high_value_member_count = sum(len(v) for v in high_value_groups.values())

    return {
        "collection": coll_dir.name,
        "domain": domain_info,
        "stats": {
            "users": len(data["users"]),
            "groups": len(data["groups"]),
            "computers": len(data["computers"]),
            "gpos": len(data["gpos"]),
            "ous": len(data["ous"]),
        },
        "kerberoastable": kerberoastable,
        "asreproastable": asreproastable,
        "admin_count_users": admin_count_users,
        "unconstrained_delegation": {
            "users": unconstrained_users,
            "computers": unconstrained_computers,
        },
        "high_value_groups": high_value_groups,
        "summary_counts": {
            "kerberoastable": len(kerberoastable),
            "asreproastable": len(asreproastable),
            "admin_count_users": len(admin_count_users),
            "unconstrained_users": len(unconstrained_users),
            "unconstrained_computers": len(unconstrained_computers),
            "high_value_groups": len(high_value_groups),
            "high_value_members": high_value_member_count,
            "kerberoastable_domain_admins": sum(
                1 for item in kerberoastable
                if item.get("is_domain_admin")
            ),
        },
    }


def _render_list_table(title: str, rows: list[dict], columns: list[str], empty_message: str):
    st.markdown(f"#### {title}")

    if not rows:
        st.info(empty_message)
        return

    df = pd.DataFrame(rows)

    visible_columns = [c for c in columns if c in df.columns]
    if visible_columns:
        df = df[visible_columns]

    st.dataframe(df, use_container_width=True, hide_index=True)


def _render_high_value_groups(high_value_groups: dict):
    st.markdown("#### 고가치 그룹 멤버십")

    if not high_value_groups:
        st.info("고가치 그룹 멤버십 정보가 없습니다.")
        return

    rows = []
    for group_name, members in high_value_groups.items():
        for member in members:
            rows.append({
                "그룹": member.get("group_short"),
                "멤버": member.get("member_short"),
                "타입": member.get("member_type"),
            })

    if not rows:
        st.info("고가치 그룹 멤버가 없습니다.")
        return

    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _build_relationship_candidates(analysis: dict) -> list[dict]:
    """
    BloodHound JSON에서 직접 확인 가능한 단일 관계/속성을
    경로 후보처럼 표현한다.

    주의:
    - 실제 BloodHound 최단 경로 계산 결과가 아님
    - MemberOf, HasSPN, DontReqPreAuth, AdminCount, UnconstrainedDelegation처럼
      JSON에 존재하는 단일 근거만 사용
    """
    rows = []

    # 1. 고가치 그룹 멤버십: 계정/그룹 -> MemberOf -> 고가치 그룹
    for group_name, members in analysis.get("high_value_groups", {}).items():
        for member in members:
            rows.append({
                "구분": "고가치 그룹 멤버십",
                "시작 객체": member.get("member_short") or member.get("member_name"),
                "관계": "MemberOf",
                "대상 객체": member.get("group_short") or group_name,
                "근거": "groups.json Members",
                "위험 설명": "고가치 그룹에 직접 포함된 객체입니다.",
            })

    # 2. Kerberoasting 후보: 계정 -> HasSPN -> Kerberoastable 후보
    for item in analysis.get("kerberoastable", []):
        spns = item.get("spns") or []
        rows.append({
            "구분": "Kerberoasting 후보",
            "시작 객체": item.get("short_name") or item.get("name"),
            "관계": "HasSPN",
            "대상 객체": "Kerberoastable 후보",
            "근거": "user.Properties.serviceprincipalnames",
            "위험 설명": f"SPN {len(spns)}개 확인: {', '.join(spns[:2])}",
        })

    # 3. AS-REP Roasting 후보: 계정 -> DontReqPreAuth -> AS-REP Roastable 후보
    for item in analysis.get("asreproastable", []):
        rows.append({
            "구분": "AS-REP Roasting 후보",
            "시작 객체": item.get("short_name") or item.get("name"),
            "관계": "DontReqPreAuth",
            "대상 객체": "AS-REP Roastable 후보",
            "근거": "user.Properties.dontreqpreauth",
            "위험 설명": "Kerberos 사전 인증이 필요하지 않은 계정입니다.",
        })

    # 4. AdminCount 사용자: 계정 -> AdminCount -> 보호 대상 이력/고권한 이력 후보
    for item in analysis.get("admin_count_users", []):
        rows.append({
            "구분": "AdminCount 사용자",
            "시작 객체": item.get("short_name") or item.get("name"),
            "관계": "AdminCount",
            "대상 객체": "Protected/Privileged history 후보",
            "근거": "user.Properties.admincount",
            "위험 설명": "과거 또는 현재 고권한 그룹과 관련된 계정일 수 있습니다.",
        })

    # 5. Unconstrained Delegation 사용자
    for item in analysis.get("unconstrained_delegation", {}).get("users", []):
        rows.append({
            "구분": "위임 설정 후보",
            "시작 객체": item.get("short_name") or item.get("name"),
            "관계": "UnconstrainedDelegation",
            "대상 객체": "Credential Exposure 후보",
            "근거": "user.Properties.unconstraineddelegation",
            "위험 설명": "사용자 계정에 unconstrained delegation 설정이 있습니다.",
        })

    # 6. Unconstrained Delegation 컴퓨터
    for item in analysis.get("unconstrained_delegation", {}).get("computers", []):
        rows.append({
            "구분": "위임 설정 후보",
            "시작 객체": item.get("short_name") or item.get("name"),
            "관계": "UnconstrainedDelegation",
            "대상 객체": "Credential Exposure 후보",
            "근거": "computer.Properties.unconstraineddelegation",
            "위험 설명": "컴퓨터 계정에 unconstrained delegation 설정이 있습니다.",
        })

    return rows


def _render_relationship_candidates(analysis: dict):
    st.markdown("### 관계/위험 후보")
    st.caption(
        "아래 항목은 BloodHound의 실제 최단 경로 계산 결과가 아니라, "
        "JSON에서 직접 확인 가능한 단일 관계와 위험 속성을 경로처럼 표현한 것입니다."
    )

    rows = _build_relationship_candidates(analysis)

    if not rows:
        st.info("표시할 관계/위험 후보가 없습니다.")
        return

    df = pd.DataFrame(rows)

    category_options = ["전체"] + sorted(df["구분"].dropna().unique().tolist())
    selected_category = st.selectbox(
        "후보 유형 필터",
        category_options,
        key="bloodhound_candidate_filter",
    )

    if selected_category != "전체":
        df = df[df["구분"] == selected_category]

    st.dataframe(
        df,
        use_container_width=True,
        hide_index=True,
    )

    with st.expander("경로형 텍스트 보기", expanded=False):
        for _, row in df.iterrows():
            st.markdown(
                f"""
                <div style="
                    border:1px solid #e5e7eb;
                    border-radius:10px;
                    padding:10px 12px;
                    margin-bottom:8px;
                    background:#ffffff;
                ">
                    <div style="font-size:0.85rem; color:#6b7280; font-weight:700;">
                        {row['구분']} · 근거: {row['근거']}
                    </div>
                    <div style="font-size:1.02rem; font-weight:700; margin-top:4px;">
                        {row['시작 객체']} 
                        <span style="color:#6b7280;">→ {row['관계']} →</span>
                        {row['대상 객체']}
                    </div>
                    <div style="font-size:0.88rem; color:#4b5563; margin-top:4px;">
                        {row['위험 설명']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def _render_bloodhound_risk_summary(coll_dir: Path):
    st.divider()
    
    st.markdown("### 위험 지표 요약")
    st.caption(
        "PowerView와 중복되는 SPN/NoPreAuth 계정 수 요약은 제외하고, "
        "BloodHound JSON에서 직접 확인 가능한 고가치 그룹 멤버십과 "
        "Unconstrained Delegation 관계를 요약합니다. "
        "실제 최단 공격 경로 계산 결과는 아닙니다."
    )

    analysis = _analyze_bloodhound_data(coll_dir)

    counts = analysis["summary_counts"]
    stats = analysis["stats"]

    m1, m2, m3 = st.columns(3)
    m1.metric("고가치 그룹에 속한 멤버 수", counts.get("high_value_members", 0))
    m2.metric("Unconstrained Users", counts.get("unconstrained_users", 0))
    m3.metric("Unconstrained Computers", counts.get("unconstrained_computers", 0))

    tab1, tab2 = st.tabs([
        "고가치 그룹",
        "위임 설정",
    ])

    with tab1:
        _render_high_value_groups(analysis["high_value_groups"])

    with tab2:
        left, right = st.columns(2)

        with left:
            _render_list_table(
                "Unconstrained Delegation 사용자",
                analysis["unconstrained_delegation"]["users"],
                ["short_name", "enabled"],
                "Unconstrained Delegation 사용자 계정이 없습니다.",
            )

        with right:
            _render_list_table(
                "Unconstrained Delegation 컴퓨터",
                analysis["unconstrained_delegation"]["computers"],
                ["short_name", "enabled"],
                "Unconstrained Delegation 컴퓨터가 없습니다.",
            )

    st.divider()
    _render_relationship_candidates(analysis)




# ------------------------------------------------------------------
# 컬렉션 목록 탐색
# ------------------------------------------------------------------
def list_collections(root: str):
    """graph.html 이 존재하는 컬렉션 디렉토리 목록 반환 (최신순)"""
    if not os.path.isdir(root):
        return []
    dirs = sorted(
        [d for d in Path(root).iterdir() if d.is_dir()],
        reverse=True,
    )
    return [(d.name, d / "graph.html") for d in dirs if (d / "graph.html").exists()]


def render_bloodhound():
    st.subheader("BloodHound 그래프 뷰어")
    st.caption("MCP에서 생성한 BloodHound graph.html 결과를 대시보드에서 확인합니다.")

    collections = list_collections(BLOODHOUND_ROOT)

    if not collections:
        st.warning(
            f"`{BLOODHOUND_ROOT}` 에 graph.html 이 포함된 컬렉션이 없습니다. "
            "AI Chat 페이지에서 BloodHound 수집 후 `generate_bloodhound_html` 을 실행하세요."
        )
        return

    col_select, col_info = st.columns([3, 7])

    # ------------------------------------------------------------------
    # 컬렉션 선택
    # ------------------------------------------------------------------
    with col_select:
        collection_names = [name for name, _ in collections]
        selected_name = st.selectbox(
            "컬렉션",
            collection_names,
            index=0,
        )

        selected_html: Path = next(path for name, path in collections if name == selected_name)

        st.divider()
        st.caption(f"파일 경로:\n`{selected_html}`")

        # 파일 다운로드 버튼
        with open(selected_html, "rb") as f:
            st.download_button(
                label="⬇ HTML 다운로드",
                data=f,
                file_name=f"{selected_name}_graph.html",
                mime="text/html",
            )

        st.divider()
        graph_height = st.slider("그래프 높이 (px)", min_value=400, max_value=1200, value=800, step=50)


    # ------------------------------------------------------------------
    # 그래프 렌더링
    # ------------------------------------------------------------------
    with col_info:
        st.markdown(f"📊 {selected_name}")

        html_content = selected_html.read_text(encoding="utf-8")

        # 메타 정보 파싱 (graph.html 의 <title> 태그 등에서 노드/엣지 수 추출 시도)
        node_match = re.search(r'"node_count"\s*:\s*(\d+)', html_content)
        edge_match = re.search(r'"edge_count"\s*:\s*(\d+)', html_content)

        if node_match or edge_match:
            col1, col2 = st.columns(2)
            if node_match:
                col1.metric("노드 수", node_match.group(1))
            if edge_match:
                col2.metric("엣지 수", edge_match.group(1))

        components.html(html_content, height=graph_height, scrolling=True)

    # ------------------------------------------------------------------
    # 
    # ------------------------------------------------------------------
    selected_collection_dir = selected_html.parent

    try:
        _render_bloodhound_risk_summary(selected_collection_dir)
    except Exception as e:
        st.error(f"BloodHound 위험 지표 요약 생성 실패: {e}")
