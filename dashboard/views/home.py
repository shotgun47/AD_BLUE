import json
import pandas as pd
import streamlit as st

import zipfile
from pathlib import Path

from api_client import (
    get_health,
    get_events,
    get_event_save_policy,
    get_scenario_runs,
    get_running_scenario_runs,
    get_latest_recon_summary,
)
from utils import safe_json_loads
from metadata import get_event_meta
from components import severity_rank, render_badge_table
from views.defense import _build_detection_summary



# ------------------------------------------------------------------
# 정찰 도구 카드 
# ------------------------------------------------------------------

def _safe_value(summary: dict, key: str, default=0):
    value = summary.get(key, default)
    if value is None:
        return default
    return value


def _render_empty_card(title: str, message: str = "저장된 결과 없음"):
    with st.container(border=True):
        st.markdown(f"**{title}**")
        st.info(message)


def _render_powerview_home_card():
    try:
        summary = get_latest_recon_summary("powerview")
    except Exception as e:
        with st.container(border=True):
            st.markdown("**PowerView**")
            st.error(f"조회 실패: {e}")
        return

    if summary.get("result") == "empty":
        _render_empty_card("PowerView")
        return

    if summary.get("result") == "error":
        with st.container(border=True):
            st.markdown("**PowerView**")
            st.error(summary.get("message", "조회 실패"))
        return

    with st.container(border=True):
        st.markdown("**PowerView**")
        st.caption("AD 객체/취약 설정 요약")

        c1, c2 = st.columns(2)
        c1.metric("사용자", _safe_value(summary, "total_users"))
        c2.metric("컴퓨터", _safe_value(summary, "total_computers"))

        c3, c4 = st.columns(2)
        c3.metric("SPN 계정", _safe_value(summary, "spn_users_count"))
        c4.metric("NoPreAuth", _safe_value(summary, "no_preauth_users_count"))

        st.write(f"Domain Admins: **{_safe_value(summary, 'domain_admins_count')}**")
        st.write(f"DnsAdmins: **{_safe_value(summary, 'dns_admins_count')}**")
        st.write(f"Interesting ACLs: **{_safe_value(summary, 'interesting_acls_count')}**")


def _render_pingcastle_home_card():
    try:
        summary = get_latest_recon_summary("pingcastle")
    except Exception as e:
        with st.container(border=True):
            st.markdown("**PingCastle**")
            st.error(f"조회 실패: {e}")
        return

    if summary.get("result") == "empty":
        _render_empty_card("PingCastle")
        return

    if summary.get("result") == "error":
        with st.container(border=True):
            st.markdown("**PingCastle**")
            st.error(summary.get("message", "조회 실패"))
        return

    with st.container(border=True):
        st.markdown("**PingCastle**")
        st.caption("AD HealthCheck 점수 · 낮을수록 양호")

        c1, c2 = st.columns(2)
        c1.metric("Global Score", _safe_value(summary, "global_score", "-"))
        c2.metric("Anomaly", _safe_value(summary, "anomaly_score", "-"))

        c3, c4 = st.columns(2)
        c3.metric("Privileged", _safe_value(summary, "privileged_group_score", "-"))
        c4.metric("Stale Objects", _safe_value(summary, "stale_objects_score", "-"))

        st.write(f"점수 있는 Risk Rule: **{_safe_value(summary, 'risk_rule_positive_count', '-')}**")
        st.write(f"10점 이상 Risk Rule: **{_safe_value(summary, 'risk_rule_high_point_count', '-')}**")
        st.write(f"전체 Risk Rule: **{_safe_value(summary, 'risk_rule_total', '-')}**")


BLOODHOUND_ROOT = Path("/data/bloodhound")


def _latest_bloodhound_collection():
    if not BLOODHOUND_ROOT.exists():
        return None

    dirs = sorted(
        [d for d in BLOODHOUND_ROOT.iterdir() if d.is_dir()],
        reverse=True,
    )

    for d in dirs:
        if (d / "graph.html").exists():
            return d

    return None


def _load_bloodhound_jsons_for_home(coll_dir: Path):
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


def _bloodhound_home_summary(coll_dir: Path):
    data = _load_bloodhound_jsons_for_home(coll_dir)

    sid2name = {}
    for arr in data.values():
        for obj in arr:
            sid = obj.get("ObjectIdentifier")
            name = obj.get("Properties", {}).get("name", sid)
            if sid:
                sid2name[sid] = name

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

    high_value_members = 0
    high_value_groups = 0

    for group in data["groups"]:
        props = group.get("Properties", {})
        group_name = props.get("name", "")
        short_group_name = group_name.split("@")[0].upper()

        if short_group_name not in high_value_names:
            continue

        members = group.get("Members", [])
        if members:
            high_value_groups += 1
            high_value_members += len(members)

    unconstrained_users = 0
    for user in data["users"]:
        props = user.get("Properties", {})
        if props.get("unconstraineddelegation"):
            unconstrained_users += 1

    unconstrained_computers = 0
    for computer in data["computers"]:
        props = computer.get("Properties", {})
        if props.get("unconstraineddelegation"):
            unconstrained_computers += 1

    return {
        "collection": coll_dir.name,
        "has_graph": (coll_dir / "graph.html").exists(),
        "users": len(data["users"]),
        "groups": len(data["groups"]),
        "computers": len(data["computers"]),
        "high_value_groups": high_value_groups,
        "high_value_members": high_value_members,
        "unconstrained_users": unconstrained_users,
        "unconstrained_computers": unconstrained_computers,
    }


def _render_bloodhound_home_card():
    coll_dir = _latest_bloodhound_collection()

    if not coll_dir:
        _render_empty_card("BloodHound", "graph.html이 포함된 컬렉션 없음")
        return

    try:
        summary = _bloodhound_home_summary(coll_dir)
    except Exception as e:
        with st.container(border=True):
            st.markdown("**BloodHound**")
            st.error(f"분석 실패: {e}")
        return

    with st.container(border=True):
        st.markdown("**BloodHound**")
        st.caption("관계 기반 위험 요약")

        c1, c2 = st.columns(2)
        c1.metric("고가치 그룹 멤버", summary.get("high_value_members", 0))
        c2.metric("고가치 그룹", summary.get("high_value_groups", 0))

        c3, c4 = st.columns(2)
        c3.metric("Unconstrained 사용자", summary.get("unconstrained_users", 0))
        c4.metric("Unconstrained 컴퓨터", summary.get("unconstrained_computers", 0))

        st.write(f"컬렉션: **{summary.get('collection', '-')}**")
        st.write(f"그래프: **{'생성됨' if summary.get('has_graph') else '없음'}**")


# ------------------------------------------------------------------
# 홈 렌더링
# ------------------------------------------------------------------

def render_home():
    st.title("🧑‍💻 2D   |   AD 공격/방어 시뮬레이션 랩")
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

    # try:
    #     running_runs = get_running_scenario_runs()
    # except Exception:
        running_runs = []

    summary_rows, defense_metrics = _build_detection_summary(events)

    detected_count = defense_metrics["detected_event_count"]
    high_count = defense_metrics["high_or_more_count"]

    # 2. 상단 상태 카드
    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Backend", "🟢 정상" if backend_ok else "🔴 오류")
    c2.metric("📥 최근 이벤트", len(events))
    c2.caption(f"최근 1시간 |\n수집 모드: `{save_mode}`")
    c3.metric("🚨 탐지 이벤트", detected_count)
    c4.metric("🔥 High 이상", high_count)
    # c5.metric("🏃 실행 중", len(running_runs) if isinstance(running_runs, list) else 0)

    st.divider()

    # 3. 최근 공격 실행 이력
    # left, right = st.columns([6, 4])

    # with left:
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
    # with right:
    #     st.markdown("### 실행 중 시나리오")

        # if not running_runs:
        #     st.info("현재 실행 중인 시나리오가 없습니다.")
        # else:
        #     for item in running_runs:
        #         with st.container(border=True):
        #             st.write(f"시나리오: **{item.get('scenario_id', '-')}**")
        #             st.write(f"타겟 IP: **{item.get('target_ip', '-')}**")
        #             st.write(f"실행자: **{item.get('requested_by', '-')}**")
        #             st.write(f"시작 시간: **{item.get('started_at', '-')}**")

    st.divider()

    # 5. 탐지 상위 룰
    col_rule, col_rule_chart = st.columns([6, 4])

    with col_rule:
        st.markdown("### 최근 탐지 룰 TOP (최근 1시간 기준)")

        if not summary_rows:
            st.info("최근 탐지된 룰이 없습니다.")
            df_top = pd.DataFrame()
        else:
            top_rows = summary_rows[:5]

            df_top = pd.DataFrame(top_rows)

            # 방어 탭 컬럼명을 홈 화면용 컬럼명으로 맞춤
            df_top = df_top.rename(columns={
                "룰 이름": "탐지 룰",
                "탐지 건수": "건수",
                "최고 점수": "최고 점수",
            })

            visible_cols = ["탐지 룰", "건수", "위험도", "최고 점수"]
            df_top = df_top[[c for c in visible_cols if c in df_top.columns]]

            render_badge_table(
                rows=df_top.to_dict("records"),
                columns=list(df_top.columns),
                badge_columns={"위험도"},
                right_columns={"건수", "최고 점수"},
            )

    with col_rule_chart:
        if not df_top.empty and "위험도" in df_top.columns and "건수" in df_top.columns:
            chart_df = df_top.set_index("위험도")[["건수"]]
            st.bar_chart(chart_df)
        else:
            st.info("차트로 표시할 탐지 룰이 없습니다.")

    # with col_event:
    st.markdown("### 이벤트 TOP (최근 1시간 기준)")

    if not events:
        st.info("이벤트가 없습니다.")
    else:
        rows = []

        for item in events:
            event_id = str(item.get("event_id", "-"))
            normalized = safe_json_loads(item.get("normalized_json"))
            event_type = normalized.get("event_type", "unknown")
            meta = get_event_meta(event_id, event_type)

            rows.append({
                "이벤트 ID": event_id,
                "이벤트 타입": meta.get("label"),
                "분류": meta.get("category"),
                "설명": meta.get("description"),
            })

        event_df = pd.DataFrame(rows)

        event_summary = (
            event_df
            .groupby(["이벤트 ID", "이벤트 타입", "분류", "설명"], dropna=False)
            .size()
            .reset_index(name="건수")
            .sort_values("건수", ascending=False)
            .head(5)
        )

        st.dataframe(event_summary, use_container_width=True, hide_index=True)

    st.divider()

    # 6. 정찰 결과 요약
    st.markdown("### 정찰 도구 최신 결과")

    r1, r2, r3 = st.columns(3)

    with r1:
        _render_powerview_home_card()

    with r2:
        _render_pingcastle_home_card()

    with r3:
        _render_bloodhound_home_card()