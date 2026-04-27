import os
import json
import requests
import streamlit as st
import pandas as pd
from streamlit_option_menu import option_menu

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
ATTACK_REQUESTED_BY = os.getenv("ATTACK_REQUESTED_BY", "")
VICTIM_URL = os.getenv("VICTIM_URL", "")

def render_param_field(scenario_id: str, field: dict):
    field_name = field.get("name")
    field_label = field.get("label") or field_name
    field_type = field.get("type", "text")
    field_required = field.get("required", False)
    field_default = field.get("default")
    field_help = field.get("help", "")
    field_options = field.get("options", [])

    if not field_name:
        return None, None

    widget_key = f"{scenario_id}_{field_name}"

    label_text = field_label
    if field_required:
        label_text += " *"

    if field_type == "number":
        value = st.number_input(
            label_text,
            value=int(field_default) if field_default is not None else 0,
            step=1,
            key=widget_key,
            help=field_help
        )

    elif field_type == "password":
        value = st.text_input(
            label_text,
            value=str(field_default) if field_default is not None else "",
            type="password",
            key=widget_key,
            help=field_help
        )

    elif field_type == "select":
        options = field_options if isinstance(field_options, list) and field_options else [""]
        default_index = 0
        if field_default in options:
            default_index = options.index(field_default)

        value = st.selectbox(
            label_text,
            options=options,
            index=default_index,
            key=widget_key,
            help=field_help
        )

    elif field_type == "checkbox":
        value = st.checkbox(
            label_text,
            value=bool(field_default) if field_default is not None else False,
            key=widget_key,
            help=field_help
        )

    elif field_type == "textarea":
        value = st.text_area(
            label_text,
            value=str(field_default) if field_default is not None else "",
            key=widget_key,
            help=field_help
        )

    else:
        value = st.text_input(
            label_text,
            value=str(field_default) if field_default is not None else "",
            key=widget_key,
            help=field_help
        )

    return field_name, value


def fetch_scenario_log(run_id: str, tail: int = 200):
    try:
        res = requests.get(f"{BACKEND_URL}/scenario/log/{run_id}", params={"tail": tail}, timeout=10)
        res.raise_for_status()
        return res.json()
    except Exception as e:
        return {"result": "error", "message": str(e)}


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def unique_keep_order(values):
    result = []
    seen = set()
    for value in values:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def normalize_matched_rules(detection: dict):
    """
    신규 구조(matched_rules)가 있으면 룰별 상세 정보를 그대로 사용하고,
    기존 DB에 저장된 all_rules/rule_name만 있는 이벤트도 깨지지 않도록 보정한다.
    """
    matched_rules = detection.get("matched_rules")
    if isinstance(matched_rules, list) and matched_rules:
        return [rule for rule in matched_rules if isinstance(rule, dict)]

    all_rules = detection.get("all_rules")
    if isinstance(all_rules, list) and all_rules:
        normalized_rules = []
        for idx, rule in enumerate(all_rules):
            if isinstance(rule, dict):
                normalized_rules.append(rule)
            else:
                normalized_rules.append({
                    "rule_id": rule,
                    "rule_name": detection.get("rule_name") if idx == 0 else None,
                    "reason": [],
                    "attack_tactic": None,
                    "attack_technique": None,
                    "response_guide": [],
                    "risk": {},
                })
        return normalized_rules

    if detection.get("rule_id") or detection.get("rule_name"):
        return [{
            "rule_id": detection.get("rule_id"),
            "rule_name": detection.get("rule_name"),
            "reason": as_list(detection.get("reason")),
            "attack_tactic": detection.get("attack_tactic"),
            "attack_technique": detection.get("attack_technique"),
            "response_guide": as_list(detection.get("response_guide")),
            "risk": {},
        }]

    return []


def rule_label(rule: dict):
    rule_id = rule.get("rule_id") or "-"
    rule_name = rule.get("rule_name") or "-"
    return f"{rule_id} / {rule_name}" if rule_name != "-" else str(rule_id)


def severity_badge(severity: str):
    severity = severity or "none"
    style_map = {
        "critical": ("#fee2e2", "#7f1d1d"),
        "high": ("#ffedd5", "#9a3412"),
        "medium": ("#fef3c7", "#92400e"),
        "low": ("#dcfce7", "#166534"),
        "none": ("#f3f4f6", "#374151"),
    }
    bg, fg = style_map.get(str(severity).lower(), ("#eef2ff", "#3730a3"))
    return f'<span style="background-color:{bg}; color:{fg}; padding:3px 8px; border-radius:999px; font-weight:700;">{severity}</span>'



st.set_page_config(page_title="AD Log Dashboard", layout="wide")
st.title("AD 공격/방어 로그 대시보드")

st.divider()

if "last_run_id" not in st.session_state:
    st.session_state.last_run_id = None
if "last_scenario_id" not in st.session_state:
    st.session_state.last_scenario_id = None
if "last_target_ip" not in st.session_state:
    st.session_state.last_target_ip = None
if "last_requested_by" not in st.session_state:
    st.session_state.last_requested_by = None



with st.sidebar:
    menu = option_menu(
        "메뉴",
        ["방어", "공격"],
        icons=["shield", "crosshair"],
        menu_icon="grid",
        default_index=0,
        styles={
            "container": {
                "padding": "0.5rem 0.4rem",
                "background-color": "transparent",
            },
            "icon": {
                "color": "#111827",
                "font-size": "18px",
            },
            "nav-link": {
                "font-size": "16px",
                "font-weight": "600",
                "text-align": "left",
                "margin": "0px",
                "padding": "10px 12px",
                "border-radius": "8px",
                "--hover-color": "#f3f4f6",
                "color": "#111827",
            },
            "nav-link-selected": {
                "background-color": "#e5e7eb",
                "color": "#111827",
                "font-weight": "700",
            },
        },
    )






if menu == "방어":
    col_title, col_refresh, col_rest = st.columns([2.5, 0.5, 7])

    with col_title:
        st.subheader("방어 모니터링")

    with col_refresh:
        if st.button("↻", help="이벤트 새로고침"):
            st.rerun()

    try:
        res = requests.get(f"{BACKEND_URL}/events?limit=100", timeout=5)
        res.raise_for_status()
        data = res.json()
    except Exception as e:
        st.error(f"백엔드 연결 실패: {e}")
        st.stop()

    if not data:
        st.info("수집된 이벤트가 없습니다.")
    else:
        df = pd.DataFrame(data)
        
        st.subheader("이벤트 요약")
        sum_col1, sum_col2 = st.columns([3, 7])

        with sum_col1:
            st.metric("총 이벤트 개수", len(df))

        with sum_col2:
            if "event_id" in df.columns:
                summary_df = (
                    df["event_id"]
                    .fillna("-")
                    .astype(str)
                    .value_counts()
                    .head(10)
                    .reset_index()
                )
                summary_df.columns = ["event_id", "count"]
                st.dataframe(summary_df, use_container_width=True, hide_index=True)
            else:
                st.info("event_id 컬럼이 없습니다.")

        col_subtitle, col_delete = st.columns([7, 3])

        with col_subtitle:
            st.subheader("최근 이벤트")

        with col_delete:
            if st.button("전체 삭제", type="secondary"):
                try:
                    delete_res = requests.delete(f"{BACKEND_URL}/events", timeout=10)
                    delete_res.raise_for_status()
                    result = delete_res.json()
                    st.success(f"전체 삭제 완료 ({result.get('deleted_count', 0)}건)")
                    st.rerun()
                except Exception as e:
                    st.error(f"전체 삭제 실패: {e}")

        filter_col1, filter_col2, filter_col3 = st.columns([3, 3, 4])

        with filter_col1:
            event_id_filter = st.text_input("이벤트 ID", value="", placeholder="예: 4625")

        with filter_col2:
            time_filter = st.selectbox(
                "시간 필터",
                ["전체", "최근 10분", "최근 1시간", "최근 24시간"],
                index=0
            )

        with filter_col3:
            date_filter = st.date_input("날짜 선택", value=None)

        filtered_data = data

        # 1) event_id 필터
        if event_id_filter.strip():
            keyword = event_id_filter.strip()
            filtered_data = [
                item for item in filtered_data
                if str(item.get("event_id", "")).strip() == keyword
            ]

        # 2) 날짜 / 최근 n분 필터
        def parse_event_time(value):
            if not value:
                return None
            try:
                return pd.to_datetime(value, utc=True)
            except Exception:
                return None

        now_utc = pd.Timestamp.utcnow()

        if time_filter != "전체":
            if time_filter == "최근 10분":
                cutoff = now_utc - pd.Timedelta(minutes=10)
            elif time_filter == "최근 1시간":
                cutoff = now_utc - pd.Timedelta(hours=1)
            else:
                cutoff = now_utc - pd.Timedelta(hours=24)

            temp = []
            for item in filtered_data:
                dt = parse_event_time(item.get("event_time"))
                if dt is not None and dt >= cutoff:
                    temp.append(item)
            filtered_data = temp

        if date_filter:
            temp = []
            for item in filtered_data:
                dt = parse_event_time(item.get("event_time"))
                if dt is not None and dt.date() == date_filter:
                    temp.append(item)
            filtered_data = temp



        col_page_size, col_page = st.columns([5, 5])
        with col_page_size:
            page_size = st.selectbox("페이지당 로그 수", [5, 10, 20], index=0)
        with col_page:
            page = st.number_input("페이지", min_value=1, value=1, step=1)


        total = len(filtered_data)
        total_pages = max(1, (total + page_size - 1) // page_size)

        if page > total_pages:
            page = total_pages

        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_items = filtered_data[start_idx:end_idx]

        st.caption(f"전체 {total}건 / {page}페이지 / 총 {total_pages}페이지")

        for item in page_items:
            try:
                event_json = json.loads(item.get("event_json") or "{}")
            except Exception:
                event_json = {}

            try:
                normalized = json.loads(item.get("normalized_json") or "{}")
            except Exception:
                normalized = {}

            try:
                detection = json.loads(item.get("detection_json") or "{}")
            except Exception:
                detection = {}

            try:
                risk = json.loads(item.get("risk_json") or "{}")
            except Exception:
                risk = {}

            try:
                raw_json = json.loads(item.get("raw_json") or "{}")
            except Exception:
                raw_json = item.get("raw_json")

            event_row_id = item.get("id")
            event_time = item.get("event_time", "-")
            event_id = item.get("event_id", "-")
            computer_name = item.get("computer_name", "-")
            username = item.get("username", "-")
            source_ip = item.get("source_ip", "-")
            group_name = item.get("group_name", "-")
            message = item.get("message", "-")

            event_type = normalized.get("event_type", "-")
            host_role = normalized.get("host_role", "-")
            account_type = normalized.get("account_type", "-")
            is_admin = normalized.get("is_admin_account", False)
            is_off_hours = normalized.get("is_off_hours", False)

            detected = detection.get("detected", False)
            matched_rules = normalize_matched_rules(detection)
            detected_rule_count = len(matched_rules)
            all_rule_labels = [rule_label(rule) for rule in matched_rules]
            representative_rule_name = detection.get("rule_name") or "-"
            rule_summary = ", ".join(all_rule_labels) if all_rule_labels else representative_rule_name

            reasons = unique_keep_order(as_list(detection.get("reason")))
            response_guide = unique_keep_order(as_list(detection.get("response_guide")))

            severity = risk.get("severity", "none")
            final_score = risk.get("final_score", 0)

            if detected_rule_count > 1:
                expander_title = f"🚨 ID {event_id}   |   {computer_name}   |   탐지 {detected_rule_count}개   |   {event_time}"
            else:
                expander_title = f"🔎 ID {event_id}   |   {computer_name}   |   {rule_summary}   |   {event_time}"

            with st.expander(expander_title, expanded=False):
                top_left, top_right = st.columns([9, 1])

                with top_left:
                    st.markdown(
                        f"""
                        <div style="
                            font-size: 1.15rem;
                            font-weight: 600;
                            margin-bottom: 0.6rem;
                            display: flex;
                            align-items: center;
                            gap: 10px;
                            flex-wrap: wrap;
                        ">
                            <span style="
                                background-color: #eef2ff;
                                color: #3730a3;
                                padding: 4px 10px;
                                border-radius: 999px;
                                font-size: 1rem;
                                font-weight: 700;
                            ">
                                🔎 ID {event_id} 
                            </span>
                            <span style="
                                background-color: #FAF4C0;
                                color: #425518;
                                padding: 4px 10px;
                                border-radius: 999px;
                                font-size: 1rem;
                                font-weight: 700;
                            ">
                                {computer_name}
                            </span>
                            <span style="color: #9ca3af;">|</span>
                            <span style="color: #6b7280; font-weight: 500;">{event_time}</span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                with top_right:
                    if event_row_id is not None and st.button("삭제", key=f"delete_event_{event_row_id}"):
                        try:
                            delete_res = requests.delete(f"{BACKEND_URL}/events/{event_row_id}", timeout=10)
                            delete_res.raise_for_status()
                            st.success(f"이벤트 {event_row_id} 삭제 완료")
                            st.rerun()
                        except Exception as e:
                            st.error(f"이벤트 삭제 실패: {e}")


                row1 = st.columns(3)
                row1[0].write(f"사용자: **{username}**")
                row1[1].write(f"이벤트 타입: **{event_type}**")
                row1[2].write(f"호스트 역할: **{host_role}**")

                row2 = st.columns(3)
                row2[0].write(f"계정 유형: **{account_type}**")
                row2[1].write(f"관리자 계정 여부: **{is_admin}**")
                row2[2].write(f"업무 외 시간 여부: **{is_off_hours}**")

                row3 = st.columns(3)
                row3[0].write(f"Source IP: **{source_ip}**")
                if group_name and group_name != "-":
                    row3[1].write(f"그룹: **{group_name}**")
                row3[2].write(f"")
                

                if message and message != "-":
                    preview_len = len(message)
                    show_message = st.toggle(
                        f"메시지 보기 ({preview_len}자)",
                        key=f"msg_{item.get('id', event_id)}"
                    )
                    if show_message:
                        st.markdown("**메시지**")
                        st.write(message)

                st.divider()
                st.markdown("**탐지 결과**")

                det1 = st.columns(4)
                det1[0].write(f"탐지 여부: **{detected}**")
                det1[1].write(f"탐지 개수: **{detected_rule_count}개**")
                det1[2].markdown(f"위험도: {severity_badge(severity)}", unsafe_allow_html=True)
                det1[3].write(f"점수: **{final_score}**")

                if matched_rules:
                    st.markdown("**탐지된 룰 목록**")
                    for idx, rule in enumerate(matched_rules, start=1):
                        rule_risk = rule.get("risk") or {}
                        rule_severity = rule_risk.get("severity", "-")
                        rule_score = rule_risk.get("final_score", "-")
                        rule_reason = as_list(rule.get("reason"))
                        rule_guides = as_list(rule.get("response_guide"))

                        with st.container(border=True):
                            c_rule_1, c_rule_2, c_rule_3 = st.columns([4, 3, 3])
                            c_rule_1.markdown(f"**{idx}. {rule_label(rule)}**")
                            c_rule_2.write(f"ATT&CK Tactic: **{rule.get('attack_tactic') or '-'}**")
                            c_rule_3.write(f"ATT&CK Technique: **{rule.get('attack_technique') or '-'}**")

                            c_rule_4, c_rule_5 = st.columns([2, 8])
                            c_rule_4.write(f"룰 위험도: **{rule_severity}**")
                            c_rule_5.write(f"룰 점수: **{rule_score}**")

                            if rule_reason:
                                st.write("사유:")
                                for r in rule_reason:
                                    st.write(f"- {r}")

                            if rule_guides:
                                st.write("대응 가이드:")
                                for g in rule_guides:
                                    st.write(f"- {g}")
                else:
                    st.info("매칭된 탐지 룰이 없습니다.")

                # 기존 구조와의 호환을 위해 통합 사유/대응 가이드도 함께 출력
                if reasons:
                    with st.expander("통합 탐지 사유 보기", expanded=False):
                        for r in reasons:
                            st.write(f"- {r}")

                if response_guide:
                    with st.expander("통합 대응 가이드 보기", expanded=False):
                        for g in response_guide:
                            st.write(f"- {g}")

                st.divider()
                show_detail = st.toggle(
                    "상세 JSON 보기",
                    key=f"detail_{item.get('id', event_id)}"
                )

                if show_detail:
                    st.markdown("**event_json**")
                    st.json(event_json)

                    st.markdown("**normalized_json**")
                    st.json(normalized)

                    st.markdown("**detection_json**")
                    st.json(detection)

                    st.markdown("**risk_json**")
                    st.json(risk)

                    st.markdown("**raw_json**")
                    if isinstance(raw_json, dict):
                        st.json(raw_json)
                    else:
                        st.code(str(raw_json))

# ------------------------------------------

elif menu == "공격":
    st.subheader("최근 실행 이력")

    st.button("실행 이력 새로고침", key="refresh_history")

    try:
        history_res = requests.get(f"{BACKEND_URL}/scenario-runs?limit=5", timeout=5)
        history_res.raise_for_status()
        history_data = history_res.json()
    except Exception as e:
        st.error(f"실행 이력 조회 실패: {e}")
        history_data = []

    if isinstance(history_data, dict) and history_data.get("result") == "error":
        st.error(history_data.get("message"))
    else:
        if not history_data:
            st.info("최근 실행 이력이 없습니다.")
        else:
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
            run_options = [row["run_id"] for row in history_rows if row.get("run_id") not in (None, "-")]


            col_run_log, col_log_lines, col_load_log, col_load_refresh = st.columns([3.5, 3.5, 1.5, 1.5])

            with col_run_log:
                selected_run_id = st.selectbox(
                    "로그를 볼 실행 선택",
                    options=run_options,
                    key="selected_run_id"
                )

            with col_log_lines:
                tail = st.selectbox(
                    "불러올 로그 줄 수",
                    [50, 100, 200, 500],
                    index=2,
                    key="selected_log_tail"
                )

            with col_load_log:
                if st.button("로그 불러오기", key="load_selected_log"):
                    log_data = fetch_scenario_log(selected_run_id, tail=tail)
                    st.session_state["selected_run_log"] = log_data

            with col_load_refresh:
                if st.button("새로고침", key="refresh_selected_log"):
                    log_data = fetch_scenario_log(selected_run_id, tail=tail)
                    st.session_state["selected_run_log"] = log_data


            cached_log = st.session_state.get("selected_run_log")

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




    st.divider()
    st.subheader("공격 시나리오 실행")

    col_target, col_user = st.columns([6, 4])
    with col_target:
        target_ip = st.text_input("대상 IP", value=VICTIM_URL)
    with col_user:
        requested_by = st.text_input("실행자", value=ATTACK_REQUESTED_BY)

    try:
        res = requests.get(f"{BACKEND_URL}/scenario/list", timeout=5)
        res.raise_for_status()
        scenarios = res.json()
    except Exception as e:
        st.error(f"시나리오 목록 조회 실패: {e}")
        st.stop()

    st.markdown("### 시나리오 목록")

    if isinstance(scenarios, dict) and scenarios.get("result") == "error":
        st.error(scenarios.get("message"))
    else:
        grouped = {
            "real_attack": [],
            "detection_test": [],
            "general": [],
        }


        for scenario in scenarios:
            scenario_id = scenario["scenario_id"]
            params_schema = scenario.get("params_schema") or []

            with st.container(border=True):
                c1, c2 = st.columns([8, 2])

                with c1:
                    scenario_type = scenario.get("scenario_type", "general")

                    type_style_map = {
                        "real_attack": {
                            "bg": "#fee2e2",
                            "fg": "#991b1b",
                            "label": "real_attack",
                        },
                        "detection_test": {
                            "bg": "#fef3c7",
                            "fg": "#92400e",
                            "label": "detection_test",
                        },
                        "general": {
                            "bg": "#e0f2fe",
                            "fg": "#075985",
                            "label": "general",
                        },
                    }

                    style_info = type_style_map.get(
                        scenario_type,
                        {
                            "bg": "#eef2ff",
                            "fg": "#3730a3",
                            "label": scenario_type,
                        }
                    )

                    st.markdown(
                        f"""
                        <div style="
                            font-size: 1.15rem;
                            font-weight: 600;
                            margin-bottom: 0.6rem;
                            display: flex;
                            align-items: center;
                            gap: 10px;
                            flex-wrap: wrap;
                        ">
                            <span style="
                                background-color: {style_info['bg']};
                                color: {style_info['fg']};
                                padding: 4px 10px;
                                border-radius: 999px;
                                font-size: 1rem;
                                font-weight: 700;
                            ">
                                {style_info['label']}
                            </span>
                            <span>{scenario['label']}</span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                extra_params = {}

                if params_schema:
                    with st.expander("파라미터 설정", expanded=False):
                        st.caption("이 시나리오는 추가 파라미터 입력을 지원합니다.")

                        for field in params_schema:
                            field_name, value = render_param_field(scenario_id, field)
                            if field_name:
                                extra_params[field_name] = value

                        helps = [
                            f"- **{f.get('label') or f.get('name')}**: {f.get('help')}"
                            for f in params_schema
                            if f.get("help")
                        ]
                        if helps:
                            st.markdown("**파라미터 설명**")
                            for line in helps:
                                st.markdown(line)

                with c2:
                    if st.button("실행", key=f"run_{scenario_id}"):
                        if not target_ip.strip():
                            st.warning("타겟 IP를 입력하세요.")
                        elif not requested_by.strip():
                            st.warning("실행자를 입력하세요.")
                        else:
                            missing_fields = []
                            for field in params_schema:
                                if not field.get("required", False):
                                    continue

                                field_name = field.get("name")
                                value = extra_params.get(field_name)

                                if value is None:
                                    missing_fields.append(field.get("label") or field_name)
                                elif isinstance(value, str) and not value.strip():
                                    missing_fields.append(field.get("label") or field_name)

                            if missing_fields:
                                st.warning(f"필수 파라미터를 입력하세요: {', '.join(missing_fields)}")
                            else:
                                params = {
                                    "target_ip": target_ip.strip(),
                                    "requested_by": requested_by.strip(),
                                }

                                for k, v in extra_params.items():
                                    if isinstance(v, str):
                                        if v.strip():
                                            params[k] = v.strip()
                                    else:
                                        params[k] = v

                                try:
                                    run_res = requests.post(
                                        f"{BACKEND_URL}/scenario/run",
                                        json={
                                            "scenario_id": scenario_id,
                                            "params": params
                                        },
                                        timeout=10
                                    )
                                    run_res.raise_for_status()
                                    result = run_res.json()

                                    if result.get("result") == "error":
                                        st.warning(result.get("message", "시나리오 실행이 거부되었습니다."))
                                    else:
                                        st.session_state.last_run_id = result.get("run_id")
                                        st.session_state.last_scenario_id = result.get("scenario_id")
                                        st.session_state.last_target_ip = target_ip.strip()
                                        st.session_state.last_requested_by = requested_by.strip()
                                        st.success(f"{scenario['label']} 실행 요청 완료")
                                except Exception as e:
                                    st.error(f"시나리오 실행 실패: {e}")
            # scenario_id = scenario["scenario_id"]
            # params_schema = scenario.get("params_schema") or []

            # with st.container(border=True):
            #     c1, c2 = st.columns([8, 2])

            #     with c1:
            #         st.markdown(f"**{scenario['label']}**")

            #     extra_params = {}

            #     # params_schema가 있을 때만 확장 입력 폼 표시
            #     if params_schema:
            #         with st.expander("파라미터 설정", expanded=False):
            #             st.caption("이 시나리오는 추가 파라미터 입력을 지원합니다.")

            #             for field in params_schema:
            #                 field_name, value = render_param_field(scenario_id, field)
            #                 if field_name:
            #                     extra_params[field_name] = value

            #             helps = [
            #                 f"- **{f.get('label') or f.get('name')}**: {f.get('help')}"
            #                 for f in params_schema
            #                 if f.get("help")
            #             ]
            #             if helps:
            #                 st.markdown("**파라미터 설명**")
            #                 for line in helps:
            #                     st.markdown(line)

            #     with c2:
            #         if st.button("실행", key=f"run_{scenario_id}"):
            #             if not target_ip.strip():
            #                 st.warning("타겟 IP를 입력하세요.")
            #             elif not requested_by.strip():
            #                 st.warning("실행자를 입력하세요.")
            #             else:
            #                 # required 검사
            #                 missing_fields = []
            #                 for field in params_schema:
            #                     if not field.get("required", False):
            #                         continue

            #                     field_name = field.get("name")
            #                     value = extra_params.get(field_name)

            #                     if value is None:
            #                         missing_fields.append(field.get("label") or field_name)
            #                     elif isinstance(value, str) and not value.strip():
            #                         missing_fields.append(field.get("label") or field_name)

            #                 if missing_fields:
            #                     st.warning(f"필수 파라미터를 입력하세요: {', '.join(missing_fields)}")
            #                 else:
            #                     params = {
            #                         "target_ip": target_ip.strip(),
            #                         "requested_by": requested_by.strip(),
            #                     }

            #                     # 빈 문자열은 제외하고 추가
            #                     for k, v in extra_params.items():
            #                         if isinstance(v, str):
            #                             if v.strip():
            #                                 params[k] = v.strip()
            #                         else:
            #                             params[k] = v

            #                     try:
            #                         run_res = requests.post(
            #                             f"{BACKEND_URL}/scenario/run",
            #                             json={
            #                                 "scenario_id": scenario_id,
            #                                 "params": params
            #                             },
            #                             timeout=10
            #                         )
            #                         run_res.raise_for_status()
            #                         result = run_res.json()

            #                         if result.get("result") == "error":
            #                             st.warning(result.get("message", "시나리오 실행이 거부되었습니다."))
            #                         else:
            #                             st.session_state.last_run_id = result.get("run_id")
            #                             st.session_state.last_scenario_id = result.get("scenario_id")
            #                             st.session_state.last_target_ip = target_ip.strip()
            #                             st.session_state.last_requested_by = requested_by.strip()
            #                             st.success(f"{scenario['label']} 실행 요청 완료")
            #                     except Exception as e:
            #                         st.error(f"시나리오 실행 실패: {e}")





    st.divider()
    st.subheader("마지막 실행 상태")

    if st.session_state.last_run_id:
        st.write(f"run_id: {st.session_state.last_run_id}")

        if st.button("상태 새로고침"):
            try:
                status_res = requests.get(
                    f"{BACKEND_URL}/scenario/status/{st.session_state.last_run_id}",
                    timeout=5
                )
                status_res.raise_for_status()
                status_data = status_res.json()

                status = status_data.get("status", "unknown")
                scenario_id = status_data.get("scenario_id", "-")
                target_ip_status = status_data.get("target_ip", st.session_state.get("last_target_ip", "-"))
                requested_by_status = status_data.get("requested_by", st.session_state.get("last_requested_by", "-"))
                started_at = status_data.get("started_at", "-")
                finished_at = status_data.get("finished_at", "-")
                return_code = status_data.get("return_code", "-")
                log_path = status_data.get("log_path", "-")

                machine_status = "사용 중" if status == "running" else "대기 중"

                if status == "running":
                    st.warning(f"현재 공격머신 상태: {machine_status}")
                elif status == "success":
                    st.success("실행 성공")
                elif status == "failed":
                    st.error("실행 실패")
                else:
                    st.info(f"상태: {status}")

                top1, top2, top3, top4 = st.columns(4)
                top1.metric("시나리오", scenario_id)
                top2.metric("상태", status)
                top3.metric("반환 코드", return_code if return_code is not None else "-")
                top4.metric("공격머신 상태", machine_status)

                c1, c2 = st.columns(2)
                with c1:
                    st.write(f"**실행자**: {requested_by_status}")
                    st.write(f"**타겟 IP**: {target_ip_status}")
                    st.write(f"**시작 시간**: {started_at}")

                with c2:
                    st.write(f"**종료 시간**: {finished_at}")
                    st.write(f"**로그 경로**: `{log_path}`")

                with st.expander("원본 상태 JSON 보기"):
                    st.json(status_data)

            except Exception as e:
                st.error(f"상태 조회 실패: {e}")
    else:
        st.info("아직 실행한 시나리오가 없습니다.")





