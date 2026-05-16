import pandas as pd
import streamlit as st

from utils import safe_json_loads, normalize_matched_rules, as_list, unique_keep_order, rule_label
from components import severity_badge, severity_rank, render_badge_table
from config import VICTIM_URL
from metadata import get_event_meta
from api_client import (
    get_events,
    delete_all_events,
    delete_event,
    get_event_save_policy,
    get_event_collection_state,
    pause_event_collection,
    resume_event_collection,
    run_event_llm_triage,
)



def _get_current_target_ip():
    target_ip = (
        st.session_state.get("attack_target_ip")
        or st.session_state.get("last_target_ip")
        or VICTIM_URL
        or "-"
    )

    return f"대상 IP: {target_ip}"

# ==========================================
# 컨텍스트 LLM 
# ==========================================

LLM_TARGET_RULE_IDS = {
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

    for rule in normalize_matched_rules(detection):
        rule_id = rule.get("rule_id")
        if rule_id:
            result.add(str(rule_id))

    return result


def _is_llm_triage_target(detection: dict, risk: dict) -> bool:
    if not detection.get("detected"):
        return False

    matched_rule_ids = _matched_rule_ids(detection)

    # RULE-041 단독은 제외. 도구/정찰 관련 룰이 있을 때만 활성화.
    if not (matched_rule_ids & LLM_TARGET_RULE_IDS):
        return False

    ai_context = risk.get("ai_context") or {}

    # real_attack은 LLM 하향/오탐 판단 대상에서 제외
    if ai_context.get("verdict") == "real_attack_no_downgrade":
        return False

    return True



def _build_detection_summary(events):
    summary = {}
    detected_event_count = 0
    high_or_more_count = 0
    max_rule_score = 0
    total_rule_hits = 0

    for item in events:
        detection = safe_json_loads(item.get("detection_json"))
        risk = safe_json_loads(item.get("risk_json"))

        if not detection.get("detected"):
            continue

        detected_event_count += 1

        matched_rules = normalize_matched_rules(detection)

        # 혹시 matched_rules 구조가 비어있고 대표 룰만 있는 경우 대비
        if not matched_rules and (detection.get("rule_id") or detection.get("rule_name")):
            matched_rules = [{
                "rule_id": detection.get("rule_id"),
                "rule_name": detection.get("rule_name"),
                "attack_tactic": detection.get("attack_tactic"),
                "attack_technique": detection.get("attack_technique"),
                "risk": risk,
            }]

        for rule in matched_rules:
            total_rule_hits += 1

            rule_id = rule.get("rule_id") or "-"
            rule_name = rule.get("rule_name") or "-"
            key = f"{rule_id}::{rule_name}"

            rule_severity = str(
                risk.get("severity")
                or "none"
            ).lower()

            try:
                rule_score = int(
                    risk.get("final_score")
                    or 0
                )
            except Exception:
                rule_score = 0

            # 요약 카드도 룰 기준으로 집계
            if rule_severity in ("high", "critical"):
                high_or_more_count += 1

            max_rule_score = max(max_rule_score, rule_score)

            if key not in summary:
                summary[key] = {
                    "룰 ID": rule_id,
                    "룰 이름": rule_name,
                    "탐지 건수": 0,
                    "최고 위험도": rule_severity,
                    "최고 점수": rule_score,
                    "ATT&CK Tactic": rule.get("attack_tactic") or "-",
                    "ATT&CK Technique": rule.get("attack_technique") or "-",
                    "최근 발생": item.get("event_time", "-"),
                }

            row = summary[key]
            row["탐지 건수"] += 1

            if severity_rank(rule_severity) > severity_rank(row["최고 위험도"]):
                row["최고 위험도"] = rule_severity

            row["최고 점수"] = max(row["최고 점수"], rule_score)

            current_time = item.get("event_time")
            if current_time and str(current_time) > str(row.get("최근 발생", "")):
                row["최근 발생"] = current_time

    rows = list(summary.values())

    rows.sort(
        key=lambda row: (
            severity_rank(row["최고 위험도"]),
            row["최고 점수"],
            row["탐지 건수"],
        ),
        reverse=True,
    )

    for row in rows:
        row["위험도"] = row["최고 위험도"]

    metrics = {
        "detected_event_count": detected_event_count,
        "total_rule_hits": total_rule_hits,
        "high_or_more_count": high_or_more_count,
        "max_event_score": max_rule_score,
    }

    return rows, metrics


def _render_detection_summary(events):
    rows, metrics = _build_detection_summary(events)

    st.subheader("탐지 요약")
    st.caption("최근 1시간 기준으로 탐지된 룰을 집계합니다.")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("탐지 이벤트", metrics["detected_event_count"])
    m2.metric("룰 매칭 수", metrics["total_rule_hits"])
    m3.metric("High 이상", metrics["high_or_more_count"])
    m4.metric("최고 점수", metrics["max_event_score"])

    if not rows:
        st.info("최근 1시간 기준으로 탐지된 룰이 없습니다.")
        return

    summary_df = pd.DataFrame(rows)

    visible_cols = [
        "룰 ID",
        "룰 이름",
        "탐지 건수",
        "위험도",
        "최고 점수",
        "ATT&CK Tactic",
        "ATT&CK Technique",
        "최근 발생",
    ]

    summary_df = summary_df[[c for c in visible_cols if c in summary_df.columns]]

    render_badge_table(
        rows=summary_df.to_dict("records"),
        columns=list(summary_df.columns),
        badge_columns={"위험도"},
        right_columns={"탐지 건수", "최고 점수"},
    )



def render_defense():
    st.title("🛡️ 방어")
    st.divider()

    col_title, col_refresh, col_rest = st.columns([6, 0.5, 3.5])

    with col_title:
        target_ip = _get_current_target_ip()
        st.subheader(f"방어 모니터링 ({target_ip})")

        try:
            collection_state = get_event_collection_state()
        except Exception:
            collection_state = {
                "paused": False,
                "reason": "-",
                "paused_at": None,
            }

        paused = bool(collection_state.get("paused"))

        state_col1, state_col2, state_col3 = st.columns([5, 2, 2])

        with state_col1:
            if paused:
                st.warning(
                    f"로그 수집 일시정지 중 "
                    f"(reason: {collection_state.get('reason', '-')}, "
                    f"paused_at: {collection_state.get('paused_at', '-')})"
                )
            else:
                st.success("로그 수집 활성화 상태")

        with state_col2:
            if st.button(
                "⏸ 수집 중단",
                disabled=paused,
                key="pause_event_collection",
                help="새로 들어오는 이벤트의 저장/탐지 처리를 잠시 중단합니다.",
            ):
                try:
                    pause_event_collection(reason="dashboard_manual_pause")
                    st.rerun()
                except Exception as e:
                    st.error(f"수집 중단 실패: {e}")

        with state_col3:
            if st.button(
                "▶ 수집 재개",
                disabled=not paused,
                key="resume_event_collection",
                help="이벤트 저장/탐지 처리를 다시 시작합니다.",
            ):
                try:
                    resume_event_collection()
                    st.rerun()
                except Exception as e:
                    st.error(f"수집 재개 실패: {e}")




    with col_refresh:
        if st.button("↻", help="이벤트 새로고침"):
            st.rerun()

    try:
        data = get_events(since_minutes=60)
    except Exception as e:
        st.error(f"백엔드 연결 실패: {e}")
        st.stop()

    try:
        save_policy = get_event_save_policy()
        save_mode = save_policy.get("mode", "-")
        important_event_count = save_policy.get("important_event_count", "-")
    except Exception:
        save_mode = "-"
        important_event_count = "-"

    if not data:
        st.info("수집된 이벤트가 없습니다.")
    else:
        df = pd.DataFrame(data)
         
        st.subheader("이벤트 요약")
        st.caption("최근 1시간 기준으로 조회된 이벤트입니다.")
        sum_col1, sum_col2 = st.columns([3, 7])

        with sum_col1:
            st.metric("총 이벤트 개수", len(df))

        with sum_col2:
            if "event_id" in df.columns:
                summary_rows = []

                for item in data:
                    event_id = str(item.get("event_id", "-"))
                    normalized = safe_json_loads(item.get("normalized_json"))
                    event_type = normalized.get("event_type", "unknown")
                    meta = get_event_meta(event_id, event_type)

                    summary_rows.append({
                        "이벤트 ID": event_id,
                        "이벤트 타입": meta.get("label"),
                        "분류": meta.get("category"),
                        "설명": meta.get("description"),
                    })

                summary_df = pd.DataFrame(summary_rows)

                summary_df = (
                    summary_df
                    .groupby(["이벤트 ID", "이벤트 타입", "분류", "설명"], dropna=False)
                    .size()
                    .reset_index(name="건수")
                    .sort_values("건수", ascending=False)
                    .head(10)
                )

                st.dataframe(summary_df, use_container_width=True, hide_index=True)
            else:
                st.info("event_id 컬럼이 없습니다.")

        
        _render_detection_summary(data)

        st.divider()

        col_subtitle, col_mode, col_delete = st.columns([3, 4, 3])

        with col_subtitle:
            st.subheader("최근 이벤트")

        with col_mode:
            st.markdown(
                f"""
        <div style="margin-top:0.45rem; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
        <span style="background-color:#eef2ff; color:#3730a3; padding:6px 12px; border-radius:999px; font-size:0.92rem; font-weight:700; white-space:nowrap;">
            수집 모드: {save_mode}
        </span>
        <span style="background-color:#f3f4f6; color:#374151; padding:6px 12px; border-radius:999px; font-size:0.88rem; font-weight:600; white-space:nowrap;">
            중요 이벤트 {important_event_count}개 기준
        </span>
        </div>
                """,
                unsafe_allow_html=True,
            )

        with col_delete:
            if st.button("전체 삭제", type="secondary"):
                try:
                    result = delete_all_events()
                    st.success(f"전체 삭제 완료 ({result.get('deleted_count', 0)}건)")
                    st.rerun()
                except Exception as e:
                    st.error(f"전체 삭제 실패: {e}")


        filter_col1, filter_col2, filter_col3, filter_col4 = st.columns([2.5, 2.5, 2.5, 2.5])
 
        with filter_col1:
            event_id_filter = st.text_input("이벤트 ID", value="", placeholder="예: 4625")

        with filter_col2:
            detection_filter = st.selectbox(
                "탐지 여부",
                ["전체", "탐지된 것", "미탐지"],
                index=0
            )

        with filter_col3:
            time_filter = st.selectbox(
                "시간 필터",
                ["전체(최근 1시간)", "최근 10분", "최근 30분"],
                index=0
            )

        with filter_col4:
            date_filter = st.date_input("날짜 선택", value=None)

        filtered_data = data

        # 1) event_id 필터
        if event_id_filter.strip():
            keyword = event_id_filter.strip()
            filtered_data = [
                item for item in filtered_data
                if str(item.get("event_id", "")).strip() == keyword
            ]

        # 2) 탐지 여부 필터
        if detection_filter != "전체":
            temp = []

            for item in filtered_data:
                detection = safe_json_loads(item.get("detection_json"))
                detected = bool(detection.get("detected"))

                if detection_filter == "탐지된 것" and detected:
                    temp.append(item)
                elif detection_filter == "미탐지" and not detected:
                    temp.append(item)

            filtered_data = temp

        # 3) 날짜 / 최근 n분 필터
        def parse_event_time(value):
            if not value:
                return None
            try:
                return pd.to_datetime(value, utc=True)
            except Exception:
                return None

        now_utc = pd.Timestamp.utcnow()

        if time_filter != "전체(최근 1시간)":
            if time_filter == "최근 10분":
                cutoff = now_utc - pd.Timedelta(minutes=10)
            elif time_filter == "최근 30분":
                cutoff = now_utc - pd.Timedelta(minutes=30)
            # else:
            #     cutoff = now_utc - pd.Timedelta(hours=24)

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
            page_size = st.selectbox("페이지당 로그 수", [10, 20, 30], index=0)
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
            event_json = safe_json_loads(item.get("event_json"))
            normalized = safe_json_loads(item.get("normalized_json"))
            detection = safe_json_loads(item.get("detection_json"))
            risk = safe_json_loads(item.get("risk_json"))
            raw_json = safe_json_loads(item.get("raw_json"), default=item.get("raw_json"))

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
            ai_context = risk.get("ai_context") or {}

            if detected_rule_count > 1:
                expander_title = f"🚨 ID {event_id}   |   {computer_name}   |   탐지 {detected_rule_count}개   |   {event_time}"
            else:
                expander_title = f"🔎 ID {event_id}   |   {computer_name}   |   {rule_summary}   |   {event_time}"

            with st.expander(expander_title, expanded=False):
                st.caption(meta.get("description"))
                
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
                            delete_event(event_row_id)
                            st.success(f"이벤트 {event_row_id} 삭제 완료")
                            st.rerun()
                        except Exception as e:
                            st.error(f"이벤트 삭제 실패: {e}")


                row1 = st.columns(3)
                row1[0].write(f"👤 사용자: **{username}**")
                row1[1].write(f"이벤트 타입: **{event_type}**")
                row1[2].write(f"호스트 역할: **{host_role}**")

                row2 = st.columns(3)
                row2[0].write(f"계정 유형: **{account_type}**")
                row2[1].write(f"관리자 계정 여부: **{is_admin}**")
                row2[2].write(f"업무 외 시간 여부: **{is_off_hours}**")

                row3 = st.columns(3)
                row3[0].write(f"🌐 Source IP: **{source_ip}**")
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




                # -----------------------------
                # 컨텍스트 기반 판단 블록
                # -----------------------------
                ai_context = risk.get("ai_context") or {}

                st.divider()
                st.markdown("**컨텍스트 기반 판단**")

                if ai_context.get("enabled"):
                    ctx_verdict = ai_context.get("verdict", "-")
                    ctx_summary = ai_context.get("summary", "-")
                    ctx_applied = ai_context.get("applied", False)
                    related = ai_context.get("related_scenario") or {}
                    ctx_reasons = ai_context.get("reasons") or []

                    if ctx_applied:
                        st.success(f"판정: **{ctx_verdict}**")
                    else:
                        st.info(f"판정: **{ctx_verdict}**")

                    st.write(ctx_summary)

                    if related:
                        st.caption(
                            f"관련 시나리오: "
                            f"{related.get('scenario_id', '-')} / "
                            f"{related.get('scenario_type', '-')} / "
                            f"{related.get('status', '-')}"
                        )

                    if ctx_reasons:
                        with st.expander("컨텍스트 판단 근거", expanded=False):
                            for reason in ctx_reasons:
                                st.write(f"- {reason}")
                else:
                    st.caption("컨텍스트 기반 판단 대상이 아닙니다.")


                # -----------------------------
                # LLM 2차 판단 블록
                # -----------------------------
                llm_triage = risk.get("llm_triage") or {}
                llm_target = _is_llm_triage_target(detection, risk)
                llm_called = bool(llm_triage.get("called"))

                st.divider()
                st.markdown("**LLM 2차 판단**")

                last_llm_result = st.session_state.get(f"llm_triage_result_{event_row_id}")

                if last_llm_result:
                    result_status = last_llm_result.get("result")

                    if result_status == "updated":
                        st.success("LLM 판단 결과가 갱신되었습니다.")
                    elif result_status == "skipped":
                        st.warning(
                            f"LLM 판단이 실행되지 않았습니다: "
                            f"{last_llm_result.get('reason', '-')}"
                        )
                    elif result_status == "frontend_error":
                        st.error(
                            f"LLM 버튼 처리 중 오류: "
                            f"{last_llm_result.get('message', '-')}"
                        )
                    else:
                        st.info(f"LLM 처리 결과: {result_status}")



                llm_col1, llm_col2 = st.columns([7, 3])

                with llm_col1:
                    if llm_called:
                        verdict = llm_triage.get("verdict", "-")
                        confidence = llm_triage.get("confidence", 0)
                        summary = llm_triage.get("summary", "-")
                        llm_error = llm_triage.get("error")

                        if llm_error:
                            st.error(f"LLM 호출 실패: **{verdict}**")
                            st.write(summary)

                            with st.expander("LLM 오류 상세", expanded=True):
                                st.code(str(llm_error), language="text")
                        else:
                            st.success(f"판정 완료: **{verdict}** / 신뢰도: **{confidence}**")
                            st.write(summary)

                    elif llm_target:
                        st.info("이 이벤트는 LLM 2차 판단 대상입니다. 버튼을 누르면 컨텍스트 기반 분석을 실행합니다.")
                    else:
                        st.caption("이 이벤트는 LLM 2차 판단 대상이 아닙니다.")

                with llm_col2:
                    if st.button(
                        "LLM 판단 실행",
                        key=f"llm_triage_{event_row_id}",
                        disabled=(not llm_target) or event_row_id is None,
                        help="도구/정찰 관련 룰이 탐지된 이벤트만 LLM 판단을 실행합니다.",
                    ):
                        try:
                            st.session_state[f"llm_triage_clicked_{event_row_id}"] = True

                            with st.spinner("LLM이 이벤트 컨텍스트를 분석 중입니다..."):
                                result = run_event_llm_triage(event_row_id)

                            st.session_state[f"llm_triage_result_{event_row_id}"] = result
                            st.rerun()

                        except Exception as e:
                            st.session_state[f"llm_triage_result_{event_row_id}"] = {
                                "result": "frontend_error",
                                "message": str(e),
                            }
                            st.rerun()

                if llm_called:
                    with st.expander("LLM 판단 근거", expanded=False):
                        suspicious_points = llm_triage.get("suspicious_points") or []
                        benign_context = llm_triage.get("benign_context") or []
                        recommended_action = llm_triage.get("recommended_action") or "-"

                        st.markdown("**의심 근거**")
                        if suspicious_points:
                            for point in suspicious_points:
                                st.write(f"- {point}")
                        else:
                            st.write("- 없음")

                        st.markdown("**정상/실습 근거**")
                        if benign_context:
                            for item_text in benign_context:
                                st.write(f"- {item_text}")
                        else:
                            st.write("- 없음")

                        st.markdown("**권고 조치**")
                        st.write(recommended_action)



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