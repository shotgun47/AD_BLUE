from streamlit_option_menu import option_menu
import streamlit as st

from config import SCENARIO_TYPE_STYLE_MAP
from api_client import run_scenario

import html


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "none": 0,
}

SEVERITY_STYLE = {
    "critical": ("#fee2e2", "#7f1d1d", "CRITICAL"),
    "high": ("#ffedd5", "#9a3412", "HIGH"),
    "medium": ("#fef3c7", "#92400e", "MEDIUM"),
    "low": ("#dcfce7", "#166534", "LOW"),
    "none": ("#f3f4f6", "#374151", "NONE"),
}


def normalize_severity(severity: str) -> str:
    severity = str(severity or "none").lower()
    return severity if severity in SEVERITY_STYLE else "none"


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(normalize_severity(severity), 0)


def severity_text(severity: str) -> str:
    severity = normalize_severity(severity)
    return SEVERITY_STYLE[severity][2]


def severity_badge(severity: str) -> str:
    severity = normalize_severity(severity)
    bg, fg, label = SEVERITY_STYLE[severity]
    return (
        f'<span style="background-color:{bg}; color:{fg}; '
        f'padding:3px 10px; border-radius:999px; font-weight:700; '
        f'font-size:0.85rem;">{label}</span>'
    )


def render_badge_table(rows, columns, badge_columns=None, right_columns=None):
    """
    st.dataframe 대신 HTML table로 출력하기 위한 공통 함수.
    badge_columns에 들어간 컬럼은 severity_badge()로 렌더링한다.
    """
    badge_columns = set(badge_columns or [])
    right_columns = set(right_columns or [])

    if not rows:
        st.info("표시할 데이터가 없습니다.")
        return

    table_html = """
    <table style="width:100%; border-collapse:collapse; margin-top:10px;">
        <thead>
            <tr style="background:#f9fafb;">
    """

    for col in columns:
        align = "right" if col in right_columns else "left"
        if col in badge_columns:
            align = "center"

        table_html += (
            f"<th style='padding:8px; border:1px solid #e5e7eb; "
            f"text-align:{align};'>{html.escape(str(col))}</th>"
        )

    table_html += """
            </tr>
        </thead>
        <tbody>
    """

    for row in rows:
        table_html += "<tr>"

        for col in columns:
            value = row.get(col, "-")
            align = "right" if col in right_columns else "left"

            if col in badge_columns:
                cell = severity_badge(value)
                align = "center"
            else:
                cell = html.escape(str(value if value is not None else "-"))

            table_html += (
                f"<td style='padding:8px; border:1px solid #e5e7eb; "
                f"text-align:{align}; color:#374151;'>{cell}</td>"
            )

        table_html += "</tr>"

    table_html += """
        </tbody>
    </table>
    """

    st.markdown(table_html, unsafe_allow_html=True)





def render_sidebar():
    with st.sidebar:
        return option_menu(
            "메뉴",
            ["홈", "방어", "공격", "정찰", "리포트", "AI Chat"],
            icons=["house", "shield", "crosshair", "diagram-3", "file-earmark-text", "robot"],
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


def execute_scenario(scenario_id: str, target_ip: str, requested_by: str, params_schema: list, extra_params: dict):
    if not target_ip.strip():
        st.warning("타겟 IP를 입력하세요.")
        return

    if not requested_by.strip():
        st.warning("실행자를 입력하세요.")
        return

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
        return

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
        result = run_scenario(
            scenario_id=scenario_id,
            params=params,
        )

        if result.get("result") == "error":
            st.warning(result.get("message", "시나리오 실행이 거부되었습니다."))
        else:
            st.session_state.last_run_id = result.get("run_id")
            st.session_state.last_scenario_id = result.get("scenario_id")
            st.session_state.last_target_ip = target_ip.strip()
            st.session_state.last_requested_by = requested_by.strip()
            st.success(f"{scenario_id} 실행 요청 완료")
    except Exception as e:
        st.error(f"시나리오 실행 실패: {e}")


def render_scenario_card(scenario: dict, target_ip: str, requested_by: str):
    scenario_id = scenario["scenario_id"]
    params_schema = scenario.get("params_schema") or []
    scenario_type = scenario.get("scenario_type", "general")
    description = scenario.get("description") or "설명이 등록되지 않은 시나리오입니다."

    style_info = SCENARIO_TYPE_STYLE_MAP.get(
        scenario_type,
        {
            "bg": "#eef2ff",
            "fg": "#3730a3",
            "label": scenario_type,
        }
    )

    with st.container(border=True):
        c1, c2 = st.columns([8, 2])

        with c1:
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

        st.caption(description)
        
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
                execute_scenario(
                    scenario_id=scenario_id,
                    target_ip=target_ip,
                    requested_by=requested_by,
                    params_schema=params_schema,
                    extra_params=extra_params,
                )