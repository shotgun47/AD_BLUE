from streamlit_option_menu import option_menu
import streamlit as st

from config import SCENARIO_TYPE_STYLE_MAP
from api_client import run_scenario


def render_sidebar():
    with st.sidebar:
        return option_menu(
            "메뉴",
            ["홈", "방어", "공격", "정찰", "AI Chat"],
            icons=["house", "shield", "crosshair", "diagram-3", "robot"],
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
    return (
        f'<span style="background-color:{bg}; color:{fg}; '
        f'padding:3px 8px; border-radius:999px; font-weight:700;">'
        f'{severity}</span>'
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