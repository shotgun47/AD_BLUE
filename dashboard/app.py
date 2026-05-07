import streamlit as st

from components import render_sidebar

from views.home import render_home
from views.defense import render_defense
from views.attack import render_attack
from views.recon import render_recon
from views.ai_chat import render_ai_chat


st.set_page_config(page_title="AD Simulation Lab", layout="wide")

if "last_run_id" not in st.session_state:
    st.session_state.last_run_id = None
if "last_scenario_id" not in st.session_state:
    st.session_state.last_scenario_id = None
if "last_target_ip" not in st.session_state:
    st.session_state.last_target_ip = None
if "last_requested_by" not in st.session_state:
    st.session_state.last_requested_by = None

menu = render_sidebar()

if menu == "홈":
    render_home()
elif menu == "방어":
    render_defense()
elif menu == "공격":
    render_attack()
elif menu == "정찰":
    render_recon()
elif menu == "AI Chat":
    render_ai_chat()