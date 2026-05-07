"""
BloodHound 그래프 뷰어
- /data/bloodhound/ 에 저장된 컬렉션 목록을 나열하고
- 선택한 컬렉션의 graph.html 을 인라인 iframe으로 렌더링한다.
"""

import os
import re
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

BLOODHOUND_ROOT = "/data/bloodhound"


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
