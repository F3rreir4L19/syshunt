from __future__ import annotations

import streamlit as st


PAGE_TARGETS = "Targets"
PAGE_FINDINGS = "Findings"
PAGE_PROGRAMS = "Programs"
PAGE_SETTINGS = "Settings"


def configure_page() -> None:
    st.set_page_config(
        page_title="Syshunt",
        page_icon="SH",
        layout="wide",
        initial_sidebar_state="expanded",
    )


def render_sidebar() -> str:
    st.sidebar.title("Syshunt")
    return st.sidebar.radio(
        "Navigation",
        [PAGE_TARGETS, PAGE_FINDINGS, PAGE_PROGRAMS, PAGE_SETTINGS],
        label_visibility="collapsed",
    )


def render_targets_page() -> None:
    st.header("Targets")
    st.info("Target management will be available in this phase.")


def render_findings_page() -> None:
    st.header("Findings")
    st.info("Finding triage will be available in this phase.")


def render_placeholder_page(title: str) -> None:
    st.header(title)
    st.info("This area is planned for a later phase.")


def render_page(page: str) -> None:
    if page == PAGE_TARGETS:
        render_targets_page()
    elif page == PAGE_FINDINGS:
        render_findings_page()
    elif page == PAGE_PROGRAMS:
        render_placeholder_page(PAGE_PROGRAMS)
    elif page == PAGE_SETTINGS:
        render_placeholder_page(PAGE_SETTINGS)
    else:
        st.error(f"Unknown page: {page}")


def main() -> None:
    configure_page()
    selected_page = render_sidebar()
    render_page(selected_page)


if __name__ == "__main__":
    main()
