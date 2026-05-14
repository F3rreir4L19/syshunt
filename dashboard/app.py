from __future__ import annotations

import streamlit as st
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from core.db.queries import (
    create_target,
    get_pipeline_status,
    list_findings,
    list_targets,
)
from core.db.session import SessionLocal
from core.pipeline.tasks import celery_app
from redis import Redis
from redis.exceptions import RedisError


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
    pipeline_status = get_pipeline_status(celery_app)
    st.sidebar.metric("Pipeline", pipeline_status["state"])
    if pipeline_status["queued"] is not None:
        st.sidebar.caption(f"Queued tasks: {pipeline_status['queued']}")
    elif pipeline_status["error"]:
        st.sidebar.caption(str(pipeline_status["error"]))

    return st.sidebar.radio(
        "Navigation",
        [PAGE_TARGETS, PAGE_FINDINGS, PAGE_PROGRAMS, PAGE_SETTINGS],
        label_visibility="collapsed",
    )


def render_targets_page() -> None:
    st.header("Targets")
    try:
        with SessionLocal() as session:
            with st.form("add-target", clear_on_submit=True):
                domain = st.text_input("Domain", placeholder="example.com")
                submitted = st.form_submit_button("Add target")

            if submitted:
                try:
                    create_target(session, domain)
                    st.success("Target added.")
                except ValueError as exc:
                    st.error(str(exc))
                except IntegrityError:
                    session.rollback()
                    st.error("Target already exists.")

            targets = list_targets(session)
    except SQLAlchemyError as exc:
        st.error(f"Database unavailable: {exc.__class__.__name__}")
        return

    if not targets:
        st.info("No targets registered yet.")
        return

    st.dataframe(
        targets,
        hide_index=True,
        use_container_width=True,
        column_order=[
            "id",
            "domain",
            "status",
            "platform",
            "recon_depth",
            "last_recon_at",
        ],
    )


def render_findings_page() -> None:
    st.header("Findings")
    try:
        with SessionLocal() as session:
            severity_filter = st.multiselect(
                "Severity",
                ["critical", "high", "medium", "low", "info"],
                default=[],
            )
            status_filter = st.multiselect(
                "Status",
                ["new", "reviewing", "valid", "reported", "closed"],
                default=[],
            )
            text_filter = st.text_input("Search", placeholder="title, URL, template")
            findings = list_findings(
                session,
                severities=severity_filter,
                statuses=status_filter,
                search=text_filter,
            )
    except SQLAlchemyError as exc:
        st.error(f"Database unavailable: {exc.__class__.__name__}")
        return

    if not findings:
        st.info("No findings match the current filters.")
        return

    st.dataframe(
        findings,
        hide_index=True,
        use_container_width=True,
        column_order=[
            "id",
            "severity",
            "status",
            "title",
            "target",
            "url",
            "confidence",
            "auto_score",
        ],
    )


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
