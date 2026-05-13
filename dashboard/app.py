from __future__ import annotations

import streamlit as st
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.db.models import Target
from core.db.session import SessionLocal


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


def normalize_domain(domain: str) -> str:
    cleaned = domain.strip().lower()
    if cleaned.startswith("http://"):
        cleaned = cleaned.removeprefix("http://")
    elif cleaned.startswith("https://"):
        cleaned = cleaned.removeprefix("https://")

    return cleaned.strip("/")


def create_target(session: Session, domain: str) -> Target:
    normalized = normalize_domain(domain)
    if not normalized:
        raise ValueError("Domain is required.")

    target = Target(domain=normalized, scope_includes=[normalized])
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


def list_targets(session: Session) -> list[dict[str, object]]:
    targets = session.query(Target).order_by(Target.created_at.desc()).all()
    return [
        {
            "id": target.id,
            "domain": target.domain,
            "status": target.status,
            "platform": target.platform or "",
            "recon_depth": target.recon_depth,
            "last_recon_at": target.last_recon_at,
        }
        for target in targets
    ]


if __name__ == "__main__":
    main()
