from __future__ import annotations

import streamlit as st
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.db.models import Finding, Target
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


def list_findings(
    session: Session,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    search: str = "",
) -> list[dict[str, object]]:
    query = session.query(Finding).join(Target).order_by(Finding.created_at.desc())

    if severities:
        query = query.filter(Finding.severity.in_(severities))
    if statuses:
        query = query.filter(Finding.status.in_(statuses))

    cleaned_search = search.strip().lower()
    findings = query.all()
    if cleaned_search:
        findings = [
            finding
            for finding in findings
            if cleaned_search in finding.title.lower()
            or (finding.url is not None and cleaned_search in finding.url.lower())
            or (
                finding.template_id is not None
                and cleaned_search in finding.template_id.lower()
            )
        ]

    return [
        {
            "id": finding.id,
            "severity": finding.severity,
            "status": finding.status,
            "title": finding.title,
            "target": finding.target.domain,
            "url": finding.url or "",
            "confidence": finding.confidence,
            "auto_score": finding.auto_score,
        }
        for finding in findings
    ]


if __name__ == "__main__":
    main()
