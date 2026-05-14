from __future__ import annotations

import csv
import io
import os

import streamlit as st
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from core.db.queries import (
    bulk_create_targets,
    create_target,
    get_finding,
    get_pipeline_status,
    get_target_screenshot_paths,
    list_findings,
    list_targets,
)
from core.db.session import SessionLocal
from core.pipeline.tasks import celery_app


PAGE_TARGETS = "Targets"
PAGE_FINDINGS = "Findings"
PAGE_PROGRAMS = "Programs"
PAGE_SETTINGS = "Settings"


def _output_dir() -> str:
    return os.getenv("OUTPUT_DIR", "/tmp/syshunt")


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


# ---------------------------------------------------------------------------
# Targets page
# ---------------------------------------------------------------------------


def _parse_domains_from_csv(content: bytes) -> list[str]:
    """Extract domains from CSV bytes.

    Accepts a file with a header row containing a 'domain' column, or a
    single-column file with no header (plain list of domains).
    """
    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    domains: list[str] = []
    if reader.fieldnames and "domain" in [f.lower() for f in (reader.fieldnames or [])]:
        domain_col = next(
            f for f in (reader.fieldnames or []) if f.lower() == "domain"
        )
        for row in reader:
            val = row.get(domain_col, "").strip()
            if val:
                domains.append(val)
    else:
        # No 'domain' column: treat first field of each line as the domain.
        # The header row (if any) will be rejected by normalize_domain validation.
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            first_col = stripped.split(",")[0].strip()
            if first_col:
                domains.append(first_col)
    return domains


def render_targets_page() -> None:
    st.header("Targets")

    tab_add, tab_csv, tab_list = st.tabs(["Add Target", "Import CSV", "Target List"])

    with tab_add:
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
        except SQLAlchemyError as exc:
            st.error(f"Database unavailable: {exc.__class__.__name__}")

    with tab_csv:
        st.markdown("Upload a CSV with a **domain** column, or one domain per line.")
        uploaded = st.file_uploader("Choose CSV file", type=["csv", "txt"])
        if uploaded is not None:
            raw_bytes = uploaded.read()
            domains = _parse_domains_from_csv(raw_bytes)
            if not domains:
                st.warning("No domains found in the uploaded file.")
            else:
                st.write(f"Found **{len(domains)}** domains. Preview:")
                st.write(domains[:10])
                if st.button("Import all"):
                    try:
                        with SessionLocal() as session:
                            created, skipped, errors = bulk_create_targets(
                                session, domains
                            )
                        st.success(
                            f"Imported {created} targets. Skipped {skipped} duplicates."
                        )
                        if errors:
                            st.warning("Errors:\n" + "\n".join(errors))
                    except SQLAlchemyError as exc:
                        st.error(f"Import failed: {exc.__class__.__name__}")

    with tab_list:
        _render_target_list()


def _render_target_list() -> None:
    try:
        with SessionLocal() as session:
            targets = list_targets(session)
    except SQLAlchemyError as exc:
        st.error(f"Database unavailable: {exc.__class__.__name__}")
        return

    if not targets:
        st.info("No targets registered yet.")
        return

    status_filter = st.multiselect(
        "Filter by status",
        ["pending", "recon_running", "recon_done", "ready_for_review", "archived"],
        default=[],
        key="targets_status_filter",
    )
    if status_filter:
        targets = [t for t in targets if t["status"] in status_filter]

    st.dataframe(
        targets,
        hide_index=True,
        use_container_width=True,
        column_order=["id", "domain", "status", "platform", "recon_depth", "last_recon_at"],
    )

    st.divider()
    st.subheader("Screenshots")
    if targets:
        target_options = {f"{t['domain']} (id={t['id']})": t["id"] for t in targets}
        selected_label = st.selectbox("Select target to view screenshots", list(target_options))
        if selected_label:
            selected_id = target_options[selected_label]
            paths = get_target_screenshot_paths(int(selected_id), _output_dir())
            if paths:
                cols = st.columns(min(3, len(paths)))
                for i, path in enumerate(paths):
                    with cols[i % 3]:
                        st.image(path, caption=path.split("/")[-1])
            else:
                st.info("No screenshots found for this target.")


# ---------------------------------------------------------------------------
# Findings page
# ---------------------------------------------------------------------------


def render_findings_page() -> None:
    st.header("Findings")

    col_filters, col_detail = st.columns([2, 1])

    with col_filters:
        _render_findings_filters_and_table()


def _render_findings_filters_and_table() -> None:
    try:
        with SessionLocal() as session:
            all_targets = list_targets(session)

        target_map: dict[str, int | None] = {"All targets": None}
        target_map.update({t["domain"]: t["id"] for t in all_targets})

        with st.form("findings-filter"):
            c1, c2 = st.columns(2)
            with c1:
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
                selected_target_label = st.selectbox(
                    "Target", list(target_map.keys())
                )
            with c2:
                score_min, score_max = st.slider(
                    "Score range", 0, 100, (0, 100), step=5
                )
                text_filter = st.text_input(
                    "Search", placeholder="title, URL, template"
                )
            apply = st.form_submit_button("Apply filters")

        selected_target_id = target_map.get(selected_target_label)

        with SessionLocal() as session:
            findings = list_findings(
                session,
                severities=severity_filter or None,
                statuses=status_filter or None,
                search=text_filter,
                target_id=selected_target_id,
                score_min=score_min,
                score_max=score_max,
            )
    except SQLAlchemyError as exc:
        st.error(f"Database unavailable: {exc.__class__.__name__}")
        return

    if not findings:
        st.info("No findings match the current filters.")
        return

    # Strip heavy fields for the table view
    table_rows = [
        {k: v for k, v in f.items() if k not in {"raw_evidence", "description", "target_id"}}
        for f in findings
    ]

    st.dataframe(
        table_rows,
        hide_index=True,
        use_container_width=True,
        column_order=["id", "severity", "status", "title", "target", "url", "confidence", "auto_score"],
    )

    st.divider()
    st.subheader("Finding Detail")
    finding_ids = [f["id"] for f in findings]
    selected_id = st.selectbox(
        "Select finding to view details",
        finding_ids,
        format_func=lambda fid: next(
            (f"{f['severity'].upper()} – {f['title']}" for f in findings if f["id"] == fid),
            str(fid),
        ),
    )
    if selected_id:
        _render_finding_detail(int(selected_id))


def _render_finding_detail(finding_id: int) -> None:
    try:
        with SessionLocal() as session:
            detail = get_finding(session, finding_id)
    except SQLAlchemyError as exc:
        st.error(f"Database error: {exc.__class__.__name__}")
        return

    if detail is None:
        st.warning("Finding not found.")
        return

    st.markdown(f"### {detail['title']}")
    col_a, col_b, col_c = st.columns(3)
    col_a.metric("Severity", str(detail["severity"]).upper())
    col_b.metric("Score", detail["auto_score"])
    col_c.metric("Confidence", detail["confidence"])

    if detail["url"]:
        st.markdown(f"**URL:** {detail['url']}")
    if detail["description"]:
        st.markdown(f"**Description:** {detail['description']}")
    st.markdown(
        f"**Type:** `{detail['type']}` | "
        f"**Exploitation:** {detail['exploitation_difficulty']} | "
        f"**Status:** {detail['status']}"
    )

    with st.expander("Raw evidence"):
        st.json(detail["raw_evidence"])

    # Screenshots associated with the finding's target
    paths = get_target_screenshot_paths(int(detail["target_id"]), _output_dir())
    if paths:
        with st.expander(f"Screenshots ({len(paths)})"):
            cols = st.columns(min(3, len(paths)))
            for i, path in enumerate(paths):
                with cols[i % 3]:
                    st.image(path, caption=path.split("/")[-1])


# ---------------------------------------------------------------------------
# Placeholder pages
# ---------------------------------------------------------------------------


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
