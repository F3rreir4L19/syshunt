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
    get_setting,
    get_target_screenshot_paths,
    list_findings,
    list_targets,
    normalize_domain,
)
from core.pipeline.tasks import run_ai_analysis
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
                auto_analyze_default = (
                    get_setting(session, "auto_analyze_default") or "true"
                ).lower() == "true"

                with st.form("add-target", clear_on_submit=True):
                    domain = st.text_input("Domain", placeholder="example.com")
                    auto_analyze = st.checkbox(
                        "Auto-analyze with AI after recon",
                        value=auto_analyze_default,
                    )
                    submitted = st.form_submit_button("Add target")

                if submitted:
                    if not domain or not domain.strip():
                        st.error("Domain is required.")
                    else:
                        try:
                            normalize_domain(domain)
                        except ValueError as exc:
                            st.error(f"Invalid domain: {exc}")
                        else:
                            try:
                                create_target(session, domain, auto_analyze=auto_analyze)
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

    classifier_used = detail.get("classifier_used") or ""
    if classifier_used.startswith("ai:"):
        st.success(f"🤖 AI ({classifier_used})")
    elif classifier_used == "heuristic":
        st.info("📐 Heuristic")
    else:
        st.caption("Not yet classified")

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

    if classifier_used == "heuristic" and detail.get("confidence_note"):
        st.warning(detail["confidence_note"])

    if detail.get("ai_reasoning"):
        with st.expander("AI Reasoning"):
            st.write(detail["ai_reasoning"])

    if detail.get("ai_report_draft"):
        with st.expander("Report Draft"):
            st.code(detail["ai_report_draft"], language="markdown")
            if st.button("Copy to clipboard", key=f"copy_{finding_id}"):
                st.write(detail["ai_report_draft"])

    with st.expander("Raw evidence"):
        st.json(detail["raw_evidence"])

    # Re-analyze button (only when not yet AI-classified)
    if not classifier_used or classifier_used == "heuristic":
        if st.button("Re-analyze with AI", key=f"reanalyze_{finding_id}"):
            try:
                run_ai_analysis.apply_async(
                    args=[int(detail["target_id"])],
                    kwargs={"force_reanalyze": True},
                )
                st.success("Re-analysis queued.")
            except Exception as exc:
                st.error(f"Could not queue re-analysis: {exc}")

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


# ---------------------------------------------------------------------------
# Settings page
# ---------------------------------------------------------------------------


def render_settings_page() -> None:  # noqa: PLR0912, PLR0915
    st.header("Settings")

    try:
        session_ctx = SessionLocal()
        session = session_ctx.__enter__()
    except SQLAlchemyError as exc:
        st.error(f"Database unavailable: {exc.__class__.__name__}")
        return

    try:
        from core.db.queries import get_setting, set_setting

        # ------------------------------------------------------------------
        # AI Provider section
        # ------------------------------------------------------------------
        st.subheader("AI Provider")
        with st.form("ai-provider-settings"):
            ai_provider_choice = st.selectbox(
                "AI Provider",
                ["Auto", "anthropic", "openai", "ollama"],
                index=["auto", "anthropic", "openai", "ollama"].index(
                    (get_setting(session, "AI_PROVIDER") or "auto").lower()
                ),
            )
            anthropic_key = st.text_input(
                "Anthropic API Key",
                value=get_setting(session, "ANTHROPIC_API_KEY") or "",
                type="password",
            )
            openai_key = st.text_input(
                "OpenAI API Key",
                value=get_setting(session, "OPENAI_API_KEY") or "",
                type="password",
            )
            openai_base_url = st.text_input(
                "OpenAI Base URL",
                value=get_setting(session, "OPENAI_BASE_URL") or "",
            )
            openai_model = st.text_input(
                "OpenAI Model",
                value=get_setting(session, "OPENAI_MODEL") or "gpt-4o-mini",
            )
            ollama_url = st.text_input(
                "Ollama Base URL",
                value=get_setting(session, "OLLAMA_BASE_URL") or "http://localhost:11434",
            )
            ollama_model = st.text_input(
                "Ollama Model",
                value=get_setting(session, "OLLAMA_MODEL") or "llama3.2",
            )
            limit_enabled = st.checkbox(
                "Limit AI analysis per target",
                value=get_setting(session, "ai_analysis_limit") is not None,
            )
            max_findings = st.number_input(
                "Max findings per target",
                min_value=1,
                value=int(get_setting(session, "ai_analysis_limit") or 50),
                disabled=not limit_enabled,
            )
            ai_call_delay = st.number_input(
                "AI call delay (seconds)",
                min_value=0.0,
                max_value=10.0,
                value=float(get_setting(session, "ai_call_delay_seconds") or "1"),
                step=0.5,
            )
            auto_analyze_default = st.checkbox(
                "Auto-analyze new targets by default",
                value=(get_setting(session, "auto_analyze_default") or "true").lower() == "true",
            )
            ai_save = st.form_submit_button("Save AI Settings")
            ai_test = st.form_submit_button("Test connection")

        if ai_save:
            set_setting(session, "AI_PROVIDER", "" if ai_provider_choice == "Auto" else ai_provider_choice)
            set_setting(session, "ANTHROPIC_API_KEY", anthropic_key)
            set_setting(session, "OPENAI_API_KEY", openai_key)
            set_setting(session, "OPENAI_BASE_URL", openai_base_url)
            set_setting(session, "OPENAI_MODEL", openai_model)
            set_setting(session, "OLLAMA_BASE_URL", ollama_url)
            set_setting(session, "OLLAMA_MODEL", ollama_model)
            set_setting(session, "ai_analysis_limit", str(int(max_findings)) if limit_enabled else "")
            set_setting(session, "ai_call_delay_seconds", str(ai_call_delay))
            set_setting(session, "auto_analyze_default", "true" if auto_analyze_default else "false")
            session.commit()
            st.success("AI settings saved.")

        if ai_test:
            from core.analysis.provider import (
                AnthropicProvider,
                OllamaProvider,
                OpenAICompatibleProvider,
            )
            # Build provider directly from form values — never mutate os.environ
            test_provider = None
            choice_lower = ai_provider_choice.lower()
            if choice_lower in ("auto", "anthropic") and anthropic_key:
                test_provider = AnthropicProvider(api_key=anthropic_key)
            elif choice_lower in ("auto", "openai") and openai_key:
                test_provider = OpenAICompatibleProvider(
                    api_key=openai_key,
                    base_url=openai_base_url or "https://api.openai.com/v1",
                    model=openai_model,
                )
            elif choice_lower in ("auto", "ollama"):
                test_provider = OllamaProvider(base_url=ollama_url, model=ollama_model)

            if test_provider is None:
                st.warning("No provider configured — check API keys.")
            elif test_provider.is_available():
                st.success(f"Connected to {type(test_provider).__name__}.")
            else:
                st.error(f"{type(test_provider).__name__} is not reachable.")

        st.divider()

        # ------------------------------------------------------------------
        # Recon Defaults section
        # ------------------------------------------------------------------
        st.subheader("Recon Defaults")
        with st.form("recon-defaults-settings"):
            recon_depth = st.number_input(
                "Recon depth",
                min_value=1,
                max_value=3,
                value=int(get_setting(session, "MAX_RECON_DEPTH") or 2),
            )
            nuclei_rate = st.number_input(
                "Nuclei rate limit",
                min_value=1,
                value=int(get_setting(session, "NUCLEI_RATE_LIMIT") or 150),
            )
            screenshot_timeout = st.number_input(
                "Screenshot timeout (s)",
                min_value=5,
                value=int(get_setting(session, "SCREENSHOT_TIMEOUT") or 30),
            )
            recon_concurrency = st.number_input(
                "Recon concurrency",
                min_value=1,
                value=int(get_setting(session, "RECON_CONCURRENCY") or 10),
            )
            nuclei_cats_default = (get_setting(session, "nuclei_categories") or "").split(",")
            nuclei_cats_default = [c for c in nuclei_cats_default if c]
            nuclei_categories = st.multiselect(
                "Nuclei categories",
                ["cve", "exposure", "misconfiguration", "default-logins", "fuzzing", "takeovers", "network"],
                default=nuclei_cats_default,
            )
            recon_save = st.form_submit_button("Save Recon Defaults")

        if recon_save:
            set_setting(session, "MAX_RECON_DEPTH", str(int(recon_depth)))
            set_setting(session, "NUCLEI_RATE_LIMIT", str(int(nuclei_rate)))
            set_setting(session, "SCREENSHOT_TIMEOUT", str(int(screenshot_timeout)))
            set_setting(session, "RECON_CONCURRENCY", str(int(recon_concurrency)))
            set_setting(session, "nuclei_categories", ",".join(nuclei_categories))
            session.commit()
            st.success("Recon defaults saved.")

        st.divider()

        # ------------------------------------------------------------------
        # Notifications section
        # ------------------------------------------------------------------
        st.subheader("Notifications")
        with st.form("notifications-settings"):
            discord_url = st.text_input(
                "Discord Webhook URL",
                value=get_setting(session, "DISCORD_WEBHOOK_URL") or "",
            )
            ev_new_program = st.checkbox(
                "New program detected",
                value=(get_setting(session, "notify_new_program") or "false") == "true",
            )
            ev_recon_done = st.checkbox(
                "Recon completed",
                value=(get_setting(session, "notify_recon_done") or "false") == "true",
            )
            ev_high_score = st.checkbox(
                "High-score finding (score ≥ 80)",
                value=(get_setting(session, "notify_high_score_finding") or "false") == "true",
            )
            ev_scope_changed = st.checkbox(
                "Scope changed",
                value=(get_setting(session, "notify_scope_changed") or "false") == "true",
            )
            ev_pipeline_error = st.checkbox(
                "Pipeline error",
                value=(get_setting(session, "notify_pipeline_error") or "false") == "true",
            )
            notif_save = st.form_submit_button("Save Notification Settings")

        if notif_save:
            set_setting(session, "DISCORD_WEBHOOK_URL", discord_url)
            set_setting(session, "notify_new_program", "true" if ev_new_program else "")
            set_setting(session, "notify_recon_done", "true" if ev_recon_done else "")
            set_setting(session, "notify_high_score_finding", "true" if ev_high_score else "")
            set_setting(session, "notify_scope_changed", "true" if ev_scope_changed else "")
            set_setting(session, "notify_pipeline_error", "true" if ev_pipeline_error else "")
            session.commit()
            st.success("Notification settings saved.")

    except SQLAlchemyError as exc:
        st.error(f"Database error while saving: {exc.__class__.__name__}")
    finally:
        session_ctx.__exit__(None, None, None)


def render_page(page: str) -> None:
    if page == PAGE_TARGETS:
        render_targets_page()
    elif page == PAGE_FINDINGS:
        render_findings_page()
    elif page == PAGE_PROGRAMS:
        render_placeholder_page(PAGE_PROGRAMS)
    elif page == PAGE_SETTINGS:
        render_settings_page()
    else:
        st.error(f"Unknown page: {page}")


def main() -> None:
    configure_page()
    selected_page = render_sidebar()
    render_page(selected_page)


if __name__ == "__main__":
    main()
