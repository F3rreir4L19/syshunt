from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog
from celery import Celery, chain

from core.db import queries
from core.db.models import Finding, ReconResult, Target
from core.db.session import SessionLocal
from tools.dnsx_wrapper import DnsxWrapper
from tools.gau_wrapper import GauWrapper
from tools.gowitness_wrapper import GoWitnessWrapper
from tools.httpx_wrapper import HttpxWrapper
from tools.katana_wrapper import KatanaWrapper
from tools.nmap_wrapper import NmapWrapper
from tools.nuclei_wrapper import NucleiWrapper
from tools.subfinder_wrapper import SubfinderWrapper


DEFAULT_REDIS_URL = "redis://localhost:6379/0"


def get_redis_url() -> str:
    return os.getenv("REDIS_URL", DEFAULT_REDIS_URL)


def should_run_tasks_eagerly() -> bool:
    return os.getenv("CELERY_TASK_ALWAYS_EAGER", "false").lower() in {
        "1",
        "true",
        "yes",
    }


def _output_dir() -> Path:
    return Path(os.getenv("OUTPUT_DIR", "/tmp/syshunt"))


def _hostname_from_item(item: str) -> str:
    """Extract hostname from a URL or return the item if it's already a domain."""
    if item.startswith(("http://", "https://")):
        return urlparse(item).hostname or item
    return item


celery_app = Celery(
    "syshunt",
    broker=get_redis_url(),
    backend=get_redis_url(),
)
celery_app.conf.update(
    task_always_eager=should_run_tasks_eagerly(),
    task_eager_propagates=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
)


@celery_app.task(name="core.pipeline.run_subdomain_enum")
def run_subdomain_enum(target_id: int) -> dict[str, int | str]:
    log = structlog.get_logger().bind(target_id=target_id, tool="subfinder")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        result = SubfinderWrapper().run(target.domain)
        if not result.success:
            log.warning("subdomain_enum_failed", error=result.error)
            raise RuntimeError(result.error or "subfinder failed")

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="subfinder",
            result_type="subdomain",
            data_items=[{"value": s} for s in result.parsed_data],
        )
        session.commit()

    log.info("subdomain_enum_completed", created=len(inserted))
    return {
        "target_id": target_id,
        "tool": "subfinder",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_http_probe")
def run_http_probe(target_id: int) -> dict[str, int | str]:
    log = structlog.get_logger().bind(target_id=target_id, tool="httpx")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        # Collect subdomains from any tool that stored them as result_type=subdomain
        subdomains = [
            r.data["value"]
            for r in session.query(ReconResult)
            .filter(
                ReconResult.target_id == target.id,
                ReconResult.result_type == "subdomain",
                ReconResult.superseded_by.is_(None),
            )
            .all()
            if "value" in r.data
        ]
        probe_targets = subdomains or [target.domain]

        errors: list[str] = []
        data_items: list[dict[str, Any]] = []

        for probe_target in probe_targets:
            if not queries.check_in_scope(
                probe_target, target.scope_includes, target.scope_excludes
            ):
                log.debug("out_of_scope", item=probe_target)
                continue
            probe_result = HttpxWrapper().run(probe_target)
            if not probe_result.success:
                log.warning(
                    "http_probe_item_failed",
                    probe_target=probe_target,
                    error=probe_result.error,
                )
                errors.append(f"{probe_target}: {probe_result.error}")
                continue
            data_items.extend(probe_result.parsed_data)

        if not data_items and errors:
            raise RuntimeError(
                f"httpx failed for all targets: {'; '.join(errors)}"
            )

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="httpx",
            result_type="http_service",
            data_items=data_items,
        )
        session.commit()

    log.info("http_probe_completed", created=len(inserted), errors=len(errors))
    return {
        "target_id": target_id,
        "tool": "httpx",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_port_scan")
def run_port_scan(target_id: int) -> dict[str, int | str]:
    """Run nmap top-1000 port scan against live HTTP hosts."""
    log = structlog.get_logger().bind(target_id=target_id, tool="nmap")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        # Use hostnames from live HTTP services; fall back to root domain
        hosts = list(
            {
                r.data.get("host")
                or urlparse(r.data.get("url", "")).hostname
                or ""
                for r in session.query(ReconResult)
                .filter(
                    ReconResult.target_id == target.id,
                    ReconResult.tool == "httpx",
                    ReconResult.result_type == "http_service",
                    ReconResult.superseded_by.is_(None),
                )
                .all()
            }
            - {"", None}
        ) or [target.domain]

        errors: list[str] = []
        data_items: list[dict[str, Any]] = []

        for host in hosts:
            if not queries.check_in_scope(
                host, target.scope_includes, target.scope_excludes
            ):
                log.debug("out_of_scope", item=host)
                continue
            scan_result = NmapWrapper().run(host)
            if not scan_result.success:
                log.warning("port_scan_item_failed", host=host, error=scan_result.error)
                errors.append(f"{host}: {scan_result.error}")
                continue
            data_items.extend(scan_result.parsed_data)

        if not data_items and errors:
            raise RuntimeError(f"nmap failed for all hosts: {'; '.join(errors)}")

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="nmap",
            result_type="open_port",
            data_items=data_items,
        )
        session.commit()

    log.info("port_scan_completed", created=len(inserted), errors=len(errors))
    return {
        "target_id": target_id,
        "tool": "nmap",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_web_crawl")
def run_web_crawl(target_id: int) -> dict[str, int | str]:
    """Crawl live HTTP services with katana (active) and gau (historical)."""
    log = structlog.get_logger().bind(target_id=target_id, tool="webcrawl")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        urls = [
            r.data["url"]
            for r in session.query(ReconResult)
            .filter(
                ReconResult.target_id == target.id,
                ReconResult.tool == "httpx",
                ReconResult.result_type == "http_service",
                ReconResult.superseded_by.is_(None),
            )
            .all()
            if "url" in r.data
        ]
        crawl_targets = urls or [f"https://{target.domain}"]

        errors: list[str] = []
        # map url -> source_tool; later entries (gau) don't overwrite katana
        url_to_source: dict[str, str] = {}

        for url in crawl_targets:
            host = _hostname_from_item(url)
            if not queries.check_in_scope(
                host, target.scope_includes, target.scope_excludes
            ):
                log.debug("out_of_scope", item=url)
                continue
            for wrapper_cls in (KatanaWrapper, GauWrapper):
                wrapper = wrapper_cls()
                result = wrapper.run(url)
                if not result.success:
                    log.warning(
                        "crawl_item_failed",
                        tool=wrapper.name,
                        url=url,
                        error=result.error,
                    )
                    errors.append(f"{wrapper.name}:{url}: {result.error}")
                    continue
                for crawled_url in result.parsed_data:
                    if crawled_url not in url_to_source:
                        url_to_source[crawled_url] = wrapper.name

        if not url_to_source and errors:
            raise RuntimeError(f"all crawlers failed: {'; '.join(errors)}")

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="webcrawl",
            result_type="crawled_url",
            data_items=[
                {"url": u, "source_tool": src} for u, src in url_to_source.items()
            ],
        )
        session.commit()

    log.info("web_crawl_completed", created=len(inserted), errors=len(errors))
    return {
        "target_id": target_id,
        "tool": "webcrawl",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_screenshot")
def run_screenshot(target_id: int) -> dict[str, int | str]:
    """Capture screenshots of live HTTP services with gowitness."""
    log = structlog.get_logger().bind(target_id=target_id, tool="gowitness")
    screenshot_dir = _output_dir() / "screenshots" / str(target_id)
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        urls = [
            r.data["url"]
            for r in session.query(ReconResult)
            .filter(
                ReconResult.target_id == target.id,
                ReconResult.tool == "httpx",
                ReconResult.result_type == "http_service",
                ReconResult.superseded_by.is_(None),
            )
            .all()
            if "url" in r.data
        ]
        screenshot_targets = urls or [f"https://{target.domain}"]

        errors: list[str] = []
        data_items: list[dict[str, Any]] = []

        from tools.base import ToolOptions

        _img_suffixes = {".png", ".jpg", ".jpeg"}

        for url in screenshot_targets:
            before: set[str] = {
                p.name
                for p in screenshot_dir.iterdir()
                if p.suffix.lower() in _img_suffixes
            }
            shot_result = GoWitnessWrapper().run(
                url, ToolOptions(screenshot_dir=screenshot_dir)
            )
            if not shot_result.success:
                log.warning("screenshot_item_failed", url=url, error=shot_result.error)
                errors.append(f"{url}: {shot_result.error}")
                continue
            after: set[str] = {
                p.name
                for p in screenshot_dir.iterdir()
                if p.suffix.lower() in _img_suffixes
            }
            new_files = sorted(after - before)
            filename = new_files[0] if new_files else None
            data_items.append({
                "url": url,
                "screenshot_dir": str(screenshot_dir.relative_to(_output_dir())),
                "filename": filename,
            })

        if not data_items and errors:
            raise RuntimeError(f"gowitness failed for all URLs: {'; '.join(errors)}")

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="gowitness",
            result_type="screenshot",
            data_items=data_items,
        )
        session.commit()

    log.info("screenshot_completed", created=len(inserted), errors=len(errors))
    return {
        "target_id": target_id,
        "tool": "gowitness",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_nuclei_scan")
def run_nuclei_scan(target_id: int) -> dict[str, int | str]:
    log = structlog.get_logger().bind(target_id=target_id, tool="nuclei")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        urls = [
            r.data["url"]
            for r in session.query(ReconResult)
            .filter(
                ReconResult.target_id == target.id,
                ReconResult.tool == "httpx",
                ReconResult.result_type == "http_service",
                ReconResult.superseded_by.is_(None),
            )
            .all()
            if "url" in r.data
        ]
        scan_targets = urls or [target.domain]

        errors: list[str] = []
        finding_data_items: list[dict[str, Any]] = []

        for scan_target in scan_targets:
            host = _hostname_from_item(scan_target)
            if not queries.check_in_scope(
                host, target.scope_includes, target.scope_excludes
            ):
                log.debug("out_of_scope", item=scan_target)
                continue
            scan_result = NucleiWrapper().run(scan_target)
            if not scan_result.success:
                log.warning(
                    "nuclei_scan_item_failed",
                    scan_target=scan_target,
                    error=scan_result.error,
                )
                errors.append(f"{scan_target}: {scan_result.error}")
                continue
            finding_data_items.extend(scan_result.parsed_data)

        if not finding_data_items and errors:
            raise RuntimeError(
                f"nuclei failed for all targets: {'; '.join(errors)}"
            )

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="nuclei",
            result_type="finding",
            data_items=finding_data_items,
        )
        for finding_data in inserted:
            session.add(_finding_from_nuclei_result(target.id, finding_data))

        target.status = "recon_done"
        target.last_recon_at = datetime.now(UTC)
        session.commit()

    log.info("nuclei_scan_completed", created=len(inserted), errors=len(errors))
    return {
        "target_id": target_id,
        "tool": "nuclei",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_dnsx_filter")
def run_dnsx_filter(target_id: int) -> dict[str, int | str]:
    """Filter subdomains by DNS resolution using dnsx.

    Non-fatal: if dnsx is not installed or fails, logs a warning and returns
    without modifying the stored subdomains. Subdomains that do not resolve are
    superseded so subsequent pipeline steps skip them.
    """
    log = structlog.get_logger().bind(target_id=target_id, tool="dnsx")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        active_subdomain_results = (
            session.query(ReconResult)
            .filter(
                ReconResult.target_id == target.id,
                ReconResult.result_type == "subdomain",
                ReconResult.superseded_by.is_(None),
            )
            .all()
        )

        if not active_subdomain_results:
            log.info("dnsx_filter_skipped", reason="no_active_subdomains")
            return {"target_id": target_id, "tool": "dnsx", "filtered": 0, "kept": 0}

        all_domains = [
            r.data["value"]
            for r in active_subdomain_results
            if r.data.get("value")
        ]
        if not all_domains:
            return {"target_id": target_id, "tool": "dnsx", "filtered": 0, "kept": 0}

        result = DnsxWrapper().run("\n".join(all_domains))
        if not result.success:
            log.warning("dnsx_filter_failed", error=result.error)
            return {
                "target_id": target_id,
                "tool": "dnsx",
                "filtered": 0,
                "kept": len(all_domains),
                "skipped": True,
            }

        resolved_set = {h.lower() for h in result.parsed_data}

        # Create a marker record so non-resolving results can reference it
        marker = ReconResult(
            target_id=target.id,
            tool="dnsx",
            result_type="dns_filter",
            data={"resolved_count": len(resolved_set)},
        )
        session.add(marker)
        session.flush()

        filtered = 0
        for sub_result in active_subdomain_results:
            domain = (sub_result.data.get("value") or "").lower()
            if domain and domain not in resolved_set:
                sub_result.superseded_by = marker.id
                filtered += 1

        session.commit()

    kept = len(all_domains) - filtered
    log.info("dnsx_filter_completed", filtered=filtered, kept=kept)
    return {"target_id": target_id, "tool": "dnsx", "filtered": filtered, "kept": kept}


@celery_app.task(name="core.pipeline.run_full_pipeline")
def run_full_pipeline(target_id: int, skip_recon: bool = False) -> dict[str, int | str]:
    """Start the full recon pipeline for a target.

    Args:
        target_id: The target to process.
        skip_recon: When True, skip steps 1-5 (subdomain → screenshot) and run
            only nuclei against existing HTTP service results.  Used for
            incremental re-scans when host data is already current.
    """
    log = structlog.get_logger().bind(target_id=target_id, skip_recon=skip_recon)
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")
        target.status = "recon_running"
        session.commit()

    log.info("pipeline_started")

    if skip_recon:
        result = run_nuclei_scan.apply_async(args=[target_id])
    else:
        result = chain(
            run_subdomain_enum.si(target_id),
            run_dnsx_filter.si(target_id),
            run_http_probe.si(target_id),
            run_port_scan.si(target_id),
            run_web_crawl.si(target_id),
            run_screenshot.si(target_id),
            run_nuclei_scan.si(target_id),
        ).apply_async()

    return {
        "target_id": target_id,
        "workflow_id": result.id or "",
        "status": "scheduled",
        "skip_recon": skip_recon,
    }


@celery_app.task(name="core.pipeline.run_recursive_subdomain_enum_task")
def run_recursive_subdomain_enum_task(
    domain: str,
    root_target_id: int,
    depth: int,
    session_key: str | None = None,
) -> dict[str, Any]:
    """Celery task wrapper for run_recursive_subdomain_enum."""
    from core.recon.recursive import run_recursive_subdomain_enum

    return run_recursive_subdomain_enum(
        domain=domain,
        root_target_id=root_target_id,
        depth=depth,
        session_key=session_key,
    )


def _finding_from_nuclei_result(target_id: int, data: dict[str, Any]) -> Finding:
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    template_id = str(data.get("template-id") or data.get("template") or "nuclei")
    title = str(info.get("name") or template_id)
    severity = str(info.get("severity") or data.get("severity") or "info").lower()
    matched_url = data.get("matched-at") or data.get("url") or data.get("host")

    return Finding(
        target_id=target_id,
        type=template_id,
        title=title,
        description=info.get("description"),
        url=str(matched_url) if matched_url else None,
        severity=severity,
        confidence="possible",
        template_id=template_id,
        raw_evidence=data,
    )
