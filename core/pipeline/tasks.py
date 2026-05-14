from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from celery import Celery

from core.db import queries
from core.db.models import Finding, ReconResult, Target
from core.db.session import SessionLocal
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
                r.data.get("host") or _extract_host(r.data.get("url", ""))
                for r in session.query(ReconResult)
                .filter(
                    ReconResult.target_id == target.id,
                    ReconResult.tool == "httpx",
                    ReconResult.result_type == "http_service",
                    ReconResult.superseded_by.is_(None),
                )
                .all()
            }
            - {""}
        ) or [target.domain]

        errors: list[str] = []
        data_items: list[dict[str, Any]] = []

        for host in hosts:
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
        all_urls: set[str] = set()

        for url in crawl_targets:
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
                all_urls.update(result.parsed_data)

        if not all_urls and errors:
            raise RuntimeError(f"all crawlers failed: {'; '.join(errors)}")

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="webcrawl",
            result_type="crawled_url",
            data_items=[{"url": u} for u in all_urls],
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

        for url in screenshot_targets:
            shot_result = GoWitnessWrapper().run(
                url, ToolOptions(screenshot_dir=screenshot_dir)
            )
            if not shot_result.success:
                log.warning("screenshot_item_failed", url=url, error=shot_result.error)
                errors.append(f"{url}: {shot_result.error}")
                continue
            # Record relative path — pipeline task resolves actual filename by
            # listing the directory before and after, but storing the URL is
            # sufficient for the dashboard to reconstruct the path.
            data_items.append({
                "url": url,
                "screenshot_dir": str(screenshot_dir.relative_to(_output_dir())),
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
        result = run_subdomain_enum.apply_async(
            args=[target_id],
            link=run_http_probe.si(target_id).set(
                link=run_port_scan.si(target_id).set(
                    link=run_web_crawl.si(target_id).set(
                        link=run_screenshot.si(target_id).set(
                            link=run_nuclei_scan.si(target_id)
                        )
                    )
                )
            ),
        )

    return {
        "target_id": target_id,
        "workflow_id": result.id or "",
        "status": "scheduled",
        "skip_recon": skip_recon,
    }


def _extract_host(url: str) -> str:
    """Extract hostname from a URL string without external dependencies."""
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            rest = url[len(prefix):]
            return rest.split("/")[0].split(":")[0]
    return ""


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
