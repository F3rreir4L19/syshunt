"""Tests for Phase 3.8 Groups D/E — failure states and pipeline validation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import Finding, Target
from core.pipeline import tasks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _add_target(sf: sessionmaker[Session], status: str = "pending") -> int:
    with sf() as session:
        target = Target(domain="example.com", status=status)
        session.add(target)
        session.commit()
        return target.id


def _add_findings(sf: sessionmaker[Session], target_id: int, count: int) -> None:
    with sf() as session:
        for i in range(count):
            session.add(
                Finding(
                    target_id=target_id,
                    type="test-vuln",
                    title=f"Finding {i}",
                    severity="medium",
                    auto_score=50,
                    status="new",
                )
            )
        session.commit()


# ---------------------------------------------------------------------------
# D1 — run_ai_analysis sets analysis_failed on unhandled error
# ---------------------------------------------------------------------------


class TestRunAiAnalysisFailureState:
    def test_sets_analysis_failed_when_classify_raises(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 1)

        def boom(finding, target, session, **kwargs):
            raise RuntimeError("AI provider unreachable")

        with patch("core.analysis.classifier.classify_finding", side_effect=boom):
            result = tasks.run_ai_analysis(target_id)

        with sf() as session:
            target = session.get(Target, target_id)
            assert target.status == "analysis_failed"

        assert "error" in result
        assert result["target_id"] == target_id

    def test_returns_error_key_on_failure(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 1)

        def boom(finding, target, session, **kwargs):
            raise ValueError("bad config")

        with patch("core.analysis.classifier.classify_finding", side_effect=boom):
            result = tasks.run_ai_analysis(target_id)

        assert result.get("error") is not None
        assert "bad config" in result["error"]

    def test_does_not_leave_target_in_analysis_running(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf, status="recon_done")
        _add_findings(sf, target_id, 2)

        def boom(finding, target, session, **kwargs):
            raise RuntimeError("crash")

        with patch("core.analysis.classifier.classify_finding", side_effect=boom):
            tasks.run_ai_analysis(target_id)

        with sf() as session:
            target = session.get(Target, target_id)
            assert target.status != "analysis_running", (
                "Target must not be left stuck in analysis_running after an error"
            )

    def test_notify_pipeline_error_called_on_failure(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 1)

        def boom(finding, target, session, **kwargs):
            raise RuntimeError("network error")

        notified: list[tuple] = []

        def fake_notify(tid, task_name, error, session=None):
            notified.append((tid, task_name, error))

        with patch("core.analysis.classifier.classify_finding", side_effect=boom):
            with patch("core.notifications.notify_pipeline_error", side_effect=fake_notify):
                tasks.run_ai_analysis(target_id)

        assert len(notified) == 1
        assert notified[0][0] == target_id
        assert notified[0][1] == "run_ai_analysis"


# ---------------------------------------------------------------------------
# D2 — run_full_pipeline sets recon_failed on dispatch error
# ---------------------------------------------------------------------------


class TestRunFullPipelineFailureState:
    def test_sets_recon_failed_when_apply_async_raises(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)

        def exploding_apply_async(*args, **kwargs):
            raise ConnectionError("Redis unavailable")

        with patch.object(tasks.run_nuclei_scan, "apply_async", side_effect=exploding_apply_async):
            result = tasks.run_full_pipeline(target_id, skip_recon=True)

        with sf() as session:
            target = session.get(Target, target_id)
            assert target.status == "recon_failed"

        assert result["status"] == "failed"

    def test_returns_failed_status_dict_on_dispatch_error(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)

        def exploding_apply_async(*args, **kwargs):
            raise RuntimeError("broker down")

        with patch.object(tasks.run_nuclei_scan, "apply_async", side_effect=exploding_apply_async):
            result = tasks.run_full_pipeline(target_id, skip_recon=True)

        assert result["target_id"] == target_id
        assert result["workflow_id"] == ""
        assert "error" in result

    def test_does_not_leave_target_in_recon_running_on_dispatch_failure(
        self, monkeypatch
    ) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)

        def exploding_apply_async(*args, **kwargs):
            raise Exception("some unexpected error")

        with patch.object(tasks.run_nuclei_scan, "apply_async", side_effect=exploding_apply_async):
            tasks.run_full_pipeline(target_id, skip_recon=True)

        with sf() as session:
            target = session.get(Target, target_id)
            assert target.status != "recon_running", (
                "Target must not be stuck in recon_running after a dispatch error"
            )

    def test_notify_pipeline_error_called_on_dispatch_failure(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)

        def exploding_apply_async(*args, **kwargs):
            raise RuntimeError("broker unavailable")

        notified: list[tuple] = []

        def fake_notify(tid, task_name, error, session=None):
            notified.append((tid, task_name, error))

        with patch.object(tasks.run_nuclei_scan, "apply_async", side_effect=exploding_apply_async):
            with patch("core.notifications.notify_pipeline_error", side_effect=fake_notify):
                tasks.run_full_pipeline(target_id, skip_recon=True)

        assert len(notified) == 1
        assert notified[0][0] == target_id
        assert notified[0][1] == "run_full_pipeline"


# ---------------------------------------------------------------------------
# E — Pipeline documentation
# ---------------------------------------------------------------------------


class TestCurrentPipelineDoc:
    def test_docs_current_pipeline_md_exists(self) -> None:
        doc_path = Path(__file__).parents[2] / "docs" / "current_pipeline.md"
        assert doc_path.exists(), (
            f"docs/current_pipeline.md not found at {doc_path}. "
            "Create it to document what actually runs in the pipeline."
        )

    def test_docs_current_pipeline_md_is_not_empty(self) -> None:
        doc_path = Path(__file__).parents[2] / "docs" / "current_pipeline.md"
        content = doc_path.read_text()
        assert len(content) > 100, "docs/current_pipeline.md looks empty or too short"

    def test_docs_current_pipeline_md_mentions_amass_status(self) -> None:
        doc_path = Path(__file__).parents[2] / "docs" / "current_pipeline.md"
        content = doc_path.read_text().lower()
        assert "amass" in content, (
            "docs/current_pipeline.md should document amass integration status"
        )

    def test_docs_current_pipeline_md_mentions_ffuf_status(self) -> None:
        doc_path = Path(__file__).parents[2] / "docs" / "current_pipeline.md"
        content = doc_path.read_text().lower()
        assert "ffuf" in content, (
            "docs/current_pipeline.md should document ffuf integration status"
        )
