"""Tests for Phase 3.7 Group A — Operabilidade mínima.

Covers:
  A1 — Dashboard authentication (_check_password, _require_auth logic)
  A2 — Start Recon / Re-scan rápido dispatch helpers
  A3 — create_target with scope / platform / depth fields
  A4 — analysis_running status transition in run_ai_analysis
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import Finding, Target
from core.db import queries
from core.pipeline import tasks


# ---------------------------------------------------------------------------
# Helpers shared across test classes
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
                    auto_score=50 - i * 5,
                    status="new",
                )
            )
        session.commit()


def _noop_classify(finding, target, session, force_reanalyze: bool = False, **kwargs) -> None:
    finding.classifier_used = "heuristic"
    finding.auto_score = finding.auto_score or 30
    finding.confidence = "possible"
    finding.confidence_note = "test"


# ---------------------------------------------------------------------------
# A1 — Authentication
# ---------------------------------------------------------------------------


class TestCheckPassword:
    def test_correct_password_returns_true(self) -> None:
        from dashboard import app
        assert app._check_password("secret", "secret") is True

    def test_wrong_password_returns_false(self) -> None:
        from dashboard import app
        assert app._check_password("wrong", "secret") is False

    def test_empty_provided_against_non_empty_expected_returns_false(self) -> None:
        from dashboard import app
        assert app._check_password("", "secret") is False

    def test_case_sensitive(self) -> None:
        from dashboard import app
        assert app._check_password("Secret", "secret") is False


# ---------------------------------------------------------------------------
# A2 — Recon dispatch
# ---------------------------------------------------------------------------


class TestReconDispatch:
    def test_start_recon_calls_apply_async_with_target_id(self, monkeypatch) -> None:
        from dashboard import app

        mock_result = MagicMock()
        mock_result.id = "task-123"
        mock_apply = MagicMock(return_value=mock_result)
        monkeypatch.setattr(app.run_full_pipeline, "apply_async", mock_apply)

        task_id = app._start_recon(42)

        mock_apply.assert_called_once_with(args=[42])
        assert task_id == "task-123"

    def test_start_rescan_passes_skip_recon_kwarg(self, monkeypatch) -> None:
        from dashboard import app

        mock_result = MagicMock()
        mock_result.id = "task-456"
        mock_apply = MagicMock(return_value=mock_result)
        monkeypatch.setattr(app.run_full_pipeline, "apply_async", mock_apply)

        task_id = app._start_rescan(42)

        mock_apply.assert_called_once_with(args=[42], kwargs={"skip_recon": True})
        assert task_id == "task-456"

    def test_start_recon_returns_empty_string_when_result_id_is_none(
        self, monkeypatch
    ) -> None:
        from dashboard import app

        mock_result = MagicMock()
        mock_result.id = None
        monkeypatch.setattr(
            app.run_full_pipeline, "apply_async", MagicMock(return_value=mock_result)
        )

        assert app._start_recon(1) == ""

    def test_start_recon_uses_correct_target_id(self, monkeypatch) -> None:
        from dashboard import app

        calls: list[list[int]] = []
        mock_result = MagicMock()
        mock_result.id = "t"

        def capture(*args, **kwargs):
            calls.append(kwargs.get("args", []))
            return mock_result

        monkeypatch.setattr(app.run_full_pipeline, "apply_async", capture)
        app._start_recon(99)

        assert calls == [[99]]


# ---------------------------------------------------------------------------
# A3 — create_target with full field set
# ---------------------------------------------------------------------------


class TestCreateTargetComplete:
    def _make_session(self) -> Session:
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        return Session(engine)

    def test_create_target_with_all_custom_fields(self) -> None:
        with self._make_session() as session:
            target = queries.create_target(
                session,
                "example.com",
                scope_includes=["example.com", "*.example.com"],
                scope_excludes=["dev.example.com"],
                platform="hackerone",
                program_id="h1-example",
                recon_depth=3,
                auto_analyze=False,
            )

        assert target.domain == "example.com"
        assert target.scope_includes == ["example.com", "*.example.com"]
        assert target.scope_excludes == ["dev.example.com"]
        assert target.platform == "hackerone"
        assert target.program_id == "h1-example"
        assert target.recon_depth == 3
        assert target.auto_analyze is False

    def test_create_target_defaults_scope_to_domain(self) -> None:
        with self._make_session() as session:
            target = queries.create_target(session, "example.com")

        assert target.scope_includes == ["example.com"]
        assert target.scope_excludes == []
        assert target.recon_depth == 2
        assert target.auto_analyze is True
        assert target.platform is None
        assert target.program_id is None

    def test_create_target_normalizes_domain_before_using_as_scope(self) -> None:
        with self._make_session() as session:
            target = queries.create_target(session, " HTTPS://Example.COM/ ")

        assert target.domain == "example.com"
        assert target.scope_includes == ["example.com"]

    def test_create_target_custom_scope_overrides_default(self) -> None:
        with self._make_session() as session:
            target = queries.create_target(
                session,
                "example.com",
                scope_includes=["*.example.com"],
            )

        assert target.scope_includes == ["*.example.com"]

    def test_create_target_empty_scope_excludes_by_default(self) -> None:
        with self._make_session() as session:
            target = queries.create_target(session, "example.com")

        assert target.scope_excludes == []


# ---------------------------------------------------------------------------
# A4 — analysis_running status transition
# ---------------------------------------------------------------------------


class TestAnalysisRunningStatus:
    def test_status_is_analysis_running_during_classify(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 2)

        status_during_classify: list[str] = []

        def track_status(finding, target, session, force_reanalyze: bool = False, **kwargs) -> None:
            # target is expired after the first session.commit(); accessing .status
            # triggers a lazy-load which returns the committed "analysis_running" value.
            status_during_classify.append(target.status)
            finding.classifier_used = "heuristic"

        with patch("core.analysis.classifier.classify_finding", side_effect=track_status):
            tasks.run_ai_analysis(target_id)

        assert status_during_classify, "classify_finding was never called"
        assert all(s == "analysis_running" for s in status_during_classify), (
            f"Expected analysis_running during classify, got: {status_during_classify}"
        )

    def test_status_is_ready_for_review_after_run_ai_analysis(
        self, monkeypatch
    ) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 1)

        with patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify):
            tasks.run_ai_analysis(target_id)

        with sf() as session:
            assert session.get(Target, target_id).status == "ready_for_review"

    def test_status_progression_recon_done_to_ready_for_review(
        self, monkeypatch
    ) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf, status="recon_done")
        _add_findings(sf, target_id, 1)

        with sf() as session:
            assert session.get(Target, target_id).status == "recon_done"

        with patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify):
            tasks.run_ai_analysis(target_id)

        with sf() as session:
            assert session.get(Target, target_id).status == "ready_for_review"

    def test_status_analysis_running_committed_before_any_classify(
        self, monkeypatch
    ) -> None:
        """analysis_running must be visible to other sessions before classify starts."""
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf, status="recon_done")
        _add_findings(sf, target_id, 1)

        first_call_status: list[str] = []

        def check_via_new_session(
            finding, target, session, force_reanalyze: bool = False, **kwargs
        ) -> None:
            if not first_call_status:
                with sf() as check_session:
                    t = check_session.get(Target, target_id)
                    first_call_status.append(t.status)
            finding.classifier_used = "heuristic"

        with patch(
            "core.analysis.classifier.classify_finding", side_effect=check_via_new_session
        ):
            tasks.run_ai_analysis(target_id)

        assert first_call_status == ["analysis_running"]
