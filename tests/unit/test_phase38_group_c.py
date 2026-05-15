"""Tests for Phase 3.8 Group C — Performance and consistency.

Covers:
  C1 — list_findings uses real DB limit/offset
  C2 — count_findings returns correct total with same filters
  C3 — provider resolved once per run_ai_analysis, not per finding
  C4 — settings helpers (_read_settings / _write_settings) use short sessions
  C5 — localhost/private IP rejected by default (ALLOW_LOCAL_TARGETS not set)
  C6 — ALLOW_LOCAL_TARGETS=true allows local/private targets
"""
from __future__ import annotations

import datetime
from unittest.mock import MagicMock, call, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import Finding, Target
from core.db import queries
from core.db.queries import (
    count_findings,
    create_target,
    bulk_create_targets,
    list_findings,
    _is_local_or_private,
)
from core.pipeline import tasks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def _session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _add_target(sf: sessionmaker[Session], domain: str = "example.com") -> int:
    with sf() as session:
        target = Target(domain=domain)
        session.add(target)
        session.commit()
        return target.id


def _add_findings(sf: sessionmaker[Session], target_id: int, count: int) -> None:
    with sf() as session:
        for i in range(count):
            session.add(Finding(
                target_id=target_id,
                type="test",
                title=f"Finding {i}",
                severity="medium",
                auto_score=50 + i,
                status="new",
            ))
        session.commit()


def _noop_classify(finding, target, session, force_reanalyze=False, provider=None, redis_client=None):
    finding.classifier_used = "heuristic"
    finding.auto_score = finding.auto_score or 30
    finding.confidence = "possible"
    finding.confidence_note = "test"


# ---------------------------------------------------------------------------
# C1 — list_findings with real DB limit/offset
# ---------------------------------------------------------------------------


class TestListFindingsPagination:
    def test_limit_restricts_result_count(self) -> None:
        with _build_session() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            for i in range(10):
                session.add(Finding(
                    target_id=target.id,
                    type="t",
                    title=f"f{i}",
                    severity="info",
                    auto_score=i,
                ))
            session.commit()

            rows = list_findings(session, limit=3)

        assert len(rows) == 3

    def test_offset_skips_rows(self) -> None:
        with _build_session() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            for i in range(5):
                session.add(Finding(
                    target_id=target.id,
                    type="t",
                    title=f"f{i}",
                    severity="info",
                    auto_score=i,
                ))
            session.commit()

            all_rows = list_findings(session)
            offset_rows = list_findings(session, offset=2)

        assert len(offset_rows) == len(all_rows) - 2

    def test_limit_and_offset_together(self) -> None:
        with _build_session() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            for i in range(10):
                session.add(Finding(
                    target_id=target.id,
                    type="t",
                    title=f"f{i}",
                    severity="info",
                    auto_score=i,
                ))
            session.commit()

            page1 = list_findings(session, limit=4, offset=0)
            page2 = list_findings(session, limit=4, offset=4)

        assert len(page1) == 4
        assert len(page2) == 4
        # No overlap
        ids1 = {r["id"] for r in page1}
        ids2 = {r["id"] for r in page2}
        assert ids1.isdisjoint(ids2)

    def test_text_search_applied_in_db(self) -> None:
        """Text search filter must not load all rows first."""
        with _build_session() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            session.add(Finding(
                target_id=target.id,
                type="t",
                title="XSS in login form",
                severity="high",
                auto_score=80,
            ))
            session.add(Finding(
                target_id=target.id,
                type="t",
                title="SQL injection in search",
                severity="high",
                auto_score=70,
            ))
            session.commit()

            results = list_findings(session, search="xss")

        assert len(results) == 1
        assert results[0]["title"] == "XSS in login form"


# ---------------------------------------------------------------------------
# C2 — count_findings
# ---------------------------------------------------------------------------


class TestCountFindings:
    def test_count_all_findings(self) -> None:
        with _build_session() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            for i in range(7):
                session.add(Finding(
                    target_id=target.id,
                    type="t",
                    title=f"f{i}",
                    severity="info",
                    auto_score=i * 10,
                ))
            session.commit()

            total = count_findings(session)

        assert total == 7

    def test_count_with_severity_filter(self) -> None:
        with _build_session() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            session.add(Finding(target_id=target.id, type="t", title="a", severity="critical", auto_score=90))
            session.add(Finding(target_id=target.id, type="t", title="b", severity="info", auto_score=10))
            session.commit()

            total = count_findings(session, severities=["critical"])

        assert total == 1

    def test_count_matches_list_total(self) -> None:
        """count_findings and len(list_findings) must agree on the same filters."""
        with _build_session() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            for i in range(15):
                session.add(Finding(
                    target_id=target.id,
                    type="t",
                    title=f"finding {i}",
                    severity="medium",
                    auto_score=40 + i,
                ))
            session.commit()

            filters = dict(score_min=45, score_max=55)
            total = count_findings(session, **filters)
            all_rows = list_findings(session, **filters)

        assert total == len(all_rows)

    def test_count_with_text_search(self) -> None:
        with _build_session() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            session.add(Finding(target_id=target.id, type="t", title="SSRF in proxy", severity="high", auto_score=80))
            session.add(Finding(target_id=target.id, type="t", title="XSS in form", severity="high", auto_score=75))
            session.commit()

            total = count_findings(session, search="ssrf")

        assert total == 1


# ---------------------------------------------------------------------------
# C3 — provider resolved once per run_ai_analysis
# ---------------------------------------------------------------------------


class TestProviderResolvedOnce:
    def test_provider_resolved_once_for_multiple_findings(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 5)

        mock_get_provider = MagicMock(return_value=None)
        mock_get_redis = MagicMock(return_value=None)

        # Patch at the definition site; run_ai_analysis imports them locally at call time
        with (
            patch("core.analysis.provider.get_provider", mock_get_provider),
            patch("core.analysis.classifier._get_redis", mock_get_redis),
            patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify),
        ):
            result = tasks.run_ai_analysis(target_id)

        assert result["classified"] == 5
        # provider and redis resolved exactly once, not once per finding
        assert mock_get_provider.call_count == 1
        assert mock_get_redis.call_count == 1

    def test_classify_finding_receives_provider_and_redis(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 2)

        sentinel_provider = object()
        sentinel_redis = object()
        calls_received = []

        def capture_classify(finding, target, session, force_reanalyze=False, provider=None, redis_client=None):
            calls_received.append({"provider": provider, "redis_client": redis_client})
            _noop_classify(finding, target, session)

        with (
            patch("core.analysis.provider.get_provider", return_value=sentinel_provider),
            patch("core.analysis.classifier._get_redis", return_value=sentinel_redis),
            patch("core.analysis.classifier.classify_finding", side_effect=capture_classify),
        ):
            tasks.run_ai_analysis(target_id)

        assert len(calls_received) == 2
        for c in calls_received:
            assert c["provider"] is sentinel_provider
            assert c["redis_client"] is sentinel_redis


# ---------------------------------------------------------------------------
# C4 — settings helpers use short sessions
# ---------------------------------------------------------------------------


class TestSettingsHelpers:
    def test_read_settings_returns_values(self) -> None:
        from dashboard.app import _read_settings
        from core.db.queries import set_setting

        sf = _session_factory()
        with sf() as session:
            set_setting(session, "TEST_KEY_C4", "hello")
            session.commit()

        # Monkeypatch SessionLocal so _read_settings uses our in-memory DB
        with patch("dashboard.app.SessionLocal", sf):
            values = _read_settings("TEST_KEY_C4", "MISSING_KEY")

        assert values["TEST_KEY_C4"] == "hello"
        assert values["MISSING_KEY"] is None

    def test_write_settings_persists_values(self) -> None:
        from dashboard.app import _write_settings
        from core.db.queries import get_setting

        sf = _session_factory()

        with patch("dashboard.app.SessionLocal", sf):
            _write_settings({"AI_PROVIDER": "anthropic", "OLLAMA_MODEL": "llama3.2"})

        with sf() as session:
            assert get_setting(session, "AI_PROVIDER") == "anthropic"
            assert get_setting(session, "OLLAMA_MODEL") == "llama3.2"

    def test_write_settings_uses_short_session(self) -> None:
        """_write_settings must open and close a session (not hold one forever)."""
        from dashboard.app import _write_settings

        enter_count = 0
        exit_count = 0

        class _FakeSession:
            def __enter__(self):
                nonlocal enter_count
                enter_count += 1
                return self

            def __exit__(self, *args):
                nonlocal exit_count
                exit_count += 1

            def commit(self): pass

        def fake_set_setting(session, key, value): pass

        with (
            patch("dashboard.app.SessionLocal", return_value=_FakeSession()),
            patch("dashboard.app.set_setting", fake_set_setting),
        ):
            _write_settings({"FOO": "bar"})

        assert enter_count == 1
        assert exit_count == 1


# ---------------------------------------------------------------------------
# C5 — ALLOW_LOCAL_TARGETS default: reject local/private
# ---------------------------------------------------------------------------


class TestIsLocalOrPrivate:
    @pytest.mark.parametrize("domain", [
        "localhost",
        "localdomain",
        "mybox.local",
        "dev.localhost",
        "127.0.0.1",
        "10.0.0.1",
        "172.16.5.5",
        "192.168.1.100",
        "169.254.1.1",
        "::1",
        "fe80::1",
    ])
    def test_detects_local_or_private(self, domain: str) -> None:
        assert _is_local_or_private(domain) is True

    @pytest.mark.parametrize("domain", [
        "example.com",
        "api.github.com",
        "8.8.8.8",
        "1.1.1.1",
    ])
    def test_allows_public(self, domain: str) -> None:
        assert _is_local_or_private(domain) is False


class TestCreateTargetLocalBlocking:
    def test_rejects_localhost_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv("ALLOW_LOCAL_TARGETS", raising=False)
        with _build_session() as session:
            with pytest.raises(ValueError, match="blocked"):
                create_target(session, "localhost")

    def test_rejects_private_ip_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv("ALLOW_LOCAL_TARGETS", raising=False)
        with _build_session() as session:
            with pytest.raises(ValueError, match="blocked"):
                create_target(session, "192.168.1.1")

    def test_rejects_dot_local_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv("ALLOW_LOCAL_TARGETS", raising=False)
        with _build_session() as session:
            with pytest.raises(ValueError, match="blocked"):
                create_target(session, "mydevbox.local")

    def test_rejects_loopback_ip_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv("ALLOW_LOCAL_TARGETS", raising=False)
        with _build_session() as session:
            with pytest.raises(ValueError, match="blocked"):
                create_target(session, "127.0.0.1")

    def test_public_domain_always_allowed(self, monkeypatch) -> None:
        monkeypatch.delenv("ALLOW_LOCAL_TARGETS", raising=False)
        with _build_session() as session:
            target = create_target(session, "example.com")
        assert target.domain == "example.com"


# ---------------------------------------------------------------------------
# C6 — ALLOW_LOCAL_TARGETS=true permits local targets
# ---------------------------------------------------------------------------


class TestAllowLocalTargets:
    def test_allow_local_true_permits_localhost(self, monkeypatch) -> None:
        monkeypatch.setenv("ALLOW_LOCAL_TARGETS", "true")
        with _build_session() as session:
            target = create_target(session, "localhost")
        assert target.domain == "localhost"

    def test_allow_local_true_permits_private_ip(self, monkeypatch) -> None:
        monkeypatch.setenv("ALLOW_LOCAL_TARGETS", "true")
        with _build_session() as session:
            target = create_target(session, "192.168.1.1")
        assert target.domain == "192.168.1.1"

    def test_bulk_create_rejects_localhost_by_default(self, monkeypatch) -> None:
        monkeypatch.delenv("ALLOW_LOCAL_TARGETS", raising=False)
        with _build_session() as session:
            created, skipped, errors = bulk_create_targets(
                session, ["example.com", "localhost", "192.168.0.1"]
            )
        assert created == 1
        assert len(errors) == 2
        assert any("localhost" in e for e in errors)

    def test_bulk_create_allows_local_when_env_true(self, monkeypatch) -> None:
        monkeypatch.setenv("ALLOW_LOCAL_TARGETS", "true")
        with _build_session() as session:
            created, skipped, errors = bulk_create_targets(
                session, ["example.com", "localhost"]
            )
        assert created == 2
        assert errors == []
