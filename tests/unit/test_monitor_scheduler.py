"""Tests for Phase 4 Group 4 — automatic scheduler."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.monitor.scheduler import _domain_from_scope_identifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session():
    """In-memory SQLite session with all tables."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from core.db.base import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


# ---------------------------------------------------------------------------
# _domain_from_scope_identifier
# ---------------------------------------------------------------------------


class TestDomainFromScopeIdentifier:
    def test_url_with_path(self):
        assert _domain_from_scope_identifier("https://example.com/foo/bar") == "example.com"

    def test_url_no_path(self):
        assert _domain_from_scope_identifier("https://example.com") == "example.com"

    def test_http_scheme(self):
        assert _domain_from_scope_identifier("http://api.example.com") == "api.example.com"

    def test_bare_domain(self):
        assert _domain_from_scope_identifier("example.com") == "example.com"

    def test_bare_subdomain(self):
        assert _domain_from_scope_identifier("api.example.com") == "api.example.com"

    def test_wildcard_stripped(self):
        assert _domain_from_scope_identifier("*.example.com") == "example.com"

    def test_wildcard_subdomain(self):
        assert _domain_from_scope_identifier("*.api.example.com") == "api.example.com"

    def test_ipv4_returns_none(self):
        assert _domain_from_scope_identifier("1.2.3.4") is None

    def test_private_ipv4_returns_none(self):
        assert _domain_from_scope_identifier("192.168.1.1") is None

    def test_cidr_returns_none(self):
        # CIDR: parsed hostname is an IP address
        assert _domain_from_scope_identifier("10.0.0.0/8") is None

    def test_empty_string_returns_none(self):
        assert _domain_from_scope_identifier("") is None

    def test_whitespace_only_returns_none(self):
        assert _domain_from_scope_identifier("   ") is None

    def test_lowercase_normalised(self):
        assert _domain_from_scope_identifier("EXAMPLE.COM") == "example.com"

    def test_url_with_port(self):
        # urlparse strips port from hostname
        assert _domain_from_scope_identifier("https://example.com:8443") == "example.com"


# ---------------------------------------------------------------------------
# poll_all_platforms
# ---------------------------------------------------------------------------


class TestPollAllPlatforms:
    def _result(self, new=0, scope_changed=0, errors=0):
        return {"fetched": 1, "new": new, "scope_changed": scope_changed, "errors": errors}

    def test_aggregates_all_platforms(self):
        from core.monitor.scheduler import poll_all_platforms

        with (
            patch("core.monitor.scheduler.poll_hackerone", return_value=self._result(new=2, scope_changed=1)) as _h,
            patch("core.monitor.scheduler.poll_bugcrowd", return_value=self._result(new=1)) as _b,
            patch("core.monitor.scheduler.poll_intigriti", return_value=self._result(scope_changed=3)) as _i,
        ):
            result = poll_all_platforms()

        assert result["total_new"] == 3
        assert result["total_scope_changed"] == 4
        assert result["total_errors"] == 0
        assert "hackerone" in result["platforms"]
        assert "bugcrowd" in result["platforms"]
        assert "intigriti" in result["platforms"]

    def test_skipped_platform_not_counted(self):
        from core.monitor.scheduler import poll_all_platforms

        with (
            patch("core.monitor.scheduler.poll_hackerone", return_value={"skipped": True}),
            patch("core.monitor.scheduler.poll_bugcrowd", return_value=self._result(new=5)),
            patch("core.monitor.scheduler.poll_intigriti", return_value={"skipped": True}),
        ):
            result = poll_all_platforms()

        assert result["total_new"] == 5
        assert result["total_scope_changed"] == 0

    def test_exception_captured_does_not_propagate(self):
        from core.monitor.scheduler import poll_all_platforms

        with (
            patch("core.monitor.scheduler.poll_hackerone", side_effect=RuntimeError("boom")),
            patch("core.monitor.scheduler.poll_bugcrowd", return_value=self._result(new=1)),
            patch("core.monitor.scheduler.poll_intigriti", return_value=self._result()),
        ):
            result = poll_all_platforms()

        assert result["platforms"]["hackerone"] == {"skipped": True, "error": "boom"}
        assert result["total_new"] == 1

    def test_all_skipped_returns_zeros(self):
        from core.monitor.scheduler import poll_all_platforms

        with (
            patch("core.monitor.scheduler.poll_hackerone", return_value={"skipped": True}),
            patch("core.monitor.scheduler.poll_bugcrowd", return_value={"skipped": True}),
            patch("core.monitor.scheduler.poll_intigriti", return_value={"skipped": True}),
        ):
            result = poll_all_platforms()

        assert result["total_new"] == 0
        assert result["total_scope_changed"] == 0
        assert result["total_errors"] == 0

    def test_errors_field_aggregated(self):
        from core.monitor.scheduler import poll_all_platforms

        with (
            patch("core.monitor.scheduler.poll_hackerone", return_value=self._result(errors=2)),
            patch("core.monitor.scheduler.poll_bugcrowd", return_value=self._result(errors=1)),
            patch("core.monitor.scheduler.poll_intigriti", return_value={"skipped": True}),
        ):
            result = poll_all_platforms()

        assert result["total_errors"] == 3


# ---------------------------------------------------------------------------
# trigger_recon_for_new_program
# ---------------------------------------------------------------------------


class TestTriggerReconForNewProgram:
    def _make_sl_factory(self, session):
        """Return a factory that always yields the same session as a context manager."""
        call_index = {"i": 0}
        sessions = [session] * 20

        def _sl():
            ctx = MagicMock()
            ctx.__enter__ = lambda s: sessions[call_index["i"] % len(sessions)]
            ctx.__exit__ = MagicMock(return_value=False)
            call_index["i"] += 1
            return ctx

        return _sl

    def test_program_not_found(self):
        from core.monitor.scheduler import trigger_recon_for_new_program

        session = _make_session()
        with patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)):
            result = trigger_recon_for_new_program(999)

        assert result["skipped"] is True
        assert result["error"] == "program_not_found"

    def test_auto_recon_disabled(self):
        from core.db.models import BountyProgram
        from core.monitor.scheduler import trigger_recon_for_new_program

        session = _make_session()
        prog = BountyProgram(
            platform="hackerone",
            program_handle="acme-disabled",
            name="Acme",
            scope=[{"asset_identifier": "https://acme.com", "asset_type": "url"}],
            auto_recon_enabled=False,
        )
        session.add(prog)
        session.commit()
        session.refresh(prog)
        program_id = prog.id

        with patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)):
            result = trigger_recon_for_new_program(program_id)

        assert result["skipped"] is True
        assert result["reason"] == "auto_recon_disabled"

    def test_creates_targets_and_dispatches(self):
        from core.db.models import BountyProgram
        from core.monitor.scheduler import trigger_recon_for_new_program

        session = _make_session()
        prog = BountyProgram(
            platform="hackerone",
            program_handle="acme-create",
            name="Acme",
            scope=[
                {"asset_identifier": "https://acme-create.com", "asset_type": "url"},
                {"asset_identifier": "https://api.acme-create.com", "asset_type": "url"},
            ],
            auto_recon_enabled=True,
        )
        session.add(prog)
        session.commit()
        session.refresh(prog)
        program_id = prog.id

        with (
            patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)),
            patch("core.pipeline.tasks.run_full_pipeline") as mock_pipeline,
        ):
            mock_pipeline.apply_async = MagicMock()
            result = trigger_recon_for_new_program(program_id)

        assert result["dispatched"] == 2
        assert result["skipped"] == 0
        assert mock_pipeline.apply_async.call_count == 2

    def test_reuses_existing_target(self):
        from core.db.models import BountyProgram, Target
        from core.monitor.scheduler import trigger_recon_for_new_program

        session = _make_session()

        existing_target = Target(
            domain="acme-reuse.com",
            scope_includes=["acme-reuse.com"],
            scope_excludes=[],
        )
        session.add(existing_target)

        prog = BountyProgram(
            platform="hackerone",
            program_handle="acme-reuse",
            name="Acme Reuse",
            scope=[{"asset_identifier": "https://acme-reuse.com", "asset_type": "url"}],
            auto_recon_enabled=True,
        )
        session.add(prog)
        session.commit()
        session.refresh(prog)
        program_id = prog.id

        with (
            patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)),
            patch("core.pipeline.tasks.run_full_pipeline") as mock_pipeline,
        ):
            mock_pipeline.apply_async = MagicMock()
            result = trigger_recon_for_new_program(program_id)

        assert result["targets_reused"] == 1
        assert result["targets_created"] == 0
        assert result["dispatched"] == 1

    def test_respects_max_targets_limit(self, monkeypatch):
        from core.db.models import BountyProgram
        from core.monitor.scheduler import trigger_recon_for_new_program

        monkeypatch.setenv("MAX_RECON_TARGETS_PER_PROGRAM", "2")

        session = _make_session()
        scope = [
            {"asset_identifier": f"https://sub{i}.acme-max.com", "asset_type": "url"}
            for i in range(5)
        ]
        prog = BountyProgram(
            platform="hackerone",
            program_handle="acme-max",
            name="Acme Max",
            scope=scope,
            auto_recon_enabled=True,
        )
        session.add(prog)
        session.commit()
        session.refresh(prog)
        program_id = prog.id

        with (
            patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)),
            patch("core.pipeline.tasks.run_full_pipeline") as mock_pipeline,
        ):
            mock_pipeline.apply_async = MagicMock()
            result = trigger_recon_for_new_program(program_id)

        assert result["dispatched"] == 2

    def test_skips_non_web_asset_types(self):
        from core.db.models import BountyProgram
        from core.monitor.scheduler import trigger_recon_for_new_program

        session = _make_session()
        prog = BountyProgram(
            platform="bugcrowd",
            program_handle="acme-types",
            name="Acme Types",
            scope=[
                {"asset_identifier": "com.example.app", "asset_type": "android"},
                {"asset_identifier": "https://acme-types.com", "asset_type": "url"},
            ],
            auto_recon_enabled=True,
        )
        session.add(prog)
        session.commit()
        session.refresh(prog)
        program_id = prog.id

        with (
            patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)),
            patch("core.pipeline.tasks.run_full_pipeline") as mock_pipeline,
        ):
            mock_pipeline.apply_async = MagicMock()
            result = trigger_recon_for_new_program(program_id)

        assert result["dispatched"] == 1

    def test_deduplicates_domains(self):
        from core.db.models import BountyProgram
        from core.monitor.scheduler import trigger_recon_for_new_program

        session = _make_session()
        prog = BountyProgram(
            platform="intigriti",
            program_handle="acme-dedup",
            name="Acme Dedup",
            scope=[
                {"asset_identifier": "https://acme-dedup.com", "asset_type": "url"},
                {"asset_identifier": "https://acme-dedup.com/login", "asset_type": "url"},
                {"asset_identifier": "*.acme-dedup.com", "asset_type": "url"},
            ],
            auto_recon_enabled=True,
        )
        session.add(prog)
        session.commit()
        session.refresh(prog)
        program_id = prog.id

        with (
            patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)),
            patch("core.pipeline.tasks.run_full_pipeline") as mock_pipeline,
        ):
            mock_pipeline.apply_async = MagicMock()
            result = trigger_recon_for_new_program(program_id)

        # All three identifiers resolve to "acme-dedup.com" — only one dispatch
        assert result["dispatched"] == 1

    def test_skips_empty_scope(self):
        from core.db.models import BountyProgram
        from core.monitor.scheduler import trigger_recon_for_new_program

        session = _make_session()
        prog = BountyProgram(
            platform="hackerone",
            program_handle="empty-scope",
            name="Empty Scope",
            scope=[],
            auto_recon_enabled=True,
        )
        session.add(prog)
        session.commit()
        session.refresh(prog)
        program_id = prog.id

        with patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)):
            result = trigger_recon_for_new_program(program_id)

        assert result["dispatched"] == 0
        assert result["targets_created"] == 0

    def test_return_shape_is_stable(self):
        from core.db.models import BountyProgram
        from core.monitor.scheduler import trigger_recon_for_new_program

        session = _make_session()
        prog = BountyProgram(
            platform="hackerone",
            program_handle="stable-shape",
            name="Stable",
            scope=[{"asset_identifier": "https://stable-shape.com", "asset_type": "url"}],
            auto_recon_enabled=True,
        )
        session.add(prog)
        session.commit()
        session.refresh(prog)
        program_id = prog.id

        with (
            patch("core.db.session.SessionLocal", side_effect=self._make_sl_factory(session)),
            patch("core.pipeline.tasks.run_full_pipeline") as mock_pipeline,
        ):
            mock_pipeline.apply_async = MagicMock()
            result = trigger_recon_for_new_program(program_id)

        assert "program_id" in result
        assert "targets_created" in result
        assert "targets_reused" in result
        assert "dispatched" in result
        assert "skipped" in result


# ---------------------------------------------------------------------------
# Beat schedule
# ---------------------------------------------------------------------------


class TestBeatSchedule:
    def test_platform_entries_present(self):
        from core.monitor.scheduler import celery_app

        schedule = celery_app.conf.beat_schedule
        assert "poll-hackerone" in schedule
        assert "poll-bugcrowd" in schedule
        assert "poll-intigriti" in schedule

    def test_entries_have_task_and_schedule(self):
        from core.monitor.scheduler import celery_app

        schedule = celery_app.conf.beat_schedule
        for key, entry in schedule.items():
            if key.startswith("poll-"):
                assert "task" in entry
                assert "schedule" in entry
                assert isinstance(entry["schedule"], int)
                assert entry["schedule"] > 0

    def test_default_interval_is_1800(self, monkeypatch):
        monkeypatch.delenv("PLATFORM_POLL_INTERVAL_SECONDS", raising=False)
        monkeypatch.delenv("HACKERONE_POLL_INTERVAL_SECONDS", raising=False)

        import importlib

        import core.monitor.scheduler as sched_mod

        importlib.reload(sched_mod)
        assert sched_mod._h1_interval == 1800

    def test_custom_platform_interval(self, monkeypatch):
        monkeypatch.setenv("HACKERONE_POLL_INTERVAL_SECONDS", "600")

        import importlib

        import core.monitor.scheduler as sched_mod

        importlib.reload(sched_mod)
        assert sched_mod._h1_interval == 600

    def test_global_fallback_interval(self, monkeypatch):
        monkeypatch.setenv("PLATFORM_POLL_INTERVAL_SECONDS", "900")
        monkeypatch.delenv("BUGCROWD_POLL_INTERVAL_SECONDS", raising=False)

        import importlib

        import core.monitor.scheduler as sched_mod

        importlib.reload(sched_mod)
        assert sched_mod._bc_interval == 900
