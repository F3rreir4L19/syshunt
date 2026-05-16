"""Tests for Phase 4 Bugcrowd monitor."""
from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.monitor.base import PlatformAPIError, ProgramInfo, RateLimitError
from core.monitor.bugcrowd import BugcrowdMonitor

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent.parent / "fixtures" / "bugcrowd"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _mock_response(data: dict) -> MagicMock:
    body = json.dumps(data).encode()
    mock = MagicMock()
    mock.read.return_value = body
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    return mock


def _make_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from core.db.base import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


# ---------------------------------------------------------------------------
# Normalize program
# ---------------------------------------------------------------------------


class TestNormalizeProgram:
    def setup_method(self):
        self.monitor = BugcrowdMonitor("bc_token")

    def test_basic_fields(self):
        raw = _load("programs_page1.json")["data"][0]
        prog = self.monitor.normalize_program(raw)
        assert prog.platform == "bugcrowd"
        assert prog.program_handle == "acme-corp"
        assert prog.name == "Acme Corporation"
        assert prog.submission_state == "open"

    def test_bounty_table(self):
        raw = _load("programs_page1.json")["data"][0]
        prog = self.monitor.normalize_program(raw)
        assert prog.bounty_table["program_type"] == "bug_bounty"
        assert prog.bounty_table["min_payout"] == 150
        assert prog.bounty_table["max_payout"] == 10000

    def test_launched_at_parsed(self):
        raw = _load("programs_page1.json")["data"][0]
        prog = self.monitor.normalize_program(raw)
        assert prog.launched_at is not None
        assert prog.launched_at.year == 2019

    def test_second_program(self):
        raw = _load("programs_page1.json")["data"][1]
        prog = self.monitor.normalize_program(raw)
        assert prog.program_handle == "beta-security"
        assert prog.name == "Beta Security Program"

    def test_missing_optional_fields(self):
        raw = {"id": "fallback-id", "type": "program", "attributes": {}}
        prog = self.monitor.normalize_program(raw)
        assert prog.program_handle == "fallback-id"
        assert prog.scope == []
        assert prog.launched_at is None

    def test_scope_starts_empty(self):
        raw = _load("programs_page1.json")["data"][0]
        prog = self.monitor.normalize_program(raw)
        assert prog.scope == []


# ---------------------------------------------------------------------------
# Extract scopes (targets)
# ---------------------------------------------------------------------------


class TestExtractScopes:
    def setup_method(self):
        self.monitor = BugcrowdMonitor("bc_token")

    def test_acme_targets_in_scope_only(self):
        raw = _load("targets_acme.json")
        scopes = self.monitor.extract_scopes(raw)
        # tgt-3 has in_scope=false — must be excluded
        assert len(scopes) == 2
        identifiers = [s["asset_identifier"] for s in scopes]
        assert "https://www.acme.com" in identifiers
        assert "https://api.acme.com" in identifiers
        assert "https://legacy.acme.com" not in identifiers

    def test_beta_targets(self):
        raw = _load("targets_beta.json")
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 1
        assert scopes[0]["asset_identifier"] == "https://app.betasecurity.io"

    def test_scope_fields_normalized(self):
        raw = _load("targets_acme.json")
        scope = self.monitor.extract_scopes(raw)[0]
        assert "asset_type" in scope
        assert "asset_identifier" in scope
        assert "eligible_for_bounty" in scope
        assert "eligible_for_submission" in scope

    def test_asset_type_maps_from_category(self):
        raw = _load("targets_acme.json")
        scopes = self.monitor.extract_scopes(raw)
        website_scope = next(
            s for s in scopes if s["asset_identifier"] == "https://www.acme.com"
        )
        assert website_scope["asset_type"] == "website"
        api_scope = next(
            s for s in scopes if s["asset_identifier"] == "https://api.acme.com"
        )
        assert api_scope["asset_type"] == "api"

    def test_missing_uri_skipped(self):
        raw = {
            "data": [
                {"id": "x", "attributes": {"in_scope": True}},
                {"id": "y", "attributes": {"in_scope": True, "uri": "https://ok.com"}},
            ]
        }
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 1
        assert scopes[0]["asset_identifier"] == "https://ok.com"

    def test_empty_response(self):
        assert self.monitor.extract_scopes({}) == []
        assert self.monitor.extract_scopes({"data": []}) == []

    def test_in_scope_absent_defaults_to_included(self):
        raw = {
            "data": [
                {
                    "id": "z",
                    "attributes": {
                        "uri": "https://default.com",
                        "category": "website",
                        # in_scope not present — should default to True (included)
                    },
                }
            ]
        }
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 1


# ---------------------------------------------------------------------------
# Auth header
# ---------------------------------------------------------------------------


class TestAuthHeader:
    def test_token_format(self):
        monitor = BugcrowdMonitor("my_secret_token")
        header = monitor._auth_header()
        assert header == "Token token=my_secret_token"

    def test_token_not_in_log_on_error(self, caplog):
        import logging

        monitor = BugcrowdMonitor("super_secret_bc_token")
        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock:
                mock.side_effect = urllib.error.HTTPError(
                    "", 500, "Server Error", None, None
                )
                try:
                    monitor._get("/programs")
                except PlatformAPIError:
                    pass
        for record in caplog.records:
            assert "super_secret_bc_token" not in record.getMessage()


# ---------------------------------------------------------------------------
# HTTP client error handling
# ---------------------------------------------------------------------------


class TestHTTPClient:
    def setup_method(self):
        self.monitor = BugcrowdMonitor("token", timeout=10)

    def test_rate_limit_raises_rate_limit_error(self):
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                "", 429, "Too Many Requests", None, None
            )
            with pytest.raises(RateLimitError):
                self.monitor._get("/programs")

    def test_http_500_raises_platform_api_error(self):
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                "", 500, "Internal Server Error", None, None
            )
            with pytest.raises(PlatformAPIError):
                self.monitor._get("/programs")

    def test_http_401_raises_platform_api_error(self):
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                "", 401, "Unauthorized", None, None
            )
            with pytest.raises(PlatformAPIError):
                self.monitor._get("/programs")

    def test_connection_error_raises_platform_api_error(self):
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.URLError("network unreachable")
            with pytest.raises(PlatformAPIError):
                self.monitor._get("/programs")

    def test_accept_header_is_bugcrowd_vnd(self):
        captured = []

        def fake_urlopen(req, timeout=None):
            captured.append(req.get_header("Accept"))
            return _mock_response({"data": [], "links": {}})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            self.monitor._get("/programs")

        assert captured[0] == "application/vnd.bugcrowd.v1+json"


# ---------------------------------------------------------------------------
# Fetch programs with pagination
# ---------------------------------------------------------------------------


class TestFetchPrograms:
    def setup_method(self):
        self.monitor = BugcrowdMonitor("token")

    def test_returns_programs_from_single_page(self):
        with patch(
            "urllib.request.urlopen",
            return_value=_mock_response(_load("programs_page1.json")),
        ):
            programs = self.monitor.fetch_programs()
        assert len(programs) == 2
        handles = [p.program_handle for p in programs]
        assert "acme-corp" in handles
        assert "beta-security" in handles

    def test_follows_pagination(self):
        page1 = _load("programs_page1_with_next.json")
        page2 = _load("programs_page2.json")
        responses = [_mock_response(page1), _mock_response(page2)]
        with patch("urllib.request.urlopen", side_effect=responses):
            programs = self.monitor.fetch_programs()
        assert len(programs) == 2
        handles = [p.program_handle for p in programs]
        assert "alpha-program" in handles
        assert "gamma-program" in handles

    def test_stops_when_no_next_link(self):
        page = _load("programs_page1.json")  # no "next" in links
        with patch(
            "urllib.request.urlopen", return_value=_mock_response(page)
        ):
            programs = self.monitor.fetch_programs()
        assert len(programs) == 2

    def test_rate_limit_stops_gracefully(self):
        call_count = [0]

        def side_effect(req, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_response(_load("programs_page1_with_next.json"))
            raise urllib.error.HTTPError("", 429, "Too Many Requests", None, None)

        with patch("urllib.request.urlopen", side_effect=side_effect):
            programs = self.monitor.fetch_programs()
        assert len(programs) == 1  # got page1 before rate limit

    def test_http_error_stops_gracefully(self):
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                "", 503, "Service Unavailable", None, None
            )
            programs = self.monitor.fetch_programs()
        assert programs == []

    def test_empty_data_returns_empty_list(self):
        empty = {"data": [], "links": {}}
        with patch(
            "urllib.request.urlopen", return_value=_mock_response(empty)
        ):
            programs = self.monitor.fetch_programs()
        assert programs == []


# ---------------------------------------------------------------------------
# fetch_program_scopes
# ---------------------------------------------------------------------------


class TestFetchProgramScopes:
    def setup_method(self):
        self.monitor = BugcrowdMonitor("token")

    def test_returns_in_scope_targets(self):
        with patch(
            "urllib.request.urlopen",
            return_value=_mock_response(_load("targets_acme.json")),
        ):
            scopes = self.monitor.fetch_program_scopes("acme-corp")
        assert len(scopes) == 2

    def test_rate_limit_returns_empty(self):
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                "", 429, "Too Many Requests", None, None
            )
            scopes = self.monitor.fetch_program_scopes("acme-corp")
        assert scopes == []

    def test_http_error_returns_empty(self):
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                "", 404, "Not Found", None, None
            )
            scopes = self.monitor.fetch_program_scopes("unknown")
        assert scopes == []


# ---------------------------------------------------------------------------
# Upsert — reuses shared queries, just validates Bugcrowd-specific shape
# ---------------------------------------------------------------------------


class TestBugcrowdUpsert:
    def test_new_program_created(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        prog, is_new, added, removed = upsert_bounty_program(
            session,
            platform="bugcrowd",
            program_handle="acme-corp",
            name="Acme Corporation",
            scope=[{"asset_identifier": "https://www.acme.com"}],
            bounty_table={"program_type": "bug_bounty"},
        )
        assert is_new is True
        assert prog.platform == "bugcrowd"
        assert prog.program_handle == "acme-corp"
        session.close()

    def test_platform_isolation_from_hackerone(self):
        """bugcrowd:acme-corp and hackerone:acme-corp are separate records."""
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(session, "hackerone", "acme-corp", "Acme H1", [], {})
        prog_bc, is_new, _, _ = upsert_bounty_program(
            session, "bugcrowd", "acme-corp", "Acme BC", [], {}
        )
        assert is_new is True
        assert prog_bc.platform == "bugcrowd"
        session.close()

    def test_scope_diff_after_update(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(
            session,
            "bugcrowd",
            "acme-corp",
            "Acme",
            [{"asset_identifier": "https://www.acme.com"}],
            {},
        )
        _, _, added, removed = upsert_bounty_program(
            session,
            "bugcrowd",
            "acme-corp",
            "Acme",
            [
                {"asset_identifier": "https://www.acme.com"},
                {"asset_identifier": "https://api.acme.com"},
            ],
            {},
        )
        assert "https://api.acme.com" in added
        assert removed == []
        session.close()


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


class TestBugcrowdNotifications:
    def test_notify_new_program_on_first_sync(self):
        from core.db.models import BountyProgram
        from core.notifications import notify_new_program

        program = BountyProgram(
            platform="bugcrowd", program_handle="acme-corp", name="Acme Corp"
        )
        with patch("core.notifications._get_flag", return_value=True), patch(
            "core.notifications._get_webhook_url",
            return_value="https://discord.test/hook",
        ), patch("core.notifications._post_discord") as mock_post:
            notify_new_program(program)
        mock_post.assert_called_once()
        content = mock_post.call_args[0][1]
        assert "bugcrowd" in content
        assert "acme-corp" in content

    def test_notify_scope_changed_includes_platform(self):
        from core.db.models import BountyProgram
        from core.notifications import notify_scope_changed

        program = BountyProgram(
            platform="bugcrowd", program_handle="beta-security", name="Beta"
        )
        with patch("core.notifications._get_flag", return_value=True), patch(
            "core.notifications._get_webhook_url",
            return_value="https://discord.test/hook",
        ), patch("core.notifications._post_discord") as mock_post:
            notify_scope_changed(
                program,
                added=["https://new.betasecurity.io"],
                removed=[],
            )
        content = mock_post.call_args[0][1]
        assert "bugcrowd" in content
        assert "new.betasecurity.io" in content


# ---------------------------------------------------------------------------
# Token safety
# ---------------------------------------------------------------------------


class TestBugcrowdTokenSafety:
    def test_token_not_in_fetch_programs_log(self, caplog):
        import logging

        monitor = BugcrowdMonitor("very_secret_bugcrowd_token")
        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock:
                mock.side_effect = urllib.error.URLError("network error")
                monitor.fetch_programs()
        for record in caplog.records:
            assert "very_secret_bugcrowd_token" not in record.getMessage()

    def test_token_not_in_scope_fetch_log(self, caplog):
        import logging

        monitor = BugcrowdMonitor("another_bc_secret_token")
        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock:
                mock.side_effect = urllib.error.HTTPError(
                    "", 403, "Forbidden", None, None
                )
                monitor.fetch_program_scopes("some-program")
        for record in caplog.records:
            assert "another_bc_secret_token" not in record.getMessage()


# ---------------------------------------------------------------------------
# Scheduler task
# ---------------------------------------------------------------------------


class TestBugcrowdScheduler:
    def test_poll_bugcrowd_skips_without_credentials(self):
        import os

        with patch.dict(os.environ, {"BUGCROWD_API_TOKEN": ""}):
            from core.monitor.scheduler import poll_bugcrowd

            result = poll_bugcrowd()
        assert result.get("skipped") is True

    def test_poll_bugcrowd_calls_sync(self):
        import os

        with patch.dict(os.environ, {"BUGCROWD_API_TOKEN": "test_token"}):
            with patch("core.monitor.bugcrowd.BugcrowdMonitor") as MockMonitor:
                mock_instance = MagicMock()
                mock_instance.sync_programs.return_value = {
                    "fetched": 3,
                    "new": 1,
                    "scope_changed": 0,
                    "errors": 0,
                }
                MockMonitor.return_value = mock_instance

                from core.monitor.scheduler import poll_bugcrowd

                result = poll_bugcrowd()
            assert result["fetched"] == 3
            assert result["new"] == 1
            mock_instance.sync_programs.assert_called_once()

    def test_poll_bugcrowd_error_returns_skip(self):
        import os

        with patch.dict(os.environ, {"BUGCROWD_API_TOKEN": "t"}):
            with patch("core.monitor.bugcrowd.BugcrowdMonitor") as MockMonitor:
                mock_instance = MagicMock()
                mock_instance.sync_programs.side_effect = RuntimeError("db down")
                MockMonitor.return_value = mock_instance

                from core.monitor.scheduler import poll_bugcrowd

                result = poll_bugcrowd()
            assert result.get("skipped") is True
            assert "db down" in result.get("error", "")


# ---------------------------------------------------------------------------
# sync_programs end-to-end (mocked HTTP + in-memory DB)
# ---------------------------------------------------------------------------


class TestBugcrowdSyncPrograms:
    def _make_monitor(self) -> BugcrowdMonitor:
        return BugcrowdMonitor("token")

    def test_sync_creates_new_programs(self):
        monitor = self._make_monitor()
        session = _make_session()

        page = _load("programs_page1.json")
        targets = _load("targets_acme.json")

        def fake_urlopen(req, timeout=None):
            url = req.full_url
            if "/targets" in url:
                return _mock_response(targets)
            return _mock_response(page)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            stats = monitor.sync_programs(session)

        assert stats["fetched"] == 2
        assert stats["new"] == 2
        assert stats["errors"] == 0
        session.close()

    def test_sync_detects_scope_change(self):
        from core.db.queries import upsert_bounty_program

        monitor = self._make_monitor()
        session = _make_session()

        # Seed with one scope entry
        upsert_bounty_program(
            session,
            "bugcrowd",
            "acme-corp",
            "Acme",
            [{"asset_identifier": "https://www.acme.com"}],
            {},
        )

        page = {"data": [_load("programs_page1.json")["data"][0]], "links": {}}
        # targets now has 2 in-scope entries (new one was added)
        targets = _load("targets_acme.json")

        def fake_urlopen(req, timeout=None):
            url = req.full_url
            if "/targets" in url:
                return _mock_response(targets)
            return _mock_response(page)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen), patch(
            "core.notifications.notify_scope_changed"
        ) as mock_notify:
            stats = monitor.sync_programs(session)

        assert stats["scope_changed"] == 1
        mock_notify.assert_called_once()
        session.close()

    def test_sync_notifies_new_program(self):
        monitor = self._make_monitor()
        session = _make_session()
        page = {"data": [_load("programs_page1.json")["data"][0]], "links": {}}
        targets = {"data": [], "links": {}}

        def fake_urlopen(req, timeout=None):
            url = req.full_url
            if "/targets" in url:
                return _mock_response(targets)
            return _mock_response(page)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen), patch(
            "core.notifications.notify_new_program"
        ) as mock_notify:
            stats = monitor.sync_programs(session)

        assert stats["new"] == 1
        mock_notify.assert_called_once()
        session.close()

    def test_sync_returns_stable_shape_on_empty(self):
        monitor = self._make_monitor()
        session = _make_session()
        empty = {"data": [], "links": {}}
        with patch("urllib.request.urlopen", return_value=_mock_response(empty)):
            stats = monitor.sync_programs(session)
        assert stats == {"fetched": 0, "new": 0, "scope_changed": 0, "errors": 0}
        session.close()
