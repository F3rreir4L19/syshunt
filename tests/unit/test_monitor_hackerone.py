"""Tests for Phase 4 HackerOne monitor — MVP."""
from __future__ import annotations

import json
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.monitor.base import PlatformAPIError, ProgramInfo, RateLimitError
from core.monitor.hackerone import HackerOneMonitor

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent.parent / "fixtures" / "hackerone"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _mock_response(data: dict) -> MagicMock:
    body = json.dumps(data).encode()
    mock = MagicMock()
    mock.read.return_value = body
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    return mock


# ---------------------------------------------------------------------------
# Normalize program
# ---------------------------------------------------------------------------


class TestNormalizeProgram:
    def setup_method(self):
        self.monitor = HackerOneMonitor("user", "token")

    def test_basic_fields(self):
        raw = _load("programs_page1.json")["data"][0]
        prog = self.monitor.normalize_program(raw)
        assert prog.platform == "hackerone"
        assert prog.program_handle == "hackerone"
        assert prog.name == "HackerOne"
        assert prog.submission_state == "open"
        assert prog.bounty_table["offers_bounties"] is True
        assert prog.bounty_table["currency"] == "USD"

    def test_launched_at_parsed(self):
        raw = _load("programs_page1.json")["data"][0]
        prog = self.monitor.normalize_program(raw)
        assert prog.launched_at is not None
        assert prog.launched_at.year == 2013

    def test_second_program(self):
        raw = _load("programs_page1.json")["data"][1]
        prog = self.monitor.normalize_program(raw)
        assert prog.program_handle == "shopify"
        assert prog.name == "Shopify"

    def test_missing_optional_fields(self):
        raw = {"id": "99", "type": "program", "attributes": {"handle": "test"}}
        prog = self.monitor.normalize_program(raw)
        assert prog.program_handle == "test"
        assert prog.name == "test"
        assert prog.scope == []
        assert prog.launched_at is None


# ---------------------------------------------------------------------------
# Extract scopes
# ---------------------------------------------------------------------------


class TestExtractScopes:
    def setup_method(self):
        self.monitor = HackerOneMonitor("user", "token")

    def test_hackerone_scopes(self):
        raw = _load("scopes_hackerone.json")
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 2
        identifiers = [s["asset_identifier"] for s in scopes]
        assert "https://hackerone.com" in identifiers
        assert "https://api.hackerone.com" in identifiers

    def test_shopify_scopes(self):
        raw = _load("scopes_shopify.json")
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 2

    def test_scope_fields_present(self):
        raw = _load("scopes_hackerone.json")
        scope = self.monitor.extract_scopes(raw)[0]
        assert "asset_type" in scope
        assert "asset_identifier" in scope
        assert "max_severity" in scope
        assert "eligible_for_bounty" in scope

    def test_missing_identifier_skipped(self):
        raw = {
            "data": [
                {"id": "1", "attributes": {}},
                {"id": "2", "attributes": {"asset_identifier": "https://example.com"}},
            ]
        }
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 1
        assert scopes[0]["asset_identifier"] == "https://example.com"

    def test_empty_response(self):
        assert self.monitor.extract_scopes({}) == []
        assert self.monitor.extract_scopes({"data": []}) == []


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


class TestHTTPClient:
    def setup_method(self):
        self.monitor = HackerOneMonitor("myuser", "secret_token", timeout=10)

    def test_auth_header_uses_base64(self):
        import base64

        header = self.monitor._auth_header()
        assert header.startswith("Basic ")
        decoded = base64.b64decode(header[6:]).decode()
        assert decoded == "myuser:secret_token"

    def test_token_not_in_log_output(self, caplog):
        """Verify the API token is not present in any log output."""
        import logging

        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.HTTPError(
                    url="https://api.hackerone.com/v1/hackers/programs",
                    code=401,
                    msg="Unauthorized",
                    hdrs=None,
                    fp=None,
                )
                with pytest.raises(PlatformAPIError):
                    self.monitor._get("/hackers/programs")
        assert "secret_token" not in caplog.text

    def test_rate_limit_raises_rate_limit_error(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="https://api.hackerone.com",
                code=429,
                msg="Too Many Requests",
                hdrs=None,
                fp=None,
            )
            with pytest.raises(RateLimitError):
                self.monitor._get("/hackers/programs")

    def test_http_500_raises_platform_api_error(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                url="https://api.hackerone.com",
                code=500,
                msg="Internal Server Error",
                hdrs=None,
                fp=None,
            )
            with pytest.raises(PlatformAPIError):
                self.monitor._get("/hackers/programs")

    def test_connection_error_raises_platform_api_error(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("connection refused")
            with pytest.raises(PlatformAPIError):
                self.monitor._get("/hackers/programs")

    def test_params_added_to_url(self):
        captured_url = []

        def fake_urlopen(req, timeout=None):
            captured_url.append(req.full_url)
            return _mock_response({"data": [], "links": {}})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            self.monitor._get(
                "/hackers/programs", params={"page[number]": 1, "page[size]": 25}
            )

        assert "page%5Bnumber%5D=1" in captured_url[0] or "page[number]=1" in captured_url[0]


# ---------------------------------------------------------------------------
# Fetch programs with pagination
# ---------------------------------------------------------------------------


class TestFetchPrograms:
    def setup_method(self):
        self.monitor = HackerOneMonitor("user", "token")

    def test_returns_programs_from_fixture(self):
        page1 = _load("programs_page1.json")
        page2 = _load("programs_page2.json")

        responses = [_mock_response(page1), _mock_response(page2)]

        with patch("urllib.request.urlopen", side_effect=responses):
            programs = self.monitor.fetch_programs()

        assert len(programs) == 2
        handles = [p.program_handle for p in programs]
        assert "hackerone" in handles
        assert "shopify" in handles

    def test_stops_when_no_next_link(self):
        single_page = _load("programs_page2.json")
        with patch("urllib.request.urlopen", return_value=_mock_response(single_page)):
            programs = self.monitor.fetch_programs()
        assert programs == []

    def test_rate_limit_stops_pagination_gracefully(self):
        page1 = _load("programs_page1.json")

        call_count = [0]

        def side_effect(req, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1:
                return _mock_response(page1)
            raise urllib.error.HTTPError("", 429, "Too Many Requests", None, None)

        with patch("urllib.request.urlopen", side_effect=side_effect):
            programs = self.monitor.fetch_programs()

        assert len(programs) == 2  # got page1 before rate limit

    def test_http_error_stops_pagination_gracefully(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.HTTPError(
                "", 503, "Service Unavailable", None, None
            )
            programs = self.monitor.fetch_programs()
        assert programs == []


# ---------------------------------------------------------------------------
# Upsert via queries.py
# ---------------------------------------------------------------------------


def _make_session():
    """Create a SQLite in-memory session for upsert tests."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from core.db.base import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


class TestUpsertBountyProgram:
    def test_new_program_created(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        prog, is_new, added, removed = upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme Corp",
            scope=[{"asset_identifier": "https://acme.com"}],
            bounty_table={"offers_bounties": True},
        )
        assert is_new is True
        assert added == []
        assert removed == []
        assert prog.program_handle == "acme"
        assert prog.first_seen_at is not None
        session.close()

    def test_existing_program_not_duplicated(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme Corp",
            scope=[],
            bounty_table={},
        )
        prog2, is_new, _, _ = upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme Corp Updated",
            scope=[],
            bounty_table={},
        )
        assert is_new is False
        assert prog2.name == "Acme Corp Updated"
        session.close()

    def test_first_seen_at_preserved_on_update(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        prog1, _, _, _ = upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme",
            scope=[],
            bounty_table={},
        )
        first = prog1.first_seen_at

        prog2, _, _, _ = upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme Updated",
            scope=[],
            bounty_table={},
        )
        assert prog2.first_seen_at == first
        session.close()

    def test_last_checked_at_updated_on_upsert(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme",
            scope=[],
            bounty_table={},
        )
        prog2, _, _, _ = upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme",
            scope=[],
            bounty_table={},
        )
        assert prog2.last_checked_at is not None
        session.close()

    def test_scope_added_detected(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme",
            scope=[{"asset_identifier": "https://acme.com"}],
            bounty_table={},
        )
        _, is_new, added, removed = upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme",
            scope=[
                {"asset_identifier": "https://acme.com"},
                {"asset_identifier": "https://api.acme.com"},
            ],
            bounty_table={},
        )
        assert is_new is False
        assert "https://api.acme.com" in added
        assert removed == []
        session.close()

    def test_scope_removed_detected(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme",
            scope=[
                {"asset_identifier": "https://acme.com"},
                {"asset_identifier": "https://legacy.acme.com"},
            ],
            bounty_table={},
        )
        _, _, added, removed = upsert_bounty_program(
            session,
            platform="hackerone",
            program_handle="acme",
            name="Acme",
            scope=[{"asset_identifier": "https://acme.com"}],
            bounty_table={},
        )
        assert "https://legacy.acme.com" in removed
        assert added == []
        session.close()


# ---------------------------------------------------------------------------
# Detect new programs / scope changes via base helpers
# ---------------------------------------------------------------------------


class TestDetectHelpers:
    def setup_method(self):
        self.monitor = HackerOneMonitor("user", "token")

    def test_detect_new_programs(self):
        session = _make_session()
        programs = [
            ProgramInfo(platform="hackerone", program_handle="acme", name="Acme"),
            ProgramInfo(platform="hackerone", program_handle="beta", name="Beta"),
        ]
        new = self.monitor.detect_new_programs(session, programs)
        assert len(new) == 2
        session.close()

    def test_detect_new_programs_skips_existing(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(
            session, "hackerone", "acme", "Acme", [], {}
        )
        programs = [
            ProgramInfo(platform="hackerone", program_handle="acme", name="Acme"),
            ProgramInfo(platform="hackerone", program_handle="beta", name="Beta"),
        ]
        new = self.monitor.detect_new_programs(session, programs)
        assert len(new) == 1
        assert new[0].program_handle == "beta"
        session.close()

    def test_detect_scope_changes(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(
            session,
            "hackerone",
            "acme",
            "Acme",
            [{"asset_identifier": "https://acme.com"}],
            {},
        )
        programs = [
            ProgramInfo(
                platform="hackerone",
                program_handle="acme",
                name="Acme",
                scope=[
                    {"asset_identifier": "https://acme.com"},
                    {"asset_identifier": "https://new.acme.com"},
                ],
            )
        ]
        changed = self.monitor.detect_scope_changes(session, programs)
        assert len(changed) == 1
        prog, added, removed = changed[0]
        assert "https://new.acme.com" in added
        assert removed == []
        session.close()

    def test_diff_scopes_no_change(self):
        old = [{"asset_identifier": "https://x.com"}]
        new = [{"asset_identifier": "https://x.com"}]
        added, removed = self.monitor.diff_scopes(old, new)
        assert added == []
        assert removed == []

    def test_diff_scopes_skips_empty_identifier(self):
        old = [{"asset_identifier": ""}]
        new = [{"other_field": "value"}]
        added, removed = self.monitor.diff_scopes(old, new)
        assert added == []
        assert removed == []


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


class TestNotifications:
    def test_notify_new_program_called(self):
        from unittest.mock import patch

        from core.db.models import BountyProgram
        from core.notifications import notify_new_program

        program = BountyProgram(
            platform="hackerone",
            program_handle="acme",
            name="Acme",
        )

        with patch("core.notifications._get_flag", return_value=True), patch(
            "core.notifications._get_webhook_url", return_value="https://discord.test/webhook"
        ), patch("core.notifications._post_discord") as mock_post:
            notify_new_program(program)
            mock_post.assert_called_once()
            content = mock_post.call_args[0][1]
            assert "acme" in content
            assert "NEW PROGRAM" in content

    def test_notify_new_program_respects_flag_false(self):
        from core.db.models import BountyProgram
        from core.notifications import notify_new_program

        program = BountyProgram(
            platform="hackerone",
            program_handle="acme",
            name="Acme",
        )

        with patch("core.notifications._get_flag", return_value=False), patch(
            "core.notifications._post_discord"
        ) as mock_post:
            notify_new_program(program)
            mock_post.assert_not_called()

    def test_notify_scope_changed_called(self):
        from core.db.models import BountyProgram
        from core.notifications import notify_scope_changed

        program = BountyProgram(
            platform="hackerone",
            program_handle="shopify",
            name="Shopify",
        )

        with patch("core.notifications._get_flag", return_value=True), patch(
            "core.notifications._get_webhook_url", return_value="https://discord.test/webhook"
        ), patch("core.notifications._post_discord") as mock_post:
            notify_scope_changed(
                program,
                added=["https://new.shopify.com"],
                removed=["https://old.shopify.com"],
            )
            mock_post.assert_called_once()
            content = mock_post.call_args[0][1]
            assert "shopify" in content
            assert "SCOPE CHANGED" in content
            assert "https://new.shopify.com" in content
            assert "https://old.shopify.com" in content

    def test_notify_scope_changed_respects_flag_false(self):
        from core.db.models import BountyProgram
        from core.notifications import notify_scope_changed

        program = BountyProgram(platform="hackerone", program_handle="x", name="X")

        with patch("core.notifications._get_flag", return_value=False), patch(
            "core.notifications._post_discord"
        ) as mock_post:
            notify_scope_changed(program, added=["https://x.com"], removed=[])
            mock_post.assert_not_called()

    def test_notify_new_program_never_raises(self):
        from core.db.models import BountyProgram
        from core.notifications import notify_new_program

        program = BountyProgram(platform="hackerone", program_handle="x", name="X")

        with patch("core.notifications._get_flag", side_effect=RuntimeError("boom")):
            notify_new_program(program)  # must not raise

    def test_notify_scope_changed_never_raises(self):
        from core.db.models import BountyProgram
        from core.notifications import notify_scope_changed

        program = BountyProgram(platform="hackerone", program_handle="x", name="X")

        with patch("core.notifications._get_flag", side_effect=RuntimeError("boom")):
            notify_scope_changed(program, added=[], removed=[])  # must not raise


# ---------------------------------------------------------------------------
# Token logging safety
# ---------------------------------------------------------------------------


class TestTokenSafety:
    def test_token_not_in_warning_log(self, caplog):
        """API token must never appear in log records."""
        import logging

        monitor = HackerOneMonitor("testuser", "super_secret_api_token")

        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.HTTPError(
                    "", 500, "error", None, None
                )
                try:
                    monitor._get("/hackers/programs")
                except PlatformAPIError:
                    pass

        for record in caplog.records:
            assert "super_secret_api_token" not in record.getMessage()

    def test_token_not_in_fetch_programs_log(self, caplog):
        import logging

        monitor = HackerOneMonitor("testuser", "another_secret_token")

        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.URLError("network error")
                monitor.fetch_programs()

        for record in caplog.records:
            assert "another_secret_token" not in record.getMessage()


# ---------------------------------------------------------------------------
# Scheduler task
# ---------------------------------------------------------------------------


class TestSchedulerTask:
    def test_poll_hackerone_skips_without_credentials(self):
        import os

        with patch.dict(
            os.environ,
            {"HACKERONE_USERNAME": "", "HACKERONE_API_TOKEN": ""},
        ):
            from core.monitor.scheduler import poll_hackerone

            result = poll_hackerone()
            assert result.get("skipped") is True

    def test_poll_hackerone_calls_sync(self):
        import os

        with patch.dict(
            os.environ,
            {"HACKERONE_USERNAME": "u", "HACKERONE_API_TOKEN": "t"},
        ):
            # HackerOneMonitor is imported inside the task body
            with patch("core.monitor.hackerone.HackerOneMonitor") as MockMonitor:
                mock_instance = MagicMock()
                mock_instance.sync_programs.return_value = {
                    "fetched": 5,
                    "new": 2,
                    "scope_changed": 0,
                    "errors": 0,
                }
                MockMonitor.return_value = mock_instance

                from core.monitor.scheduler import poll_hackerone

                result = poll_hackerone()
                assert result["fetched"] == 5
                assert result["new"] == 2
                mock_instance.sync_programs.assert_called_once()


# ---------------------------------------------------------------------------
# list_bounty_programs
# ---------------------------------------------------------------------------


class TestListBountyPrograms:
    def test_returns_empty_list_when_none(self):
        from core.db.queries import list_bounty_programs

        session = _make_session()
        result = list_bounty_programs(session)
        assert result == []
        session.close()

    def test_returns_inserted_programs(self):
        from core.db.queries import list_bounty_programs, upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(session, "hackerone", "acme", "Acme", [], {})
        upsert_bounty_program(session, "hackerone", "beta", "Beta Corp", [], {})
        result = list_bounty_programs(session)
        assert len(result) == 2
        handles = [r["program_handle"] for r in result]
        assert "acme" in handles
        assert "beta" in handles
        session.close()

    def test_result_has_expected_fields(self):
        from core.db.queries import list_bounty_programs, upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(
            session,
            "hackerone",
            "acme",
            "Acme",
            [{"asset_identifier": "https://acme.com"}],
            {"offers_bounties": True},
        )
        result = list_bounty_programs(session)[0]
        assert result["platform"] == "hackerone"
        assert result["program_handle"] == "acme"
        assert result["name"] == "Acme"
        assert result["scope_count"] == 1
        assert "last_checked_at" in result
        assert "first_seen_at" in result
        session.close()
