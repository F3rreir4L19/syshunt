"""Tests for Phase 4 Intigriti monitor — OAuth2 + REST."""
from __future__ import annotations

import json
import time
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from core.monitor.base import PlatformAPIError, ProgramInfo, RateLimitError
from core.monitor.intigriti import IntigritiMonitor, _TOKEN_URL

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent.parent / "fixtures" / "intigriti"


def _load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text())


def _mock_response(data: object) -> MagicMock:
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


def _monitor() -> IntigritiMonitor:
    return IntigritiMonitor(client_id="cid", client_secret="csecret")


# ---------------------------------------------------------------------------
# OAuth2 token fetch
# ---------------------------------------------------------------------------


class TestFetchToken:
    def test_posts_to_token_url(self):
        captured_url = []

        def fake_urlopen(req, timeout=None):
            captured_url.append(req.full_url)
            return _mock_response(_load("token_response.json"))

        m = _monitor()
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            m._fetch_token()

        assert captured_url[0] == _TOKEN_URL

    def test_stores_access_token(self):
        m = _monitor()
        with patch(
            "urllib.request.urlopen",
            return_value=_mock_response(_load("token_response.json")),
        ):
            m._fetch_token()

        assert m._access_token == "test_bearer_token_value"

    def test_sets_expiry(self):
        m = _monitor()
        before = time.time()
        with patch(
            "urllib.request.urlopen",
            return_value=_mock_response(_load("token_response.json")),
        ):
            m._fetch_token()

        assert m._token_expires_at >= before + 3600 - 1

    def test_http_error_raises_platform_api_error(self):
        m = _monitor()
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                _TOKEN_URL, 400, "Bad Request", None, None
            )
            with pytest.raises(PlatformAPIError, match="OAuth2"):
                m._fetch_token()

    def test_connection_error_raises_platform_api_error(self):
        m = _monitor()
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.URLError("connection refused")
            with pytest.raises(PlatformAPIError, match="connection"):
                m._fetch_token()

    def test_missing_access_token_in_response_raises(self):
        m = _monitor()
        with patch(
            "urllib.request.urlopen",
            return_value=_mock_response({"token_type": "Bearer", "expires_in": 3600}),
        ):
            with pytest.raises(PlatformAPIError, match="access_token"):
                m._fetch_token()

    def test_client_secret_not_in_error_message(self):
        m = IntigritiMonitor("cid", "super_secret_value")
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                _TOKEN_URL, 401, "Unauthorized", None, None
            )
            with pytest.raises(PlatformAPIError) as exc_info:
                m._fetch_token()
        assert "super_secret_value" not in str(exc_info.value)

    def test_client_id_in_post_body(self):
        captured_body = []

        def fake_urlopen(req, timeout=None):
            captured_body.append(req.data)
            return _mock_response(_load("token_response.json"))

        m = IntigritiMonitor("my_client_id_xyz", "secret")
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            m._fetch_token()

        body_str = captured_body[0].decode()
        assert "my_client_id_xyz" in body_str
        assert "client_credentials" in body_str


# ---------------------------------------------------------------------------
# ensure_token / caching / invalidation
# ---------------------------------------------------------------------------


class TestEnsureToken:
    def test_fetches_when_no_token(self):
        m = _monitor()
        with patch.object(m, "_fetch_token") as mock_fetch:
            mock_fetch.side_effect = lambda: setattr(m, "_access_token", "tok") or setattr(
                m, "_token_expires_at", time.time() + 3600
            )
            token = m._ensure_token()
        mock_fetch.assert_called_once()
        assert token == "tok"

    def test_returns_cached_token_when_valid(self):
        m = _monitor()
        m._access_token = "cached_token"
        m._token_expires_at = time.time() + 3600
        with patch.object(m, "_fetch_token") as mock_fetch:
            token = m._ensure_token()
        mock_fetch.assert_not_called()
        assert token == "cached_token"

    def test_refreshes_when_near_expiry(self):
        m = _monitor()
        m._access_token = "old_token"
        m._token_expires_at = time.time() + 30  # within 60s buffer

        def set_new():
            m._access_token = "new_token"
            m._token_expires_at = time.time() + 3600

        with patch.object(m, "_fetch_token", side_effect=set_new):
            token = m._ensure_token()
        assert token == "new_token"

    def test_invalidate_clears_token(self):
        m = _monitor()
        m._access_token = "some_token"
        m._token_expires_at = time.time() + 3600
        m._invalidate_token()
        assert m._access_token is None
        assert m._token_expires_at == 0.0


# ---------------------------------------------------------------------------
# _get — 401 retry logic
# ---------------------------------------------------------------------------


class TestGetRetryOn401:
    def _setup_monitor_with_token(self) -> IntigritiMonitor:
        m = _monitor()
        m._access_token = "initial_token"
        m._token_expires_at = time.time() + 3600
        return m

    def test_retries_on_401_with_fresh_token(self):
        m = self._setup_monitor_with_token()
        call_count = [0]

        def fake_urlopen(req, timeout=None):
            call_count[0] += 1
            if call_count[0] == 1 and "api.intigriti.com" in req.full_url:
                raise urllib.error.HTTPError("", 401, "Unauthorized", None, None)
            if "login.intigriti.com" in req.full_url:
                # token refresh
                m._access_token = "refreshed_token"
                m._token_expires_at = time.time() + 3600
                return _mock_response(_load("token_response.json"))
            return _mock_response([])

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = m._get("/researcher/programs")

        assert result == []

    def test_raises_on_second_401(self):
        m = self._setup_monitor_with_token()

        def fake_urlopen(req, timeout=None):
            if "login.intigriti.com" in req.full_url:
                m._access_token = "refreshed"
                m._token_expires_at = time.time() + 3600
                return _mock_response(_load("token_response.json"))
            raise urllib.error.HTTPError("", 401, "Unauthorized", None, None)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with pytest.raises(PlatformAPIError):
                m._get("/researcher/programs")

    def test_rate_limit_raises(self):
        m = self._setup_monitor_with_token()
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError("", 429, "Rate Limit", None, None)
            with pytest.raises(RateLimitError):
                m._get("/researcher/programs")

    def test_500_raises_platform_api_error(self):
        m = self._setup_monitor_with_token()
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError(
                "", 500, "Server Error", None, None
            )
            with pytest.raises(PlatformAPIError):
                m._get("/researcher/programs")

    def test_url_error_raises_platform_api_error(self):
        m = self._setup_monitor_with_token()
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.URLError("network error")
            with pytest.raises(PlatformAPIError):
                m._get("/researcher/programs")


# ---------------------------------------------------------------------------
# normalize_program
# ---------------------------------------------------------------------------


class TestNormalizeProgram:
    def setup_method(self):
        self.monitor = _monitor()

    def test_basic_fields(self):
        raw = _load("programs.json")[0]
        prog = self.monitor.normalize_program(raw)
        assert prog.platform == "intigriti"
        assert prog.program_handle == "acme"
        assert prog.name == "Acme Security Program"

    def test_submission_state_lowercased(self):
        raw = _load("programs.json")[0]
        prog = self.monitor.normalize_program(raw)
        assert prog.submission_state == "open"

    def test_bounty_table(self):
        raw = _load("programs.json")[0]
        prog = self.monitor.normalize_program(raw)
        assert prog.bounty_table["min_bounty"] == 100
        assert prog.bounty_table["max_bounty"] == 5000
        assert prog.bounty_table["average_bounty"] == 750

    def test_launched_at_parsed(self):
        raw = _load("programs.json")[0]
        prog = self.monitor.normalize_program(raw)
        assert prog.launched_at is not None
        assert prog.launched_at.year == 2021

    def test_second_program(self):
        raw = _load("programs.json")[1]
        prog = self.monitor.normalize_program(raw)
        assert prog.program_handle == "delta-corp"
        assert prog.name == "Delta Security"

    def test_missing_handle_falls_back_to_id(self):
        raw = {"id": "fallback-id", "name": "Test"}
        prog = self.monitor.normalize_program(raw)
        assert prog.program_handle == "fallback-id"

    def test_scope_starts_empty(self):
        raw = _load("programs.json")[0]
        prog = self.monitor.normalize_program(raw)
        assert prog.scope == []


# ---------------------------------------------------------------------------
# extract_scopes
# ---------------------------------------------------------------------------


class TestExtractScopes:
    def setup_method(self):
        self.monitor = _monitor()

    def test_acme_in_scope_only(self):
        raw = _load("domains_acme.json")
        scopes = self.monitor.extract_scopes(raw)
        # domain-3 has inScope=false
        assert len(scopes) == 2
        identifiers = [s["asset_identifier"] for s in scopes]
        assert "https://www.acme.com" in identifiers
        assert "https://api.acme.com" in identifiers
        assert "https://internal.acme.com" not in identifiers

    def test_delta_targets(self):
        raw = _load("domains_delta.json")
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 1
        assert scopes[0]["asset_identifier"] == "https://app.deltacorp.io"

    def test_fields_present(self):
        raw = _load("domains_acme.json")
        scope = self.monitor.extract_scopes(raw)[0]
        assert "asset_type" in scope
        assert "asset_identifier" in scope
        assert "eligible_for_bounty" in scope
        assert "eligible_for_submission" in scope

    def test_asset_type_from_type_value(self):
        raw = _load("domains_acme.json")
        scope = self.monitor.extract_scopes(raw)[0]
        assert scope["asset_type"] == "url"

    def test_bounty_field_mapped(self):
        raw = _load("domains_acme.json")
        scopes = self.monitor.extract_scopes(raw)
        bounty_scopes = [s for s in scopes if s["eligible_for_bounty"]]
        assert len(bounty_scopes) == 2

    def test_in_scope_absent_defaults_to_included(self):
        raw = [{"id": "x", "endpoint": "https://default.com", "type": {"value": "url"}}]
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 1

    def test_missing_endpoint_skipped(self):
        raw = [
            {"id": "a", "inScope": True, "type": {"value": "url"}},
            {"id": "b", "inScope": True, "endpoint": "https://valid.com"},
        ]
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 1
        assert scopes[0]["asset_identifier"] == "https://valid.com"

    def test_dict_wrapper_accepted(self):
        raw = {"data": _load("domains_acme.json")}
        scopes = self.monitor.extract_scopes(raw)
        assert len(scopes) == 2

    def test_empty_list(self):
        assert self.monitor.extract_scopes([]) == []

    def test_empty_dict(self):
        assert self.monitor.extract_scopes({}) == []


# ---------------------------------------------------------------------------
# fetch_programs
# ---------------------------------------------------------------------------


class TestFetchPrograms:
    def _fake_urlopen_both(self, token_body, api_body):
        """Return a side_effect that routes token vs API calls."""

        def side_effect(req, timeout=None):
            if "login.intigriti.com" in req.full_url:
                return _mock_response(token_body)
            return _mock_response(api_body)

        return side_effect

    def test_returns_programs(self):
        m = _monitor()
        with patch(
            "urllib.request.urlopen",
            side_effect=self._fake_urlopen_both(
                _load("token_response.json"), _load("programs.json")
            ),
        ):
            programs = m.fetch_programs()
        assert len(programs) == 2
        handles = [p.program_handle for p in programs]
        assert "acme" in handles
        assert "delta-corp" in handles

    def test_returns_empty_on_rate_limit(self):
        m = _monitor()
        m._access_token = "tok"
        m._token_expires_at = time.time() + 3600
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError("", 429, "Rate Limit", None, None)
            programs = m.fetch_programs()
        assert programs == []

    def test_returns_empty_on_http_error(self):
        m = _monitor()
        m._access_token = "tok"
        m._token_expires_at = time.time() + 3600
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError("", 503, "Unavailable", None, None)
            programs = m.fetch_programs()
        assert programs == []

    def test_handles_dict_wrapped_response(self):
        m = _monitor()
        wrapped = {"data": _load("programs.json")}
        with patch(
            "urllib.request.urlopen",
            side_effect=self._fake_urlopen_both(_load("token_response.json"), wrapped),
        ):
            programs = m.fetch_programs()
        assert len(programs) == 2


# ---------------------------------------------------------------------------
# fetch_program_scopes
# ---------------------------------------------------------------------------


class TestFetchProgramScopes:
    def test_returns_in_scope_entries(self):
        m = _monitor()
        m._access_token = "tok"
        m._token_expires_at = time.time() + 3600
        with patch(
            "urllib.request.urlopen",
            return_value=_mock_response(_load("domains_acme.json")),
        ):
            scopes = m.fetch_program_scopes("acme")
        assert len(scopes) == 2

    def test_rate_limit_returns_empty(self):
        m = _monitor()
        m._access_token = "tok"
        m._token_expires_at = time.time() + 3600
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError("", 429, "Rate Limit", None, None)
            scopes = m.fetch_program_scopes("acme")
        assert scopes == []

    def test_http_error_returns_empty(self):
        m = _monitor()
        m._access_token = "tok"
        m._token_expires_at = time.time() + 3600
        with patch("urllib.request.urlopen") as mock:
            mock.side_effect = urllib.error.HTTPError("", 404, "Not Found", None, None)
            scopes = m.fetch_program_scopes("unknown")
        assert scopes == []


# ---------------------------------------------------------------------------
# Credential safety (never log secrets)
# ---------------------------------------------------------------------------


class TestCredentialSafety:
    def test_client_secret_not_in_log_on_token_error(self, caplog):
        import logging

        m = IntigritiMonitor("cid", "my_very_secret_client_secret")
        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock:
                mock.side_effect = urllib.error.HTTPError(
                    _TOKEN_URL, 401, "Unauthorized", None, None
                )
                try:
                    m._fetch_token()
                except PlatformAPIError:
                    pass
        for record in caplog.records:
            assert "my_very_secret_client_secret" not in record.getMessage()

    def test_client_secret_not_in_api_error_log(self, caplog):
        import logging

        m = IntigritiMonitor("cid", "another_super_secret")
        m._access_token = "tok"
        m._token_expires_at = time.time() + 3600
        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock:
                mock.side_effect = urllib.error.URLError("network error")
                m.fetch_programs()
        for record in caplog.records:
            assert "another_super_secret" not in record.getMessage()

    def test_bearer_token_not_in_api_error_log(self, caplog):
        """The cached access token must not leak into log messages."""
        import logging

        m = _monitor()
        m._access_token = "secret_bearer_token_value"
        m._token_expires_at = time.time() + 3600
        with caplog.at_level(logging.WARNING):
            with patch("urllib.request.urlopen") as mock:
                mock.side_effect = urllib.error.HTTPError(
                    "", 503, "Server Error", None, None
                )
                m.fetch_programs()
        for record in caplog.records:
            assert "secret_bearer_token_value" not in record.getMessage()


# ---------------------------------------------------------------------------
# Upsert — platform isolation
# ---------------------------------------------------------------------------


class TestIntigritiUpsert:
    def test_new_program_created(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        prog, is_new, added, removed = upsert_bounty_program(
            session,
            platform="intigriti",
            program_handle="acme",
            name="Acme Security Program",
            scope=[{"asset_identifier": "https://www.acme.com"}],
            bounty_table={"min_bounty": 100},
        )
        assert is_new is True
        assert prog.platform == "intigriti"
        session.close()

    def test_intigriti_isolated_from_other_platforms(self):
        from core.db.queries import upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(session, "hackerone", "acme", "Acme H1", [], {})
        upsert_bounty_program(session, "bugcrowd", "acme", "Acme BC", [], {})
        prog, is_new, _, _ = upsert_bounty_program(
            session, "intigriti", "acme", "Acme IT", [], {}
        )
        assert is_new is True
        assert prog.platform == "intigriti"
        session.close()


# ---------------------------------------------------------------------------
# Scheduler task
# ---------------------------------------------------------------------------


class TestIntigritiScheduler:
    def test_skips_without_credentials(self):
        import os

        with patch.dict(
            os.environ,
            {"INTIGRITI_CLIENT_ID": "", "INTIGRITI_CLIENT_SECRET": ""},
        ):
            from core.monitor.scheduler import poll_intigriti

            result = poll_intigriti()
        assert result.get("skipped") is True

    def test_skips_when_only_client_id_set(self):
        import os

        with patch.dict(
            os.environ,
            {"INTIGRITI_CLIENT_ID": "cid", "INTIGRITI_CLIENT_SECRET": ""},
        ):
            from core.monitor.scheduler import poll_intigriti

            result = poll_intigriti()
        assert result.get("skipped") is True

    def test_calls_sync_with_credentials(self):
        import os

        with patch.dict(
            os.environ,
            {"INTIGRITI_CLIENT_ID": "cid", "INTIGRITI_CLIENT_SECRET": "csec"},
        ):
            with patch("core.monitor.intigriti.IntigritiMonitor") as MockMonitor:
                mock_instance = MagicMock()
                mock_instance.sync_programs.return_value = {
                    "fetched": 4,
                    "new": 2,
                    "scope_changed": 1,
                    "errors": 0,
                }
                MockMonitor.return_value = mock_instance

                from core.monitor.scheduler import poll_intigriti

                result = poll_intigriti()

            assert result["fetched"] == 4
            assert result["new"] == 2
            mock_instance.sync_programs.assert_called_once()

    def test_returns_skip_on_exception(self):
        import os

        with patch.dict(
            os.environ,
            {"INTIGRITI_CLIENT_ID": "cid", "INTIGRITI_CLIENT_SECRET": "csec"},
        ):
            with patch("core.monitor.intigriti.IntigritiMonitor") as MockMonitor:
                mock_instance = MagicMock()
                mock_instance.sync_programs.side_effect = RuntimeError("db error")
                MockMonitor.return_value = mock_instance

                from core.monitor.scheduler import poll_intigriti

                result = poll_intigriti()

            assert result.get("skipped") is True
            assert "db error" in result.get("error", "")


# ---------------------------------------------------------------------------
# sync_programs end-to-end
# ---------------------------------------------------------------------------


class TestIntigritiSyncPrograms:
    def _fake_urlopen(self, programs_body, domains_body):
        def side_effect(req, timeout=None):
            url = req.full_url
            if "login.intigriti.com" in url:
                return _mock_response(_load("token_response.json"))
            if "/domains" in url:
                return _mock_response(domains_body)
            return _mock_response(programs_body)

        return side_effect

    def test_sync_creates_new_programs(self):
        m = _monitor()
        session = _make_session()
        with patch(
            "urllib.request.urlopen",
            side_effect=self._fake_urlopen(
                _load("programs.json"), _load("domains_acme.json")
            ),
        ):
            stats = m.sync_programs(session)
        assert stats["fetched"] == 2
        assert stats["new"] == 2
        assert stats["errors"] == 0
        session.close()

    def test_sync_detects_scope_change(self):
        from core.db.queries import upsert_bounty_program

        m = _monitor()
        session = _make_session()
        upsert_bounty_program(
            session,
            "intigriti",
            "acme",
            "Acme",
            [{"asset_identifier": "https://www.acme.com"}],
            {},
        )
        only_acme = [_load("programs.json")[0]]
        with patch(
            "urllib.request.urlopen",
            side_effect=self._fake_urlopen(only_acme, _load("domains_acme.json")),
        ), patch("core.notifications.notify_scope_changed") as mock_notify:
            stats = m.sync_programs(session)
        assert stats["scope_changed"] == 1
        mock_notify.assert_called_once()
        session.close()

    def test_sync_notifies_new_program(self):
        m = _monitor()
        session = _make_session()
        only_acme = [_load("programs.json")[0]]
        with patch(
            "urllib.request.urlopen",
            side_effect=self._fake_urlopen(only_acme, []),
        ), patch("core.notifications.notify_new_program") as mock_notify:
            stats = m.sync_programs(session)
        assert stats["new"] == 1
        mock_notify.assert_called_once()
        session.close()

    def test_sync_empty_returns_stable_shape(self):
        m = _monitor()
        session = _make_session()
        with patch(
            "urllib.request.urlopen",
            side_effect=self._fake_urlopen([], []),
        ):
            stats = m.sync_programs(session)
        assert stats == {"fetched": 0, "new": 0, "scope_changed": 0, "errors": 0}
        session.close()

    def test_token_fetched_once_for_multiple_programs(self):
        m = _monitor()
        session = _make_session()
        token_call_count = [0]

        def side_effect(req, timeout=None):
            if "login.intigriti.com" in req.full_url:
                token_call_count[0] += 1
                return _mock_response(_load("token_response.json"))
            if "/domains" in req.full_url:
                return _mock_response([])
            return _mock_response(_load("programs.json"))

        with patch("urllib.request.urlopen", side_effect=side_effect):
            m.sync_programs(session)

        # Token should be fetched only once even for multiple programs
        assert token_call_count[0] == 1
        session.close()
