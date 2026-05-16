"""Intigriti platform monitor — OAuth2 Client Credentials."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog

from core.monitor.base import PlatformAPIError, PlatformMonitor, ProgramInfo, RateLimitError

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

_log = structlog.get_logger()

_TOKEN_URL = "https://login.intigriti.com/connect/token"
_BASE_URL = "https://api.intigriti.com/v1"
_TOKEN_SCOPE = "core:read:researcher"
_TOKEN_EXPIRY_BUFFER = 60  # seconds before expiry to refresh


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class IntigritiMonitor(PlatformMonitor):
    """Monitor for the Intigriti bug bounty platform.

    Uses OAuth2 Client Credentials flow.  The access token is cached in the
    instance and refreshed automatically when it expires.
    Credentials are never logged.
    """

    PLATFORM = "intigriti"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        timeout: int = 30,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0

    @property
    def platform_name(self) -> str:
        return self.PLATFORM

    # ------------------------------------------------------------------
    # OAuth2 token management
    # ------------------------------------------------------------------

    def _fetch_token(self) -> None:
        """Request a new OAuth2 access token and cache it.

        client_secret is used only in the POST body and is never logged.
        Raises PlatformAPIError on failure.
        """
        body = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": _TOKEN_SCOPE,
            }
        ).encode()
        req = urllib.request.Request(
            _TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise PlatformAPIError(
                f"Intigriti OAuth2 token request failed (HTTP {exc.code})"
            ) from exc
        except urllib.error.URLError as exc:
            raise PlatformAPIError(
                f"Intigriti OAuth2 connection error: {exc.reason}"
            ) from exc

        token = data.get("access_token")
        if not token:
            raise PlatformAPIError(
                "Intigriti OAuth2: no access_token in response"
            )
        expires_in = int(data.get("expires_in", 3600))
        self._access_token = token
        self._token_expires_at = time.time() + expires_in

    def _ensure_token(self) -> str:
        """Return a valid access token, fetching one if expired or absent."""
        if (
            self._access_token is None
            or time.time() >= self._token_expires_at - _TOKEN_EXPIRY_BUFFER
        ):
            self._fetch_token()
        return self._access_token  # type: ignore[return-value]

    def _invalidate_token(self) -> None:
        self._access_token = None
        self._token_expires_at = 0.0

    # ------------------------------------------------------------------
    # HTTP helper
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Authenticated GET.  Returns dict or list depending on endpoint.

        Retries once on HTTP 401 (token expired in flight).
        """
        for attempt in range(2):
            try:
                token = self._ensure_token()
                url = f"{_BASE_URL}{path}"
                if params:
                    url += "?" + urllib.parse.urlencode(params)
                req = urllib.request.Request(
                    url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))

            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 0:
                    # Token may have expired in flight — refresh once
                    self._invalidate_token()
                    continue
                if exc.code == 429:
                    raise RateLimitError(
                        f"Intigriti rate limit exceeded (HTTP 429) for {path}"
                    ) from exc
                raise PlatformAPIError(
                    f"Intigriti API error HTTP {exc.code} for {path}"
                ) from exc
            except urllib.error.URLError as exc:
                raise PlatformAPIError(
                    f"Intigriti connection error for {path}: {exc.reason}"
                ) from exc
        # Should be unreachable, but satisfy type checker
        raise PlatformAPIError(f"Intigriti _get failed after retries for {path}")

    # ------------------------------------------------------------------
    # PlatformMonitor interface
    # ------------------------------------------------------------------

    def fetch_programs(self) -> list[ProgramInfo]:
        """Fetch all accessible programs.

        The Intigriti API returns a flat array (no pagination wrapper).
        """
        try:
            data = self._get("/researcher/programs")
        except RateLimitError:
            _log.warning("intigriti_rate_limit", endpoint="/researcher/programs")
            return []
        except PlatformAPIError as exc:
            _log.warning("intigriti_fetch_error", error=str(exc))
            return []

        if isinstance(data, dict):
            data = data.get("data") or []

        programs: list[ProgramInfo] = []
        for item in data or []:
            try:
                programs.append(self.normalize_program(item))
            except Exception as exc:
                _log.warning(
                    "intigriti_normalize_error",
                    handle=item.get("handle") if isinstance(item, dict) else None,
                    error=str(exc),
                )
        return programs

    def fetch_program_scopes(self, handle: str) -> list[dict[str, Any]]:
        """Fetch in-scope domains for a single program handle."""
        try:
            data = self._get(f"/researcher/programs/{handle}/domains")
        except RateLimitError:
            _log.warning("intigriti_scope_rate_limit", handle=handle)
            return []
        except PlatformAPIError as exc:
            _log.warning("intigriti_scope_error", handle=handle, error=str(exc))
            return []

        if isinstance(data, dict):
            data = data.get("data") or []
        return self.extract_scopes(data or [])

    def normalize_program(self, raw: dict[str, Any]) -> ProgramInfo:
        """Normalize a single Intigriti program API item."""
        handle = raw.get("handle") or raw.get("id") or ""
        name = raw.get("name") or handle
        status_obj = raw.get("status") or {}
        status = status_obj.get("value", "open").lower() if isinstance(status_obj, dict) else str(status_obj).lower()
        launched_at = _parse_dt(raw.get("lastUpdateAt") or raw.get("createdAt"))
        min_bounty = raw.get("minBounty")
        max_bounty = raw.get("maxBounty")
        avg_bounty = raw.get("averageBounty")
        bounty_table: dict[str, Any] = {
            "min_bounty": min_bounty,
            "max_bounty": max_bounty,
            "average_bounty": avg_bounty,
        }
        return ProgramInfo(
            platform=self.PLATFORM,
            program_handle=handle,
            name=name,
            scope=[],
            bounty_table=bounty_table,
            launched_at=launched_at,
            submission_state=status,
        )

    def extract_scopes(self, raw: Any) -> list[dict[str, Any]]:
        """Extract normalized scope items from an Intigriti domains response.

        *raw* may be a list of domain objects (the normal Intigriti format)
        or a dict with a ``data`` key.  Only entries with ``inScope: true``
        (or absent, defaulting to True) are included.  Maps ``endpoint``
        → ``asset_identifier`` and ``type.value`` → ``asset_type``.
        """
        items: list[dict[str, Any]]
        if isinstance(raw, dict):
            items = raw.get("data") or []
        elif isinstance(raw, list):
            items = raw
        else:
            return []

        scopes: list[dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if not item.get("inScope", True):
                continue
            endpoint = item.get("endpoint")
            if not endpoint:
                continue
            type_obj = item.get("type") or {}
            asset_type = (
                type_obj.get("value", "") if isinstance(type_obj, dict) else str(type_obj)
            )
            scopes.append(
                {
                    "asset_type": asset_type,
                    "asset_identifier": endpoint,
                    "eligible_for_bounty": item.get("bounty", False),
                    "eligible_for_submission": item.get("inScope", True),
                }
            )
        return scopes

    # ------------------------------------------------------------------
    # Sync — fetch + persist + notify
    # ------------------------------------------------------------------

    def sync_programs(self, session: "Session") -> dict[str, Any]:
        """Fetch all programs, upsert to DB, detect changes, send notifications.

        Returns stats dict: {fetched, new, scope_changed, errors}.
        """
        from core.db.queries import upsert_bounty_program
        from core.notifications import notify_new_program, notify_scope_changed

        programs = self.fetch_programs()
        stats: dict[str, Any] = {
            "fetched": len(programs),
            "new": 0,
            "scope_changed": 0,
            "errors": 0,
        }

        for prog in programs:
            try:
                if prog.program_handle:
                    prog.scope = self.fetch_program_scopes(prog.program_handle)

                bounty_program, is_new, added, removed = upsert_bounty_program(
                    session,
                    platform=self.PLATFORM,
                    program_handle=prog.program_handle,
                    name=prog.name,
                    scope=prog.scope,
                    bounty_table=prog.bounty_table,
                )

                if is_new:
                    stats["new"] += 1
                    notify_new_program(bounty_program, session=session)
                elif added or removed:
                    stats["scope_changed"] += 1
                    notify_scope_changed(
                        bounty_program, added=added, removed=removed, session=session
                    )

            except Exception as exc:
                stats["errors"] += 1
                _log.warning(
                    "intigriti_sync_program_error",
                    handle=prog.program_handle,
                    error=str(exc),
                )

        _log.info("intigriti_sync_complete", **stats)
        return stats
