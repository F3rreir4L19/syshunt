"""Bugcrowd platform monitor."""
from __future__ import annotations

import json
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

_BASE_URL = "https://api.bugcrowd.com"


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class BugcrowdMonitor(PlatformMonitor):
    """Monitor for the Bugcrowd bug bounty platform.

    Authenticates with a Bugcrowd API token via the ``Authorization: Token``
    header.  Tokens are never logged.
    """

    PLATFORM = "bugcrowd"

    def __init__(self, api_token: str, timeout: int = 30) -> None:
        self._api_token = api_token
        self._timeout = timeout

    @property
    def platform_name(self) -> str:
        return self.PLATFORM

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _auth_header(self) -> str:
        return f"Token token={self._api_token}"

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{_BASE_URL}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": self._auth_header(),
                "Accept": "application/vnd.bugcrowd.v1+json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise RateLimitError(
                    f"Bugcrowd rate limit exceeded (HTTP 429) for {path}"
                ) from exc
            raise PlatformAPIError(
                f"Bugcrowd API error HTTP {exc.code} for {path}"
            ) from exc
        except urllib.error.URLError as exc:
            raise PlatformAPIError(
                f"Bugcrowd connection error for {path}: {exc.reason}"
            ) from exc

    # ------------------------------------------------------------------
    # PlatformMonitor interface
    # ------------------------------------------------------------------

    def fetch_programs(self) -> list[ProgramInfo]:
        """Fetch all accessible programs, following pagination."""
        programs: list[ProgramInfo] = []
        page = 1
        page_size = 25

        while True:
            try:
                resp = self._get(
                    "/programs",
                    params={"page[number]": page, "page[size]": page_size},
                )
            except RateLimitError:
                _log.warning("bugcrowd_rate_limit", page=page)
                break
            except PlatformAPIError as exc:
                _log.warning("bugcrowd_fetch_error", page=page, error=str(exc))
                break

            data = resp.get("data") or []
            for item in data:
                try:
                    programs.append(self.normalize_program(item))
                except Exception as exc:
                    _log.warning(
                        "bugcrowd_normalize_error",
                        code=item.get("attributes", {}).get("code"),
                        error=str(exc),
                    )

            links = resp.get("links") or {}
            if not links.get("next"):
                break
            page += 1

        return programs

    def fetch_program_scopes(self, code: str) -> list[dict[str, Any]]:
        """Fetch in-scope targets for a single program code."""
        try:
            resp = self._get(f"/programs/{code}/targets")
        except RateLimitError:
            _log.warning("bugcrowd_scope_rate_limit", code=code)
            return []
        except PlatformAPIError as exc:
            _log.warning("bugcrowd_scope_error", code=code, error=str(exc))
            return []
        return self.extract_scopes(resp)

    def normalize_program(self, raw: dict[str, Any]) -> ProgramInfo:
        """Normalize a single Bugcrowd program API item."""
        attrs = raw.get("attributes") or {}
        code = attrs.get("code") or raw.get("id") or ""
        name = attrs.get("name") or code
        status = attrs.get("status") or "open"
        launched_at = _parse_dt(attrs.get("starts_at"))
        program_type = attrs.get("program_type", "")
        min_points = attrs.get("min_points") or attrs.get("min_payout")
        max_points = attrs.get("max_points") or attrs.get("max_payout")
        bounty_table: dict[str, Any] = {
            "program_type": program_type,
            "min_payout": min_points,
            "max_payout": max_points,
        }
        return ProgramInfo(
            platform=self.PLATFORM,
            program_handle=code,
            name=name,
            scope=[],
            bounty_table=bounty_table,
            launched_at=launched_at,
            submission_state=status,
        )

    def extract_scopes(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract normalized scope items from a Bugcrowd targets response.

        Only includes targets where ``in_scope`` is True (or absent, defaulting
        to True).  Maps ``uri`` → ``asset_identifier`` and ``category`` →
        ``asset_type`` so the shape matches the common interface.
        """
        scopes: list[dict[str, Any]] = []
        for item in raw.get("data") or []:
            attrs = item.get("attributes") or {}
            if not attrs.get("in_scope", True):
                continue
            uri = attrs.get("uri")
            if not uri:
                continue
            scopes.append(
                {
                    "asset_type": attrs.get("category", ""),
                    "asset_identifier": uri,
                    "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
                    "eligible_for_submission": attrs.get("in_scope", True),
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
                    "bugcrowd_sync_program_error",
                    code=prog.program_handle,
                    error=str(exc),
                )

        _log.info("bugcrowd_sync_complete", **stats)
        return stats
