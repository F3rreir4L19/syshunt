"""Abstract base for platform monitors."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@dataclass
class ProgramInfo:
    platform: str
    program_handle: str
    name: str
    scope: list[dict[str, Any]] = field(default_factory=list)
    bounty_table: dict[str, Any] = field(default_factory=dict)
    launched_at: datetime | None = None
    submission_state: str = "open"


class PlatformAPIError(Exception):
    """Raised when a platform API call fails with an HTTP error."""


class RateLimitError(PlatformAPIError):
    """Raised when the platform returns HTTP 429."""


class PlatformMonitor(ABC):
    """Common interface for bug bounty platform monitors."""

    @property
    @abstractmethod
    def platform_name(self) -> str: ...

    @abstractmethod
    def fetch_programs(self) -> list[ProgramInfo]:
        """Fetch and normalize all accessible programs from the platform."""

    @abstractmethod
    def normalize_program(self, raw: dict[str, Any]) -> ProgramInfo:
        """Convert a raw API response item to a ProgramInfo."""

    @abstractmethod
    def extract_scopes(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract normalized scope items from a raw scope API response."""

    # ------------------------------------------------------------------
    # Helpers that operate on in-memory data (no DB access needed)
    # ------------------------------------------------------------------

    def diff_scopes(
        self,
        old_scope: list[dict[str, Any]],
        new_scope: list[dict[str, Any]],
    ) -> tuple[list[str], list[str]]:
        """Return (added, removed) asset_identifier strings between two scope lists."""
        key = "asset_identifier"
        old_ids = {item.get(key, "") for item in old_scope if item.get(key)}
        new_ids = {item.get(key, "") for item in new_scope if item.get(key)}
        added = sorted(new_ids - old_ids)
        removed = sorted(old_ids - new_ids)
        return added, removed

    # ------------------------------------------------------------------
    # DB-backed detection helpers
    # ------------------------------------------------------------------

    def detect_new_programs(
        self,
        session: "Session",
        programs: list[ProgramInfo],
    ) -> list[ProgramInfo]:
        """Return programs from *programs* that have no matching DB record."""
        from core.db.queries import get_bounty_program_by_handle

        new: list[ProgramInfo] = []
        for prog in programs:
            existing = get_bounty_program_by_handle(
                session, self.platform_name, prog.program_handle
            )
            if existing is None:
                new.append(prog)
        return new

    def detect_scope_changes(
        self,
        session: "Session",
        programs: list[ProgramInfo],
    ) -> list[tuple[ProgramInfo, list[str], list[str]]]:
        """Return programs whose scope differs from the stored version.

        Each entry is (program, added_identifiers, removed_identifiers).
        New programs (not yet in DB) are skipped.
        """
        from core.db.queries import get_bounty_program_by_handle

        changed: list[tuple[ProgramInfo, list[str], list[str]]] = []
        for prog in programs:
            existing = get_bounty_program_by_handle(
                session, self.platform_name, prog.program_handle
            )
            if existing is None:
                continue
            added, removed = self.diff_scopes(existing.scope or [], prog.scope)
            if added or removed:
                changed.append((prog, added, removed))
        return changed
