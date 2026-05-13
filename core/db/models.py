from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from core.db.base import Base, TimestampMixin


def list_default() -> list[str]:
    return []


def dict_default() -> dict[str, Any]:
    return {}


class Target(TimestampMixin, Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    scope_includes: Mapped[list[str]] = mapped_column(JSON, default=list_default)
    scope_excludes: Mapped[list[str]] = mapped_column(JSON, default=list_default)
    status: Mapped[str] = mapped_column(String(50), default="pending", index=True)
    platform: Mapped[str | None] = mapped_column(String(50), nullable=True)
    program_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_recon_at: Mapped[datetime | None] = mapped_column(nullable=True)
    recon_depth: Mapped[int] = mapped_column(Integer, default=2)
