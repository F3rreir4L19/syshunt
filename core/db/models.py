from datetime import datetime
from typing import Any

from sqlalchemy import JSON, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

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

    findings: Mapped[list["Finding"]] = relationship(back_populates="target")
    recon_results: Mapped[list["ReconResult"]] = relationship(back_populates="target")


class Finding(TimestampMixin, Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    type: Mapped[str] = mapped_column(String(100), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    confidence: Mapped[str] = mapped_column(String(20), default="possible", index=True)
    exploitation_difficulty: Mapped[str] = mapped_column(
        String(20),
        default="medium",
    )
    auto_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    template_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict_default)
    screenshots: Mapped[list[str]] = mapped_column(JSON, default=list_default)
    reviewed_at: Mapped[datetime | None] = mapped_column(nullable=True)

    target: Mapped[Target] = relationship(back_populates="findings")


class ReconResult(TimestampMixin, Base):
    __tablename__ = "recon_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    tool: Mapped[str] = mapped_column(String(100), index=True)
    result_type: Mapped[str] = mapped_column(String(100), index=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict_default)
    superseded_by: Mapped[int | None] = mapped_column(
        ForeignKey("recon_results.id"),
        nullable=True,
    )

    target: Mapped[Target] = relationship(back_populates="recon_results")
    superseded_by_result: Mapped["ReconResult | None"] = relationship(remote_side=[id])
