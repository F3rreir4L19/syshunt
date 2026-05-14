"""add auto_analyze column to targets

Revision ID: 20260513_0004
Revises: 20260513_0003
Create Date: 2026-05-13 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260513_0004"
down_revision: str | None = "20260513_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "targets",
        sa.Column("auto_analyze", sa.Boolean(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("targets", "auto_analyze")
