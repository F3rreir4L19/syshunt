"""add badge and scope_history to bounty_programs

Revision ID: 20260515_0007
Revises: 20260515_0006
Create Date: 2026-05-15 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260515_0007"
down_revision: str | None = "20260515_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "bounty_programs",
        sa.Column("badge", sa.String(50), nullable=True),
    )
    op.add_column(
        "bounty_programs",
        sa.Column("scope_history", sa.JSON, nullable=True),
    )


def downgrade() -> None:
    op.drop_column("bounty_programs", "scope_history")
    op.drop_column("bounty_programs", "badge")
