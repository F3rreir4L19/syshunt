"""add unique constraint on bounty_programs(platform, program_handle)

Revision ID: 20260515_0006
Revises: 20260515_0005
Create Date: 2026-05-15 00:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260515_0006"
down_revision: str | None = "20260515_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # create_unique_constraint is not supported in SQLite; a unique index is equivalent
    op.create_index(
        "uq_bounty_programs_platform_handle",
        "bounty_programs",
        ["platform", "program_handle"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_bounty_programs_platform_handle", table_name="bounty_programs")
