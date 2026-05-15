"""add composite index on findings(target_id, template_id, url) for deduplication

Revision ID: 20260515_0005
Revises: 20260513_0004
Create Date: 2026-05-15 00:00:00
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260515_0005"
down_revision: str | None = "20260513_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_findings_target_template_url",
        "findings",
        ["target_id", "template_id", "url"],
    )


def downgrade() -> None:
    op.drop_index("ix_findings_target_template_url", table_name="findings")
