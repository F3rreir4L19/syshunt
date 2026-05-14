"""add classifier fields to findings

Revision ID: 20260513_0002
Revises: 20260513_0001
Create Date: 2026-05-13 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260513_0002"
down_revision: str | None = "20260513_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("classifier_used", sa.String(length=50), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("confidence_note", sa.Text(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("ai_reasoning", sa.Text(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("ai_report_draft", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "ai_report_draft")
    op.drop_column("findings", "ai_reasoning")
    op.drop_column("findings", "confidence_note")
    op.drop_column("findings", "classifier_used")
