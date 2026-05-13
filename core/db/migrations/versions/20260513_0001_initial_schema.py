"""initial schema

Revision ID: 20260513_0001
Revises:
Create Date: 2026-05-13 00:00:00
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "20260513_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "bounty_programs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("platform", sa.String(length=50), nullable=False),
        sa.Column("program_handle", sa.String(length=255), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("bounty_table", sa.JSON(), nullable=False),
        sa.Column("auto_recon_enabled", sa.Boolean(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_bounty_programs")),
    )
    op.create_index(
        op.f("ix_bounty_programs_platform"),
        "bounty_programs",
        ["platform"],
        unique=False,
    )
    op.create_index(
        op.f("ix_bounty_programs_program_handle"),
        "bounty_programs",
        ["program_handle"],
        unique=False,
    )

    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("scope_includes", sa.JSON(), nullable=False),
        sa.Column("scope_excludes", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("platform", sa.String(length=50), nullable=True),
        sa.Column("program_id", sa.String(length=255), nullable=True),
        sa.Column("last_recon_at", sa.DateTime(), nullable=True),
        sa.Column("recon_depth", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_targets")),
    )
    op.create_index(op.f("ix_targets_domain"), "targets", ["domain"], unique=True)
    op.create_index(op.f("ix_targets_status"), "targets", ["status"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("parameter", sa.String(length=255), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("exploitation_difficulty", sa.String(length=20), nullable=False),
        sa.Column("auto_score", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("template_id", sa.String(length=255), nullable=True),
        sa.Column("raw_evidence", sa.JSON(), nullable=False),
        sa.Column("screenshots", sa.JSON(), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_findings_target_id_targets"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
    )
    op.create_index(
        op.f("ix_findings_auto_score"),
        "findings",
        ["auto_score"],
        unique=False,
    )
    op.create_index(
        op.f("ix_findings_confidence"),
        "findings",
        ["confidence"],
        unique=False,
    )
    op.create_index(
        op.f("ix_findings_severity"),
        "findings",
        ["severity"],
        unique=False,
    )
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
    op.create_index(
        op.f("ix_findings_target_id"),
        "findings",
        ["target_id"],
        unique=False,
    )
    op.create_index(op.f("ix_findings_type"), "findings", ["type"], unique=False)

    op.create_table(
        "recon_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(length=100), nullable=False),
        sa.Column("result_type", sa.String(length=100), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("superseded_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["superseded_by"],
            ["recon_results.id"],
            name=op.f("fk_recon_results_superseded_by_recon_results"),
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name=op.f("fk_recon_results_target_id_targets"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recon_results")),
    )
    op.create_index(
        op.f("ix_recon_results_result_type"),
        "recon_results",
        ["result_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_recon_results_target_id"),
        "recon_results",
        ["target_id"],
        unique=False,
    )
    op.create_index(op.f("ix_recon_results_tool"), "recon_results", ["tool"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_recon_results_tool"), table_name="recon_results")
    op.drop_index(op.f("ix_recon_results_target_id"), table_name="recon_results")
    op.drop_index(op.f("ix_recon_results_result_type"), table_name="recon_results")
    op.drop_table("recon_results")
    op.drop_index(op.f("ix_findings_type"), table_name="findings")
    op.drop_index(op.f("ix_findings_target_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_confidence"), table_name="findings")
    op.drop_index(op.f("ix_findings_auto_score"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_targets_status"), table_name="targets")
    op.drop_index(op.f("ix_targets_domain"), table_name="targets")
    op.drop_table("targets")
    op.drop_index(op.f("ix_bounty_programs_program_handle"), table_name="bounty_programs")
    op.drop_index(op.f("ix_bounty_programs_platform"), table_name="bounty_programs")
    op.drop_table("bounty_programs")
