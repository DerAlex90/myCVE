"""initial inventory sources findings and history

Revision ID: 86082dd56fbe
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "86082dd56fbe"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("environment", sa.String(length=100), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("exposure", sa.String(length=20), nullable=False),
        sa.Column("criticality", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("primary_alias", sa.String(length=200), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=False),
        sa.Column("kev_due_date", sa.String(length=30), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_vulnerabilities_primary_alias"), "vulnerabilities", ["primary_alias"], unique=False
    )
    op.create_table(
        "aliases",
        sa.Column("alias", sa.String(length=200), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
        ),
        sa.PrimaryKeyConstraint("alias"),
    )
    op.create_index(
        op.f("ix_aliases_vulnerability_id"), "aliases", ["vulnerability_id"], unique=False
    )
    op.create_table(
        "installations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("identity_key", sa.String(length=64), nullable=False),
        sa.Column(
            "component",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "identity_key"),
    )
    op.create_index(op.f("ix_installations_asset_id"), "installations", ["asset_id"], unique=False)
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "result",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "source_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=30), nullable=False),
        sa.Column("external_id", sa.String(length=500), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column(
            "payload",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("source_modified", sa.String(length=100), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("current", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "external_id", "checksum"),
    )
    op.create_index(op.f("ix_source_records_current"), "source_records", ["current"], unique=False)
    op.create_index(
        op.f("ix_source_records_vulnerability_id"),
        "source_records",
        ["vulnerability_id"],
        unique=False,
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("priority", sa.String(length=10), nullable=False),
        sa.Column("priority_score", sa.Integer(), nullable=False),
        sa.Column(
            "priority_reasons",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "fixed_versions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "evidence",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("checked_version", sa.String(length=300), nullable=True),
        sa.Column("workflow", sa.String(length=30), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["installations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["vulnerability_id"],
            ["vulnerabilities.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("installation_id", "vulnerability_id"),
    )
    op.create_index(
        op.f("ix_findings_installation_id"), "findings", ["installation_id"], unique=False
    )
    op.create_index(
        op.f("ix_findings_vulnerability_id"), "findings", ["vulnerability_id"], unique=False
    )
    op.create_table(
        "finding_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column(
            "before",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "after",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_finding_events_finding_id"), "finding_events", ["finding_id"], unique=False
    )


def downgrade():
    op.drop_index(op.f("ix_finding_events_finding_id"), table_name="finding_events")
    op.drop_table("finding_events")
    op.drop_index(op.f("ix_findings_vulnerability_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_installation_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_source_records_vulnerability_id"), table_name="source_records")
    op.drop_index(op.f("ix_source_records_current"), table_name="source_records")
    op.drop_table("source_records")
    op.drop_table("scan_jobs")
    op.drop_index(op.f("ix_installations_asset_id"), table_name="installations")
    op.drop_table("installations")
    op.drop_index(op.f("ix_aliases_vulnerability_id"), table_name="aliases")
    op.drop_table("aliases")
    op.drop_index(op.f("ix_vulnerabilities_primary_alias"), table_name="vulnerabilities")
    op.drop_table("vulnerabilities")
    op.drop_table("assets")
