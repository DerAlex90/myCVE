"""add device scoped agents and inventory history

Revision ID: ae5a55a8f79e
Revises: 86082dd56fbe
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "ae5a55a8f79e"
down_revision = "86082dd56fbe"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_suffix", sa.String(length=8), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_inventory_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("agent_version", sa.String(length=100), nullable=False),
        sa.Column(
            "host",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "collectors",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("scan_pending", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_table(
        "inventory_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("agent_id", sa.String(length=36), nullable=False),
        sa.Column("report_id", sa.String(length=36), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checksum", sa.String(length=64), nullable=False),
        sa.Column("partial", sa.Boolean(), nullable=False),
        sa.Column(
            "changes",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column(
            "payload",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["agents.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id", "report_id"),
    )
    op.create_index(
        op.f("ix_inventory_snapshots_agent_id"), "inventory_snapshots", ["agent_id"], unique=False
    )
    op.create_table(
        "inventory_changes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column(
            "before",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "after",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["installation_id"],
            ["installations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["snapshot_id"],
            ["inventory_snapshots.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_inventory_changes_installation_id"),
        "inventory_changes",
        ["installation_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_inventory_changes_snapshot_id"), "inventory_changes", ["snapshot_id"], unique=False
    )
    op.add_column(
        "installations",
        sa.Column("origin", sa.String(length=150), server_default="manual", nullable=False),
    )
    op.add_column(
        "installations",
        sa.Column(
            "inventory",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            server_default="{}",
            nullable=False,
        ),
    )
    op.create_index(op.f("ix_installations_origin"), "installations", ["origin"], unique=False)


def downgrade():
    op.drop_index(op.f("ix_installations_origin"), table_name="installations")
    op.drop_column("installations", "inventory")
    op.drop_column("installations", "origin")
    op.drop_index(op.f("ix_inventory_changes_snapshot_id"), table_name="inventory_changes")
    op.drop_index(op.f("ix_inventory_changes_installation_id"), table_name="inventory_changes")
    op.drop_table("inventory_changes")
    op.drop_index(op.f("ix_inventory_snapshots_agent_id"), table_name="inventory_snapshots")
    op.drop_table("inventory_snapshots")
    op.drop_table("agents")
