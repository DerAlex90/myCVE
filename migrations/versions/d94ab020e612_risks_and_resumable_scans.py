"""Package context, explicit fix status and persistent resumable scan work."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d94ab020e612"
down_revision = "c735cf38e815"
branch_labels = None
depends_on = None


def upgrade():
    json_type = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
    op.add_column(
        "installations", sa.Column("context", json_type, nullable=False, server_default="{}")
    )
    op.add_column(
        "findings",
        sa.Column("patch_status", sa.String(20), nullable=False, server_default="unknown"),
    )
    for column in [
        sa.Column("progress", json_type, nullable=False, server_default="{}"),
        sa.Column("cache_scope", sa.String(36), nullable=False, server_default=""),
        sa.Column("resume_of", sa.String(36), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    ]:
        op.add_column("scan_jobs", column)
    op.create_table(
        "scan_cache",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scope", sa.String(36), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("payload", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scope", "key"),
    )
    op.create_index("ix_scan_cache_scope", "scan_cache", ["scope"])
    op.create_index("ix_scan_cache_created_at", "scan_cache", ["created_at"])
    op.create_table(
        "runtime_state",
        sa.Column("name", sa.String(80), primary_key=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("data", json_type, nullable=False),
    )
    op.execute(
        sa.text(
            "UPDATE agents SET scan_pending = true WHERE revoked_at IS NULL AND last_inventory_at IS NOT NULL"
        )
    )
    # Existing nonempty version lists are positive evidence; empty lists remain unknown.
    connection = op.get_bind()
    rows = connection.execute(sa.text("SELECT id, fixed_versions FROM findings"))
    import json

    for row in rows:
        versions = (
            json.loads(row.fixed_versions)
            if isinstance(row.fixed_versions, str)
            else row.fixed_versions
        )
        if versions:
            connection.execute(
                sa.text("UPDATE findings SET patch_status = 'available' WHERE id = :id"),
                {"id": row.id},
            )


def downgrade():
    op.drop_table("runtime_state")
    op.drop_table("scan_cache")
    for column in ["heartbeat_at", "cancel_requested", "resume_of", "cache_scope", "progress"]:
        op.drop_column("scan_jobs", column)
    op.drop_column("findings", "patch_status")
    op.drop_column("installations", "context")
