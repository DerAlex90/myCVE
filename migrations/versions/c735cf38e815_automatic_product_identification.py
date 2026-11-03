"""Automatic product identification, retaining original inventory unchanged."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c735cf38e815"
down_revision = "ae5a55a8f79e"
branch_labels = None
depends_on = None


def upgrade():
    json_type = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
    op.add_column(
        "installations",
        sa.Column("identification", json_type, server_default="{}", nullable=False),
    )
    op.create_table(
        "product_identity_cache",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("result", json_type, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_product_identity_cache_expires_at", "product_identity_cache", ["expires_at"]
    )
    op.execute(
        sa.text(
            "UPDATE agents SET scan_pending = true WHERE revoked_at IS NULL AND last_inventory_at IS NOT NULL"
        )
    )


def downgrade():
    op.drop_table("product_identity_cache")
    op.drop_column("installations", "identification")
