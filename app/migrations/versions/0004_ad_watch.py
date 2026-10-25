"""AD change watch: last-seen state of managed AD objects, and alerts for changes made
outside the consumer.

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, JsonType, schema

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ad_watch_state",
        sa.Column("dn", sa.String(length=1000), nullable=False),
        sa.Column("object_class", sa.String(length=40), nullable=False),
        sa.Column("attrs", JsonType, nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.Float(), nullable=False),
        sa.Column("updated_by", sa.String(length=20), nullable=False),
        sa.PrimaryKeyConstraint("dn"),
        schema=schema(),
    )
    op.create_table(
        "ad_change_alerts",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("at", sa.Float(), nullable=False),
        sa.Column("dn", sa.String(length=1000), nullable=False),
        sa.Column("object_class", sa.String(length=40), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("changes", JsonType, nullable=False),
        sa.Column("acknowledged_by", sa.String(length=120), nullable=True),
        sa.Column("acknowledged_at", sa.Float(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_index(op.f("ix_ad_change_alerts_at"), "ad_change_alerts", ["at"], unique=False,
                    schema=schema())


def downgrade() -> None:
    op.drop_table("ad_change_alerts", schema=schema())
    op.drop_table("ad_watch_state", schema=schema())
