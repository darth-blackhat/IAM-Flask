"""Notification outbox (email / webhooks) and overdue tracking for certification campaigns.

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, JsonType, schema

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("at", sa.Float(), nullable=False),
        sa.Column("event", sa.String(length=60), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("data", JsonType, nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("sent_at", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_index("notifications_pending", "notifications", ["status", "id"], schema=schema())
    with op.batch_alter_table("cert_campaigns", schema=schema()) as b:
        b.add_column(sa.Column("overdue_notified_at", sa.Float(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("cert_campaigns", schema=schema()) as b:
        b.drop_column("overdue_notified_at")
    op.drop_index("notifications_pending", table_name="notifications", schema=schema())
    op.drop_table("notifications", schema=schema())
