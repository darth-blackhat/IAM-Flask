"""AD receipts: consumer outbox, and per-instruction status on the producer.

Revision ID: 0012
Revises: 0011
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, JsonType, schema

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "consumer_receipts",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("at", sa.Float(), nullable=False),
        sa.Column("payload", JsonType, nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("file", sa.Text(), nullable=True),
        sa.Column("written_at", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_index("consumer_receipts_pending", "consumer_receipts", ["status", "id"], schema=schema())
    op.create_table(
        "ad_receipts",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("site", sa.String(length=63), nullable=False),
        sa.Column("receipt_id", sa.BigInteger(), nullable=False),
        sa.Column("zip_name", sa.String(length=500), nullable=True),
        sa.Column("zip_sha256", sa.String(length=64), nullable=True),
        sa.Column("domain", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("received_at", sa.Float(), nullable=False),
        sa.Column("signed_by", sa.String(length=63), nullable=True),
        sa.Column("payload", JsonType, nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("site", "receipt_id", name="ad_receipts_site_receipt"),
        schema=schema(),
    )
    op.create_index(op.f("ix_ad_receipts_received_at"), "ad_receipts", ["received_at"], schema=schema())
    op.create_table(
        "ad_receipt_items",
        sa.Column("instruction_id", sa.String(length=64), nullable=False),
        sa.Column("site", sa.String(length=63), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("at", sa.Float(), nullable=False),
        sa.Column("receipt", IdType, nullable=True),
        sa.PrimaryKeyConstraint("instruction_id", "site"),
        schema=schema(),
    )


def downgrade() -> None:
    op.drop_table("ad_receipt_items", schema=schema())
    op.drop_index(op.f("ix_ad_receipts_received_at"), table_name="ad_receipts", schema=schema())
    op.drop_table("ad_receipts", schema=schema())
    op.drop_index("consumer_receipts_pending", table_name="consumer_receipts", schema=schema())
    op.drop_table("consumer_receipts", schema=schema())
