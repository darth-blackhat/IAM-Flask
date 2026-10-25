"""AD target: plans of LDAP changes per zip, with approval.

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, JsonType, schema

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ad_plans",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("at", sa.Float(), nullable=False),
        sa.Column("file_sha256", sa.String(length=64), nullable=False),
        sa.Column("domain", sa.String(length=500), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("lines", JsonType, nullable=False),
        sa.Column("items", JsonType, nullable=False),
        sa.Column("summary", JsonType, nullable=False),
        sa.Column("decided_by", sa.String(length=120), nullable=True),
        sa.Column("decided_at", sa.Float(), nullable=True),
        sa.Column("applied_at", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_index(op.f("ix_ad_plans_at"), "ad_plans", ["at"], unique=False, schema=schema())
    op.create_index(op.f("ix_ad_plans_file_sha256"), "ad_plans", ["file_sha256"], unique=False,
                    schema=schema())


def downgrade() -> None:
    op.drop_table("ad_plans", schema=schema())
