"""Time-limited access: memberships granted until a date and removed automatically.

Revision ID: 0009
Revises: 0008
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, JsonType, schema

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "timed_grants",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("request_id", IdType, nullable=True),
        sa.Column("params", JsonType, nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("removal_request_id", IdType, nullable=True),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_index(op.f("ix_timed_grants_expires_at"), "timed_grants", ["expires_at"], schema=schema())


def downgrade() -> None:
    op.drop_index(op.f("ix_timed_grants_expires_at"), table_name="timed_grants", schema=schema())
    op.drop_table("timed_grants", schema=schema())
