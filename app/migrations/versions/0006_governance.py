"""Governance: segregation-of-duties policies and access certification campaigns.

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, schema

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sod_policies",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("left_kind", sa.String(length=20), nullable=False),
        sa.Column("left_name", sa.String(length=500), nullable=False),
        sa.Column("right_kind", sa.String(length=20), nullable=False),
        sa.Column("right_name", sa.String(length=500), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        schema=schema(),
    )
    op.create_table(
        "cert_campaigns",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("scope_kind", sa.String(length=20), nullable=True),
        sa.Column("scope_name", sa.String(length=500), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("due_at", sa.Float(), nullable=True),
        sa.Column("closed_by", sa.String(length=120), nullable=True),
        sa.Column("closed_at", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_table(
        "cert_items",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("campaign_id", IdType, nullable=False),
        sa.Column("employee_id", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("object_name", sa.String(length=500), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("decision", sa.String(length=20), nullable=True),
        sa.Column("decided_by", sa.String(length=120), nullable=True),
        sa.Column("decided_at", sa.Float(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("request_id", IdType, nullable=True),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_index(op.f("ix_cert_items_campaign_id"), "cert_items", ["campaign_id"],
                    unique=False, schema=schema())


def downgrade() -> None:
    op.drop_index(op.f("ix_cert_items_campaign_id"), table_name="cert_items", schema=schema())
    op.drop_table("cert_items", schema=schema())
    op.drop_table("cert_campaigns", schema=schema())
    op.drop_table("sod_policies", schema=schema())
