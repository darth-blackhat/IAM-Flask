"""Scheduled reports, saved searches, and the employee a web user is (self-service).

Revision ID: 0010
Revises: 0009
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, schema

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("web_users", schema=schema()) as b:
        b.add_column(sa.Column("employee_id", sa.String(length=255), nullable=True))
    op.create_table(
        "report_schedules",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("report", sa.String(length=60), nullable=False),
        sa.Column("every", sa.String(length=20), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_run_at", sa.Float(), nullable=True),
        sa.Column("last_file", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_table(
        "saved_searches",
        sa.Column("id", IdType, autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("path", sa.String(length=1000), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        schema=schema(),
    )
    op.create_index(op.f("ix_saved_searches_username"), "saved_searches", ["username"], schema=schema())


def downgrade() -> None:
    op.drop_index(op.f("ix_saved_searches_username"), table_name="saved_searches", schema=schema())
    op.drop_table("saved_searches", schema=schema())
    op.drop_table("report_schedules", schema=schema())
    with op.batch_alter_table("web_users", schema=schema()) as b:
        b.drop_column("employee_id")
