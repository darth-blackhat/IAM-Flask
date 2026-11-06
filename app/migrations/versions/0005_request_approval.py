"""Approval of operator requests: directory changes wait in the database as
awaiting_approval until a second person approves (or rejects) them.

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import schema

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("operator_requests", schema=schema()) as batch:
        batch.add_column(sa.Column("decided_by", sa.String(length=120), nullable=True))
        batch.add_column(sa.Column("decided_at", sa.Float(), nullable=True))
        batch.add_column(sa.Column("decision_note", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("operator_requests", schema=schema()) as batch:
        batch.drop_column("decision_note")
        batch.drop_column("decided_at")
        batch.drop_column("decided_by")
