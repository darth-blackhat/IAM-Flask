"""operator_requests.checks: what the service found out while a request waits
(e.g. its Jira ticket's status), shown to approvers.

Revision ID: 0013
Revises: 0012
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import JsonType, schema

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("operator_requests", schema=schema()) as b:
        b.add_column(sa.Column("checks", JsonType, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("operator_requests", schema=schema()) as b:
        b.drop_column("checks")
