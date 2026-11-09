"""Web users signed in through AD (LDAP): where the account comes from and its AD DN.

Revision ID: 0014
Revises: 0013
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import schema

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("web_users", schema=schema()) as b:
        b.add_column(sa.Column("auth_source", sa.String(length=20), nullable=True))
        b.add_column(sa.Column("external_dn", sa.String(length=1000), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("web_users", schema=schema()) as b:
        b.drop_column("external_dn")
        b.drop_column("auth_source")
