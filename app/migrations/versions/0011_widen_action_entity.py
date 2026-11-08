"""consumer_actions.entity: 20 -> 60 characters.

AD actions are logged as "ad:<object class>"; "ad:organizationalUnit" is 21 characters,
so on PostgreSQL every OU applied to AD failed to be recorded (SQLite does not enforce
string lengths, which hid it).

Revision ID: 0011
Revises: 0010
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import schema

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("consumer_actions", schema=schema()) as b:
        b.alter_column("entity", existing_type=sa.String(length=20), type_=sa.String(length=60),
                       existing_nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("consumer_actions", schema=schema()) as b:
        b.alter_column("entity", existing_type=sa.String(length=60), type_=sa.String(length=20),
                       existing_nullable=True)
