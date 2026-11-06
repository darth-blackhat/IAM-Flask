"""Security: MFA (TOTP + recovery codes) and approval scope for web users, a hash chain
over the audit trail, and multi-person approval of operator requests.

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import JsonType, schema

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("web_users", schema=schema()) as b:
        b.add_column(sa.Column("totp_secret", sa.Text(), nullable=True))
        b.add_column(sa.Column("totp_last_counter", sa.BigInteger(), nullable=True))
        b.add_column(sa.Column("recovery_codes", JsonType, nullable=True))
        b.add_column(sa.Column("approver_scope", JsonType, nullable=True))
    with op.batch_alter_table("audit_trail", schema=schema()) as b:
        b.add_column(sa.Column("prev_hash", sa.String(length=64), nullable=True))
        b.add_column(sa.Column("hash", sa.String(length=64), nullable=True))
    with op.batch_alter_table("operator_requests", schema=schema()) as b:
        b.add_column(sa.Column("approvals", JsonType, nullable=True))
        b.add_column(sa.Column("required_approvals", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("operator_requests", schema=schema()) as b:
        b.drop_column("required_approvals")
        b.drop_column("approvals")
    with op.batch_alter_table("audit_trail", schema=schema()) as b:
        b.drop_column("hash")
        b.drop_column("prev_hash")
    with op.batch_alter_table("web_users", schema=schema()) as b:
        b.drop_column("approver_scope")
        b.drop_column("recovery_codes")
        b.drop_column("totp_last_counter")
        b.drop_column("totp_secret")
