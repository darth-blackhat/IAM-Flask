"""Security and operations: API keys, web users, audit trail, operator requests, drift reports.

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, JsonType, schema  # noqa: F401

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('api_keys',
    sa.Column('id', IdType, autoincrement=True, nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('key_prefix', sa.String(length=16), nullable=False),
    sa.Column('key_hash', sa.String(length=64), nullable=False),
    sa.Column('scopes', JsonType, nullable=False),
    sa.Column('allowed_cidrs', JsonType, nullable=False),
    sa.Column('created_at', sa.Float(), nullable=False),
    sa.Column('created_by', sa.String(length=100), nullable=True),
    sa.Column('last_used_at', sa.Float(), nullable=True),
    sa.Column('expires_at', sa.Float(), nullable=True),
    sa.Column('revoked_at', sa.Float(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('key_hash'),
    sa.UniqueConstraint('name'),
    schema=schema(),
    )
    op.create_table('audit_trail',
    sa.Column('id', IdType, autoincrement=True, nullable=False),
    sa.Column('at', sa.Float(), nullable=False),
    sa.Column('channel', sa.String(length=10), nullable=False),
    sa.Column('actor', sa.String(length=120), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('action', sa.String(length=60), nullable=False),
    sa.Column('target', sa.Text(), nullable=True),
    sa.Column('ok', sa.Boolean(), nullable=False),
    sa.Column('detail', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    schema=schema(),
    )
    op.create_index(op.f('ix_audit_trail_actor'), 'audit_trail', ['actor'], unique=False, schema=schema())
    op.create_index(op.f('ix_audit_trail_at'), 'audit_trail', ['at'], unique=False, schema=schema())
    op.create_table('drift_reports',
    sa.Column('id', IdType, autoincrement=True, nullable=False),
    sa.Column('at', sa.Float(), nullable=False),
    sa.Column('domain', sa.String(length=500), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('summary', JsonType, nullable=False),
    sa.Column('items', JsonType, nullable=False),
    sa.Column('requested_by', sa.String(length=120), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    schema=schema(),
    )
    op.create_index(op.f('ix_drift_reports_domain'), 'drift_reports', ['domain'], unique=False, schema=schema())
    op.create_table('operator_requests',
    sa.Column('id', IdType, autoincrement=True, nullable=False),
    sa.Column('at', sa.Float(), nullable=False),
    sa.Column('requested_by', sa.String(length=120), nullable=False),
    sa.Column('service', sa.String(length=20), nullable=False),
    sa.Column('action', sa.String(length=40), nullable=False),
    sa.Column('params', JsonType, nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('started_at', sa.Float(), nullable=True),
    sa.Column('finished_at', sa.Float(), nullable=True),
    sa.Column('result', JsonType, nullable=True),
    sa.PrimaryKeyConstraint('id'),
    schema=schema(),
    )
    op.create_index('operator_requests_pending', 'operator_requests', ['service', 'status', 'id'], unique=False, schema=schema())
    op.create_table('web_users',
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('password_hash', sa.Text(), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('disabled', sa.Boolean(), nullable=False),
    sa.Column('failed_logins', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.Float(), nullable=True),
    sa.Column('session_epoch', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.Float(), nullable=False),
    sa.Column('last_login_at', sa.Float(), nullable=True),
    sa.Column('password_changed_at', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('username'),
    schema=schema(),
    )


def downgrade() -> None:
    op.drop_table('drift_reports', schema=schema())
    op.drop_table('operator_requests', schema=schema())
    op.drop_table('audit_trail', schema=schema())
    op.drop_table('web_users', schema=schema())
    op.drop_table('api_keys', schema=schema())
