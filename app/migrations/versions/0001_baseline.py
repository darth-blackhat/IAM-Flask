"""Baseline: change detection, outbox, producer and consumer tables.

Revision ID: 0001
Revises: None
"""

import sqlalchemy as sa
from alembic import op

from app.migrations.helpers import IdType, JsonType, schema  # noqa: F401

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('consumer_actions',
    sa.Column('id', IdType, autoincrement=True, nullable=False),
    sa.Column('at', sa.Float(), nullable=False),
    sa.Column('file_sha256', sa.String(length=64), nullable=True),
    sa.Column('domain', sa.String(length=500), nullable=True),
    sa.Column('entity', sa.String(length=20), nullable=True),
    sa.Column('source_id', sa.String(length=255), nullable=True),
    sa.Column('action', sa.String(length=40), nullable=False),
    sa.Column('ok', sa.Boolean(), nullable=False),
    sa.Column('detail', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    schema=schema(),
    )
    op.create_index(op.f('ix_consumer_actions_file_sha256'), 'consumer_actions', ['file_sha256'], unique=False, schema=schema())
    op.create_table('consumer_domains',
    sa.Column('domain', sa.String(length=500), nullable=False),
    sa.Column('last_generated_at', sa.String(length=64), nullable=False),
    sa.Column('last_file', sa.String(length=64), nullable=False),
    sa.Column('records', sa.Integer(), nullable=False),
    sa.Column('updated_at', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('domain'),
    schema=schema(),
    )
    op.create_table('consumer_files',
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=500), nullable=False),
    sa.Column('domain', sa.String(length=500), nullable=True),
    sa.Column('generated_at', sa.String(length=64), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('received_at', sa.Float(), nullable=False),
    sa.Column('processed_at', sa.Float(), nullable=True),
    sa.Column('counts', JsonType, nullable=True),
    sa.Column('summary', JsonType, nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('stored_at', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('sha256'),
    schema=schema(),
    )
    op.create_index(op.f('ix_consumer_files_received_at'), 'consumer_files', ['received_at'], unique=False, schema=schema())
    op.create_table('consumer_records',
    sa.Column('domain', sa.String(length=500), nullable=False),
    sa.Column('entity', sa.String(length=20), nullable=False),
    sa.Column('source_id', sa.String(length=255), nullable=False),
    sa.Column('hash', sa.String(length=64), nullable=False),
    sa.Column('remote_id', sa.String(length=255), nullable=True),
    sa.Column('granted', JsonType, nullable=True),
    sa.Column('updated_at', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('domain', 'entity', 'source_id'),
    schema=schema(),
    )
    op.create_table('producer_activity',
    sa.Column('id', IdType, autoincrement=True, nullable=False),
    sa.Column('at', sa.Float(), nullable=False),
    sa.Column('employee_id', sa.String(length=255), nullable=False),
    sa.Column('event_type', sa.String(length=20), nullable=False),
    sa.Column('event_id', sa.String(length=255), nullable=True),
    sa.Column('ok', sa.Boolean(), nullable=False),
    sa.Column('duplicate', sa.Boolean(), nullable=False),
    sa.Column('user_id', sa.String(length=255), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('result', JsonType, nullable=False),
    sa.PrimaryKeyConstraint('id'),
    schema=schema(),
    )
    op.create_index(op.f('ix_producer_activity_at'), 'producer_activity', ['at'], unique=False, schema=schema())
    op.create_index(op.f('ix_producer_activity_employee_id'), 'producer_activity', ['employee_id'], unique=False, schema=schema())
    op.create_table('producer_directory',
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('name', sa.String(length=500), nullable=False),
    sa.Column('object_id', sa.String(length=255), nullable=False),
    sa.PrimaryKeyConstraint('kind', 'name'),
    schema=schema(),
    )
    op.create_table('producer_memberships',
    sa.Column('employee_id', sa.String(length=255), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('object_id', sa.String(length=255), nullable=False),
    sa.PrimaryKeyConstraint('employee_id', 'kind', 'object_id'),
    schema=schema(),
    )
    op.create_table('producer_people',
    sa.Column('employee_id', sa.String(length=255), nullable=False),
    sa.Column('user_id', sa.String(length=255), nullable=False),
    sa.Column('employment_target', sa.String(length=20), nullable=False),
    sa.Column('employment', sa.String(length=20), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('assignments', JsonType, nullable=False),
    sa.Column('statuses', JsonType, nullable=False),
    sa.Column('updated_at', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('employee_id'),
    schema=schema(),
    )
    op.create_table('producer_processed',
    sa.Column('event_id', sa.String(length=255), nullable=False),
    sa.Column('result', JsonType, nullable=False),
    sa.Column('at', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('event_id'),
    schema=schema(),
    )
    op.create_table('sync_entity_state',
    sa.Column('entity_type', sa.String(length=100), nullable=False),
    sa.Column('entity_id', sa.String(length=255), nullable=False),
    sa.Column('hash', sa.String(length=64), nullable=False),
    sa.Column('data', JsonType, nullable=False),
    sa.Column('updated_at', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('entity_type', 'entity_id'),
    schema=schema(),
    )
    op.create_table('sync_exports',
    sa.Column('domain', sa.String(length=500), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('file', sa.Text(), nullable=False),
    sa.Column('records', sa.Integer(), nullable=False),
    sa.Column('exported_at', sa.Float(), nullable=False),
    sa.PrimaryKeyConstraint('domain'),
    schema=schema(),
    )
    op.create_table('sync_outbox',
    sa.Column('seq', IdType, autoincrement=True, nullable=False),
    sa.Column('event_id', sa.String(length=64), nullable=False),
    sa.Column('payload', JsonType, nullable=False),
    sa.Column('created_at', sa.Float(), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('next_attempt', sa.Float(), nullable=False),
    sa.Column('delivered_at', sa.Float(), nullable=True),
    sa.Column('dead', sa.Boolean(), nullable=False),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('seq'),
    sa.UniqueConstraint('event_id'),
    schema=schema(),
    )
    op.create_index('sync_outbox_pending', 'sync_outbox', ['delivered_at', 'dead', 'seq'], unique=False, schema=schema())
    op.create_table('sync_runs',
    sa.Column('id', IdType, autoincrement=True, nullable=False),
    sa.Column('started_at', sa.Float(), nullable=False),
    sa.Column('finished_at', sa.Float(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('summary', JsonType, nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    schema=schema(),
    )


def downgrade() -> None:
    op.drop_table('consumer_domains', schema=schema())
    op.drop_table('consumer_actions', schema=schema())
    op.drop_table('consumer_records', schema=schema())
    op.drop_table('consumer_files', schema=schema())
    op.drop_table('producer_processed', schema=schema())
    op.drop_table('producer_activity', schema=schema())
    op.drop_table('producer_directory', schema=schema())
    op.drop_table('producer_memberships', schema=schema())
    op.drop_table('producer_people', schema=schema())
    op.drop_table('sync_exports', schema=schema())
    op.drop_table('sync_runs', schema=schema())
    op.drop_table('sync_outbox', schema=schema())
    op.drop_table('sync_entity_state', schema=schema())
