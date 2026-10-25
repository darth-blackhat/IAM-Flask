"""Every table of the backend's own database, in one place.

The schema itself is created and changed by Alembic migrations (app/migrations); this
module is the current shape the code works with. When you change it, add a migration.
"""

from types import SimpleNamespace

from sqlalchemy import (JSON, BigInteger, Boolean, Column, Float, Index, Integer, MetaData,
                        String, Table, Text)
from sqlalchemy.dialects import postgresql

# JSONB on PostgreSQL so stored records can be queried; plain JSON text on SQLite.
JsonType = JSON().with_variant(postgresql.JSONB(), "postgresql")
# SQLite only auto-increments a column declared exactly INTEGER PRIMARY KEY.
IdType = BigInteger().with_variant(Integer(), "sqlite")


def define_tables(metadata: MetaData) -> SimpleNamespace:
    m = metadata
    t = SimpleNamespace()

    # ---- change detection + outbox (producer site) --------------------------
    t.sync_entity_state = Table(
        "sync_entity_state", m,
        Column("entity_type", String(100), primary_key=True),
        Column("entity_id", String(255), primary_key=True),
        Column("hash", String(64), nullable=False),
        Column("data", JsonType, nullable=False),
        Column("updated_at", Float, nullable=False))
    t.sync_outbox = Table(
        "sync_outbox", m,
        Column("seq", IdType, primary_key=True, autoincrement=True),
        Column("event_id", String(64), nullable=False, unique=True),
        Column("payload", JsonType, nullable=False),
        Column("created_at", Float, nullable=False),
        Column("attempts", Integer, nullable=False, default=0),
        Column("next_attempt", Float, nullable=False, default=0),
        Column("delivered_at", Float),
        Column("dead", Boolean, nullable=False, default=False),
        Column("last_error", Text),
        Index("sync_outbox_pending", "delivered_at", "dead", "seq"))
    t.sync_runs = Table(
        "sync_runs", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("started_at", Float, nullable=False),
        Column("finished_at", Float),
        Column("status", String(20), nullable=False),
        Column("summary", JsonType),
        Column("error", Text))
    t.sync_exports = Table(
        "sync_exports", m,
        Column("domain", String(500), primary_key=True),
        Column("content_hash", String(64), nullable=False),
        Column("file", Text, nullable=False),
        Column("records", Integer, nullable=False),
        Column("exported_at", Float, nullable=False))

    # ---- producer intake (producer site) -------------------------------------
    t.producer_people = Table(
        "producer_people", m,
        Column("employee_id", String(255), primary_key=True),
        Column("user_id", String(255), nullable=False),
        Column("employment_target", String(20), nullable=False),
        Column("employment", String(20), nullable=False),
        Column("enabled", Boolean, nullable=False),
        Column("assignments", JsonType, nullable=False),
        Column("statuses", JsonType, nullable=False),
        Column("updated_at", Float, nullable=False))
    t.producer_memberships = Table(
        "producer_memberships", m,
        Column("employee_id", String(255), primary_key=True),
        Column("kind", String(20), primary_key=True),
        Column("object_id", String(255), primary_key=True))
    t.producer_directory = Table(
        "producer_directory", m,
        Column("kind", String(20), primary_key=True),
        Column("name", String(500), primary_key=True),
        Column("object_id", String(255), nullable=False))
    t.producer_activity = Table(
        "producer_activity", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("at", Float, nullable=False, index=True),
        Column("employee_id", String(255), nullable=False, index=True),
        Column("event_type", String(20), nullable=False),
        Column("event_id", String(255)),
        Column("ok", Boolean, nullable=False),
        Column("duplicate", Boolean, nullable=False),
        Column("user_id", String(255)),
        Column("error", Text),
        Column("result", JsonType, nullable=False))
    t.producer_processed = Table(
        "producer_processed", m,
        Column("event_id", String(255), primary_key=True),
        Column("result", JsonType, nullable=False),
        Column("at", Float, nullable=False))

    # ---- consumer (remote site) ----------------------------------------------
    t.consumer_files = Table(
        "consumer_files", m,
        Column("sha256", String(64), primary_key=True),
        Column("name", String(500), nullable=False),
        Column("domain", String(500)),
        Column("generated_at", String(64)),
        Column("status", String(20), nullable=False),
        Column("received_at", Float, nullable=False, index=True),
        Column("processed_at", Float),
        Column("counts", JsonType),
        Column("summary", JsonType),
        Column("error", Text),
        Column("stored_at", Text))
    t.consumer_records = Table(
        "consumer_records", m,
        Column("domain", String(500), primary_key=True),
        Column("entity", String(20), primary_key=True),
        Column("source_id", String(255), primary_key=True),
        Column("hash", String(64), nullable=False),
        Column("remote_id", String(255)),
        Column("granted", JsonType),
        Column("updated_at", Float, nullable=False))
    t.consumer_actions = Table(
        "consumer_actions", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("at", Float, nullable=False),
        Column("file_sha256", String(64), index=True),
        Column("domain", String(500)),
        Column("entity", String(20)),
        Column("source_id", String(255)),
        Column("action", String(40), nullable=False),
        Column("ok", Boolean, nullable=False),
        Column("detail", Text))
    t.consumer_domains = Table(
        "consumer_domains", m,
        Column("domain", String(500), primary_key=True),
        Column("last_generated_at", String(64), nullable=False),
        Column("last_file", String(64), nullable=False),
        Column("records", Integer, nullable=False),
        Column("updated_at", Float, nullable=False))

    # ---- security + operations (migration 0002) ------------------------------
    t.api_keys = Table(
        "api_keys", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("name", String(100), nullable=False, unique=True),
        Column("key_prefix", String(16), nullable=False),        # shown in lists and logs
        Column("key_hash", String(64), nullable=False, unique=True),  # sha256 of the secret
        Column("scopes", JsonType, nullable=False),
        Column("allowed_cidrs", JsonType, nullable=False),        # [] = any source address
        Column("created_at", Float, nullable=False),
        Column("created_by", String(100)),
        Column("last_used_at", Float),
        Column("expires_at", Float),
        Column("revoked_at", Float))
    t.web_users = Table(
        "web_users", m,
        Column("username", String(100), primary_key=True),
        Column("password_hash", Text, nullable=False),            # scrypt
        Column("role", String(20), nullable=False),               # viewer | operator | admin
        Column("disabled", Boolean, nullable=False, default=False),
        Column("failed_logins", Integer, nullable=False, default=0),
        Column("locked_until", Float),
        Column("session_epoch", Integer, nullable=False, default=0),  # bump = log out everywhere
        Column("created_at", Float, nullable=False),
        Column("last_login_at", Float),
        Column("password_changed_at", Float, nullable=False))
    t.audit_trail = Table(
        "audit_trail", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("at", Float, nullable=False, index=True),
        Column("channel", String(10), nullable=False),            # web | api | cli | system
        Column("actor", String(120), nullable=False, index=True),
        Column("ip", String(64)),
        Column("action", String(60), nullable=False),
        Column("target", Text),
        Column("ok", Boolean, nullable=False),
        Column("detail", Text))
    t.operator_requests = Table(
        "operator_requests", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("at", Float, nullable=False),
        Column("requested_by", String(120), nullable=False),
        Column("service", String(20), nullable=False),            # producer | consumer
        Column("action", String(40), nullable=False),
        Column("params", JsonType, nullable=False),
        Column("status", String(20), nullable=False),             # pending | running | done | failed
        Column("started_at", Float),
        Column("finished_at", Float),
        Column("result", JsonType),
        Index("operator_requests_pending", "service", "status", "id"))
    t.drift_reports = Table(
        "drift_reports", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("at", Float, nullable=False),
        Column("domain", String(500), nullable=False, index=True),
        Column("status", String(20), nullable=False),             # clean | drift | failed
        Column("summary", JsonType, nullable=False),
        Column("items", JsonType, nullable=False),
        Column("requested_by", String(120)))

    # ---- AD target plans (migration 0003) --------------------------------------
    t.ad_plans = Table(
        "ad_plans", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("at", Float, nullable=False, index=True),
        Column("file_sha256", String(64), nullable=False, index=True),
        Column("domain", String(500), nullable=False),
        Column("mode", String(20), nullable=False),               # dry_run | approve | auto
        # planned | awaiting_approval | applied | partial | rejected | failed
        Column("status", String(20), nullable=False),
        Column("lines", JsonType, nullable=False),                # the zip's instruction lines
        Column("items", JsonType, nullable=False),                # planned / applied LDAP changes
        Column("summary", JsonType, nullable=False),
        Column("decided_by", String(120)),
        Column("decided_at", Float),
        Column("applied_at", Float))

    # ---- AD change watch (migration 0004) --------------------------------------
    t.ad_watch_state = Table(
        "ad_watch_state", m,
        Column("dn", String(1000), primary_key=True),
        Column("object_class", String(40), nullable=False),
        Column("attrs", JsonType, nullable=False),               # watched attributes, last seen
        Column("hash", String(64), nullable=False),
        Column("updated_at", Float, nullable=False),
        Column("updated_by", String(20), nullable=False))        # consumer | poll
    t.ad_change_alerts = Table(
        "ad_change_alerts", m,
        Column("id", IdType, primary_key=True, autoincrement=True),
        Column("at", Float, nullable=False, index=True),
        Column("dn", String(1000), nullable=False),
        Column("object_class", String(40), nullable=False),
        Column("kind", String(30), nullable=False),               # modified | appeared | disappeared
        Column("severity", String(10), nullable=False),           # info | warning | critical
        Column("changes", JsonType, nullable=False),
        Column("acknowledged_by", String(120)),
        Column("acknowledged_at", Float),
        Column("note", Text))
    return t


BASELINE_TABLES = (
    "sync_entity_state", "sync_outbox", "sync_runs", "sync_exports",
    "producer_people", "producer_memberships", "producer_directory", "producer_activity",
    "producer_processed", "consumer_files", "consumer_records", "consumer_actions",
    "consumer_domains")
