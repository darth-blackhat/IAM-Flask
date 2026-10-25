import asyncio

import pytest
from sqlalchemy import text

from app.db import Database, LockTimeout
from app.sync import Store


def test_lock_excludes_within_one_instance(database):
    async def go():
        async with database.lock("job"):
            with pytest.raises(LockTimeout):
                async with database.lock("job", timeout=0):
                    pass
            async with database.lock("other", timeout=0):  # different name: independent
                pass
        async with database.lock("job", timeout=0):  # released
            pass
    asyncio.run(go())


def test_upsert_insert_then_update_and_do_nothing(database):
    store = Store(database)
    with store.connect() as conn:
        store.upsert_state(conn, "user", "u1", "h1", {"a": 1})
        store.upsert_state(conn, "user", "u1", "h2", {"a": 2})
    with store.connect() as conn:
        assert store.load_state(conn, "user") == {"u1": ("h2", {"a": 2})}


@pytest.fixture
def second_instance(database):
    if not database.is_postgres:
        pytest.skip("cross-instance locking needs PostgreSQL (set TEST_DATABASE_URL)")
    other = Database(str(database.engine.url.render_as_string(hide_password=False)), database.schema)
    yield other
    other.engine.dispose()


def test_advisory_lock_excludes_across_instances(database, second_instance):
    async def go():
        async with database.lock("sync"):
            with pytest.raises(LockTimeout, match="another backend instance"):
                async with second_instance.lock("sync", timeout=0.5):
                    pass
        async with second_instance.lock("sync", timeout=0):
            pass
    asyncio.run(go())


def test_postgres_tables_live_in_schema_as_jsonb(database):
    if not database.is_postgres:
        pytest.skip("PostgreSQL only")
    Store(database)
    with database.engine.connect() as conn:
        kind = conn.execute(text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_schema = :s AND table_name = 'sync_outbox' AND column_name = 'payload'"),
            {"s": database.schema}).scalar()
    assert kind == "jsonb"


def test_migrations_reach_head_and_are_idempotent(database):
    assert database.schema_version() == "0004"
    database.migrate()  # every service start runs it again
    assert database.schema_version() == "0004"
    names = {t for t in database.metadata.tables}
    with database.engine.connect() as conn:
        from sqlalchemy import inspect
        existing = set(inspect(conn).get_table_names(schema=database.schema))
    assert {n.split(".")[-1] for n in names} <= existing


def test_database_created_before_migrations_is_adopted(tmp_path):
    from app.schema import BASELINE_TABLES
    db = Database(f"sqlite:///{(tmp_path / 'old.db').as_posix()}")
    # Old deployments: tables made by create_all, some missing, no alembic_version.
    old = [getattr(db.tables, n) for n in BASELINE_TABLES if n != "sync_exports"]
    db.metadata.create_all(db.engine, tables=old)
    with db.engine.begin() as conn:
        conn.execute(db.tables.sync_runs.insert().values(started_at=1.0, status="ok"))
    db.migrate()
    assert db.schema_version() == "0004"
    with db.engine.connect() as conn:
        assert conn.execute(db.tables.sync_runs.select()).first().status == "ok"  # data kept
        conn.execute(db.tables.sync_exports.select()).all()   # missing baseline table added
        conn.execute(db.tables.api_keys.select()).all()       # 0002 applied
    db.engine.dispose()


def test_concurrent_migrations_of_an_old_database(database, tmp_path):
    """Several services start at once against a database from before migrations."""
    import threading

    from app.schema import BASELINE_TABLES
    if database.is_postgres:
        url, schema = database.engine.url.render_as_string(hide_password=False), database.schema
        with database.engine.begin() as conn:     # simulate the old state in this schema
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    else:
        url, schema = f"sqlite:///{(tmp_path / 'race.db').as_posix()}", None
    old = Database(url, schema)
    old.metadata.create_all(old.engine, tables=[getattr(old.tables, n) for n in BASELINE_TABLES])
    old.engine.dispose()

    errors = []

    def start_service():
        db = Database(url, schema)
        try:
            db.migrate()
        except Exception as e:
            errors.append(e)
        finally:
            db.engine.dispose()
    threads = [threading.Thread(target=start_service) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    check = Database(url, schema)
    assert check.schema_version() == "0004"
    name = f'"{schema}".alembic_version' if schema else "alembic_version"
    with check.engine.connect() as conn:
        assert conn.execute(text(f"SELECT count(*) FROM {name}")).scalar() == 1
    check.engine.dispose()
