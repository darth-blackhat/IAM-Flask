"""Database access shared by the sync and producer stores.

PostgreSQL in production (DATABASE_URL=postgresql+psycopg://...), SQLite for local
development and tests. This is the backend's own database: never point it at OpenIAM's.
"""

import asyncio
import hashlib
import os
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

from sqlalchemy import Connection, MetaData, Table, create_engine, inspect, text
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Engine, make_url

from .schema import BASELINE_TABLES, define_tables

MIGRATIONS = Path(__file__).parent / "migrations"
_MIGRATE_LOCK = 0x6269616D6D6967   # pg_advisory_xact_lock key for migrations


class LockTimeout(Exception):
    pass


class Database:
    def __init__(self, url: str, schema: str | None = None):
        u = make_url(url)
        self.is_postgres = u.get_backend_name() == "postgresql"
        if u.get_backend_name() == "sqlite":
            if u.database and u.database != ":memory:":
                Path(u.database).parent.mkdir(parents=True, exist_ok=True)
            self.engine: Engine = create_engine(url, connect_args={"timeout": 30})
            # SQLite has no schemas; table names stay unqualified.
            schema = None
        else:
            self.engine = create_engine(url, pool_pre_ping=True)
        self.metadata = MetaData(schema=schema)
        self.schema = schema
        self.tables = define_tables(self.metadata)
        self._local_locks: dict[str, asyncio.Lock] = {}

    def migrate(self) -> None:
        """Bring the schema to the latest version (Alembic). Safe to call on every start."""
        from alembic import command
        from alembic.config import Config

        cfg = Config()
        cfg.set_main_option("script_location", str(MIGRATIONS))
        # Several services / instances start together: one migrates, the others wait and
        # then find nothing left to do (otherwise two could stamp the same old database).
        with self._migration_lock(), self.engine.begin() as conn:
            if self.is_postgres:
                conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _MIGRATE_LOCK})
            if self.schema:
                conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"'))
            cfg.attributes["connection"] = conn
            cfg.attributes["schema"] = self.schema
            insp = inspect(conn)
            if (not insp.has_table("alembic_version", schema=self.schema)
                    and insp.has_table("sync_outbox", schema=self.schema)):
                # Created before migrations existed: complete the baseline, mark it 0001.
                baseline = [getattr(self.tables, n) for n in BASELINE_TABLES]
                self.metadata.create_all(conn, tables=baseline)
                command.stamp(cfg, "0001")
            command.upgrade(cfg, "head")

    @contextmanager
    def _migration_lock(self, timeout: float = 120.0):
        """SQLite (development): a lock file next to the database. PostgreSQL uses an
        advisory lock inside the migration transaction instead."""
        if self.is_postgres or not self.engine.url.database or self.engine.url.database == ":memory:":
            yield
            return
        lock = Path(self.engine.url.database + ".migrate.lock")
        deadline = time.monotonic() + timeout
        while True:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                try:   # left behind by a crashed process
                    if time.time() - lock.stat().st_mtime > timeout:
                        lock.unlink(missing_ok=True)
                        continue
                except FileNotFoundError:
                    continue
                if time.monotonic() > deadline:
                    raise LockTimeout(f"database migration lock {lock} is held") from None
                time.sleep(0.2)
        try:
            yield
        finally:
            os.close(fd)
            lock.unlink(missing_ok=True)

    def schema_version(self) -> str | None:
        with self.engine.connect() as conn:
            if not inspect(conn).has_table("alembic_version", schema=self.schema):
                return None
            name = f'"{self.schema}".alembic_version' if self.schema else "alembic_version"
            return conn.execute(text(f"SELECT version_num FROM {name}")).scalar()

    @contextmanager
    def begin(self):
        """A connection inside one transaction: commit on success, roll back on error."""
        with self.engine.begin() as conn:
            yield conn

    def upsert(self, conn: Connection, table: Table, rows: dict | list[dict], keys: list[str],
               update: bool = True) -> None:
        """INSERT ... ON CONFLICT (keys) DO UPDATE (or DO NOTHING), on either database."""
        rows = [rows] if isinstance(rows, dict) else rows
        if not rows:
            return
        insert = postgresql.insert if self.is_postgres else sqlite.insert
        stmt = insert(table).values(rows)
        if update:
            cols = [c for c in rows[0] if c not in keys]
            stmt = stmt.on_conflict_do_update(index_elements=keys,
                                              set_={c: stmt.excluded[c] for c in cols})
        else:
            stmt = stmt.on_conflict_do_nothing(index_elements=keys)
        conn.execute(stmt)

    @asynccontextmanager
    async def lock(self, name: str, timeout: float | None = 30.0) -> AsyncIterator[None]:
        """Mutual exclusion across every backend instance sharing this database.

        PostgreSQL advisory lock held on a dedicated connection; on SQLite (one process)
        an asyncio lock. timeout=0 tries once; None waits forever. Raises LockTimeout.
        """
        local = self._local_locks.setdefault(name, asyncio.Lock())
        if timeout == 0:
            if local.locked():
                raise LockTimeout(f"{name} is busy")
            await local.acquire()
        else:
            try:
                await asyncio.wait_for(local.acquire(), timeout)
            except TimeoutError:
                raise LockTimeout(f"{name} is busy") from None
        try:
            if not self.is_postgres:
                yield
                return
            key = int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big", signed=True)
            conn = self.engine.connect()
            try:
                deadline = None if timeout is None else time.monotonic() + timeout
                while not conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar():
                    conn.rollback()
                    if deadline is not None and time.monotonic() >= deadline:
                        raise LockTimeout(f"{name} is held by another backend instance")
                    await asyncio.sleep(0.25)
                conn.commit()
                try:
                    yield
                finally:
                    conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
                    conn.commit()
            finally:
                conn.close()
        finally:
            local.release()
