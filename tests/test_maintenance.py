import time

from sqlalchemy import func, select

from app.config import Settings
from app.maintenance import DAY, DailyPurge, purge


def count(db, table):
    with db.engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(table)).scalar()


def test_purge_keeps_pending_dead_and_recent(database):
    t, now = database.tables, time.time()
    with database.begin() as conn:
        def ev(event_id, delivered_at=None, dead=False, created_at=0.0):
            return {"event_id": event_id, "payload": {}, "created_at": created_at,
                    "delivered_at": delivered_at, "dead": dead}
        conn.execute(t.sync_outbox.insert(), [
            ev("old-delivered", now - 200 * DAY), ev("new-delivered", now - 1 * DAY),
            ev("pending", created_at=now - 900 * DAY), ev("dead", dead=True)])
        conn.execute(t.audit_trail.insert(), [
            {"at": now - 800 * DAY, "channel": "web", "actor": "a", "action": "login", "ok": True},
            {"at": now - 10 * DAY, "channel": "web", "actor": "a", "action": "login", "ok": True}])
        conn.execute(t.operator_requests.insert(), [
            {"at": now - 400 * DAY, "requested_by": "a", "service": "producer", "action": "x",
             "params": {}, "status": "pending"},
            {"at": now - 400 * DAY, "requested_by": "a", "service": "producer", "action": "x",
             "params": {}, "status": "done"}])

    settings = Settings(_env_file=None)
    assert purge(database, settings, dry_run=True)["delivered outbox events"] == 1
    assert count(database, t.sync_outbox) == 4  # dry run deletes nothing
    removed = purge(database, settings)
    assert removed["delivered outbox events"] == 1 and removed["audit trail"] == 1
    assert removed["operator requests"] == 1     # the pending one stays
    with database.engine.connect() as conn:
        left = {r.event_id for r in conn.execute(select(t.sync_outbox.c.event_id))}
    assert left == {"new-delivered", "pending", "dead"}


def test_zero_keeps_forever_and_daily_runs_once(database):
    t = database.tables
    with database.begin() as conn:
        conn.execute(t.sync_runs.insert().values(started_at=1.0, status="ok"))
    assert purge(database, Settings(_env_file=None, retention_runs_days=0)).get("sync runs") is None
    daily = DailyPurge(database, Settings(_env_file=None))
    assert daily.maybe_run()["sync runs"] == 1
    assert daily.maybe_run() is None
