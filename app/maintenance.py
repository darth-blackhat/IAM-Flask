"""Retention: delete old rows from tables that only ever grow.

Runs once a day inside the long-running services, or by hand: `iam maintenance purge`.
Each window is a setting in days; 0 keeps rows forever. Only finished, historical rows
are purged: pending outbox events, dead events and current state are never touched.
"""

import time
from typing import Any

from sqlalchemy import delete, func, select

from .config import Settings
from .db import Database
from .logs import logger

DAY = 86400


def _rules(db: Database, s: Settings) -> list[tuple[str, Any, Any, int]]:
    t = db.tables
    return [
        ("delivered outbox events", t.sync_outbox, t.sync_outbox.c.delivered_at, s.retention_outbox_days),
        ("sync runs", t.sync_runs, t.sync_runs.c.started_at, s.retention_runs_days),
        ("producer activity", t.producer_activity, t.producer_activity.c.at, s.retention_activity_days),
        ("producer idempotency records", t.producer_processed, t.producer_processed.c.at,
         s.retention_activity_days),
        ("consumer actions", t.consumer_actions, t.consumer_actions.c.at, s.retention_activity_days),
        ("consumer file records", t.consumer_files, t.consumer_files.c.received_at,
         s.retention_activity_days),
        ("operator requests", t.operator_requests, t.operator_requests.c.at, s.retention_runs_days),
        ("drift reports", t.drift_reports, t.drift_reports.c.at, s.retention_runs_days),
        ("audit trail", t.audit_trail, t.audit_trail.c.at, s.retention_audit_days),
    ]


def purge(db: Database, settings: Settings, *, dry_run: bool = False,
          now: float | None = None) -> dict[str, int]:
    now = now or time.time()
    counts: dict[str, int] = {}
    with db.begin() as conn:
        for label, table, column, days in _rules(db, settings):
            if days <= 0:
                continue
            cutoff = now - days * DAY
            cond = (column.is_not(None)) & (column < cutoff)
            if table is db.tables.operator_requests:
                cond = cond & table.c.status.in_(["done", "failed"])
            if dry_run:
                counts[label] = conn.execute(select(func.count()).select_from(table).where(cond)).scalar()
            else:
                counts[label] = conn.execute(delete(table).where(cond)).rowcount
    removed = {k: v for k, v in counts.items() if v}
    if removed and not dry_run:
        logger.info("retention purge removed {}", removed)
    return counts


class DailyPurge:
    """Call `maybe_run()` from a service loop; purges at most once per day."""

    def __init__(self, db: Database, settings: Settings):
        self.db, self.settings, self._last = db, settings, 0.0

    def maybe_run(self) -> dict[str, int] | None:
        if time.time() - self._last < DAY:
            return None
        self._last = time.time()
        try:
            return purge(self.db, self.settings)
        except Exception as e:  # retention must never stop the service
            logger.error("retention purge failed: {}", e)
            return None
