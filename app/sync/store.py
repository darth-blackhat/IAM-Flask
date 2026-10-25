"""Last-seen state of every entity, plus an outbox of change events.

State and events are written in one transaction, so a detected change is never lost
and never recorded without its event.
"""

import time
from collections.abc import Iterable
from typing import Any

from sqlalchemy import Connection, case, delete, func, insert, select, update

from ..db import Database


class Store:
    def __init__(self, db: Database):
        self.db = db
        t = db.tables
        self.state = t.sync_entity_state
        self.outbox = t.sync_outbox
        self.runs = t.sync_runs
        self.exports = t.sync_exports

    def connect(self):
        """One transaction: `with store.connect() as conn: ...`."""
        return self.db.begin()

    # ---- state --------------------------------------------------------------

    def load_state(self, conn: Connection, entity_type: str) -> dict[str, tuple[str, dict]]:
        s = self.state.c
        rows = conn.execute(select(s.entity_id, s.hash, s.data).where(s.entity_type == entity_type))
        return {r.entity_id: (r.hash, r.data) for r in rows}

    def upsert_state(self, conn: Connection, entity_type: str, entity_id: str,
                     hash_: str, data: dict) -> None:
        self.db.upsert(conn, self.state, {"entity_type": entity_type, "entity_id": entity_id,
                                          "hash": hash_, "data": data, "updated_at": time.time()},
                       keys=["entity_type", "entity_id"])

    def delete_state(self, conn: Connection, entity_type: str, entity_id: str) -> None:
        s = self.state.c
        conn.execute(delete(self.state).where(s.entity_type == entity_type, s.entity_id == entity_id))

    def snapshot(self, entity_type: str, offset: int = 0, limit: int = 500) -> list[dict]:
        s = self.state.c
        with self.connect() as conn:
            rows = conn.execute(select(s.data).where(s.entity_type == entity_type)
                                .order_by(s.entity_id).limit(limit).offset(offset))
            return [r.data for r in rows]

    def counts(self) -> dict[str, int]:
        s = self.state.c
        with self.connect() as conn:
            rows = conn.execute(select(s.entity_type, func.count()).group_by(s.entity_type))
            return {t: n for t, n in rows}

    # ---- outbox -------------------------------------------------------------

    def add_events(self, conn: Connection, events: Iterable[dict[str, Any]]) -> None:
        now = time.time()
        rows = [{"event_id": e["event_id"], "payload": e, "created_at": now} for e in events]
        if rows:
            conn.execute(insert(self.outbox), rows)

    def _pending_q(self):
        o = self.outbox.c
        return o.delivered_at.is_(None) & o.dead.is_(False)

    def pending(self, limit: int) -> list[dict[str, Any]]:
        """Oldest undelivered events, or none while the oldest one is in backoff.

        Delivery is strictly in order, so the target never sees an update before its create.
        """
        o = self.outbox.c
        with self.connect() as conn:
            rows = conn.execute(select(o.seq, o.payload, o.next_attempt).where(self._pending_q())
                                .order_by(o.seq).limit(limit)).all()
        if rows and rows[0].next_attempt > time.time():
            return []
        return [{**r.payload, "seq": r.seq} for r in rows]

    def mark_delivered(self, seqs: list[int]) -> None:
        o = self.outbox.c
        with self.connect() as conn:
            conn.execute(update(self.outbox).where(o.seq.in_(seqs))
                         .values(delivered_at=time.time(), last_error=None))

    def mark_failed(self, seqs: list[int], error: str, max_attempts: int) -> None:
        o = self.outbox.c
        with self.connect() as conn:
            for seq in seqs:
                attempts = conn.execute(select(o.attempts).where(o.seq == seq)).scalar_one() + 1
                conn.execute(update(self.outbox).where(o.seq == seq).values(
                    attempts=attempts, next_attempt=time.time() + min(2 ** attempts, 3600),
                    last_error=error[:2000], dead=attempts >= max_attempts))

    def events_after(self, after_seq: int, limit: int) -> list[dict[str, Any]]:
        """Pull-mode feed for the other site: every event with seq > after_seq."""
        o = self.outbox.c
        with self.connect() as conn:
            rows = conn.execute(select(o.seq, o.payload).where(o.seq > after_seq)
                                .order_by(o.seq).limit(limit))
            return [{**r.payload, "seq": r.seq} for r in rows]

    def retry_dead(self) -> int:
        o = self.outbox.c
        with self.connect() as conn:
            return conn.execute(update(self.outbox).where(o.dead.is_(True))
                                .values(dead=False, attempts=0, next_attempt=0)).rowcount

    def outbox_stats(self) -> dict[str, Any]:
        o = self.outbox.c
        with self.connect() as conn:
            r = conn.execute(select(
                func.sum(case((self._pending_q(), 1), else_=0)).label("pending"),
                func.sum(case((o.delivered_at.is_not(None), 1), else_=0)).label("delivered"),
                func.sum(case((o.dead.is_(True), 1), else_=0)).label("dead"),
                func.max(o.seq).label("last_seq"))).one()
            err = conn.execute(select(o.last_error).where(o.delivered_at.is_(None),
                                                          o.last_error.is_not(None))
                               .order_by(o.seq).limit(1)).scalar()
        return {"pending": r.pending or 0, "delivered": r.delivered or 0, "dead": r.dead or 0,
                "last_seq": r.last_seq or 0, "last_error": err}

    # ---- runs ---------------------------------------------------------------

    def start_run(self) -> int:
        with self.connect() as conn:
            res = conn.execute(insert(self.runs).values(started_at=time.time(), status="running"))
            return res.inserted_primary_key[0]

    def finish_run(self, run_id: int, status: str, summary: dict | None = None,
                   error: str | None = None) -> None:
        with self.connect() as conn:
            conn.execute(update(self.runs).where(self.runs.c.id == run_id).values(
                finished_at=time.time(), status=status, summary=summary, error=error))

    def recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(select(self.runs).order_by(self.runs.c.id.desc()).limit(limit))
            return [dict(r._mapping) for r in rows]

    # ---- exports ------------------------------------------------------------

    def last_exports(self) -> dict[str, dict[str, Any]]:
        with self.connect() as conn:
            return {r.domain: dict(r._mapping) for r in conn.execute(select(self.exports))}

    def record_export(self, domain: str, content_hash: str, file: str, records: int) -> None:
        with self.connect() as conn:
            self.db.upsert(conn, self.exports, {"domain": domain, "content_hash": content_hash,
                                                "file": file, "records": records,
                                                "exported_at": time.time()}, keys=["domain"])

    def recent_events(self, limit: int = 100, before_seq: int | None = None) -> list[dict[str, Any]]:
        """Outbox rows with delivery status, newest first (for the web UI)."""
        o = self.outbox.c
        q = select(self.outbox).order_by(o.seq.desc()).limit(limit)
        if before_seq:
            q = q.where(o.seq < before_seq)
        with self.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]

    def event(self, seq: int) -> dict[str, Any] | None:
        with self.connect() as conn:
            r = conn.execute(select(self.outbox).where(self.outbox.c.seq == seq)).first()
            return dict(r._mapping) if r else None

    def last_run_start(self) -> float | None:
        """Start of the last run that recorded state: changes after it are in the next diff."""
        r = self.runs.c
        with self.connect() as conn:
            return conn.execute(select(func.max(r.started_at))
                                .where(r.status.in_(["ok", "baseline"]))).scalar()

    def pending_all(self) -> list[dict[str, Any]]:
        """Every undelivered event, oldest first, ignoring backoff (zip target)."""
        o = self.outbox.c
        with self.connect() as conn:
            rows = conn.execute(select(o.seq, o.payload).where(self._pending_q()).order_by(o.seq))
            return [{**r.payload, "seq": r.seq} for r in rows]

    def state_record(self, entity_type: str, entity_id: str) -> dict | None:
        s = self.state.c
        with self.connect() as conn:
            return conn.execute(select(s.data).where(s.entity_type == entity_type,
                                                     s.entity_id == entity_id)).scalar()
