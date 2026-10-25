"""What the consumer received and what it applied to the remote OpenIAM."""

import time
from typing import Any

from sqlalchemy import delete, func, insert, select, update

from ..db import Database


class ConsumerStore:
    def __init__(self, db: Database):
        self.db = db
        t = db.tables
        self.plans = t.ad_plans
        self.files = t.consumer_files
        self.records = t.consumer_records
        self.actions = t.consumer_actions
        self.domains = t.consumer_domains

    # ---- files --------------------------------------------------------------

    def file(self, sha: str) -> dict[str, Any] | None:
        with self.db.begin() as conn:
            r = conn.execute(select(self.files).where(self.files.c.sha256 == sha)).first()
            return dict(r._mapping) if r else None

    def save_file(self, **row: Any) -> None:
        with self.db.begin() as conn:
            self.db.upsert(conn, self.files, row, keys=["sha256"])

    def update_file(self, sha: str, **values: Any) -> None:
        with self.db.begin() as conn:
            conn.execute(update(self.files).where(self.files.c.sha256 == sha).values(**values))

    def recent_files(self, limit: int = 100, status: str | None = None,
                     domain: str | None = None) -> list[dict[str, Any]]:
        f = self.files.c
        q = select(self.files).order_by(f.received_at.desc()).limit(limit)
        if status:
            q = q.where(f.status == status)
        if domain:
            q = q.where(f.domain == domain)
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]

    # ---- per-record state ---------------------------------------------------

    def records_for(self, domain: str, entity: str) -> dict[str, dict[str, Any]]:
        r = self.records.c
        with self.db.begin() as conn:
            rows = conn.execute(select(self.records).where(r.domain == domain, r.entity == entity))
            return {row.source_id: dict(row._mapping) for row in rows}

    def save_record(self, domain: str, entity: str, source_id: str, hash_: str,
                    remote_id: str | None, granted: dict | None = None) -> None:
        with self.db.begin() as conn:
            self.db.upsert(conn, self.records, {
                "domain": domain, "entity": entity, "source_id": source_id, "hash": hash_,
                "remote_id": remote_id, "granted": granted, "updated_at": time.time()},
                keys=["domain", "entity", "source_id"])

    def drop_record(self, domain: str, entity: str, source_id: str) -> None:
        r = self.records.c
        with self.db.begin() as conn:
            conn.execute(delete(self.records).where(r.domain == domain, r.entity == entity,
                                                    r.source_id == source_id))

    # ---- domains ------------------------------------------------------------

    def domain_state(self, domain: str) -> dict[str, Any] | None:
        with self.db.begin() as conn:
            r = conn.execute(select(self.domains).where(self.domains.c.domain == domain)).first()
            return dict(r._mapping) if r else None

    def save_domain(self, domain: str, generated_at: str, sha: str, records: int) -> None:
        with self.db.begin() as conn:
            self.db.upsert(conn, self.domains, {
                "domain": domain, "last_generated_at": generated_at, "last_file": sha,
                "records": records, "updated_at": time.time()}, keys=["domain"])

    def all_domains(self) -> list[dict[str, Any]]:
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in
                    conn.execute(select(self.domains).order_by(self.domains.c.domain))]

    # ---- actions log --------------------------------------------------------

    def log_action(self, file_sha: str | None, domain: str | None, entity: str | None,
                   source_id: str | None, action: str, ok: bool, detail: str | None = None) -> None:
        with self.db.begin() as conn:
            conn.execute(insert(self.actions).values(
                at=time.time(), file_sha256=file_sha, domain=domain, entity=entity,
                source_id=source_id, action=action, ok=ok, detail=detail))

    def actions_page(self, *, file_sha: str | None = None, ok: bool | None = None,
                     limit: int = 200, before_id: int | None = None) -> list[dict[str, Any]]:
        a = self.actions.c
        q = select(self.actions).order_by(a.id.desc()).limit(limit)
        if file_sha:
            q = q.where(a.file_sha256 == file_sha)
        if ok is not None:
            q = q.where(a.ok.is_(ok))
        if before_id:
            q = q.where(a.id < before_id)
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]

    def file_stats(self, since: float) -> dict[str, int]:
        f = self.files.c
        with self.db.begin() as conn:
            rows = conn.execute(select(f.status, func.count()).where(f.received_at >= since)
                                .group_by(f.status))
            return {s: n for s, n in rows}

    # ---- AD plans -----------------------------------------------------------

    def save_plan(self, **row: Any) -> int:
        with self.db.begin() as conn:
            return conn.execute(insert(self.plans).values(at=time.time(), **row)).inserted_primary_key[0]

    def update_plan(self, plan_id: int, **values: Any) -> None:
        with self.db.begin() as conn:
            conn.execute(update(self.plans).where(self.plans.c.id == plan_id).values(**values))

    def plan(self, plan_id: int) -> dict[str, Any] | None:
        with self.db.begin() as conn:
            r = conn.execute(select(self.plans).where(self.plans.c.id == plan_id)).first()
            return dict(r._mapping) if r else None

    def plans_page(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        q = select(self.plans).order_by(self.plans.c.id.desc()).limit(limit)
        if status:
            q = q.where(self.plans.c.status == status)
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]

    # ---- AD change watch ----------------------------------------------------

    def watch_state(self) -> dict[str, dict[str, Any]]:
        t = self.db.tables.ad_watch_state
        with self.db.begin() as conn:
            return {r.dn.lower(): dict(r._mapping) for r in conn.execute(select(t))}

    def watch_put(self, rows: list[tuple]) -> None:
        if not rows:
            return
        t = self.db.tables.ad_watch_state
        now = time.time()
        with self.db.begin() as conn:
            self.db.upsert(conn, t, [{"dn": dn, "object_class": cls, "attrs": attrs, "hash": h,
                                      "updated_at": now, "updated_by": by}
                                     for dn, cls, attrs, h, by in rows], keys=["dn"])

    def watch_delete(self, dns: list[str]) -> None:
        if dns:
            t = self.db.tables.ad_watch_state
            with self.db.begin() as conn:
                conn.execute(delete(t).where(t.c.dn.in_(dns)))

    def add_alerts(self, alerts: list[dict[str, Any]]) -> None:
        t = self.db.tables.ad_change_alerts
        now = time.time()
        with self.db.begin() as conn:
            conn.execute(insert(t), [{"at": now, **a} for a in alerts])

    def alerts_page(self, *, open_only: bool = False, severity: str | None = None,
                    limit: int = 200) -> list[dict[str, Any]]:
        t = self.db.tables.ad_change_alerts
        q = select(t).order_by(t.c.id.desc()).limit(limit)
        if open_only:
            q = q.where(t.c.acknowledged_at.is_(None))
        if severity:
            q = q.where(t.c.severity == severity)
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]

    def acknowledge(self, alert_id: int, by: str, note: str | None) -> bool:
        t = self.db.tables.ad_change_alerts
        with self.db.begin() as conn:
            return conn.execute(update(t).where(t.c.id == alert_id, t.c.acknowledged_at.is_(None))
                                .values(acknowledged_by=by, acknowledged_at=time.time(),
                                        note=(note or "")[:1000] or None)).rowcount > 0
