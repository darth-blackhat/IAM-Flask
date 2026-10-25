"""Record of what the producer asked for and what has been applied in OpenIAM.

people.assignments / statuses / employment_target are the producer's desired state.
people.employment / enabled and the memberships table are what OpenIAM has been told,
so a failed step is simply retried on the next event for that person.
"""

import time
from dataclasses import dataclass, field

from typing import Any

from sqlalchemy import delete, func, insert, select

from ..db import Database


@dataclass
class Person:
    employee_id: str
    user_id: str
    employment_target: str = "active"   # active | leave | terminated
    employment: str = "active"
    enabled: bool = True
    # kind -> names the producer assigned directly
    assignments: dict[str, list[str]] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)


class ProducerStore:
    def __init__(self, db: Database):
        self.db = db
        t = db.tables
        self.people = t.producer_people
        self.memberships_t = t.producer_memberships
        self.directory = t.producer_directory
        self.activity = t.producer_activity
        self.processed_t = t.producer_processed

    def get_person(self, employee_id: str) -> Person | None:
        p = self.people.c
        with self.db.begin() as conn:
            r = conn.execute(select(self.people).where(p.employee_id == employee_id)).first()
        if r is None:
            return None
        return Person(r.employee_id, r.user_id, r.employment_target, r.employment, r.enabled,
                      r.assignments, r.statuses)

    def save_person(self, person: Person) -> None:
        with self.db.begin() as conn:
            self.db.upsert(conn, self.people, {
                "employee_id": person.employee_id, "user_id": person.user_id,
                "employment_target": person.employment_target, "employment": person.employment,
                "enabled": person.enabled, "assignments": person.assignments,
                "statuses": person.statuses, "updated_at": time.time()}, keys=["employee_id"])

    def memberships(self, employee_id: str, kind: str) -> set[str]:
        m = self.memberships_t.c
        with self.db.begin() as conn:
            rows = conn.execute(select(m.object_id).where(m.employee_id == employee_id, m.kind == kind))
            return {r.object_id for r in rows}

    def add_memberships(self, employee_id: str, kind: str, ids: set[str]) -> None:
        with self.db.begin() as conn:
            self.db.upsert(conn, self.memberships_t,
                           [{"employee_id": employee_id, "kind": kind, "object_id": i} for i in sorted(ids)],
                           keys=["employee_id", "kind", "object_id"], update=False)

    def remove_memberships(self, employee_id: str, kind: str, ids: set[str]) -> None:
        m = self.memberships_t.c
        with self.db.begin() as conn:
            conn.execute(delete(self.memberships_t).where(
                m.employee_id == employee_id, m.kind == kind, m.object_id.in_(ids)))

    def lookup(self, kind: str, name: str) -> str | None:
        d = self.directory.c
        with self.db.begin() as conn:
            return conn.execute(select(d.object_id).where(d.kind == kind, d.name == name)).scalar()

    def remember(self, kind: str, name: str, object_id: str) -> None:
        with self.db.begin() as conn:
            self.db.upsert(conn, self.directory, {"kind": kind, "name": name, "object_id": object_id},
                           keys=["kind", "name"])

    def processed(self, event_id: str) -> dict | None:
        p = self.processed_t.c
        with self.db.begin() as conn:
            return conn.execute(select(p.result).where(p.event_id == event_id)).scalar()

    def mark_processed(self, event_id: str, result: dict) -> None:
        with self.db.begin() as conn:
            self.db.upsert(conn, self.processed_t,
                           {"event_id": event_id, "result": result, "at": time.time()},
                           keys=["event_id"])

    def name_for(self, kind: str, object_id: str) -> str | None:
        d = self.directory.c
        with self.db.begin() as conn:
            return conn.execute(select(d.name).where(d.kind == kind, d.object_id == object_id)
                                .limit(1)).scalar()

    # ---- activity log (shown by the web UI) ---------------------------------

    def record_activity(self, result: dict[str, Any]) -> None:
        with self.db.begin() as conn:
            conn.execute(insert(self.activity).values(
                at=time.time(), employee_id=result["employee_id"], event_type=result["type"],
                event_id=result.get("event_id"), ok=result["ok"],
                duplicate=result.get("duplicate", False), user_id=result.get("user_id"),
                error=result.get("error"), result=result))

    def activity_page(self, *, employee_id: str | None = None, event_type: str | None = None,
                      ok: bool | None = None, limit: int = 100,
                      before_id: int | None = None) -> list[dict[str, Any]]:
        a = self.activity.c
        q = select(self.activity).order_by(a.id.desc()).limit(limit)
        if employee_id:
            q = q.where(a.employee_id == employee_id)
        if event_type:
            q = q.where(a.event_type == event_type)
        if ok is not None:
            q = q.where(a.ok.is_(ok))
        if before_id:
            q = q.where(a.id < before_id)
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]

    def activity_entry(self, entry_id: int) -> dict[str, Any] | None:
        with self.db.begin() as conn:
            r = conn.execute(select(self.activity).where(self.activity.c.id == entry_id)).first()
            return dict(r._mapping) if r else None

    def activity_stats(self, since: float) -> dict[str, int]:
        a = self.activity.c
        with self.db.begin() as conn:
            rows = conn.execute(select(a.ok, func.count()).where(a.at >= since).group_by(a.ok))
            counts = {bool(ok): n for ok, n in rows}
        return {"ok": counts.get(True, 0), "failed": counts.get(False, 0)}

    def attribution(self, user_id: str, since: float) -> dict[str, Any] | None:
        """What producer events did to this OpenIAM user since `since` (None: nothing)."""
        a = self.activity.c
        with self.db.begin() as conn:
            rows = conn.execute(select(a.event_id, a.result).where(
                a.user_id == user_id, a.ok.is_(True), a.duplicate.is_(False), a.at >= since)).all()
        if not rows:
            return None
        fields: set[str] = set()
        for r in rows:
            fields.update(r.result.get("fields_set") or [])
        return {"fields": sorted(fields),
                "created": any("user created" in (r.result.get("actions") or []) for r in rows),
                "state_changed": any(r.result.get("state_changed") for r in rows),
                "event_ids": [r.event_id for r in rows if r.event_id]}
