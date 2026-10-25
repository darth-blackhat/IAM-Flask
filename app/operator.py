"""Operator requests: the web UI asks, the producer / consumer service does.

The web apps hold no OpenIAM or AD credentials. A button press stores a request row; the
service that owns the work claims it (atomically, so two instances never run the same
request), runs it and stores the result, which the web shows.
"""

import time
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import insert, select, update

from .db import Database
from .logs import logger

Handler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]

ACTIONS = {
    "producer": {
        "sync_run": "Run change detection now",
        "sync_run_allow_mass_delete": "Run change detection, allowing a blocked mass delete",
        "export": "Export changed domains now",
        "export_force": "Export every domain now",
        "deliver": "Deliver pending instructions now",
    },
    "consumer": {
        "scan": "Scan the inbox now",
        "reprocess": "Apply an already received zip again",
        "drift": "Run a drift report for a domain",
        "ad_approve": "Apply an approved AD plan",
        "ad_watch": "Check AD for changes made outside the consumer now",
    },
}


class OperatorRequests:
    def __init__(self, db: Database):
        self.db, self.t = db, db.tables.operator_requests

    def create(self, service: str, action: str, params: dict[str, Any], requested_by: str) -> int:
        if action not in ACTIONS.get(service, {}):
            raise ValueError(f"unknown action {service}/{action}")
        with self.db.begin() as conn:
            return conn.execute(insert(self.t).values(
                at=time.time(), requested_by=requested_by, service=service, action=action,
                params=params, status="pending")).inserted_primary_key[0]

    def _claim(self, service: str) -> dict[str, Any] | None:
        c = self.t.c
        with self.db.begin() as conn:
            row = conn.execute(select(self.t).where(c.service == service, c.status == "pending")
                               .order_by(c.id).limit(1)).first()
            if row is None:
                return None
            claimed = conn.execute(update(self.t).where(c.id == row.id, c.status == "pending")
                                   .values(status="running", started_at=time.time())).rowcount
            return dict(row._mapping) if claimed else None

    def _finish(self, request_id: int, ok: bool, result: dict[str, Any]) -> None:
        with self.db.begin() as conn:
            conn.execute(update(self.t).where(self.t.c.id == request_id).values(
                status="done" if ok else "failed", finished_at=time.time(), result=result))

    async def run_pending(self, service: str, handlers: dict[str, Handler]) -> int:
        """Run every pending request for `service`. Returns how many ran."""
        n = 0
        while (req := self._claim(service)) is not None:
            n += 1
            handler = handlers.get(req["action"])
            try:
                if handler is None:
                    raise RuntimeError(f"this service cannot run {req['action']}")
                result, ok = await handler(req["params"] or {}), True
            except Exception as e:
                result, ok = {"error": f"{type(e).__name__}: {e}"}, False
            self._finish(req["id"], ok, result)
            logger.bind(request_id=req["id"], requested_by=req["requested_by"]).info(
                "operator request {} {} by {}: {}", req["id"], req["action"], req["requested_by"],
                "done" if ok else result["error"])
        return n

    def page(self, service: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        q = select(self.t).order_by(self.t.c.id.desc()).limit(limit)
        if service:
            q = q.where(self.t.c.service == service)
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]
