"""Operator requests: the web UI asks, the producer / consumer service does.

The web apps hold no OpenIAM or AD credentials. A button press stores a request row; the
service that owns the work claims it (atomically, so two instances never run the same
request), runs it and stores the result, which the web shows.
"""

import time
from collections.abc import Awaitable, Callable
from typing import Any

import threading

from sqlalchemy import func, insert, select, text, update

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
        "directory": "Change a user, group, organization or role",
        "directory_batch": "Several directory changes approved together (bulk import, mover)",
    },
    "consumer": {
        "scan": "Scan the inbox now",
        "reprocess": "Apply an already received zip again",
        "drift": "Run a drift report for a domain",
        "ad_approve": "Apply an approved AD plan",
        "ad_watch": "Check AD for changes made outside the consumer now",
    },
}


# Actions that wait in the database until a second person approves them: nothing is
# written to OpenIAM and no AD instruction is queued before that.
NEEDS_APPROVAL = {("producer", "directory"), ("producer", "directory_batch")}
_DECIDE_LOCK = threading.Lock()
_DECIDE_PG_LOCK = 0x62696170   # pg_advisory_xact_lock(key, request id)

# Changes that remove things, or many at once, need more than one approver.
DESTRUCTIVE_OPS = {"delete"}


def approvals_needed(params: dict[str, Any], destructive: int = 2, bulk_over: int = 10) -> int:
    items = params.get("items")
    if items is not None:      # a batch: destructive if any row is, or if it is large
        if len(items) > bulk_over or any(i.get("op") in DESTRUCTIVE_OPS for i in items):
            return max(1, destructive)
        return 1
    if params.get("op") in DESTRUCTIVE_OPS:
        return max(1, destructive)
    return 1


def in_scope(scope: list[str] | None, params: dict[str, Any]) -> bool:
    """May an approver limited to `scope` (domains / organizations) decide this request?
    No scope = everything. A request that names no domain or organization needs an
    approver without a scope."""
    if not scope:
        return True
    if params.get("items") is not None:
        return bool(params["items"]) and all(in_scope(scope, i) for i in params["items"])
    wanted = {s.lower() for s in scope}
    touched = {str(params[k]).lower() for k in ("domain",) if params.get(k)}
    if params.get("kind") == "organization" and params.get("name"):
        touched.add(str(params["name"]).lower())
    return bool(touched) and touched <= wanted


class ApprovalError(ValueError):
    pass


class OperatorRequests:
    def __init__(self, db: Database):
        self.db, self.t = db, db.tables.operator_requests

    def create(self, service: str, action: str, params: dict[str, Any], requested_by: str,
               *, destructive_approvals: int = 2, bulk_over: int = 10,
               preapproved_by: str | None = None) -> int:
        """`preapproved_by`: only for system follow-ups of an already approved change (e.g. the
        removal at the end of time-limited access); it runs without a new approval."""
        if action not in ACTIONS.get(service, {}):
            raise ValueError(f"unknown action {service}/{action}")
        gated = (service, action) in NEEDS_APPROVAL and not preapproved_by
        now = time.time()
        with self.db.begin() as conn:
            return conn.execute(insert(self.t).values(
                at=now, requested_by=requested_by, service=service, action=action,
                params=params, status="awaiting_approval" if gated else "pending", approvals=[],
                required_approvals=approvals_needed(params, destructive_approvals, bulk_over) if gated else 0,
                **({"decided_by": preapproved_by, "decided_at": now} if preapproved_by else {}),
            )).inserted_primary_key[0]

    def get(self, request_id: int) -> dict[str, Any] | None:
        with self.db.begin() as conn:
            row = conn.execute(select(self.t).where(self.t.c.id == request_id)).first()
            return dict(row._mapping) if row else None

    def decide(self, request_id: int, approve: bool, decided_by: str, note: str | None = None) -> str:
        """Approve or reject an awaiting request. Returns the new status: "pending" (it runs),
        "awaiting_approval" (more approvers needed) or "rejected". Never your own request,
        and each approver counts once. One rejection is final. Decisions on one request are
        serialised (lock + re-read in the same transaction), so none is lost."""
        c, now = self.t.c, time.time()
        with _DECIDE_LOCK, self.db.begin() as conn:
            if self.db.is_postgres:
                conn.execute(text("SELECT pg_advisory_xact_lock(:k, :id)"),
                             {"k": _DECIDE_PG_LOCK, "id": int(request_id) % 2**31})
            row = conn.execute(select(self.t).where(c.id == request_id)).first()
            req = dict(row._mapping) if row else None
            if req is None or req["status"] != "awaiting_approval":
                raise ApprovalError(f"request {request_id} is not awaiting approval")
            if req["requested_by"] == decided_by:
                raise ApprovalError("a request must be approved or rejected by someone else")
            approvals = list(req["approvals"] or [])
            if any(a["by"] == decided_by for a in approvals):
                raise ApprovalError("you already approved this request; another person must approve it too")
            if approve:
                approvals.append({"by": decided_by, "at": now, "note": note or None})
                values: dict[str, Any] = {"approvals": approvals}
                if len(approvals) >= (req["required_approvals"] or 1):
                    values.update(status="pending", decided_by=", ".join(a["by"] for a in approvals),
                                  decided_at=now, decision_note=note or None)
            else:
                values = {"status": "rejected", "decided_by": decided_by, "decided_at": now,
                          "decision_note": note or None, "finished_at": now}
            conn.execute(update(self.t).where(c.id == request_id).values(**values))
        return values.get("status", "awaiting_approval")

    def awaiting(self, service: str) -> int:
        c = self.t.c
        with self.db.begin() as conn:
            return conn.execute(select(func.count()).select_from(self.t)
                                .where(c.service == service, c.status == "awaiting_approval")).scalar()

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
                params = dict(req["params"] or {})
                if req["action"].startswith("directory"):
                    params["request_id"] = req["id"]     # lets the change refer to its approval
                result, ok = await handler(params), True
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
