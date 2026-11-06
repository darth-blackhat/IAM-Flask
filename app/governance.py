"""Identity governance on the producer site: who has what, toxic combinations, reviews.

- Entitlements: every (employee, kind, object) known here, from what the producer granted
  and from the OpenIAM snapshot (change detection), so access granted directly in OpenIAM
  is covered too.
- Segregation of duties (SoD): a policy names two entitlements nobody may hold together.
  Directory requests that would create a toxic combination are refused when asked for and
  again when approved; current violations are reported.
- Access certification: a campaign lists entitlements for review. Each is certified or
  revoked; a revocation becomes a normal directory request, so it still needs a second
  person's approval before anything changes in OpenIAM or AD.
- Reports: CSV, with spreadsheet formula injection neutralised.
"""

import csv
import io
import json
import time
from typing import Any, Iterable

from sqlalchemy import func, insert, select, update

from .db import Database

KINDS = ("group", "role", "organization")
# OpenIAM snapshot field -> kind, for entitlement lists carried on user records.
SNAPSHOT_FIELDS = {"groups": "group", "memberOf": "group", "roles": "role",
                   "organizations": "organization", "affiliations": "organization"}
MAX_NAME = 500


class GovernanceError(ValueError):
    pass


Entitlement = tuple[str, str, str]      # (employee_id, kind, object name)


def _names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out = []
    for x in value:
        name = x.get("name") if isinstance(x, dict) else x
        if isinstance(name, (str, int)) and str(name):
            out.append(str(name))
    return out


class Governance:
    def __init__(self, db: Database):
        self.db, self.t = db, db.tables

    # ---- entitlements --------------------------------------------------------

    def entitlements(self) -> dict[Entitlement, str]:
        """(employee_id, kind, name) -> source ("producer" wins over "openiam")."""
        out: dict[Entitlement, str] = {}
        s = self.t.sync_entity_state.c
        with self.db.begin() as conn:
            for (data,) in conn.execute(select(s.data).where(s.entity_type == "user")):
                eid = str((data or {}).get("employeeId") or "")
                if not eid:
                    continue
                for field, kind in SNAPSHOT_FIELDS.items():
                    for name in _names(data.get(field)):
                        out[(eid, kind, name)] = "openiam"
            m, d = self.t.producer_memberships.c, self.t.producer_directory.c
            rows = conn.execute(select(m.employee_id, m.kind, m.object_id, d.name)
                                .select_from(self.t.producer_memberships.outerjoin(
                                    self.t.producer_directory,
                                    (d.kind == m.kind) & (d.object_id == m.object_id))))
            for eid, kind, object_id, name in rows:
                out[(eid, kind, name or object_id)] = "producer"
        return out

    def of_user(self, employee_id: str) -> set[tuple[str, str]]:
        return {(k, n) for (e, k, n) in self.entitlements() if e == employee_id}

    # ---- segregation of duties ----------------------------------------------

    def policies(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        p = self.t.sod_policies
        q = select(p).order_by(p.c.name)
        if enabled_only:
            q = q.where(p.c.enabled.is_(True))
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]

    def add_policy(self, name: str, left: tuple[str, str], right: tuple[str, str],
                   created_by: str, description: str | None = None) -> int:
        name = (name or "").strip()
        sides = [(k, (n or "").strip()) for k, n in (left, right)]
        if not name or len(name) > 200:
            raise GovernanceError("a policy needs a name (at most 200 characters)")
        for kind, obj in sides:
            if kind not in KINDS:
                raise GovernanceError(f"kind must be one of {KINDS}")
            if not obj or len(obj) > MAX_NAME or any(ord(c) < 32 for c in obj):
                raise GovernanceError("each side needs a valid name")
        if sides[0] == sides[1]:
            raise GovernanceError("the two sides must differ")
        if any(p["name"] == name for p in self.policies()):
            raise GovernanceError(f"a policy named {name!r} already exists")
        with self.db.begin() as conn:
            return conn.execute(insert(self.t.sod_policies).values(
                name=name, description=(description or "").strip()[:2000] or None,
                left_kind=sides[0][0], left_name=sides[0][1],
                right_kind=sides[1][0], right_name=sides[1][1], enabled=True,
                created_by=created_by, created_at=time.time())).inserted_primary_key[0]

    def set_policy_enabled(self, policy_id: int, enabled: bool) -> bool:
        p = self.t.sod_policies
        with self.db.begin() as conn:
            return bool(conn.execute(update(p).where(p.c.id == policy_id)
                                     .values(enabled=enabled)).rowcount)

    @staticmethod
    def _conflicts(held: set[tuple[str, str]], policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [p for p in policies
                if (p["left_kind"], p["left_name"]) in held and (p["right_kind"], p["right_name"]) in held]

    def violations(self) -> list[dict[str, Any]]:
        policies = self.policies(enabled_only=True)
        if not policies:
            return []
        by_user: dict[str, set[tuple[str, str]]] = {}
        for (eid, kind, name) in self.entitlements():
            by_user.setdefault(eid, set()).add((kind, name))
        return [{"employee_id": eid, "policy": p["name"], "policy_id": p["id"],
                 "left": f"{p['left_kind']}:{p['left_name']}",
                 "right": f"{p['right_kind']}:{p['right_name']}"}
                for eid, held in sorted(by_user.items()) for p in self._conflicts(held, policies)]

    @staticmethod
    def _changes(params: dict[str, Any]) -> list[tuple[str, str, str, bool]]:
        """(employee, kind, name, added?) a single directory request makes."""
        if params.get("member_kind") == "user" and params.get("op") in ("add_member", "remove_member"):
            return [(params.get("member"), params.get("kind"), params.get("name"), params["op"] == "add_member")]
        if params.get("kind") == "user" and params.get("op") == "create":
            return [(params.get("name"), k, n, True)
                    for field, k in (("groups", "group"), ("roles", "role"), ("organizations", "organization"))
                    for n in params.get(field) or []]
        return []

    def check_request(self, params: dict[str, Any]) -> list[str]:
        """Policies a directory request (or a whole batch, rows taken together) would newly
        break. Empty = allowed."""
        policies = self.policies(enabled_only=True)
        if not policies:
            return []
        rows = params.get("items") if params.get("items") is not None else [params]
        changes = [c for row in rows for c in self._changes(row)]
        out = []
        for employee in sorted({c[0] for c in changes if c[0]}):
            before = self.of_user(employee)
            after = set(before)
            for e, kind, name, added in changes:
                if e == employee:
                    (after.add if added else after.discard)((kind, name))
            old = {p["id"] for p in self._conflicts(before, policies)}
            out += [f"{employee}: {p['name']}: {p['left_kind']} {p['left_name']} + {p['right_kind']} {p['right_name']}"
                    for p in self._conflicts(after, policies) if p["id"] not in old]
        return out

    # ---- access certification -------------------------------------------------

    def campaigns(self) -> list[dict[str, Any]]:
        c, i = self.t.cert_campaigns, self.t.cert_items.c
        with self.db.begin() as conn:
            rows = [dict(r._mapping) for r in conn.execute(select(c).order_by(c.c.id.desc()))]
            counts = {(cid, dec): n for cid, dec, n in conn.execute(
                select(i.campaign_id, i.decision, func.count()).group_by(i.campaign_id, i.decision))}
        for r in rows:
            r["total"] = sum(n for (cid, _), n in counts.items() if cid == r["id"])
            r["certified"] = counts.get((r["id"], "certify"), 0)
            r["revoked"] = counts.get((r["id"], "revoke"), 0)
            r["open_items"] = r["total"] - r["certified"] - r["revoked"]
        return rows

    def campaign(self, campaign_id: int) -> dict[str, Any] | None:
        return next((c for c in self.campaigns() if c["id"] == campaign_id), None)

    def start_campaign(self, name: str, created_by: str, *, scope_kind: str | None = None,
                       scope_name: str | None = None, due_days: int | None = None) -> int:
        name = (name or "").strip()
        if not name or len(name) > 200:
            raise GovernanceError("a campaign needs a name (at most 200 characters)")
        if scope_kind and scope_kind not in KINDS:
            raise GovernanceError(f"scope must be one of {KINDS}")
        scope_name = (scope_name or "").strip() or None
        items = [(e, k, n, src) for (e, k, n), src in sorted(self.entitlements().items())
                 if (not scope_kind or k == scope_kind) and (not scope_name or n == scope_name)]
        if not items:
            raise GovernanceError("nothing to review in that scope")
        now = time.time()
        with self.db.begin() as conn:
            cid = conn.execute(insert(self.t.cert_campaigns).values(
                name=name, scope_kind=scope_kind or None, scope_name=scope_name, status="open",
                created_by=created_by, created_at=now,
                due_at=now + due_days * 86400 if due_days else None)).inserted_primary_key[0]
            conn.execute(insert(self.t.cert_items), [
                {"campaign_id": cid, "employee_id": e, "kind": k, "object_name": n, "source": src}
                for e, k, n, src in items])
        return cid

    def items(self, campaign_id: int) -> list[dict[str, Any]]:
        i = self.t.cert_items
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(i).where(i.c.campaign_id == campaign_id).order_by(i.c.employee_id, i.c.kind,
                                                                         i.c.object_name))]

    def decide_item(self, item_id: int, decision: str, decided_by: str,
                    note: str | None = None, request_id: int | None = None) -> dict[str, Any]:
        if decision not in ("certify", "revoke"):
            raise GovernanceError("decision is certify or revoke")
        i, c = self.t.cert_items, self.t.cert_campaigns
        with self.db.begin() as conn:
            row = conn.execute(select(i, c.c.status).join(c, c.c.id == i.c.campaign_id)
                               .where(i.c.id == item_id)).first()
            if row is None:
                raise GovernanceError("no such review item")
            if row.status != "open":
                raise GovernanceError("this campaign is closed")
            if row.decision:
                raise GovernanceError("already decided")
            n = conn.execute(update(i).where(i.c.id == item_id, i.c.decision.is_(None)).values(
                decision=decision, decided_by=decided_by, decided_at=time.time(),
                note=(note or "").strip()[:1000] or None, request_id=request_id)).rowcount
            if not n:
                raise GovernanceError("decided by someone else just now")
            return dict(row._mapping)

    def item(self, item_id: int) -> dict[str, Any] | None:
        i, c = self.t.cert_items, self.t.cert_campaigns
        with self.db.begin() as conn:
            row = conn.execute(select(i, c.c.status).join(c, c.c.id == i.c.campaign_id)
                               .where(i.c.id == item_id)).first()
            return dict(row._mapping) if row else None

    def overdue_campaigns(self) -> list[dict[str, Any]]:
        """Open campaigns past their due date not yet reported; marks them reported."""
        c, now = self.t.cert_campaigns, time.time()
        due = [x for x in self.campaigns() if x["status"] == "open" and x["due_at"] and x["due_at"] < now
               and not x["overdue_notified_at"]]
        if due:
            with self.db.begin() as conn:
                conn.execute(update(c).where(c.c.id.in_([x["id"] for x in due])).values(overdue_notified_at=now))
        return due

    def close_campaign(self, campaign_id: int, closed_by: str) -> None:
        c = self.t.cert_campaigns
        with self.db.begin() as conn:
            n = conn.execute(update(c).where(c.c.id == campaign_id, c.c.status == "open")
                             .values(status="closed", closed_by=closed_by, closed_at=time.time())).rowcount
        if not n:
            raise GovernanceError("campaign is not open")


# ---- reports ---------------------------------------------------------------------------

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(v: Any) -> Any:
    if isinstance(v, (dict, list)):
        v = json.dumps(v, sort_keys=True, default=str)
    if isinstance(v, str) and v.startswith(FORMULA_START):
        return "'" + v     # a spreadsheet must show it as text, never run it
    return v


def report_csv(rows: Iterable[dict[str, Any]]) -> str:
    rows = list(rows)
    columns = list(dict.fromkeys(k for row in rows for k in row))
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=columns or ["empty"], extrasaction="ignore")
    w.writeheader()
    for row in rows:
        w.writerow({k: _cell(v) for k, v in row.items()})
    return out.getvalue()
