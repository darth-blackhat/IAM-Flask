"""CSV reports, on demand (web UI) or on a schedule (written by the producer service into
REPORTS_FOLDER; a notification says where)."""

import os
import time
from pathlib import Path
from typing import Any

from sqlalchemy import insert, select, update

from .db import Database
from .governance import Governance, report_csv
from .insights import Insights

REPORTS = {
    "users": "Users (OpenIAM snapshot)",
    "entitlements": "Who has what: every group, role and organization membership",
    "sod-violations": "Segregation-of-duties violations",
    "certifications": "Access certification decisions",
    "requests": "Directory requests and approvals",
    "orphans": "Orphan accounts: OpenIAM users with no HR record",
    "dormant": "Dormant accounts: no sign-in for 90 days (or never)",
    "role-candidates": "Role mining: group / role combinations many people share",
    "peer-outliers": "Access few of a person's peers have",
    "time-limited": "Time-limited access still active",
}
USER_FIELDS = ("employeeId", "firstName", "lastName", "login", "email", "title", "domain",
               "userStatus", "status", "id")
SCHEDULE_EVERY = {"daily": 86400, "weekly": 7 * 86400}


def report_rows(db: Database, name: str) -> list[dict[str, Any]]:
    from .directory import TimedGrants
    from .operator import OperatorRequests
    from .sync.store import Store
    gov, ins = Governance(db), Insights(db)
    if name == "users":
        return [{k: rec.get(k) for k in USER_FIELDS} for rec in Store(db).snapshot("user", 0, 100000)]
    if name == "entitlements":
        return [{"employee_id": e, "kind": k, "name": n, "source": src}
                for (e, k, n), src in sorted(gov.entitlements().items())]
    if name == "sod-violations":
        return gov.violations()
    if name == "certifications":
        return [{"campaign": c["name"], "campaign_id": c["id"], "employee_id": i["employee_id"], "kind": i["kind"],
                 "name": i["object_name"], "source": i["source"], "decision": i["decision"] or "pending",
                 "decided_by": i["decided_by"], "note": i["note"], "revocation_request": i["request_id"]}
                for c in gov.campaigns() for i in gov.items(c["id"])]
    if name == "requests":
        return [{"id": r["id"], "action": r["action"], "asked_by": r["requested_by"], "status": r["status"],
                 "approvals": ", ".join(a["by"] for a in r["approvals"] or []), "decided_by": r["decided_by"],
                 "decision_note": r["decision_note"], **{k: v for k, v in (r["params"] or {}).items() if k != "items"},
                 "rows": len((r["params"] or {}).get("items") or []) or None}
                for r in OperatorRequests(db).page("producer", 10000) if r["action"].startswith("directory")]
    if name == "orphans":
        return ins.orphans()
    if name == "dormant":
        return ins.dormant()
    if name == "role-candidates":
        return [{"users": c["users"], "size": c["size"], "entitlements": "; ".join(c["entitlements"])}
                for c in ins.role_candidates()]
    if name == "peer-outliers":
        return ins.peer_outliers()
    if name == "time-limited":
        return [{"ends": time.strftime("%Y-%m-%d", time.gmtime(g["expires_at"])), "member": g["params"].get("member"),
                 "kind": g["params"].get("kind"), "name": g["params"].get("name"),
                 "jira_ticket": g["params"].get("jira_ticket"), "request": g["request_id"]}
                for g in TimedGrants(db).active()]
    raise KeyError(name)


class ReportSchedules:
    def __init__(self, db: Database):
        self.db, self.t = db, db.tables.report_schedules

    def list(self) -> list[dict[str, Any]]:
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(select(self.t).order_by(self.t.c.id))]

    def add(self, report: str, every: str, created_by: str) -> int:
        if report not in REPORTS or every not in SCHEDULE_EVERY:
            raise ValueError("unknown report or interval")
        with self.db.begin() as conn:
            return conn.execute(insert(self.t).values(report=report, every=every, enabled=True,
                                                      created_by=created_by, created_at=time.time())).inserted_primary_key[0]

    def set_enabled(self, sid: int, enabled: bool) -> bool:
        with self.db.begin() as conn:
            return bool(conn.execute(update(self.t).where(self.t.c.id == sid).values(enabled=enabled)).rowcount)

    def run_due(self, folder: str, now: float | None = None) -> list[str]:
        """Write every due report as CSV (atomically) into `folder`. Returns the files."""
        from .notify import Notifications
        now = now or time.time()
        written = []
        for s in self.list():
            if not s["enabled"] or (s["last_run_at"] and now - s["last_run_at"] < SCHEDULE_EVERY[s["every"]]):
                continue
            dest = Path(folder)
            dest.mkdir(parents=True, exist_ok=True)
            rows = report_rows(self.db, s["report"])
            path = dest / f"backend-iam-{s['report']}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))}.csv"
            tmp = path.with_suffix(".csv.partial")
            tmp.write_text(report_csv(rows), encoding="utf-8")
            os.replace(tmp, path)
            with self.db.begin() as conn:
                conn.execute(update(self.t).where(self.t.c.id == s["id"]).values(last_run_at=now, last_file=str(path)))
            Notifications(self.db).add("report.scheduled", f"Report ready: {REPORTS[s['report']]}",
                                       f"{len(rows)} row(s) written to {path}", {"report": s["report"], "file": str(path)})
            written.append(str(path))
        return written
