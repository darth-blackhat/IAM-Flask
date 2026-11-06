"""Insight pages of the producer UI: role mining and peer outliers, account hygiene, the
organization tree, self-service access requests, saved searches, scheduled reports."""

import time
from typing import Any

from flask import Flask, abort, flash, g, redirect, render_template, request
from pydantic import ValidationError

from ..directory import DirectoryRequest
from ..governance import Governance
from ..insights import Insights
from ..notify import Notifications
from ..operator import OperatorRequests
from ..reports import REPORTS, SCHEDULE_EVERY, ReportSchedules
from ..sync.store import Store

MAX_SAVED = 30


def register(app: Flask) -> None:
    ext = app.extensions["biam"]
    db, record, require_role, can = ext["db"], ext["record"], ext["require_role"], ext["can"]
    ins, gov, requests, notes = Insights(db), Governance(db), OperatorRequests(db), Notifications(db)
    schedules, snapshot, t = ReportSchedules(db), Store(db), db.tables.saved_searches

    # ---- insights ------------------------------------------------------------------

    @app.get("/governance/insights")
    def insights():
        try:
            min_users = max(2, min(50, int(request.args.get("min_users", "3"))))
        except ValueError:
            min_users = 3
        peer_field = request.args.get("peer") if request.args.get("peer") in ("title", "domain") else "title"
        return render_template("p_insights.html", candidates=ins.role_candidates(min_users=min_users),
                               outliers=ins.peer_outliers(peer_field=peer_field)[:200], orphans=ins.orphans()[:200],
                               dormant=ins.dormant()[:200], min_users=min_users, peer=peer_field)

    @app.get("/directory/tree")
    def org_tree():
        return render_template("p_tree.html", roots=ins.org_tree())

    # ---- self-service access requests --------------------------------------------------

    def _me_employee() -> str | None:
        return (g.user.get("employee_id") or "").strip() or None

    @app.route("/request-access", methods=["GET", "POST"])
    def request_access():
        """Anyone signed in asks for (or gives back) a group / role. A viewer can only ask for
        themselves (their linked employee id); operators can ask for others. Same rules as
        any change: Jira ticket, justification, SoD check, approval by someone else."""
        own = _me_employee()
        if request.method == "GET":
            names = sorted({str(r.get("name")) for k in ("group", "role") for r in snapshot.snapshot(k, 0, 5000)
                            if r.get("name")})
            return render_template("p_request_access.html", own=own, names=names, others=can("operator"))
        f = request.form
        member = (f.get("member") or "").strip()
        if not can("operator"):
            if not own:
                flash("Your web account is not linked to an employee id; ask an admin to link it.", "error")
                return redirect("/request-access")
            member = own                                  # viewers: only for themselves
        params = {"via": "openiam", "kind": f.get("kind") if f.get("kind") in ("group", "role") else "group",
                  "op": "remove_member" if f.get("op") == "remove" else "add_member", "name": f.get("name"),
                  "member_kind": "user", "member": member, "jira_ticket": f.get("jira_ticket"),
                  "reason": f.get("reason"), "expires_on": f.get("expires_on") or None,
                  "requested_by": g.user["username"]}
        try:
            req = DirectoryRequest.model_validate(params)
        except ValidationError as e:
            flash("Not sent: " + "; ".join(err["msg"].removeprefix("Value error, ") for err in e.errors()), "error")
            return redirect("/request-access")
        clean = req.model_dump(exclude_none=True, exclude_defaults=True)
        clean.update(via=req.via, kind=req.kind, op=req.op)
        if broken := gov.check_request(clean):
            record("sod.blocked", ok=False, target=f"{req.kind}:{req.name}", detail="; ".join(broken))
            notes.add("sod.blocked", f"Refused (segregation of duties): access request for {member}",
                      "; ".join(broken), {"jira_ticket": req.jira_ticket})
            flash("Not sent: it would break segregation of duties: " + "; ".join(broken), "error")
            return redirect("/request-access")
        rid = requests.create("producer", "directory", clean, f"web:{g.user['username']}",
                              destructive_approvals=ext["settings"].approvals_for_destructive)
        what = f"{'access to' if req.op == 'add_member' else 'removal from'} {req.kind} {req.name} for {member}"
        notes.add("request.awaiting_approval", f"Access request: {what}",
                  f"Request {rid} ({req.jira_ticket}) by {g.user['username']}.\nJustification: {req.reason}",
                  {"request_id": rid, "jira_ticket": req.jira_ticket})
        record("access.request", target=f"{req.kind}:{req.name}", detail=f"request {rid} for {member} [{req.jira_ticket}]")
        flash(f"Sent: request {rid}, {what}. An approver will decide.", "ok")
        return redirect("/request-access")

    # ---- saved searches ----------------------------------------------------------------

    def _mine() -> list[dict[str, Any]]:
        from sqlalchemy import select
        with db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(t).where(t.c.username == g.user["username"]).order_by(t.c.name))]

    @app.context_processor
    def _saved():
        from markupsafe import Markup
        return {"saved_searches": lambda: _mine() if getattr(g, "user", None) else [],
                "save_search_form": lambda: Markup(render_template("save_search.html"))}

    @app.post("/searches")
    def search_save():
        from sqlalchemy import insert
        name = (request.form.get("name") or "").strip()[:100]
        path = request.form.get("path") or ""
        # Only this UI's own list pages: never an external or protocol-relative URL.
        if not name or not path.startswith(("/directory?", "/producer?", "/governance/insights?")) or "//" in path:
            flash("Not saved: give it a name.", "error")
            return redirect(path if path.startswith("/") and not path.startswith("//") else "/directory")
        if len(_mine()) >= MAX_SAVED:
            flash(f"At most {MAX_SAVED} saved searches.", "error")
            return redirect(path)
        with db.begin() as conn:
            conn.execute(insert(t).values(username=g.user["username"], name=name, path=path[:1000],
                                          created_at=time.time()))
        flash(f"Saved search '{name}'.", "ok")
        return redirect(path)

    @app.post("/searches/<int:sid>/delete")
    def search_delete(sid: int):
        from sqlalchemy import delete
        with db.begin() as conn:            # only your own
            conn.execute(delete(t).where(t.c.id == sid, t.c.username == g.user["username"]))
        back = request.form.get("back") or "/directory"
        return redirect(back if back.startswith("/") and not back.startswith("//") else "/directory")

    # ---- scheduled reports -------------------------------------------------------------

    @app.post("/reports/schedules")
    @require_role("admin")
    def schedule_add():
        try:
            sid = schedules.add(request.form.get("report") or "", request.form.get("every") or "",
                                f"web:{g.user['username']}")
        except ValueError as e:
            flash(str(e), "error")
            return redirect("/reports")
        record("report.schedule", target=request.form.get("report"), detail=f"schedule {sid} {request.form.get('every')}")
        flash("Scheduled. The producer service writes it into the reports folder.", "ok")
        return redirect("/reports")

    @app.post("/reports/schedules/<int:sid>/<state>")
    @require_role("admin")
    def schedule_toggle(sid: int, state: str):
        if state not in ("enable", "disable"):
            abort(404)
        ok = schedules.set_enabled(sid, state == "enable")
        record(f"report.schedule_{state}", ok=ok, target=str(sid))
        return redirect("/reports")

    app.extensions["biam"]["report_schedules"] = schedules
    app.extensions["biam"]["schedule_every"] = SCHEDULE_EVERY
    app.extensions["biam"]["reports"] = REPORTS
