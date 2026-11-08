"""Governance and report pages of the producer UI.

SoD policies and campaigns are managed by admins; operators review campaign items and
download reports. A revocation is saved as a directory request, so it is applied only
after a second person approves it (Approvals).
"""

import time

from flask import Flask, Response, abort, flash, g, redirect, render_template, request
from pydantic import ValidationError

from ..directory import DirectoryRequest
from ..governance import KINDS, Governance, GovernanceError, report_csv
from ..reports import REPORTS, report_rows
from ..notify import Notifications
from ..operator import OperatorRequests

def register(app: Flask) -> None:
    ext = app.extensions["biam"]
    db, record, require_role = ext["db"], ext["record"], ext["require_role"]
    gov, requests = Governance(db), OperatorRequests(db)
    notes = Notifications(db)

    def who() -> str:
        return f"web:{g.user['username']}"

    # ---- overview, SoD ----------------------------------------------------------

    @app.get("/governance")
    def governance():
        from ..directory import TimedGrants
        return render_template("p_governance.html", policies=gov.policies(), violations=gov.violations(),
                               campaigns=gov.campaigns(), kinds=KINDS, grants=TimedGrants(db).active())

    @app.post("/governance/sod")
    @require_role("admin")
    def sod_add():
        f = request.form
        try:
            pid = gov.add_policy(f.get("name") or "", (f.get("left_kind") or "", f.get("left_name") or ""),
                                 (f.get("right_kind") or "", f.get("right_name") or ""), who(),
                                 f.get("description"))
        except GovernanceError as e:
            flash(f"Not added: {e}", "error")
            return redirect("/governance")
        record("sod.add", target=f.get("name"), detail=f"policy {pid}")
        flash("Policy added. New requests that would break it are refused.", "ok")
        return redirect("/governance")

    @app.post("/governance/sod/<int:policy_id>/<state>")
    @require_role("admin")
    def sod_toggle(policy_id: int, state: str):
        if state not in ("enable", "disable"):
            abort(404)
        ok = gov.set_policy_enabled(policy_id, state == "enable")
        record(f"sod.{state}", ok=ok, target=str(policy_id))
        return redirect("/governance")

    # ---- certification campaigns ------------------------------------------------

    @app.post("/governance/campaigns")
    @require_role("admin")
    def campaign_start():
        f = request.form
        days = f.get("due_days") or ""
        try:
            cid = gov.start_campaign(f.get("name") or "", who(), scope_kind=f.get("scope_kind") or None,
                                     scope_name=f.get("scope_name"),
                                     due_days=int(days) if days.isdigit() and 0 < int(days) <= 365 else None)
        except GovernanceError as e:
            flash(f"Not started: {e}", "error")
            return redirect("/governance")
        record("cert.start", target=str(cid), detail=f.get("name"))
        c = gov.campaign(cid)
        notes.add("campaign.started", f"Access review started: {c['name']}",
                  f"{c['total']} entitlement(s) to review" + (" (due " + time.strftime("%Y-%m-%d", time.gmtime(c["due_at"])) + ")" if c["due_at"] else "")
                  + f". Started by {g.user['username']}.", {"campaign_id": cid})
        return redirect(f"/governance/campaigns/{cid}")

    @app.get("/governance/campaigns/<int:campaign_id>")
    @require_role("operator")
    def campaign_view(campaign_id: int):
        c = gov.campaign(campaign_id) or abort(404)
        return render_template("p_campaign.html", c=c, items=gov.items(campaign_id))

    @app.post("/governance/items/<int:item_id>/<decision>")
    @require_role("operator")
    def item_decide(item_id: int, decision: str):
        if decision not in ("certify", "revoke"):
            abort(404)
        item = gov.item(item_id) or abort(404)
        note = (request.form.get("note") or "").strip()[:1000] or None
        back = f"/governance/campaigns/{item['campaign_id']}"
        request_id = None
        try:
            if item["decision"] or item["status"] != "open":
                raise GovernanceError("already decided, or the campaign is closed")
            if decision == "revoke":
                via = request.form.get("via") if request.form.get("via") in ("openiam", "ad") else "openiam"
                params = {"via": via, "kind": item["kind"], "op": "remove_member", "name": item["object_name"],
                          "member_kind": "user", "member": item["employee_id"],
                          "jira_ticket": request.form.get("jira_ticket") or "",
                          "reason": f"access certification #{item['campaign_id']}: {note or ''}".strip(),
                          "requested_by": g.user["username"]}
                try:   # same rules as any directory request: ticket + justification
                    checked = DirectoryRequest.model_validate({**params, "reason": note or ""})
                except ValidationError as e:
                    raise GovernanceError("Not revoked: " + "; ".join(
                        err["msg"].removeprefix("Value error, ") for err in e.errors())) from None
                params["jira_ticket"] = checked.jira_ticket
                request_id = requests.create("producer", "directory", params, who())
                notes.add("request.awaiting_approval",
                          f"Approval needed: remove {item['employee_id']} from {item['kind']} {item['object_name']}",
                          f"Request {request_id} ({checked.jira_ticket}) from access review #{item['campaign_id']}"
                          f" by {g.user['username']}.\nJustification: {note}",
                          {"request_id": request_id, "jira_ticket": checked.jira_ticket})
            gov.decide_item(item_id, decision, who(), note, request_id)
        except GovernanceError as e:
            flash(str(e), "error")
            return redirect(back)
        record(f"cert.{decision}", target=f"{item['employee_id']} {item['kind']}:{item['object_name']}",
               detail=f"item {item_id}" + (f", request {request_id}" if request_id else ""))
        if request_id:
            flash(f"Revoked: removal saved as request {request_id}; it runs after a second person approves it.",
                  "ok")
        return redirect(back)

    @app.post("/governance/campaigns/<int:campaign_id>/close")
    @require_role("admin")
    def campaign_close(campaign_id: int):
        try:
            gov.close_campaign(campaign_id, who())
        except GovernanceError as e:
            flash(str(e), "error")
        else:
            record("cert.close", target=str(campaign_id))
        return redirect(f"/governance/campaigns/{campaign_id}")

    # ---- notifications -----------------------------------------------------------------

    @app.get("/admin/notifications")
    @require_role("admin")
    def notifications_page():
        from ..notify import EVENTS
        return render_template("p_notifications.html", rows=notes.recent(200), events=EVENTS)

    # ---- reports -------------------------------------------------------------------

    @app.get("/reports")
    @require_role("operator")
    def reports():
        return render_template("p_reports.html", reports=REPORTS, schedules=ext["report_schedules"].list(),
                               every=ext["schedule_every"], folder=ext["settings"].reports_folder)

    @app.get("/reports/<name>.csv")
    @require_role("operator")
    def report_download(name: str):
        if name not in REPORTS:
            abort(404)
        rows = report_rows(db, name)
        record("report.download", target=name, detail=f"{len(rows)} rows")
        return Response(report_csv(rows), mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="backend-iam-{name}.csv"'})
