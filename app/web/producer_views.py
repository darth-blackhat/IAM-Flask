"""Pages of the producer-site UI (`iam web`)."""

import time

from flask import Flask, abort, flash, g, redirect, render_template, request

from ..operator import ACTIONS, OperatorRequests
from ..producer.store import ProducerStore
from ..security import SCOPES, ApiKeyStore
from ..sync.store import Store

PAGE = 100


def register(app: Flask) -> None:
    ext = app.extensions["biam"]
    db, record, require_role = ext["db"], ext["record"], ext["require_role"]
    producer, outbox, keys, requests = ProducerStore(db), Store(db), ApiKeyStore(db), OperatorRequests(db)

    def _who() -> str:
        return f"web:{g.user['username']}"

    def _int(name: str) -> int | None:
        v = request.args.get(name, "")
        return int(v) if v.isdigit() else None

    @app.get("/")
    def dashboard():
        runs = outbox.recent_runs(5)
        blocked = next((r["error"] for r in runs[:1] if "MassDeleteError" in (r["error"] or "")), None)
        exports = sorted(outbox.last_exports().values(), key=lambda e: e["domain"])
        return render_template("p_dashboard.html", producer=producer.activity_stats(time.time() - 86400),
                               outbox=outbox.outbox_stats(), runs=runs, blocked=blocked, exports=exports)

    @app.get("/producer")
    def activity():
        rows = producer.activity_page(employee_id=request.args.get("employee") or None,
                                      event_type=request.args.get("type") or None,
                                      ok={"ok": True, "failed": False}.get(request.args.get("status", "")),
                                      limit=PAGE, before_id=_int("before"))
        return render_template("p_activity.html", rows=rows, args=request.args,
                               next_before=rows[-1]["id"] if len(rows) == PAGE else None)

    @app.get("/producer/<int:entry_id>")
    def activity_detail(entry_id: int):
        entry = producer.activity_entry(entry_id) or abort(404)
        person = producer.get_person(entry["employee_id"])
        return render_template("p_activity_detail.html", e=entry, person=vars(person) if person else None)

    @app.get("/outbox")
    def outbox_list():
        rows = outbox.recent_events(PAGE, _int("before"))
        return render_template("p_outbox.html", rows=rows, stats=outbox.outbox_stats(),
                               next_before=rows[-1]["seq"] if len(rows) == PAGE else None)

    @app.get("/outbox/<int:seq>")
    def outbox_detail(seq: int):
        return render_template("p_outbox_detail.html", e=outbox.event(seq) or abort(404))

    @app.post("/outbox/retry-dead")
    @require_role("operator")
    def retry_dead():
        n = outbox.retry_dead()
        record("outbox.retry_dead", detail=f"{n} batch(es) re-queued")
        flash(f"{n} instruction batch(es) queued for delivery again.", "ok")
        return redirect("/outbox")

    @app.get("/runs")
    def runs():
        return render_template("p_runs.html", runs=outbox.recent_runs(50), actions=ACTIONS["producer"])

    @app.post("/runs/request")
    @require_role("operator")
    def run_request():
        action = request.form.get("action") or ""
        try:
            rid = requests.create("producer", action, {}, _who())
        except ValueError as e:
            flash(str(e), "error")
            return redirect("/runs")
        record("request", target=action, detail=f"request {rid}")
        flash(f"Queued: {ACTIONS['producer'][action]} (request {rid}).", "ok")
        return redirect("/requests")

    @app.get("/admin/apikeys")
    @require_role("admin")
    def apikeys():
        return render_template("p_apikeys.html", keys=keys.list(), scopes=SCOPES, new_key=None)

    @app.post("/admin/apikeys")
    @require_role("admin")
    def apikey_create():
        name = (request.form.get("name") or "").strip()
        scopes = request.form.getlist("scope")
        cidrs = [c.strip() for c in (request.form.get("cidrs") or "").split(",") if c.strip()]
        days = request.form.get("expires_days") or ""
        try:
            key = keys.create(name, scopes, cidrs, int(days) if days.isdigit() else None,
                              created_by=_who())
        except Exception as e:
            record("apikey.create", ok=False, target=name, detail=str(e))
            flash(f"Not created: {e}", "error")
            return redirect("/admin/apikeys")
        record("apikey.create", target=name, detail=f"scopes={scopes} cidrs={cidrs}")
        # Rendered once, never stored: only its hash is kept.
        return render_template("p_apikeys.html", keys=keys.list(), scopes=SCOPES,
                               new_key={"name": name, "key": key})

    @app.post("/admin/apikeys/<name>/revoke")
    @require_role("admin")
    def apikey_revoke(name: str):
        ok = keys.revoke(name)
        record("apikey.revoke", ok=ok, target=name)
        flash(f"{name} revoked." if ok else f"{name}: not active.", "ok" if ok else "error")
        return redirect("/admin/apikeys")
