"""Pages of the consumer-site UI (`iam oversight`)."""

import time

from flask import Flask, abort, flash, g, redirect, render_template, request

from ..consumer.store import ConsumerStore
from ..operator import OperatorRequests

PAGE = 100


def register(app: Flask) -> None:
    ext = app.extensions["biam"]
    db, record, require_role, settings = ext["db"], ext["record"], ext["require_role"], ext["settings"]
    store, requests = ConsumerStore(db), OperatorRequests(db)
    target = settings.consumer_target
    drift_t = db.tables.drift_reports

    def who() -> str:
        return f"web:{g.user['username']}"

    try:
        from ..consumer.config import load_consumer_config
        cfg = load_consumer_config(settings.consumer_config_path)
        mode = cfg.ad.mode if cfg.ad else "not configured"
    except Exception:   # the UI still works without the consumer's config file
        mode = "unknown"

    def ad_mode() -> str:
        return mode

    def queue(action: str, params: dict, back: str):
        rid = requests.create("consumer", action, {**params, "by": who()}, who())
        record("request", target=action, detail=f"request {rid} {params}")
        flash(f"Queued request {rid}: the consumer service runs it within seconds.", "ok")
        return redirect(back)

    def latest_drift() -> dict:
        from sqlalchemy import func, select
        latest = select(drift_t.c.domain, func.max(drift_t.c.id).label("id")).group_by(drift_t.c.domain).subquery()
        with db.begin() as conn:
            rows = conn.execute(select(drift_t).join(latest, drift_t.c.id == latest.c.id)).all()
        return {r.domain: dict(r._mapping) for r in rows}

    def _int(name: str) -> int | None:
        v = request.args.get(name, "")
        return int(v) if v.isdigit() else None

    @app.context_processor
    def _consumer_ctx():
        return {"target": target, "ad_mode": ad_mode()}

    @app.get("/")
    def dashboard():
        drift = latest_drift()
        return render_template(
            "c_dashboard.html", files=store.file_stats(time.time() - 86400), domains=store.all_domains(),
            waiting=len(store.plans_page("awaiting_approval")), drift=drift,
            drifting=sum(1 for r in drift.values() if r["status"] != "clean"),
            alerts=len([a for a in store.alerts_page(open_only=True) if a["severity"] != "info"]))

    @app.get("/files")
    def files():
        return render_template("c_files.html", rows=store.recent_files(PAGE, status=request.args.get("status") or None,
                                                                       domain=request.args.get("domain") or None),
                               args=request.args, domains=store.all_domains())

    @app.get("/files/<sha>")
    def file_detail(sha: str):
        f = store.file(sha) or abort(404)
        return render_template("c_file.html", f=f, actions=store.actions_page(file_sha=sha, limit=2000))

    @app.post("/files/<sha>/reprocess")
    @require_role("operator")
    def reprocess(sha: str):
        store.file(sha) or abort(404)
        return queue("reprocess", {"sha256": sha}, f"/files/{sha}")

    @app.post("/scan")
    @require_role("operator")
    def scan():
        return queue("scan", {}, "/")

    @app.get("/actions")
    def actions():
        rows = store.actions_page(ok={"ok": True, "failed": False}.get(request.args.get("status", "")),
                                  limit=PAGE * 2, before_id=_int("before"))
        return render_template("c_actions.html", rows=rows, args=request.args,
                               next_before=rows[-1]["id"] if len(rows) == PAGE * 2 else None)

    # ---- drift ---------------------------------------------------------------------

    @app.get("/drift")
    def drift():
        from sqlalchemy import select
        with db.begin() as conn:
            rows = [dict(r._mapping) for r in conn.execute(select(drift_t).order_by(drift_t.c.id.desc()).limit(PAGE))]
        return render_template("c_drift.html", rows=rows, domains=store.all_domains())

    @app.post("/drift")
    @require_role("operator")
    def drift_run():
        domain = request.form.get("domain") or ""
        return queue("drift", {"domain": domain} if domain else {}, "/requests")

    @app.get("/drift/<int:report_id>")
    def drift_detail(report_id: int):
        from sqlalchemy import select
        with db.begin() as conn:
            r = conn.execute(select(drift_t).where(drift_t.c.id == report_id)).first()
        return render_template("c_drift_detail.html", r=dict(r._mapping) if r else abort(404))

    # ---- AD plans / AD changes ------------------------------------------------------

    @app.get("/ad/plans")
    def plans():
        return render_template("c_plans.html", rows=store.plans_page(request.args.get("status") or None),
                               args=request.args)

    @app.get("/ad/plans/<int:plan_id>")
    def plan(plan_id: int):
        return render_template("c_plan.html", p=store.plan(plan_id) or abort(404))

    @app.post("/ad/plans/<int:plan_id>/approve")
    @require_role("operator")
    def plan_approve(plan_id: int):
        p = store.plan(plan_id) or abort(404)
        if p["status"] != "awaiting_approval":
            flash("This plan is not awaiting approval.", "error")
            return redirect(f"/ad/plans/{plan_id}")
        return queue("ad_approve", {"plan_id": plan_id}, f"/ad/plans/{plan_id}")

    @app.post("/ad/plans/<int:plan_id>/reject")
    @require_role("operator")
    def plan_reject(plan_id: int):
        p = store.plan(plan_id) or abort(404)
        if p["status"] != "awaiting_approval":
            flash("This plan is not awaiting approval.", "error")
        else:
            store.update_plan(plan_id, status="rejected", decided_by=who(), decided_at=time.time())
            store.update_file(p["file_sha256"], status="rejected")
            record("ad_plan.reject", target=str(plan_id))
            flash(f"Plan {plan_id} rejected: nothing is applied.", "ok")
        return redirect(f"/ad/plans/{plan_id}")

    @app.get("/ad/changes")
    def ad_changes():
        open_only = request.args.get("show") != "all"
        return render_template("c_alerts.html", rows=store.alerts_page(
            open_only=open_only, severity=request.args.get("severity") or None, limit=PAGE * 2),
            args=request.args, open_only=open_only)

    @app.post("/ad/changes/<int:alert_id>/ack")
    @require_role("operator")
    def ad_change_ack(alert_id: int):
        ok = store.acknowledge(alert_id, who(), request.form.get("note"))
        record("ad_alert.ack", ok=ok, target=str(alert_id), detail=request.form.get("note"))
        flash("Acknowledged." if ok else "Already acknowledged.", "ok" if ok else "error")
        return redirect("/ad/changes")

    @app.post("/ad/changes/check")
    @require_role("operator")
    def ad_change_check():
        return queue("ad_watch", {}, "/ad/changes")
