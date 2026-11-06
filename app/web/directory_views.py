"""Directory pages of the producer UI: users, groups, organizations (OUs) and roles.

Lists come from the change-detection snapshot (OpenIAM as last seen by `iam sync run`).
Every change is queued as a `directory` operator request; the producer service (`iam serve`)
writes it to OpenIAM and / or queues AD instructions (see app/directory.py). This UI holds
no OpenIAM or AD credentials.
"""

from typing import Any

from flask import Flask, abort, flash, g, redirect, render_template, request
from pydantic import ValidationError

import csv
import io
import os

from ..directory import KINDS, ORG_TYPES, DirectoryRequest, TimedGrants, plan
from ..governance import Governance
from ..notify import Notifications
from ..operator import ApprovalError, OperatorRequests, approvals_needed, in_scope
from ..producer.store import ProducerStore
from ..sync.store import Store

LABELS = {"user": "Users", "group": "Groups", "organization": "Organizations (OUs)", "role": "Roles"}
SINGULAR = {"user": "user", "group": "group", "organization": "organization", "role": "role"}
SCAN = 5000           # snapshot rows scanned for one page
FORM_FIELDS = ("via", "kind", "op", "name", "new_name", "description", "org_type", "first_name", "last_name",
               "email", "login", "title", "domain", "member_kind", "member", "jira_ticket", "reason",
               "expires_on")


# Bulk import: CSV columns per format. Lists (groups, roles, organizations) use ";".
BULK_FORMATS = {
    "user": ["employee_id", "first_name", "last_name", "email", "login", "title", "domain", "groups",
             "roles", "organizations"],
    "group": ["name", "description", "domain"],
    "role": ["name", "description", "domain"],
    "organization": ["name", "type", "description", "domain"],
    "membership": ["op", "kind", "name", "member_kind", "member", "domain", "expires_on"],
}


def parse_bulk(fmt: str, text: str, via: str, max_rows: int) -> list[dict[str, Any]]:
    """CSV text -> directory request params (not yet validated)."""
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise ValueError("no rows (the first line must be the header)")
    if len(rows) > max_rows:
        raise ValueError(f"at most {max_rows} rows per import")
    header = {h.strip().lower() for h in rows[0].keys() if h}
    missing = {c for c in BULK_FORMATS[fmt][:3] if c in ("employee_id", "first_name", "last_name", "name", "op",
                                                         "kind")} - header
    if missing:
        raise ValueError("missing column(s): " + ", ".join(sorted(missing)))
    out = []
    for raw in rows:
        r = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        if fmt == "user":
            item = {"kind": "user", "op": "create", "name": r.get("employee_id"),
                    **{k: r.get(k) for k in ("first_name", "last_name", "email", "login", "title", "domain")},
                    **{k: [s for s in (r.get(k) or "").split(";")] for k in ("groups", "roles", "organizations")}}
        elif fmt == "membership":
            op = {"add": "add_member", "remove": "remove_member"}.get((r.get("op") or "").lower(), r.get("op"))
            item = {"op": op, **{k: r.get(k) for k in ("kind", "name", "member_kind", "member", "domain", "expires_on")}}
            item["member_kind"] = item["member_kind"] or "user"
        else:
            item = {"kind": fmt, "op": "create", "name": r.get("name"), "description": r.get("description"),
                    "domain": r.get("domain")}
            if fmt == "organization":
                item["org_type"] = (r.get("type") or "").lower().replace(" ", "_") or None
        out.append({"via": via, **{k: v for k, v in item.items() if v not in (None, "", [])}})
    return out


def _name_of(kind: str, rec: dict[str, Any]) -> str:
    return str(rec.get("employeeId") or "") if kind == "user" else str(rec.get("name") or "")


def _domain_of(rec: dict[str, Any]) -> str:
    d = rec.get("domain")
    return d if isinstance(d, str) else ""


def _org_type_of(rec: dict[str, Any]) -> str:
    """ORG_TYPES key of a snapshot organization, matched on key or label (else "")."""
    for field in ("organizationType", "organizationTypeName", "organizationTypeId", "type"):
        v = rec.get(field)
        if isinstance(v, dict):
            v = v.get("name") or v.get("id")
        if isinstance(v, str) and v:
            low = v.strip().lower().replace(" ", "_")
            for key, label in ORG_TYPES.items():
                if low in (key, label.lower().replace(" ", "_")):
                    return key
    return ""


def _member_of(rec: dict[str, Any] | None) -> dict[str, list[str]]:
    """memberOf-style lists a snapshot record may carry (depends on the OpenIAM search)."""
    out: dict[str, list[str]] = {}
    for key in ("memberOf", "groups", "parentGroups", "childGroups", "roles", "organizations",
                "affiliations"):
        v = (rec or {}).get(key)
        if isinstance(v, list) and v:
            out[key] = [str(x.get("name") or x.get("id")) if isinstance(x, dict) else str(x) for x in v]
    return out


def register(app: Flask) -> None:
    ext = app.extensions["biam"]
    db, record, require_role = ext["db"], ext["record"], ext["require_role"]
    snapshot, producer, requests = Store(db), ProducerStore(db), OperatorRequests(db)
    governance = Governance(db)
    notes = Notifications(db)

    def _kind(kind: str) -> str:
        if kind not in KINDS:
            abort(404)
        return kind

    def _rows(kind: str, q: str) -> list[dict[str, Any]]:
        q = q.lower()
        rows = []
        for rec in snapshot.snapshot(kind, 0, SCAN):
            name = _name_of(kind, rec)
            if q and q not in " ".join(str(v) for v in rec.values() if isinstance(v, (str, int))).lower():
                continue
            rows.append({"name": name, "rec": rec, "domain": _domain_of(rec),
                         "org_type": ORG_TYPES.get(_org_type_of(rec), "") if kind == "organization" else ""})
        return sorted(rows, key=lambda r: r["name"].lower())

    def _find(kind: str, name: str) -> dict[str, Any] | None:
        return next((r["rec"] for r in _rows(kind, "") if r["name"] == name), None)

    def _history(kind: str, name: str) -> list[dict[str, Any]]:
        """Recent directory requests about this object (as the object or as the member)."""
        def about(p: dict[str, Any]) -> bool:
            if p.get("items") is not None:
                return any(about(i) for i in p["items"])
            return ((p.get("kind") == kind and p.get("name") == name)
                    or (p.get("member_kind") == kind and p.get("member") == name))
        return [r for r in requests.page("producer", 500)
                if r["action"].startswith("directory") and about(r["params"] or {})][:30]

    def _domains() -> list[str]:
        return sorted(snapshot.last_exports())

    @app.get("/directory")
    def directory():
        kind = _kind(request.args.get("kind") or "user")
        q = request.args.get("q") or ""
        rows = _rows(kind, q)
        return render_template("p_directory.html", kind=kind, labels=LABELS, single=SINGULAR,
                               rows=rows, q=q, total=snapshot.counts().get(kind, 0), org_types=ORG_TYPES)

    @app.get("/directory/<kind>/new")
    @require_role("operator")
    def directory_new(kind: str):
        return render_template("p_dir_new.html", kind=_kind(kind), labels=LABELS, single=SINGULAR,
                               domains=_domains(), org_types=ORG_TYPES)

    @app.get("/directory/<kind>/view")
    def directory_view(kind: str):
        kind = _kind(kind)
        name = request.args.get("name") or abort(404)
        rec = _find(kind, name)
        memberships: dict[str, list[str]] = {}
        person = None
        if kind == "user":
            person = producer.get_person(name)
            for k in ("group", "role", "organization"):
                ids = producer.memberships(name, k)
                names = sorted(producer.name_for(k, i) or i for i in ids)
                if names:
                    memberships[k] = names
        return render_template("p_dir_object.html", kind=kind, name=name, rec=rec, labels=LABELS,
                               single=SINGULAR, memberships=memberships, member_of=_member_of(rec),
                               person=vars(person) if person else None, domains=_domains(),
                               domain=_domain_of(rec or {}), history=_history(kind, name),
                               org_types=ORG_TYPES, org_type=_org_type_of(rec or {}))

    @app.post("/directory/request")
    @require_role("operator")
    def directory_request():
        form = request.form
        params: dict[str, Any] = {k: form.get(k) for k in FORM_FIELDS if form.get(k) is not None}
        for k in ("groups", "roles", "organizations"):
            params[k] = [s for s in (form.get(k) or "").replace("\n", ",").split(",")]
        params["requested_by"] = g.user["username"]
        back = form.get("back") or "/directory"
        if not back.startswith("/directory"):
            back = "/directory"
        try:
            req = DirectoryRequest.model_validate(params)
        except ValidationError as e:
            msg = "; ".join(err["msg"].removeprefix("Value error, ") for err in e.errors())
            flash(f"Not queued: {msg}", "error")
            return redirect(back)
        clean = req.model_dump(exclude_none=True, exclude_defaults=True)
        clean.update(via=req.via, kind=req.kind, op=req.op)
        if broken := governance.check_request(clean):
            record("sod.blocked", ok=False, target=f"{req.kind}:{req.name}", detail="; ".join(broken))
            notes.add("sod.blocked", f"Refused (segregation of duties): {req.op} {req.kind} {req.name}",
                      f"{req.jira_ticket}: requested by {g.user['username']}. Breaks: " + "; ".join(broken),
                      {"jira_ticket": req.jira_ticket, "policies": broken})
            flash("Not saved: segregation of duties would be broken: " + "; ".join(broken), "error")
            return redirect(back)
        rid = requests.create("producer", "directory", clean, f"web:{g.user['username']}",
                              destructive_approvals=ext["settings"].approvals_for_destructive,
                              bulk_over=ext["settings"].bulk_dual_approval_over)
        what = f"{req.op} {req.kind} {req.name}" + (f" ({req.member_kind} {req.member})" if req.member else "")
        notes.add("request.awaiting_approval", f"Approval needed: {what}",
                  f"Request {rid} ({req.jira_ticket}) by {g.user['username']}, via {req.via}.\n"
                  f"Justification: {req.reason}\nApprove or reject in the producer UI under Approvals.",
                  {"request_id": rid, "jira_ticket": req.jira_ticket, "kind": req.kind, "op": req.op,
                   "name": req.name, "domain": req.domain})
        record("directory.request", target=f"{req.kind}:{req.name}",
               detail=f"request {rid} [{req.jira_ticket}]: {what} via {req.via}; why: {req.reason}")
        flash(f"Saved request {rid} ({req.jira_ticket}): {what} via "
              f"{'OpenIAM + AD' if req.via == 'openiam' else 'AD instructions only'}. "
              "It waits for a manager's approval; nothing reaches OpenIAM or AD before that.", "ok")
        return redirect(back)

    # ---- preview, batches (bulk import, mover) --------------------------------

    def _configs():
        """AD mapping / producer config for previews, when this host has the files."""
        settings = ext["settings"]
        ad = cfg = None
        try:
            if os.path.isfile(settings.sync_config_path):
                from ..sync.config import load_config
                ad = load_config(settings.sync_config_path).ad
            if os.path.isfile(settings.producer_config_path):
                from ..producer.config import load_producer_config
                cfg = load_producer_config(settings.producer_config_path)
        except Exception:
            pass
        return ad, cfg

    def _form_params() -> dict[str, Any]:
        form = request.form
        params: dict[str, Any] = {k: form.get(k) for k in FORM_FIELDS if form.get(k) is not None}
        for k in ("groups", "roles", "organizations"):
            params[k] = [s for s in (form.get(k) or "").replace("\n", ",").split(",")]
        params["requested_by"] = g.user["username"]
        return params

    def _errors(e: ValidationError) -> str:
        return "; ".join(err["msg"].removeprefix("Value error, ") for err in e.errors())

    def _hidden() -> list[tuple[str, str]]:
        return [(k, v) for k, v in request.form.items(multi=True) if k not in ("csrf_token",)]

    @app.post("/directory/preview")
    @require_role("operator")
    def directory_preview():
        back = request.form.get("back") or "/directory"
        if not back.startswith("/directory"):
            back = "/directory"
        try:
            req = DirectoryRequest.model_validate(_form_params())
        except ValidationError as e:
            flash(f"Not valid: {_errors(e)}", "error")
            return redirect(back)
        ad, cfg = _configs()
        clean = req.model_dump(exclude_none=True, exclude_defaults=True)
        clean.update(via=req.via, kind=req.kind, op=req.op)
        return render_template("p_preview.html", plans=[(clean, plan(req, ad, cfg))], hidden=_hidden(),
                               action="/directory/request", sod=governance.check_request(clean),
                               approvals=approvals_needed(clean, ext["settings"].approvals_for_destructive),
                               mapping_known=ad is not None, title="Preview", back=back)

    def _create_batch(items: list[dict[str, Any]], label: str, common: dict[str, Any]) -> int | None:
        settings = ext["settings"]
        params = {"items": items, "label": label, **common, "requested_by": g.user["username"]}
        if broken := governance.check_request(params):
            record("sod.blocked", ok=False, target=label, detail="; ".join(broken))
            notes.add("sod.blocked", f"Refused (segregation of duties): {label}",
                      f"{common.get('jira_ticket')}: requested by {g.user['username']}. Breaks: " + "; ".join(broken),
                      {"jira_ticket": common.get("jira_ticket"), "policies": broken})
            flash("Not saved: segregation of duties would be broken: " + "; ".join(broken), "error")
            return None
        rid = requests.create("producer", "directory_batch", params, f"web:{g.user['username']}",
                              destructive_approvals=settings.approvals_for_destructive,
                              bulk_over=settings.bulk_dual_approval_over)
        notes.add("request.awaiting_approval", f"Approval needed: {label} ({len(items)} changes)",
                  f"Request {rid} ({common.get('jira_ticket')}) by {g.user['username']}.\n"
                  f"Justification: {common.get('reason')}", {"request_id": rid, "jira_ticket": common.get("jira_ticket")})
        record("directory.batch", target=label, detail=f"request {rid} [{common.get('jira_ticket')}]: {len(items)} rows")
        flash(f"Saved request {rid} ({common.get('jira_ticket')}): {label}, {len(items)} change(s). "
              "It waits for approval; nothing reaches OpenIAM or AD before that.", "ok")
        return rid

    def _validate_batch(items: list[dict[str, Any]], common: dict[str, Any]):
        """[(row, params, plan | None, error | None)]"""
        ad, cfg = _configs()
        out = []
        for i, item in enumerate(items, 1):
            try:
                req = DirectoryRequest.model_validate({**item, **common, "requested_by": g.user["username"]})
                clean = req.model_dump(exclude_none=True, exclude_defaults=True)
                clean.update(via=req.via, kind=req.kind, op=req.op)
                clean.pop("requested_by", None)
                for k in ("jira_ticket", "reason"):
                    clean.pop(k, None)
                out.append((i, clean, plan(req, ad, cfg), None))
            except ValidationError as e:
                out.append((i, item, None, _errors(e)))
        return out

    @app.route("/directory/import", methods=["GET", "POST"])
    @require_role("operator")
    def directory_import():
        if request.method == "GET":
            return render_template("p_import.html", formats=BULK_FORMATS)
        kind = request.form.get("format") or ""
        if kind not in BULK_FORMATS:
            abort(400)
        upload = request.files.get("file")
        text = upload.read().decode("utf-8-sig", errors="replace") if upload and upload.filename else (request.form.get("csv") or "")
        common = {"jira_ticket": request.form.get("jira_ticket") or "", "reason": request.form.get("reason") or ""}
        via = request.form.get("via") if request.form.get("via") in ("openiam", "ad") else "openiam"
        try:
            items = parse_bulk(kind, text, via, ext["settings"].bulk_max_rows)
        except ValueError as e:
            flash(f"Not read: {e}", "error")
            return redirect("/directory/import")
        rows = _validate_batch(items, common)
        bad = [r for r in rows if r[3]]
        sod = governance.check_request({"items": [r[1] for r in rows if not r[3]]})
        if request.form.get("step") == "save" and not bad and not sod:
            rid = _create_batch([r[1] for r in rows], f"bulk import: {kind}", common)
            return redirect("/approvals" if rid and can_admin() else "/directory")
        if bad:
            flash(f"{len(bad)} of {len(rows)} row(s) are not valid: fix the file; nothing was saved.", "error")
        hidden = [("format", kind), ("csv", text), ("via", via), ("jira_ticket", common["jira_ticket"]),
                  ("reason", common["reason"]), ("step", "save")]
        return render_template("p_batch_preview.html", rows=rows, ok=not bad, hidden=hidden,
                               action="/directory/import", label=f"Bulk import: {kind}", sod=sod,
                               approvals=approvals_needed({"items": [r[1] for r in rows]},
                                                          ext["settings"].approvals_for_destructive,
                                                          ext["settings"].bulk_dual_approval_over))

    def can_admin() -> bool:
        return ext["can"]("admin")

    @app.route("/directory/user/move", methods=["GET", "POST"])
    @require_role("operator")
    def directory_move():
        name = request.values.get("name") or abort(404)
        rec = _find("user", name)
        current = sorted(governance.of_user(name))
        if request.method == "GET":
            return render_template("p_move.html", name=name, rec=rec, current=current, domains=_domains(),
                                   domain=_domain_of(rec or {}))
        f = request.form
        via = f.get("via") if f.get("via") in ("openiam", "ad") else "openiam"
        common = {"jira_ticket": f.get("jira_ticket") or "", "reason": f.get("reason") or ""}
        domain = (f.get("domain") or "").strip() or None
        items: list[dict[str, Any]] = []
        if (f.get("title") or "").strip() or (domain and domain != _domain_of(rec or {})):
            if not rec or not rec.get("firstName") or not rec.get("lastName"):
                flash("This user is not in the OpenIAM snapshot: the profile cannot be updated here.", "error")
                return redirect(f"/directory/user/move?name={name}")
            items.append({"via": via, "kind": "user", "op": "update", "name": name, "first_name": rec["firstName"],
                          "last_name": rec["lastName"], "title": (f.get("title") or "").strip() or rec.get("title"),
                          "domain": domain})
        for value in f.getlist("remove"):
            kind, _, obj = value.partition(":")
            items.append({"via": via, "kind": kind, "op": "remove_member", "name": obj, "member_kind": "user",
                          "member": name, "domain": domain})
        for field, kind in (("add_groups", "group"), ("add_roles", "role"), ("add_organizations", "organization")):
            for obj in [s.strip() for s in (f.get(field) or "").split(",") if s.strip()]:
                items.append({"via": via, "kind": kind, "op": "add_member", "name": obj, "member_kind": "user",
                              "member": name, "domain": domain})
        if not items:
            flash("Nothing to change.", "error")
            return redirect(f"/directory/user/move?name={name}")
        rows = _validate_batch(items, common)
        bad = [r for r in rows if r[3]]
        sod = governance.check_request({"items": [r[1] for r in rows if not r[3]]})
        if f.get("step") == "save" and not bad and not sod:
            rid = _create_batch([r[1] for r in rows], f"mover: {name}", common)
            return redirect(f"/directory/user/view?name={name}" if rid else f"/directory/user/move?name={name}")
        hidden = [(k, v) for k, v in f.items(multi=True) if k not in ("csrf_token", "step")] + [("step", "save")]
        return render_template("p_batch_preview.html", rows=rows, ok=not bad, hidden=hidden,
                               action="/directory/user/move", label=f"Mover: {name}", sod=sod,
                               approvals=approvals_needed({"items": [r[1] for r in rows]},
                                                          ext["settings"].approvals_for_destructive,
                                                          ext["settings"].bulk_dual_approval_over))

    # ---- approval (four eyes) ------------------------------------------------

    @app.get("/approvals")
    @require_role("admin")
    def approvals():
        rows = [r for r in requests.page("producer", 500) if r["action"].startswith("directory")]
        waiting = sorted((r for r in rows if r["status"] == "awaiting_approval"), key=lambda r: r["id"])
        decided = [r for r in rows if r["decided_by"]][:50]
        scope = g.user.get("approver_scope")
        for r in waiting:
            r["mine"] = in_scope(scope, r["params"] or {})
            r["approved_by_me"] = any(a["by"] == f"web:{g.user['username']}" for a in r["approvals"] or [])
        return render_template("p_approvals.html", waiting=waiting, decided=decided,
                               me=f"web:{g.user['username']}", scope=scope)

    @app.post("/approvals/<int:request_id>/<decision>")
    @require_role("admin")
    def approval_decide(request_id: int, decision: str):
        if decision not in ("approve", "reject"):
            abort(404)
        note = (request.form.get("note") or "").strip()[:1000] or None
        pending = requests.get(request_id)
        if pending and not in_scope(g.user.get("approver_scope"), pending["params"] or {}):
            record(f"directory.{decision}", ok=False, target=str(request_id), detail="outside approver scope")
            flash("This change is outside the domains / organizations you may approve.", "error")
            return redirect("/approvals")
        if decision == "approve" and pending and pending["action"].startswith("directory"):
            # Access may have changed since it was asked for: check again.
            if broken := governance.check_request(pending["params"] or {}):
                record("sod.blocked", ok=False, target=str(request_id), detail="; ".join(broken))
                flash("Cannot approve: segregation of duties would be broken: " + "; ".join(broken),
                      "error")
                return redirect("/approvals")
        try:
            status = requests.decide(request_id, decision == "approve", f"web:{g.user['username']}", note)
        except ApprovalError as e:
            record(f"directory.{decision}", ok=False, target=str(request_id), detail=str(e))
            flash(str(e), "error")
            return redirect("/approvals")
        record(f"directory.{decision}", target=str(request_id),
               detail=f"{status}" + (f"; {note}" if note else ""))
        if status in ("pending", "rejected"):
            p = pending["params"] or {}
            notes.add("request.approved" if status == "pending" else "request.rejected",
                      f"{'Approved' if status == 'pending' else 'Rejected'}: {p.get('op')} {p.get('kind')} {p.get('name')}",
                      f"Request {request_id} ({p.get('jira_ticket')}) {'approved' if status == 'pending' else 'rejected'}"
                      f" by {g.user['username']}." + (f"\nNote: {note}" if note else ""),
                      {"request_id": request_id, "jira_ticket": p.get("jira_ticket"), "decided_by": g.user["username"]})
        flash({"pending": f"Request {request_id} approved: the producer service runs it within seconds.",
               "awaiting_approval": f"Request {request_id}: your approval is recorded; it needs another approver.",
               "rejected": f"Request {request_id} rejected."}[status], "ok")
        return redirect("/approvals")
