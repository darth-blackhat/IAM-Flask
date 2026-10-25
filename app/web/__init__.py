"""The two web UIs (Flask):

  iam web        producer site: producer activity, AD instructions, change detection,
                 exports, API keys
  iam oversight  consumer site: zips received, what was applied to the remote OpenIAM or
                 to Active Directory (plans and approval), drift reports

Shared: named users with roles (viewer < operator < admin), signed session cookies with
idle and absolute timeouts, CSRF tokens and an origin check on every POST, lockout after
repeated failed logins, and an audit trail of logins, page views and actions. The UIs
hold no OpenIAM or AD credentials: operator buttons queue requests that the producer /
consumer service runs.
"""

import hmac
import json
import secrets
import time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from jinja2 import DictLoader
from markupsafe import Markup

from ..config import Settings
from ..db import Database
from ..logs import logger
from ..security import AuditTrail, client_ip, parse_networks
from .auth import RANK, ROLES, WebUserStore
from .templates import TEMPLATES

PAGE = 100
SITES = {"producer": "backend-iam · producer", "consumer": "backend-iam · oversight"}


class LoginThrottle:
    """At most `limit` login attempts per address per window (in addition to user lockout)."""

    def __init__(self, limit: int = 20, window: int = 600):
        self.limit, self.window, self.hits = limit, window, {}

    def allow(self, ip: str) -> bool:
        now = time.time()
        hits = [t for t in self.hits.get(ip, []) if now - t < self.window]
        self.hits[ip] = hits + [now]
        return len(hits) < self.limit


def create_app(settings: Settings, db: Database | None = None, site: str = "producer") -> Flask:
    if site not in SITES:
        raise ValueError(f"site must be one of {list(SITES)}")
    if db is None:
        db = Database(settings.database_url, settings.database_schema)
        db.migrate()
    users = WebUserStore(db, settings.web_max_failures, settings.web_lock_minutes)
    audit = AuditTrail(db)
    trusted = parse_networks(settings.trusted_proxies)
    throttle = LoginThrottle()
    _bootstrap_admin(users, audit, settings)

    app = Flask(__name__)
    secret = settings.web_secret_key.get_secret_value()
    if not secret:
        secret = secrets.token_urlsafe(32)
        logger.warning("WEB_SECRET_KEY is not set: sessions end when this service restarts")
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_NAME=f"biam_{site}",          # the two UIs may share a host name
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=settings.web_cookie_secure,
        PERMANENT_SESSION_LIFETIME=settings.web_session_hours * 3600,
        MAX_CONTENT_LENGTH=1024 * 1024)
    app.jinja_loader = DictLoader(TEMPLATES)
    app.extensions["biam"] = {"db": db, "users": users, "audit": audit, "settings": settings,
                              "site": site}

    @app.template_filter("ts")
    def _ts(value):
        if not value:
            return ""
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    @app.template_filter("pretty")
    def _pretty(value):
        return json.dumps(value, indent=2, sort_keys=True, default=str)

    def ip() -> str | None:
        return client_ip(request.remote_addr, request.headers.get("X-Forwarded-For"), trusted)

    def record(action: str, ok: bool = True, target: str | None = None, detail: str | None = None,
               actor: str | None = None) -> None:
        who = actor or (g.user["username"] if getattr(g, "user", None) else "anonymous")
        audit.record("web", f"{site}:{who}", action, ok=ok, ip=ip(), target=target, detail=detail)

    def can(min_role: str) -> bool:
        user = getattr(g, "user", None)
        return bool(user) and RANK[user["role"]] >= RANK[min_role]

    @app.context_processor
    def _ctx():
        token = session.get("csrf", "")
        return {"user": getattr(g, "user", None), "can": can, "site": site,
                "site_title": SITES[site], "now": time.time(),
                "nav": NAV[site], "csrf": lambda: Markup(
                    f'<input type="hidden" name="csrf_token" value="{token}">')}

    # ---- every request ----------------------------------------------------------

    @app.before_request
    def _gate():
        g.user = None
        if request.path == "/healthz":
            return None
        if request.method == "POST":
            _check_origin()
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
            if not session.get("csrf") or not hmac.compare_digest(sent, session["csrf"]):
                record("csrf", ok=False, target=request.path, detail="missing or wrong CSRF token")
                abort(400, "invalid form token: reload the page and try again")
        if request.path == "/login":
            session.setdefault("csrf", secrets.token_urlsafe(32))
            return None
        user = _session_user()
        if user is None:
            session.clear()
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        g.user = user

    def _check_origin() -> None:
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if origin:
            o, h = urlparse(origin), urlparse(request.host_url)
            if (o.scheme, o.netloc) != (h.scheme, h.netloc):
                record("origin", ok=False, target=request.path, detail=f"cross-site POST from {origin}")
                abort(403, "cross-site request refused")

    def _session_user():
        name = session.get("u")
        if not name:
            return None
        now = time.time()
        user = users.get(name)
        if (user is None or user["disabled"] or user["session_epoch"] != session.get("epoch")
                or now - session.get("seen", 0) > settings.web_idle_minutes * 60
                or now - session.get("iat", 0) > settings.web_session_hours * 3600):
            return None
        if now - session.get("seen", 0) > 60:   # refresh the idle timer at most once a minute
            session["seen"] = now
        return user

    @app.after_request
    def _after(resp: Response) -> Response:
        resp.headers["Content-Security-Policy"] = ("default-src 'none'; style-src 'unsafe-inline'; "
                                                   "form-action 'self'; frame-ancestors 'none'; "
                                                   "base-uri 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        if settings.web_cookie_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if (getattr(g, "user", None) and request.method == "GET" and resp.status_code == 200
                and request.path not in ("/healthz",)):
            record("view", target=request.full_path.rstrip("?"))
        return resp

    def require_role(min_role: str):
        def deco(fn):
            @wraps(fn)
            def inner(*a, **kw):
                if not can(min_role):
                    record("forbidden", ok=False, target=request.path, detail=f"needs {min_role}")
                    abort(403)
                return fn(*a, **kw)
            return inner
        return deco

    app.extensions["biam"].update(record=record, require_role=require_role, can=can)

    # ---- login / account --------------------------------------------------------

    @app.get("/healthz")
    def healthz():
        return "ok"

    @app.route("/login", methods=["GET", "POST"])
    def login():
        nxt = request.values.get("next") or "/"
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = "/"   # only local redirects
        if request.method == "GET":
            return render_template("login.html", next=nxt)
        name = (request.form.get("username") or "").strip()
        if not throttle.allow(ip() or "?"):
            record("login", ok=False, actor=name or "?", detail="too many attempts from this address")
            flash("Too many attempts. Wait a few minutes.", "error")
            return render_template("login.html", next=nxt), 429
        user, reason = users.authenticate(name, request.form.get("password") or "")
        if user is None:
            record("login", ok=False, actor=name or "?", detail=reason)
            flash("Invalid username or password.", "error")   # same text whatever the reason
            return render_template("login.html", next=nxt), 401
        session.clear()   # new session id material: no fixation
        now = time.time()
        session.update(u=user["username"], epoch=user["session_epoch"], iat=now, seen=now,
                       csrf=secrets.token_urlsafe(32))
        session.permanent = True
        g.user = user
        record("login")
        return redirect(nxt)

    @app.post("/logout")
    def logout():
        record("logout")
        session.clear()
        return redirect(url_for("login"))

    @app.get("/account")
    def account():
        return render_template("account.html")

    @app.post("/account/password")
    def account_password():
        me = g.user["username"]
        ok, _ = users.authenticate(me, request.form.get("current") or "")
        if not ok:
            record("password.change", ok=False, detail="wrong current password")
            flash("Current password is wrong.", "error")
            return redirect("/account")
        try:
            users.set_password(me, request.form.get("new") or "")
        except ValueError as e:
            flash(str(e), "error")
            return redirect("/account")
        record("password.change")
        session.clear()
        flash("Password changed. Sign in again.", "ok")
        return redirect(url_for("login"))

    @app.post("/account/logout-everywhere")
    def logout_everywhere():
        users.logout_everywhere(g.user["username"])
        record("logout.everywhere")
        session.clear()
        return redirect(url_for("login"))

    # ---- admin: users, audit ----------------------------------------------------

    @app.get("/admin/users")
    @require_role("admin")
    def admin_users():
        return render_template("admin_users.html", users=users.list(), roles=ROLES)

    @app.post("/admin/users")
    @require_role("admin")
    def admin_user_create():
        name = (request.form.get("username") or "").strip()
        try:
            users.create(name, request.form.get("password") or "", request.form.get("role") or "viewer")
            record("user.create", target=name, detail=request.form.get("role"))
            flash(f"User {name} created.", "ok")
        except Exception as e:
            record("user.create", ok=False, target=name, detail=str(e))
            flash(f"Not created: {e}", "error")
        return redirect("/admin/users")

    @app.post("/admin/users/<name>/<op>")
    @require_role("admin")
    def admin_user_op(name: str, op: str):
        me = g.user["username"]
        try:
            if op == "role":
                if name == me and request.form.get("role") != "admin":
                    raise ValueError("you cannot remove your own admin role")
                ok = users.set_role(name, request.form.get("role") or "")
            elif op in ("disable", "enable"):
                if name == me:
                    raise ValueError("you cannot disable yourself")
                ok = users.set_disabled(name, op == "disable")
            elif op == "unlock":
                ok = users.unlock(name)
            elif op == "password":
                users.set_password(name, request.form.get("password") or "")
                ok = True
            else:
                abort(404)
            record(f"user.{op}", ok=bool(ok), target=name)
            flash(f"{name}: {op} done." if ok else f"{name}: nothing changed.", "ok" if ok else "error")
        except ValueError as e:
            record(f"user.{op}", ok=False, target=name, detail=str(e))
            flash(str(e), "error")
        return redirect("/admin/users")

    @app.get("/admin/audit")
    @require_role("admin")
    def admin_audit():
        before = request.args.get("before", "")
        rows = audit.page(actor=request.args.get("actor") or None,
                          channel=request.args.get("channel") or None,
                          ok={"ok": True, "failed": False}.get(request.args.get("status", "")),
                          limit=PAGE * 2, before_id=int(before) if before.isdigit() else None)
        return render_template("admin_audit.html", rows=rows, args=request.args,
                               next_before=rows[-1]["id"] if len(rows) == PAGE * 2 else None)

    @app.get("/requests")
    @require_role("operator")
    def requests_page():
        from ..operator import OperatorRequests
        return render_template("requests.html", rows=OperatorRequests(db).page(site),
                               service=site)

    if site == "producer":
        from .producer_views import register
    else:
        from .consumer_views import register
    register(app)
    return app


NAV = {
    "producer": [("/", "Dashboard", "viewer"), ("/producer", "Producer activity", "viewer"),
                 ("/outbox", "AD instructions", "viewer"), ("/runs", "Sync runs", "viewer"),
                 ("/requests", "Requests", "operator"), ("/admin/apikeys", "API keys", "admin"),
                 ("/admin/users", "Users", "admin"), ("/admin/audit", "Audit", "admin")],
    "consumer": [("/", "Dashboard", "viewer"), ("/files", "Files", "viewer"),
                 ("/actions", "Actions", "viewer"), ("/ad/plans", "AD plans", "viewer"),
                 ("/ad/changes", "AD changes", "viewer"), ("/drift", "Drift", "viewer"), ("/requests", "Requests", "operator"),
                 ("/admin/users", "Users", "admin"), ("/admin/audit", "Audit", "admin")],
}


def _bootstrap_admin(users: WebUserStore, audit: AuditTrail, settings: Settings) -> None:
    password = settings.web_password.get_secret_value()
    if users.count() == 0 and password:
        users.create(settings.web_username, password, "admin")
        audit.record("system", "bootstrap", "user.create", ok=True, target=settings.web_username,
                     detail="first admin from WEB_USERNAME / WEB_PASSWORD")
        logger.info("created first web admin {}", settings.web_username)
    elif users.count() == 0:
        logger.warning("no web users exist: set WEB_PASSWORD for the first admin, or run "
                       "`iam webuser add NAME --role admin`")


def serve(settings: Settings, host: str, port: int, site: str = "producer") -> None:
    from waitress import serve as waitress_serve

    app = create_app(settings, site=site)
    if host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning("{} UI listening on {}: put it behind the HTTPS proxy", site, host)
    logger.info("{} UI on http://{}:{}/", site, host, port)
    waitress_serve(app, host=host, port=port, trusted_proxy=None)
