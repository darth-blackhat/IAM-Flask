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
import mimetypes
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
from .mfa import (MfaError, hash_recovery, new_recovery_codes, new_secret, otpauth_uri,
                  seal, unseal)
from .mfa import verify as verify_totp
from .templates import TEMPLATES

PAGE = 100
SITES = {"producer": "backend-iam · producer", "consumer": "backend-iam · oversight"}
THEME_COOKIE, THEMES = "biam_theme", ("light", "dark", "auto")
MFA_PENDING_SECONDS, MFA_MAX_TRIES = 300, 5     # password -> code: 5 minutes, 5 tries
# Windows can map .js / .css to odd types from the registry; with nosniff that blocks them.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/css", ".css")


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
    # MFA secrets are sealed only with the configured key (a random one would not survive
    # a restart and would lock users out); without it MFA cannot be set up.
    mfa_key = secret
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

    jira_base = settings.jira_base_url.strip().rstrip("/")
    if jira_base and urlparse(jira_base).scheme not in ("http", "https"):
        logger.warning("JIRA_BASE_URL must be http(s); ticket links are off")
        jira_base = ""

    @app.template_filter("jira")
    def _jira(key):
        """A Jira key as a link to the issue (only valid keys; everything else is plain text)."""
        from ..directory import JIRA_KEY
        if not key:
            return ""
        key = str(key)
        if jira_base and JIRA_KEY.match(key):
            return Markup('<a class="mono" href="{}/browse/{}" rel="noopener noreferrer" target="_blank">{}</a>'
                          ).format(jira_base, key, key)
        return Markup('<span class="mono">{}</span>').format(key)

    @app.template_filter("pretty")
    def _pretty(value):
        return json.dumps(value, indent=2, sort_keys=True, default=str)

    def ip() -> str | None:
        return client_ip(request.remote_addr, request.headers.get("X-Forwarded-For"), trusted)

    def record(action: str, ok: bool = True, target: str | None = None, detail: str | None = None,
               actor: str | None = None) -> None:
        who = actor or (g.user["username"] if getattr(g, "user", None) else "anonymous")
        audit.record("web", f"{site}:{who}", action, ok=ok, ip=ip(), target=target, detail=detail)

    def mfa_required(user: dict) -> bool:
        need = settings.web_mfa_required_role
        return need in RANK and RANK[user["role"]] >= RANK[need]

    def can(min_role: str) -> bool:
        user = getattr(g, "user", None)
        return bool(user) and RANK[user["role"]] >= RANK[min_role]

    @app.context_processor
    def _ctx():
        token = session.get("csrf", "")
        theme = request.cookies.get(THEME_COOKIE)
        return {"user": getattr(g, "user", None), "can": can, "site": site,
                "theme": theme if theme in THEMES else "auto",
                "site_title": SITES[site], "now": time.time(),
                "nav": NAV[site], "csrf": lambda: Markup(
                    f'<input type="hidden" name="csrf_token" value="{token}">')}

    # ---- every request ----------------------------------------------------------

    @app.before_request
    def _gate():
        g.user = None
        if request.path in ("/healthz", "/favicon.ico") or (
                request.method == "GET" and request.path.startswith("/static/")):
            return None
        if request.method == "POST":
            _check_origin()
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
            if not session.get("csrf") or not hmac.compare_digest(sent, session["csrf"]):
                record("csrf", ok=False, target=request.path, detail="missing or wrong CSRF token")
                if request.path == "/login":
                    # Stale login page (e.g. the service restarted): nothing was done, so
                    # just show a fresh form. The credentials are not looked at.
                    session.clear()
                    session["csrf"] = secrets.token_urlsafe(32)
                    flash("The sign-in page had expired. Please sign in again.", "error")
                    return redirect(url_for("login"))
                abort(400, "invalid form token: reload the page and try again")
        if request.path in ("/login", "/login/mfa"):
            session.setdefault("csrf", secrets.token_urlsafe(32))
            return None
        user = _session_user()
        if user is None:
            # Drop any old sign-in, but keep the form token: browsers fetch things like
            # /favicon.ico in the background, and wiping it would break the open login form.
            # Same for a sign-in waiting for its second factor (password already checked).
            keep = {k: v for k, v in session.items() if k == "csrf" or k.startswith("mfa_")}
            session.clear()
            session.update(keep)
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        g.user = user
        if (mfa_required(user) and not user["totp_secret"]
                and not request.path.startswith(("/account", "/logout", "/theme"))):
            flash("Your role requires two-factor sign-in: set it up to continue.", "error")
            return redirect("/account/mfa")

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
        # Same-origin files only: no inline script or style anywhere (static/app.js, app.css).
        resp.headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; "
                                                   "style-src 'self'; img-src 'self'; "
                                                   "form-action 'self'; frame-ancestors 'none'; "
                                                   "base-uri 'none'; object-src 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Permissions-Policy"] = ("camera=(), microphone=(), geolocation=(), payment=(), "
                                              "usb=(), interest-cohort=()")
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

    @app.get("/favicon.ico")
    def favicon():
        return Response(status=204)   # no icon; answered without touching the session

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
        if user["totp_secret"]:
            # Password is right; the second factor decides. Nothing is signed in yet.
            session.clear()
            session.update(mfa_u=user["username"], mfa_epoch=user["session_epoch"], mfa_at=time.time(),
                           mfa_next=nxt, mfa_tries=0, csrf=secrets.token_urlsafe(32))
            record("login.password", actor=user["username"])
            return redirect(url_for("login_mfa"))
        return _finish_login(user, nxt)

    def _finish_login(user: dict, nxt: str, mfa: bool = False):
        session.clear()   # new session id material: no fixation
        now = time.time()
        session.update(u=user["username"], epoch=user["session_epoch"], iat=now, seen=now,
                       csrf=secrets.token_urlsafe(32), mfa=mfa)
        session.permanent = True
        g.user = user
        record("login", detail="with MFA" if mfa else None)
        return redirect(nxt)

    @app.route("/login/mfa", methods=["GET", "POST"])
    def login_mfa():
        name = session.get("mfa_u")
        if not name or time.time() - session.get("mfa_at", 0) > MFA_PENDING_SECONDS:
            session.clear()
            flash("Sign in again.", "error")
            return redirect(url_for("login"))
        if request.method == "GET":
            return render_template("login_mfa.html")
        if not throttle.allow(ip() or "?"):
            record("login.mfa", ok=False, actor=name, detail="too many attempts from this address")
            flash("Too many attempts. Wait a few minutes.", "error")
            return render_template("login_mfa.html"), 429
        user = users.get(name)
        if (user is None or user["disabled"] or not user["totp_secret"]
                or user["session_epoch"] != session.get("mfa_epoch")):
            session.clear()
            return redirect(url_for("login"))
        code = (request.form.get("code") or "").strip()
        if request.form.get("kind") == "recovery":
            ok, how = users.use_recovery_code(name, hash_recovery(code)), "recovery code"
        else:
            try:
                counter = verify_totp(unseal(user["totp_secret"], mfa_key), code, user["totp_last_counter"])
            except MfaError as e:
                record("login.mfa", ok=False, actor=name, detail=str(e))
                flash(str(e), "error")
                return render_template("login_mfa.html"), 401
            ok, how = counter is not None and users.accept_counter(name, counter), "authenticator code"
        if not ok:
            session["mfa_tries"] = session.get("mfa_tries", 0) + 1
            record("login.mfa", ok=False, actor=name, detail=f"wrong {how}")
            if session["mfa_tries"] >= MFA_MAX_TRIES:
                session.clear()
                flash("Too many wrong codes. Sign in again.", "error")
                return redirect(url_for("login"))
            flash("That code is not valid.", "error")
            return render_template("login_mfa.html"), 401
        if how == "recovery code":
            left = len(users.get(name)["recovery_codes"] or [])
            record("mfa.recovery_used", actor=name, detail=f"{left} recovery codes left")
        return _finish_login(users.get(name), session.get("mfa_next") or "/", mfa=True)

    @app.post("/logout")
    def logout():
        record("logout")
        session.clear()
        return redirect(url_for("login"))

    @app.post("/theme")
    def set_theme():
        """Light / dark / auto (follow the OS). A plain preference cookie, kept after logout."""
        theme = request.form.get("theme")
        # Back to the page it was pressed on: its path only, never another host.
        ref = urlparse(request.referrer or "")
        back = ref.path + (f"?{ref.query}" if ref.query else "")
        if not back.startswith("/") or back.startswith("//") or "\\" in back:
            back = "/"
        resp = redirect(back)
        if theme in THEMES:
            resp.set_cookie(THEME_COOKIE, theme, max_age=365 * 86400, httponly=True,
                            samesite="Strict", secure=settings.web_cookie_secure)
        return resp

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

    @app.get("/account/mfa")
    def account_mfa():
        me = users.get(g.user["username"])
        if me["totp_secret"]:
            return render_template("account_mfa.html", enrolled=True,
                                   recovery_left=len(me["recovery_codes"] or []), required=mfa_required(me))
        try:
            if "mfa_setup" not in session:
                session["mfa_setup"] = seal(new_secret(), mfa_key)
            pending = unseal(session["mfa_setup"], mfa_key)
        except MfaError as e:
            flash(str(e), "error")
            return redirect("/account")
        return render_template("account_mfa.html", enrolled=False, secret_b32=pending,
                               uri=otpauth_uri(pending, me["username"], SITES[site]))

    @app.post("/account/mfa/enable")
    def account_mfa_enable():
        me = g.user["username"]
        try:
            pending = unseal(session.get("mfa_setup") or "", mfa_key)
        except MfaError:
            return redirect("/account/mfa")
        counter = verify_totp(pending, request.form.get("code") or "", None)
        if counter is None:
            record("mfa.enable", ok=False, detail="wrong code")
            flash("That code is not valid: check the app and the clock, then try again.", "error")
            return redirect("/account/mfa")
        codes, hashes = new_recovery_codes()
        users.enable_mfa(me, seal(pending, mfa_key), counter, hashes)
        session.pop("mfa_setup", None)
        session.update(epoch=users.get(me)["session_epoch"], mfa=True)   # this session stays signed in
        record("mfa.enable")
        return render_template("account_mfa_codes.html", codes=codes)

    def _second_factor_ok(me: dict) -> bool:
        code = request.form.get("code") or ""
        try:
            counter = verify_totp(unseal(me["totp_secret"], mfa_key), code, me["totp_last_counter"])
        except MfaError:
            return False
        if counter is not None and users.accept_counter(me["username"], counter):
            return True
        return users.use_recovery_code(me["username"], hash_recovery(code))

    @app.post("/account/mfa/disable")
    def account_mfa_disable():
        me = users.get(g.user["username"])
        if mfa_required(me):
            flash("Your role requires two-factor sign-in; it cannot be turned off.", "error")
            return redirect("/account/mfa")
        ok, _ = users.authenticate(me["username"], request.form.get("password") or "")
        if not ok or not _second_factor_ok(me):
            record("mfa.disable", ok=False, detail="wrong password or code")
            flash("Wrong password or code.", "error")
            return redirect("/account/mfa")
        users.disable_mfa(me["username"])
        record("mfa.disable")
        session.clear()
        flash("Two-factor sign-in is off. Sign in again.", "ok")
        return redirect(url_for("login"))

    @app.post("/account/mfa/recovery")
    def account_mfa_recovery():
        me = users.get(g.user["username"])
        if not me["totp_secret"] or not _second_factor_ok(me):
            record("mfa.recovery_regenerate", ok=False, detail="wrong code")
            flash("That code is not valid.", "error")
            return redirect("/account/mfa")
        codes, hashes = new_recovery_codes()
        fresh = users.get(me["username"])
        users.enable_mfa(me["username"], fresh["totp_secret"], fresh["totp_last_counter"] or 0, hashes)
        session.update(epoch=users.get(me["username"])["session_epoch"])
        record("mfa.recovery_regenerate")
        return render_template("account_mfa_codes.html", codes=codes)

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
            elif op == "mfa-reset":
                if name == me:
                    raise ValueError("reset your own MFA from your account page")
                ok = users.disable_mfa(name)
            elif op == "employee":
                eid = (request.form.get("employee_id") or "").strip()
                if len(eid) > 255 or any(ord(ch) < 32 for ch in eid):
                    raise ValueError("invalid employee id")
                ok = users._set(name, employee_id=eid or None)
            elif op == "scope":
                users.set_approver_scope(name, (request.form.get("scope") or "").split(","))
                ok = True
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

    @app.post("/admin/audit/verify")
    @require_role("admin")
    def admin_audit_verify():
        result = audit.verify()
        record("audit.verify", ok=result["ok"], detail=str(result))
        flash(f"Audit trail intact: {result['checked']} entries checked." if result["ok"] else
              f"AUDIT TRAIL TAMPERED at entry {result['first_bad_id']}: {result['problem']}.",
              "ok" if result["ok"] else "error")
        return redirect("/admin/audit")

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
        from .directory_views import register as register_directory
        from .governance_views import register as register_governance
        from .producer_views import register
        from .insight_views import register as register_insights
        register_directory(app)
        register_governance(app)
        register_insights(app)
    else:
        from .consumer_views import register
    register(app)
    return app


NAV = {
    "producer": [("/", "Dashboard", "viewer"), ("/producer", "Producer activity", "viewer"),
                 ("/directory", "Directory", "viewer"), ("/governance", "Governance", "viewer"),
                 ("/governance/insights", "Insights", "viewer"), ("/request-access", "Request access", "viewer"),
                 ("/reports", "Reports", "operator"), ("/outbox", "AD instructions", "viewer"),
                 ("/runs", "Sync runs", "viewer"),
                 ("/requests", "Requests", "operator"), ("/approvals", "Approvals", "admin"),
                 ("/admin/notifications", "Alerts", "admin"),
                 ("/admin/apikeys", "API keys", "admin"),
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
