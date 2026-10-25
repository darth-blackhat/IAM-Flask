import re
import time

import pytest

from app.config import Settings
from app.consumer import ConsumerStore
from app.operator import OperatorRequests
from app.producer import ProducerStore
from app.security import AuditTrail
from app.sync import Store
from app.web import create_app
from app.web.auth import WebUserStore

ADMIN_PW = "admin-password-123"


@pytest.fixture
def make_web(database):
    def _make(site="producer", **over):
        settings = Settings(_env_file=None, web_username="boss", web_password=ADMIN_PW,
                            web_cookie_secure=False, web_secret_key="test-secret", **over)
        app = create_app(settings, database, site=site)
        app.testing = True
        return app.test_client()
    return _make


def csrf(client, path="/login"):
    page = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


def login(client, user="boss", pw=ADMIN_PW, next_="/"):
    return client.post("/login", data={"username": user, "password": pw, "next": next_,
                                       "csrf_token": csrf(client)})


def add_user(database, name, role, pw="a-long-password-1"):
    WebUserStore(database).create(name, pw, role)
    return pw


def test_anonymous_gets_login_and_health(make_web):
    c = make_web()
    assert c.get("/healthz").data == b"ok"
    r = c.get("/outbox")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert "frame-ancestors 'none'" in c.get("/login").headers["Content-Security-Policy"]


def test_bootstrap_admin_login_and_generic_failure(make_web):
    c = make_web()
    r = login(c, pw="wrong-password-xx")
    assert r.status_code == 401 and b"Invalid username or password" in r.data
    r = login(c, user="nobody", pw="whatever-password")
    assert r.status_code == 401 and b"Invalid username or password" in r.data   # same message
    assert login(c).status_code == 302
    assert b"boss" in c.get("/").data


def test_lockout_after_repeated_failures(make_web, database):
    c = make_web(web_max_failures=3)
    for _ in range(3):
        login(c, pw="wrong-password-xx")
    assert login(c).status_code == 401                    # right password, but locked
    WebUserStore(database).unlock("boss")
    assert login(c).status_code == 302


def test_csrf_and_cross_site_posts_are_refused(make_web):
    c = make_web()
    login(c)
    assert c.post("/runs/request", data={"action": "sync_run"}).status_code == 400
    token = csrf(c, "/runs")
    r = c.post("/runs/request", data={"action": "sync_run", "csrf_token": token},
               headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_roles(make_web, database):
    add_user(database, "vera", "viewer")
    add_user(database, "otto", "operator")
    viewer = make_web()
    login(viewer, "vera", "a-long-password-1")
    assert viewer.get("/admin/users").status_code == 403
    assert viewer.post("/runs/request", data={"action": "sync_run",
                                              "csrf_token": csrf(viewer, "/runs")}).status_code == 403
    assert b"Requests" not in viewer.get("/").data            # nav hides what you cannot use

    op = make_web()
    login(op, "otto", "a-long-password-1")
    r = op.post("/runs/request", data={"action": "sync_run_allow_mass_delete",
                                       "csrf_token": csrf(op, "/runs")})
    assert r.status_code == 302
    [req] = OperatorRequests(database).page("producer")
    assert req["requested_by"] == "web:otto" and req["action"] == "sync_run_allow_mass_delete"
    assert op.get("/admin/apikeys").status_code == 403


def test_session_expiry_and_logout_everywhere(make_web, database):
    c = make_web()
    login(c)
    with c.session_transaction() as s:
        s["seen"] = time.time() - 31 * 60                       # idle for 31 minutes
    assert c.get("/").status_code == 302

    a, b = make_web(), make_web()
    login(a)
    login(b)
    a.post("/account/logout-everywhere", data={"csrf_token": csrf(a, "/account")})
    assert b.get("/").status_code == 302                       # the other session ended too


def test_open_redirect_is_blocked(make_web):
    c = make_web()
    r = login(c, next_="//evil.example/x")
    assert r.headers["Location"] == "/"


def test_api_key_is_shown_once_and_stored_hashed(make_web, database):
    c = make_web()
    login(c)
    r = c.post("/admin/apikeys", data={"name": "hr", "scope": ["producer:write"], "cidrs": "10.0.0.0/8",
                                       "csrf_token": csrf(c, "/admin/apikeys")})
    key = re.search(r"(biam_[0-9a-f]+_[\w-]+)", r.get_data(as_text=True)).group(1)
    assert key not in c.get("/admin/apikeys").get_data(as_text=True)
    with database.engine.connect() as conn:
        assert key not in str(conn.execute(database.tables.api_keys.select()).all())


def test_admin_cannot_lock_themselves_out(make_web):
    c = make_web()
    login(c)
    c.post("/admin/users/boss/role", data={"role": "viewer", "csrf_token": csrf(c, "/admin/users")})
    assert b"remove your own admin role" in c.get("/admin/users").data


def test_producer_pages_render_and_escape(make_web, database):
    evil = "<script>alert(1)</script>"
    ProducerStore(database).record_activity({
        "employee_id": evil, "type": "hire", "event_id": "m1", "ok": True, "duplicate": False,
        "user_id": "u1", "error": None, "actions": ["user created"], "warnings": [],
        "instructions": [{"op": "create", "object_class": "user", "key": {"employeeID": evil},
                          "why": {"summary": evil}}]})
    store = Store(database)
    with store.connect() as conn:
        store.add_events(conn, [{"event_id": "e1", "type": "producer.hire", "entity": "user",
                                 "entity_id": "u1", "why": {"source": "source-of-truth", "summary": evil},
                                 "instructions": [{"op": "create", "object_class": "user",
                                                   "key": {"employeeID": evil}}]}])
    c = make_web()
    login(c)
    entry = ProducerStore(database).activity_page()[0]["id"]
    for path in ["/", "/producer", f"/producer/{entry}", "/outbox", "/outbox/1", "/runs",
                 "/requests", "/admin/apikeys", "/admin/users", "/admin/audit", "/account"]:
        r = c.get(path)
        assert r.status_code == 200, path
        assert evil.encode() not in r.data, path
    rows = AuditTrail(database).page(actor="producer:boss")
    assert {"login", "view"} <= {r["action"] for r in rows}


def test_consumer_site_pages_and_operator_actions(make_web, database):
    cs = ConsumerStore(database)
    cs.save_file(sha256="ab" * 32, name="openiam-corp-20260101T000000000000Z.zip", domain="corp",
                 generated_at="2026-01-01T00:00:00+00:00", status="awaiting_approval", received_at=1.0,
                 processed_at=2.0, summary={"changes": 1})
    cs.save_domain("corp", "2026-01-01T00:00:00+00:00", "ab" * 32, 1)
    plan_id = cs.save_plan(file_sha256="ab" * 32, domain="corp", mode="approve", status="awaiting_approval",
                           lines=[], summary={"changes": 1},
                           items=[{"seq": 1, "op": "create", "object_class": "user",
                                   "key": {"employeeID": "E1"}, "ldap": "add", "dn": "CN=x"}])
    cs.add_alerts([{"dn": "CN=Domain Admins,CN=Users,DC=corp", "object_class": "group", "kind": "modified",
                    "severity": "critical", "changes": {"member": {"added": ["cn=x"], "removed": []}}}])
    add_user(database, "otto", "operator")
    c = make_web("consumer", consumer_target="ad")
    login(c, "otto", "a-long-password-1")
    for path in ["/", "/files", f"/files/{'ab' * 32}", "/actions", "/ad/plans", f"/ad/plans/{plan_id}",
                 "/ad/changes", "/drift", "/requests"]:
        assert c.get(path).status_code == 200, path
    assert b"Domain Admins" in c.get("/ad/changes").data

    c.post(f"/ad/plans/{plan_id}/approve", data={"csrf_token": csrf(c, f"/ad/plans/{plan_id}")})
    c.post("/drift", data={"domain": "corp", "csrf_token": csrf(c, "/drift")})
    assert [r["action"] for r in OperatorRequests(database).page("consumer")] == ["drift", "ad_approve"]

    [alert] = cs.alerts_page(open_only=True)
    c.post(f"/ad/changes/{alert['id']}/ack", data={"note": "approved change", "csrf_token": csrf(c, "/ad/changes")})
    assert cs.alerts_page(open_only=True) == []
    assert cs.alerts_page()[0]["acknowledged_by"] == "web:otto"


def test_the_two_uis_use_different_cookies(make_web):
    p, o = make_web("producer"), make_web("consumer")
    login(p)
    login(o)
    assert {c.key for c in p._cookies.values()} == {"biam_producer"}
    assert {c.key for c in o._cookies.values()} == {"biam_consumer"}
