"""MFA, approver scope, multi-person approval, tamper-evident audit trail."""

import base64
import re
import time

import pytest
from sqlalchemy import update

from app.operator import ApprovalError, OperatorRequests, in_scope
from app.security import AuditTrail
from app.web.auth import WebUserStore
from app.web.mfa import code_at, seal, unseal, verify, MfaError, STEP

from .test_web import ADMIN_PW, add_user, csrf, login, make_web  # noqa: F401 (fixture)


def now_code(secret: str, offset: int = 0) -> str:
    return code_at(secret, int(time.time() // STEP) + offset)


# ---- TOTP --------------------------------------------------------------------------

def test_totp_matches_rfc_6238_vector():
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert code_at(secret, 59 // 30) == "287082"           # RFC 6238 T=59, last 6 digits
    assert code_at(secret, 1111111109 // 30) == "081804"


def test_totp_rejects_replay_and_far_codes():
    secret = base64.b32encode(b"12345678901234567890").decode()
    t = 1_700_000_000
    c = int(t // STEP)
    assert verify(secret, code_at(secret, c), None, now=t) == c
    assert verify(secret, code_at(secret, c), c, now=t) is None          # already used
    assert verify(secret, code_at(secret, c - 5), None, now=t) is None   # too old
    assert verify(secret, "12345", None, now=t) is None


def test_sealed_secret_needs_the_right_key():
    sealed = seal("ABCDEF", "key-one")
    assert unseal(sealed, "key-one") == "ABCDEF"
    with pytest.raises(MfaError):
        unseal(sealed, "key-two")
    with pytest.raises(MfaError):
        seal("ABCDEF", "")


# ---- MFA in the web UI -----------------------------------------------------------

def enroll(c) -> tuple[str, list[str]]:
    page = c.get("/account/mfa").get_data(as_text=True)
    secret = re.search(r'<div class="secret">([A-Z2-7]+)</div>', page).group(1)
    r = c.post("/account/mfa/enable", data={"csrf_token": csrf(c, "/account"), "code": now_code(secret)})
    block = re.search(r'<div class="secret">(.*?)</div>', r.get_data(as_text=True), re.S).group(1)
    codes = re.findall(r"([a-z2-9]{5}-[a-z2-9]{5})", block)
    assert len(codes) == 10
    return secret, codes


def test_mfa_enrol_then_login_needs_a_code(make_web, database):
    c = make_web()
    login(c)
    secret, codes = enroll(c)
    assert c.get("/").status_code == 200                    # enrolling kept this session
    # A new sign-in stops after the password.
    d = make_web()
    r = login(d)
    assert r.headers["Location"].endswith("/login/mfa")
    assert d.get("/").status_code == 302                    # not signed in yet
    t = csrf(d, "/login/mfa")
    assert d.post("/login/mfa", data={"csrf_token": t, "code": "000000"}).status_code == 401
    # The step used at enrolment cannot be replayed; the next one works.
    WebUserStore(database)._set("boss", totp_last_counter=int(time.time() // STEP) - 2)
    r = d.post("/login/mfa", data={"csrf_token": t, "code": now_code(secret)})
    assert r.status_code == 302 and d.get("/").status_code == 200
    # A recovery code works once.
    e = make_web()
    login(e)
    t = csrf(e, "/login/mfa")
    assert e.post("/login/mfa", data={"csrf_token": t, "kind": "recovery", "code": codes[0]}).status_code == 302
    f = make_web()
    login(f)
    t = csrf(f, "/login/mfa")
    assert f.post("/login/mfa", data={"csrf_token": t, "kind": "recovery", "code": codes[0]}).status_code == 401
    assert "totp_secret" not in WebUserStore(database).list()[0]          # never listed


def test_too_many_wrong_codes_restart_sign_in(make_web):
    c = make_web()
    login(c)
    enroll(c)
    d = make_web()
    login(d)
    t = csrf(d, "/login/mfa")
    for _ in range(4):
        assert d.post("/login/mfa", data={"csrf_token": t, "code": "000000"}).status_code == 401
    r = d.post("/login/mfa", data={"csrf_token": t, "code": "000000"})
    assert r.headers["Location"].endswith("/login")


def test_required_role_must_enrol_before_anything_else(make_web):
    c = make_web(web_mfa_required_role="admin")
    login(c)
    r = c.get("/directory")
    assert r.status_code == 302 and r.headers["Location"].endswith("/account/mfa")
    assert c.get("/account/mfa").status_code == 200
    enroll(c)
    assert c.get("/directory").status_code == 200


def test_mfa_needs_a_configured_secret_key(database):
    from app.config import Settings
    from app.web import create_app
    app = create_app(Settings(_env_file=None, web_username="boss", web_password=ADMIN_PW,
                              web_cookie_secure=False, web_secret_key=""), database)
    app.testing = True
    c = app.test_client()
    login(c)
    r = c.get("/account/mfa")
    assert r.status_code == 302                              # refused, with a message
    assert "WEB_SECRET_KEY" in c.get("/account").get_data(as_text=True)


def test_admin_resets_someone_elses_mfa(make_web, database):
    add_user(database, "mia", "admin")
    add_user(database, "zed", "admin")
    c = make_web()
    login(c, "mia", "a-long-password-1")
    enroll(c)
    boss = make_web()
    login(boss, "zed", "a-long-password-1")
    boss.post("/admin/users/mia/mfa-reset", data={"csrf_token": csrf(boss, "/admin/users")})
    assert WebUserStore(database).get("mia")["totp_secret"] is None
    r = boss.post("/admin/users/zed/mfa-reset", data={"csrf_token": csrf(boss, "/admin/users")})
    assert r.status_code == 302                              # refused for yourself (flash)


# ---- approvals -------------------------------------------------------------------

def test_destructive_changes_need_two_approvers(database):
    reqs = OperatorRequests(database)
    rid = reqs.create("producer", "directory", {"op": "delete", "kind": "group", "name": "G"}, "web:otto")
    assert reqs.get(rid)["required_approvals"] == 2
    assert reqs.decide(rid, True, "web:mia") == "awaiting_approval"
    with pytest.raises(ApprovalError, match="already approved"):
        reqs.decide(rid, True, "web:mia")
    assert reqs.decide(rid, True, "web:boss") == "pending"
    assert reqs.get(rid)["decided_by"] == "web:mia, web:boss"
    other = reqs.create("producer", "directory", {"op": "create", "kind": "group", "name": "H"}, "web:otto")
    assert reqs.get(other)["required_approvals"] == 1
    assert reqs.decide(other, False, "web:mia") == "rejected"


def test_approver_scope():
    assert in_scope(None, {"domain": "x"}) and in_scope([], {})
    assert in_scope(["corp.example"], {"domain": "Corp.Example"})
    assert not in_scope(["corp.example"], {"domain": "lab.example"})
    assert not in_scope(["corp.example"], {"kind": "group", "name": "G"})   # names no domain
    assert in_scope(["Lagos"], {"kind": "organization", "name": "Lagos"})


def test_web_scope_blocks_approval_outside_it(make_web, database):
    add_user(database, "otto", "operator")
    add_user(database, "mia", "admin")
    WebUserStore(database).set_approver_scope("mia", ["corp.example"])
    reqs = OperatorRequests(database)
    rid = reqs.create("producer", "directory", {"via": "ad", "op": "create", "kind": "group", "name": "G",
                                                "domain": "lab.example", "jira_ticket": "IAM-1",
                                                "reason": "x" * 12}, "web:otto")
    c = make_web()
    login(c, "mia", "a-long-password-1")
    assert "outside your approval scope" in c.get("/approvals").get_data(as_text=True)
    c.post(f"/approvals/{rid}/approve", data={"csrf_token": csrf(c, "/approvals")})
    assert reqs.get(rid)["status"] == "awaiting_approval"


# ---- audit chain -----------------------------------------------------------------

def test_audit_chain_detects_changes_and_deletions(database):
    a = AuditTrail(database)
    for i in range(5):
        a.record("web", "producer:boss", "test", ok=True, target=str(i))
    assert a.verify() == {"ok": True, "checked": 5, "first_bad_id": None, "problem": None}
    t = database.tables.audit_trail
    with database.begin() as conn:
        conn.execute(update(t).where(t.c.id == 3).values(detail="covered up"))
    bad = a.verify()
    assert not bad["ok"] and bad["first_bad_id"] == 3 and "changed" in bad["problem"]
    with database.begin() as conn:
        conn.execute(update(t).where(t.c.id == 3).values(detail=None))
        conn.execute(t.delete().where(t.c.id == 2))
    bad = a.verify()
    assert not bad["ok"] and bad["first_bad_id"] == 3 and "removed" in bad["problem"]


def test_audit_verify_button(make_web):
    c = make_web()
    login(c)
    c.post("/admin/audit/verify", data={"csrf_token": csrf(c, "/admin/audit")})
    assert "Audit trail intact" in c.get("/admin/audit").get_data(as_text=True)
