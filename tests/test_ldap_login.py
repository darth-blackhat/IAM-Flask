"""Sign-in through AD (read-only LDAP), the auth mode switch, and the auditor role."""

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from app.config import Settings
from app.operator import OperatorRequests
from app.web.auth import WebUserStore, allowed
from app.web.ldap_auth import LdapAuth, LdapUnavailable

from .conftest import ADMIN_PW
from .test_web import add_user, csrf

BASE = "DC=corp,DC=example"
OU = f"OU=Staff,{BASE}"
ADMINS, AUDITORS = f"CN=GRP-IAM-Admins,{OU}", f"CN=GRP-IAM-Auditors,{OU}"


@pytest.fixture
def directory(monkeypatch):
    """A mock AD: ada is an admin through a nested group, bob an auditor, carl in nothing."""
    server = Server("mock-dc", get_info=OFFLINE_AD_2012_R2)
    seed = Connection(server, user=f"CN=svc-iam,{OU}", password="svc-pw", client_strategy=MOCK_SYNC)
    add = seed.strategy.add_entry
    add(f"CN=svc-iam,{OU}", {"objectClass": ["user"], "userPassword": "svc-pw", "sAMAccountName": "svc-iam"})
    for cn, pw in (("ada", "ada-pw-123"), ("bob", "bob-pw-123"), ("carl", "carl-pw-123"), ("boss", "ad-boss-pw")):
        add(f"CN={cn},{OU}", {"objectClass": ["top", "person", "organizationalPerson", "user"],
                              "objectCategory": "person", "sAMAccountName": cn, "userPassword": pw,
                              "displayName": cn.title()})
    add(f"CN=GRP-Helpdesk,{OU}", {"objectClass": ["top", "group"], "member": [f"CN=ada,{OU}"]})
    add(ADMINS, {"objectClass": ["top", "group"], "member": [f"CN=GRP-Helpdesk,{OU}", f"CN=boss,{OU}"]})
    add(AUDITORS, {"objectClass": ["top", "group"], "member": [f"CN=bob,{OU}"]})

    def connect(self, user, password):
        conn = Connection(server, user=user, password=password, client_strategy=MOCK_SYNC, read_only=True)
        conn.bind()
        return conn
    monkeypatch.setattr(LdapAuth, "_real_connect", connect)
    return server


def ldap_settings(**over):
    base = dict(web_ldap_base_dn=BASE, web_ldap_bind_dn=f"CN=svc-iam,{OU}", web_ldap_bind_password="svc-pw",
                web_ldap_group_admin=ADMINS, web_ldap_group_auditor=AUDITORS)
    return {**base, **over}


def auth() -> LdapAuth:
    return LdapAuth(Settings(_env_file=None, **ldap_settings()))


def test_roles_from_nested_groups(directory):
    info, _ = auth().authenticate("ada", "ada-pw-123")
    assert (info["username"], info["role"]) == ("ada", "admin")             # via GRP-Helpdesk
    assert auth().authenticate("bob", "bob-pw-123")[0]["role"] == "auditor"
    assert auth().authenticate("carl", "carl-pw-123") == (None, "not in any AD group that gives access")


def test_bad_credentials_and_injection_are_refused(directory):
    a = auth()
    assert a.authenticate("ada", "wrong")[0] is None
    assert a.authenticate("ada", "") == (None, "empty password")
    for evil in ("*", "ada)(objectClass=*", "a*", "ad a", "../x"):
        assert a.authenticate(evil, "x")[0] is None
    assert a.authenticate("nobody", "x") == (None, "unknown AD account")


def test_service_account_failure_is_unavailable_not_wrong_password(directory):
    a = LdapAuth(Settings(_env_file=None, **ldap_settings(web_ldap_bind_password="wrong")))
    with pytest.raises(LdapUnavailable):
        a.authenticate("ada", "ada-pw-123")


def test_plain_ldap_is_refused():
    a = LdapAuth(Settings(_env_file=None, **ldap_settings(web_ldap_urls="ldap://dc1.corp.example")))
    with pytest.raises(LdapUnavailable, match="plain LDAP refused"):
        a._real_connect("x", "y")


def signin(client, user, pw):
    return client.post("/login", data={"username": user, "password": pw, "next": "/",
                                       "csrf_token": csrf(client)})


def test_mode_ldap_signs_in_ad_users_only(make_web, database, directory):
    c = make_web(web_auth_mode="ldap", **ldap_settings())
    assert signin(c, "ada", "ada-pw-123").status_code == 302 and c.get("/").status_code == 200
    me = WebUserStore(database).get("ada")
    assert (me["auth_source"], me["role"]) == ("ldap", "admin") and me["password_hash"] == "!external"
    d = make_web(web_auth_mode="ldap", **ldap_settings())
    add_user(database, "localonly", "admin")
    assert signin(d, "localonly", "a-long-password-1").status_code == 401   # local accounts off
    assert signin(d, "carl", "carl-pw-123").status_code == 401              # no mapped group


def test_mode_both_falls_back_to_local_and_never_takes_over(make_web, database, directory, monkeypatch):
    c = make_web(web_auth_mode="both", **ldap_settings())
    # "boss" is the bootstrapped LOCAL admin; an AD account with the same name must not take it over.
    assert signin(c, "boss", "ad-boss-pw").status_code == 401
    assert WebUserStore(database).get("boss")["auth_source"] in (None, "local")
    assert signin(c, "boss", ADMIN_PW).status_code == 302                   # local still works

    def down(self, user, password):
        raise LdapUnavailable("AD unreachable: test")
    monkeypatch.setattr(LdapAuth, "_real_connect", down)
    d = make_web(web_auth_mode="both", **ldap_settings())
    assert signin(d, "boss", ADMIN_PW).status_code == 302                   # break-glass while AD is down


def test_ad_role_change_applies_at_next_sign_in(make_web, database, directory):
    c = make_web(web_auth_mode="ldap", **ldap_settings())
    signin(c, "bob", "bob-pw-123")
    assert WebUserStore(database).get("bob")["role"] == "auditor"
    d = make_web(web_auth_mode="ldap", **ldap_settings(web_ldap_group_operator=AUDITORS, web_ldap_group_auditor=""))
    signin(d, "bob", "bob-pw-123")
    assert WebUserStore(database).get("bob")["role"] == "operator"
    assert c.get("/").status_code == 302                                    # old session ended (role changed)
    with pytest.raises(ValueError, match="AD"):
        WebUserStore(database).set_password("bob", "a-new-long-password")


def test_auditor_reads_but_never_acts(make_web, database):
    assert allowed("auditor", "admin|auditor") and not allowed("operator", "admin|auditor")
    assert allowed("admin", "admin|auditor") and not allowed("auditor", "operator")
    add_user(database, "aud", "auditor")
    add_user(database, "otto", "operator")
    rid = OperatorRequests(database).create("producer", "directory", {"op": "create", "kind": "group", "name": "G",
                                                                      "jira_ticket": "IAM-1", "reason": "x" * 12}, "web:otto")
    c = make_web()
    signin(c, "aud", "a-long-password-1")
    for path in ["/admin/audit", "/approvals", "/reports", "/reports/users.csv", "/admin/notifications", "/requests"]:
        assert c.get(path).status_code == 200, path
    for path in ["/admin/users", "/directory/group/new", "/admin/apikeys"]:
        assert c.get(path).status_code == 403, path
    page = c.get("/approvals").get_data(as_text=True)
    assert "waiting for an approver" in page and f"/approvals/{rid}/approve" not in page
    t = csrf(c, "/approvals")
    assert c.post(f"/approvals/{rid}/approve", data={"csrf_token": t}).status_code == 403
    assert c.post("/directory/request", data={"csrf_token": t, "via": "ad", "kind": "group", "op": "create",
                                              "name": "X", "jira_ticket": "IAM-2",
                                              "reason": "auditor tries to act"}).status_code == 403
    o = make_web()
    signin(o, "otto", "a-long-password-1")
    assert o.get("/admin/audit").status_code == 403                         # operators do not read the audit trail
