"""Directory changes from the web UI: saved for approval, then OpenIAM and / or AD instructions."""

import asyncio

import pytest

from app.directory import DirectoryError, DirectoryRequest, DirectoryService
from app.operator import ApprovalError, OperatorRequests
from app.producer import ProducerConfig, ProducerProcessor, ProducerStore
from app.sync import Store, SyncConfig, SyncService

from .test_web import add_user, csrf, login, make_web  # noqa: F401 (fixture)

GROUPS = "/webconsole/rest/api/groups"
# Every directory request names a Jira ticket and a justification.
J = {"jira_ticket": "IAM-101", "reason": "needed for the test case"}


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def sync(database, make_client, tmp_path):
    cfg = SyncConfig.model_validate({
        "entities": {"user": {"path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}]},
                     "group": {"path": f"{GROUPS}/search", "queries": [{"name": "*"}]}},
        "export": {"folder": str(tmp_path / "share"),
                   "domains": {"by_field": {"user": "domain", "group": "domain"}}},
    })
    return SyncService(make_client(), Store(database), cfg, None)


@pytest.fixture
def service(sync, database, make_client, settings):
    cfg = ProducerConfig.model_validate({"directories": {"group": {
        "search_path": f"{GROUPS}/search", "create_path": f"{GROUPS}/save",
        "create_body": {"name": "{name}", "description": "{description}"}}}})
    producer = ProducerProcessor(make_client(), ProducerStore(database), cfg, settings,
                                 ad=sync.cfg.ad, outbox=sync.store)
    return DirectoryService(make_client(), producer=producer, sync=sync)


def queued(sync):
    return [e for e in sync.store.pending_all()]


def test_group_via_openiam_creates_it_and_queues_the_ad_instruction(service, sync, fake):
    out = run(service.handle({**J, "via": "openiam", "kind": "group", "op": "create", "name": "GRP-Ops",
                              "description": "Operations", "domain": "corp.example"}))
    assert [g["name"] for g in fake.groups.values()] == ["GRP-Ops"]
    [event] = queued(sync)
    [ins] = event["instructions"]
    assert (ins["op"], ins["object_class"], ins["key"]) == ("create", "group", {"cn": "GRP-Ops"})
    assert ins["attributes"] == {"cn": "GRP-Ops", "description": "Operations"}
    assert ins["why"]["source"] == "web-operator" and event["data"]["domain"] == "corp.example"
    assert out["instructions"] == 1


def test_ad_only_leaves_openiam_alone(service, sync, fake):
    run(service.handle({**J, "via": "ad", "kind": "group", "op": "create", "name": "GRP-AD-Only"}))
    assert fake.groups == {}
    assert queued(sync)[0]["instructions"][0]["why"]["via"] == "ad"


def test_nested_group_is_member_of_another_group(service, sync, fake):
    fake.groups.update({"g1": {"id": "g1", "name": "Parent"}, "g2": {"id": "g2", "name": "Child"}})
    run(service.handle({**J, "via": "ad", "kind": "group", "op": "add_member", "name": "Parent",
                        "member_kind": "group", "member": "Child"}))
    [ins] = queued(sync)[0]["instructions"]
    assert ins["op"] == "add_member" and ins["key"] == {"cn": "Parent"}
    assert ins["member"]["object_class"] == "group" and ins["member"]["key"] == {"cn": "Child"}
    # Via OpenIAM it needs the (unpublished) nesting endpoint configured.
    with pytest.raises(DirectoryError, match="add_child_path"):
        run(service.handle({**J, "via": "openiam", "kind": "group", "op": "add_member", "name": "Parent",
                            "member_kind": "group", "member": "Child"}))


def test_user_via_openiam_goes_through_the_producer_engine(service, sync, fake):
    out = run(service.handle({**J, "via": "openiam", "kind": "user", "op": "create", "name": "E9",
                              "first_name": "Kat", "last_name": "Johnson", "email": "kat@corp.example",
                              "login": "kjohnson", "domain": "corp.example"}))
    [user] = fake.users.values()
    assert user["employeeId"] == "E9" and user["domain"] == "corp.example"
    assert "user created" in out["actions"]
    assert ProducerStore(service.producer.store.db).get_person("E9") is not None
    ops = [i["op"] for e in queued(sync) for i in e["instructions"]]
    assert ops == ["create"]


def test_requests_are_validated_strictly():
    bad = [
        {"via": "ad", "kind": "group", "op": "enable", "name": "G"},                 # users only
        {"via": "ad", "kind": "user", "op": "create", "name": "E1"},                 # no names
        {"via": "ad", "kind": "group", "op": "update", "name": "G", "new_name": "H"},  # AD rename
        {"via": "ad", "kind": "role", "op": "add_member", "name": "R", "member_kind": "group",
         "member": "G"},                                                              # nesting: groups only
        {"via": "ad", "kind": "group", "op": "create", "name": "G\nx"},             # control char
        {"via": "ad", "kind": "group", "op": "create", "name": "G" * 300},          # too long
        {"via": "ad", "kind": "group", "op": "create", "name": "G", "surprise": 1},  # unknown field
        {"via": "ldap", "kind": "group", "op": "create", "name": "G"},              # no direct AD
    ]
    for params in bad:
        with pytest.raises(ValueError):
            DirectoryRequest.model_validate({**J, **params})


def test_directory_requests_wait_for_someone_elses_approval(database):
    reqs = OperatorRequests(database)
    rid = reqs.create("producer", "directory", {"via": "ad", "kind": "group", "op": "create",
                                                "name": "G"}, "web:otto")
    assert reqs.get(rid)["status"] == "awaiting_approval"
    ran = []

    async def handler(params):
        ran.append(params)
        return {"ok": True}
    assert run(reqs.run_pending("producer", {"directory": handler})) == 0 and ran == []
    with pytest.raises(ApprovalError, match="someone else"):
        reqs.decide(rid, True, "web:otto")
    reqs.decide(rid, True, "web:boss", "ticket 42")
    assert run(reqs.run_pending("producer", {"directory": handler})) == 1
    assert reqs.get(rid)["status"] == "done" and reqs.get(rid)["decided_by"] == "web:boss"

    rid2 = reqs.create("producer", "directory", {"via": "ad", "kind": "group", "op": "delete",
                                                 "name": "G"}, "web:otto")
    reqs.decide(rid2, False, "web:boss")
    assert reqs.get(rid2)["status"] == "rejected"
    with pytest.raises(ApprovalError):
        reqs.decide(rid2, True, "web:boss")
    assert run(reqs.run_pending("producer", {"directory": handler})) == 0


def test_web_directory_pages_save_for_approval(make_web, database):
    store = Store(database)
    evil = "<script>alert(1)</script>"
    with store.connect() as conn:
        store.upsert_state(conn, "user", "u1", "h", {"id": "u1", "employeeId": "E1", "firstName": evil,
                                                     "lastName": "L", "domain": "corp"})
        store.upsert_state(conn, "group", "g1", "h", {"id": "g1", "name": "Staff"})
    add_user(database, "otto", "operator")
    add_user(database, "mia", "admin")
    c = make_web()
    login(c, "otto", "a-long-password-1")
    for path in ["/directory", "/directory?kind=group", "/directory/user/new", "/directory/group/new",
                 "/directory/user/view?name=E1", "/directory/group/view?name=Staff"]:
        r = c.get(path)
        assert r.status_code == 200, path
        assert evil.encode() not in r.data, path
    assert c.get("/approvals").status_code == 403          # operators cannot approve
    r = c.post("/directory/request", data={"csrf_token": csrf(c, "/directory/group/new"), "via": "ad",
                                           "kind": "group", "op": "create", "name": "GRP-New",
                                           "jira_ticket": "iam-7", "reason": "new team needs a group",
                                           "back": "https://evil.example/"})
    assert r.headers["Location"] == "/directory"
    [req] = OperatorRequests(database).page("producer")
    assert req["status"] == "awaiting_approval" and req["requested_by"] == "web:otto"
    assert req["params"]["requested_by"] == "otto" and req["params"]["jira_ticket"] == "IAM-7"

    boss = make_web()
    login(boss, "mia", "a-long-password-1")
    assert b"GRP-New" in boss.get("/approvals").data
    boss.post(f"/approvals/{req['id']}/approve", data={"csrf_token": csrf(boss, "/approvals")})
    assert OperatorRequests(database).get(req["id"])["status"] == "pending"


def test_static_assets_theme_and_strict_csp(make_web):
    c = make_web()
    for path in ["/static/app.js", "/static/app.css", "/static/vendor/jquery.min.js",
                 "/static/vendor/dataTables.min.js"]:
        r = c.get(path)                                   # also before login
        assert r.status_code == 200, path
        assert r.mimetype in ("text/javascript", "text/css"), path
    csp = c.get("/login").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    login(c)
    page = c.get("/").get_data(as_text=True)
    assert "<style>" not in page and "<script>" not in page and 'integrity="sha384-' in page
    c.post("/theme", data={"theme": "dark", "csrf_token": csrf(c, "/")},
           headers={"Referer": "http://localhost//evil.example/"})
    assert 'data-theme="dark"' in c.get("/").get_data(as_text=True)
    r = c.post("/theme", data={"theme": "<x>", "csrf_token": csrf(c, "/")})
    assert r.headers["Location"] == "/"
    assert 'data-theme="dark"' in c.get("/").get_data(as_text=True)


def test_organization_type_goes_to_openiam_and_ad(sync, database, make_client, settings, fake):
    cfg = ProducerConfig.model_validate({
        "organization_type_ids": {"branch": "ORG-TYPE-BRANCH"},
        "directories": {"organization": {
            "search_path": "/webconsole/rest/api/organizations/search",
            "create_path": f"{GROUPS}/save",      # the fake stores whatever it is sent
            "create_body": {"name": "{name}", "organizationTypeId": "{type_id}", "label": "{type}"}}}})
    svc = DirectoryService(make_client(), sync=sync, producer_cfg=cfg)
    run(svc.handle({**J, "via": "openiam", "kind": "organization", "op": "create", "name": "Lagos",
                    "org_type": "branch", "description": "West Africa"}))
    [sent] = fake.groups.values()
    assert sent["organizationTypeId"] == "ORG-TYPE-BRANCH" and sent["label"] == "Branch"
    [ins] = queued(sync)[0]["instructions"]
    assert ins["object_class"] == "organizationalUnit"
    assert ins["attributes"] == {"ou": "Lagos", "description": "West Africa", "businessCategory": "Branch"}
    for bad in ({"kind": "organization", "org_type": "galaxy"}, {"kind": "group", "org_type": "office"}):
        with pytest.raises(ValueError):
            DirectoryRequest.model_validate({**J, "via": "ad", "op": "create", "name": "X", **bad})


def test_ticket_and_justification_are_required_and_travel_with_the_change(service, sync):
    base = {"via": "ad", "kind": "group", "op": "create", "name": "G"}
    for bad in ({}, {"jira_ticket": "IAM-1"}, {"jira_ticket": "IAM-1", "reason": "too short"},
                {"jira_ticket": "not a key", "reason": "long enough justification"},
                {"jira_ticket": "IAM-0", "reason": "long enough justification"}):
        with pytest.raises(DirectoryError):
            run(service.handle({**base, **bad}))
    out = run(service.handle({**base, "jira_ticket": "iam-42", "reason": "new team needs a group"}))
    assert out["jira_ticket"] == "IAM-42"
    [ins] = queued(sync)[0]["instructions"]
    assert ins["why"]["jira_ticket"] == "IAM-42" and ins["why"]["summary"].startswith("IAM-42:")
    assert ins["reason"] == "IAM-42: new team needs a group"


def test_jira_links_only_for_valid_keys(make_web, database):
    from app.operator import OperatorRequests as R
    R(database).create("producer", "directory", {"via": "ad", "kind": "group", "op": "create", "name": "G",
                                                  "jira_ticket": "IAM-9", "reason": "x" * 12}, "web:otto")
    R(database).create("producer", "directory", {"via": "ad", "kind": "group", "op": "create", "name": "H",
                                                  "jira_ticket": "javascript:alert(1)", "reason": "x" * 12},
                       "web:otto")
    c = make_web(jira_base_url="https://acme.atlassian.net/")
    login(c)
    page = c.get("/approvals").get_data(as_text=True)
    assert 'href="https://acme.atlassian.net/browse/IAM-9"' in page
    assert 'href="javascript' not in page and "javascript:alert(1)" in page   # shown, not linked
    assert make_web(jira_base_url="javascript:alert(1)//") is not None          # bad base: links off
