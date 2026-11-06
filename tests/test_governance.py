"""Segregation of duties, access certification and reports."""

import pytest

from app.governance import Governance, GovernanceError, report_csv
from app.operator import OperatorRequests
from app.producer import ProducerStore
from app.sync import Store

from .test_web import add_user, csrf, login, make_web  # noqa: F401 (fixture)


def seed(database):
    store = Store(database)
    with store.connect() as conn:
        store.upsert_state(conn, "user", "u1", "h", {"id": "u1", "employeeId": "E1", "firstName": "Ada",
                                                     "groups": [{"name": "AP-Pay"}], "roles": ["Viewer"]})
        store.upsert_state(conn, "user", "u2", "h", {"id": "u2", "employeeId": "E2", "firstName": "Bob",
                                                     "groups": [{"name": "AP-Pay"}, {"name": "AP-Approve"}]})
    ps = ProducerStore(database)
    ps.remember("group", "Staff", "g-staff")
    ps.add_memberships("E1", "group", {"g-staff"})


def test_entitlements_merge_producer_and_snapshot(database):
    seed(database)
    ents = Governance(database).entitlements()
    assert ents[("E1", "group", "Staff")] == "producer"
    assert ents[("E1", "group", "AP-Pay")] == "openiam"
    assert ("E1", "role", "Viewer") in ents and ("E2", "group", "AP-Approve") in ents


def test_sod_reports_violations_and_blocks_new_toxic_combinations(database):
    seed(database)
    gov = Governance(database)
    pid = gov.add_policy("Pay vs approve", ("group", "AP-Pay"), ("group", "AP-Approve"), "web:boss")
    assert [v["employee_id"] for v in gov.violations()] == ["E2"]
    add = {"op": "add_member", "kind": "group", "name": "AP-Approve", "member_kind": "user", "member": "E1"}
    assert gov.check_request(add) and "Pay vs approve" in gov.check_request(add)[0]
    hire = {"op": "create", "kind": "user", "name": "E3", "groups": ["AP-Pay", "AP-Approve"]}
    assert gov.check_request(hire)
    assert gov.check_request({**add, "name": "Other"}) == []
    gov.set_policy_enabled(pid, False)
    assert gov.check_request(add) == [] and gov.violations() == []
    with pytest.raises(GovernanceError):
        gov.add_policy("Same", ("group", "A"), ("group", "A"), "web:boss")
    with pytest.raises(GovernanceError):
        gov.add_policy("Bad kind", ("user", "A"), ("group", "B"), "web:boss")


def test_certification_campaign(database):
    seed(database)
    gov = Governance(database)
    cid = gov.start_campaign("Q4 groups", "web:boss", scope_kind="group")
    items = gov.items(cid)
    assert {(i["employee_id"], i["object_name"]) for i in items} == {
        ("E1", "AP-Pay"), ("E1", "Staff"), ("E2", "AP-Pay"), ("E2", "AP-Approve")}
    gov.decide_item(items[0]["id"], "certify", "web:otto")
    with pytest.raises(GovernanceError, match="already"):
        gov.decide_item(items[0]["id"], "revoke", "web:otto")
    gov.close_campaign(cid, "web:boss")
    with pytest.raises(GovernanceError, match="closed"):
        gov.decide_item(items[1]["id"], "certify", "web:otto")
    c = gov.campaign(cid)
    assert (c["total"], c["certified"], c["status"]) == (4, 1, "closed")
    with pytest.raises(GovernanceError, match="nothing"):
        gov.start_campaign("empty", "web:boss", scope_name="No-Such-Group")


def test_report_csv_neutralises_formulas():
    out = report_csv([{"name": "=HYPERLINK(\"http://evil\")", "n": "-1+1", "ok": "Ada", "x": ["a"]}])
    lines = out.splitlines()
    assert lines[0] == "name,n,ok,x"
    assert lines[1].startswith("\"'=HYPERLINK") and ",'-1+1," in lines[1]


def test_web_governance_flow(make_web, database):
    seed(database)
    add_user(database, "otto", "operator")
    add_user(database, "mia", "admin")
    admin = make_web()
    login(admin, "mia", "a-long-password-1")
    t = csrf(admin, "/governance")
    admin.post("/governance/sod", data={"csrf_token": t, "name": "Pay vs approve", "left_kind": "group",
                                        "left_name": "AP-Pay", "right_kind": "group",
                                        "right_name": "AP-Approve"})
    assert b"Pay vs approve" in admin.get("/governance").data
    r = admin.post("/governance/campaigns", data={"csrf_token": t, "name": "Q4", "scope_kind": "group"})
    cid = int(r.headers["Location"].rsplit("/", 1)[1])

    op = make_web()
    login(op, "otto", "a-long-password-1")
    assert op.post("/governance/sod", data={"csrf_token": csrf(op, "/governance"), "name": "x"}).status_code == 403
    # SoD blocks the directory request outright.
    op.post("/directory/request", data={"csrf_token": csrf(op, "/directory"), "via": "ad", "kind": "group",
                                        "op": "add_member", "name": "AP-Approve", "member_kind": "user",
                                        "member": "E1", "jira_ticket": "IAM-5",
                                        "reason": "moving to approvals team"})
    assert OperatorRequests(database).page("producer") == []
    # Revoking in a campaign saves a removal request that still needs approval.
    item = next(i for i in Governance(database).items(cid)
                if (i["employee_id"], i["object_name"]) == ("E2", "AP-Approve"))
    t = csrf(op, f"/governance/campaigns/{cid}")
    op.post(f"/governance/items/{item['id']}/revoke", data={"csrf_token": t, "note": "left AP team"})
    assert OperatorRequests(database).page("producer") == []          # no Jira ticket: refused
    op.post(f"/governance/items/{item['id']}/revoke", data={"csrf_token": t, "note": "left AP team",
                                                            "jira_ticket": "iam-77"})
    [req] = OperatorRequests(database).page("producer")
    assert req["status"] == "awaiting_approval" and req["params"]["op"] == "remove_member"
    assert req["params"]["member"] == "E2" and req["params"]["jira_ticket"] == "IAM-77"
    for name in ["users", "entitlements", "sod-violations", "certifications", "requests"]:
        r = op.get(f"/reports/{name}.csv")
        assert r.status_code == 200 and r.mimetype == "text/csv", name
        assert "attachment" in r.headers["Content-Disposition"]
    assert b"E2" in op.get("/reports/sod-violations.csv").data
    assert op.get("/reports/../etc.csv").status_code == 404
