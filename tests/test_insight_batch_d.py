"""Role mining, peer outliers, orphans / dormant, org tree, self-service, saved searches,
scheduled reports, dashboard chart."""

import time

import pytest

from app.insights import Insights
from app.operator import OperatorRequests
from app.producer import ProducerStore
from app.reports import REPORTS, ReportSchedules
from app.sync import Store
from app.web.auth import WebUserStore
from app.web.charts import line_chart

from .test_web import add_user, csrf, login

DAY = 86400


def seed(database, n=5):
    store = Store(database)
    with store.connect() as conn:
        for i in range(n):
            groups = [{"name": "Staff"}, {"name": "VPN"}] + ([{"name": "Payroll-Admin"}] if i == 0 else [])
            store.upsert_state(conn, "user", f"u{i}", "h", {
                "id": f"u{i}", "employeeId": f"E{i}", "firstName": f"F{i}", "lastName": "L", "title": "Clerk",
                "groups": groups, "lastLogin": int((time.time() - (200 if i == 1 else 5) * DAY) * 1000)})
        store.upsert_state(conn, "user", "ux", "h", {"id": "ux", "firstName": "No", "lastName": "Id"})
        store.upsert_state(conn, "organization", "o1", "h", {"id": "o1", "name": "Acme", "organizationTypeName": "Company"})
        store.upsert_state(conn, "organization", "o2", "h", {"id": "o2", "name": "Finance", "parentId": "o1"})
        store.upsert_state(conn, "organization", "o3", "h", {"id": "o3", "name": "Lagos", "parentId": "o2"})
    ps = ProducerStore(database)
    from app.producer.store import Person
    for i in range(3):
        ps.save_person(Person(f"E{i}", f"u{i}"))


def test_role_mining_and_outliers(database):
    seed(database)
    ins = Insights(database)
    [top] = [c for c in ins.role_candidates(min_users=3) if c["size"] == 2]
    assert top["entitlements"] == ["group:Staff", "group:VPN"] and top["users"] == 5
    out = ins.peer_outliers()
    assert [(o["employee_id"], o["name"]) for o in out] == [("E0", "Payroll-Admin")]


def test_orphans_and_dormant(database):
    seed(database)
    ins = Insights(database)
    orphans = {(o["employee_id"], o["reason"]) for o in ins.orphans()}
    assert (None, "no employee id") in orphans and ("E3", "no HR record") in orphans
    assert ("E0", "no HR record") not in orphans
    dormant = {d["employee_id"]: d for d in ins.dormant(days=90)}
    assert dormant["E1"]["days"] >= 199 and "E0" not in dormant
    assert dormant[None]["last_login"] is None                         # never / unknown


def test_org_tree(database):
    seed(database)
    [root] = Insights(database).org_tree()
    assert root["name"] == "Acme" and root["children"][0]["name"] == "Finance"
    assert root["children"][0]["children"][0]["name"] == "Lagos"


def test_chart_is_safe_svg():
    svg = str(line_chart(["01 Jan", "08 Jan"], {"<b>x</b>": [1, 3]}, "t"))
    assert svg.startswith("<svg") and "style=" not in svg and "<b>" not in svg
    assert "<title>&lt;b&gt;x&lt;/b&gt; · week of 08 Jan: 3</title>" in svg


def test_scheduled_reports_are_written(database, tmp_path):
    seed(database)
    s = ReportSchedules(database)
    s.add("dormant", "daily", "web:boss")
    with pytest.raises(ValueError):
        s.add("../etc/passwd", "daily", "web:boss")
    [path] = s.run_due(str(tmp_path))
    assert path.endswith(".csv") and "E1" in open(path, encoding="utf-8").read()
    assert s.run_due(str(tmp_path)) == []                              # not due again yet
    assert s.run_due(str(tmp_path), now=time.time() + 2 * DAY)


def test_pages_render(make_web, database):
    seed(database)
    c = make_web()
    login(c)
    for path in ["/", "/governance/insights", "/directory/tree", "/request-access", "/reports",
                 "/governance/insights?min_users=2&peer=domain"]:
        r = c.get(path)
        assert r.status_code == 200, path
    assert "Joiners" in c.get("/").get_data(as_text=True)
    for name in REPORTS:
        assert c.get(f"/reports/{name}.csv").status_code == 200, name


def test_self_service_viewer_only_for_themselves(make_web, database):
    add_user(database, "vic", "viewer")
    c = make_web()
    login(c, "vic", "a-long-password-1")
    data = {"csrf_token": csrf(c, "/request-access"), "op": "add", "kind": "group", "name": "VPN",
            "member": "E99", "jira_ticket": "IAM-20", "reason": "needs remote access for travel"}
    c.post("/request-access", data=data)
    assert OperatorRequests(database).page("producer") == []           # not linked: refused
    WebUserStore(database)._set("vic", employee_id="E7")
    c.post("/request-access", data=data)
    [req] = OperatorRequests(database).page("producer")
    assert req["params"]["member"] == "E7"                              # not E99: only themselves
    assert req["status"] == "awaiting_approval" and req["params"]["via"] == "openiam"


def test_saved_searches_are_private_and_local(make_web, database):
    add_user(database, "otto", "operator")
    add_user(database, "mia", "admin")
    c = make_web()
    login(c, "mia", "a-long-password-1")
    t = csrf(c, "/directory")
    c.post("/searches", data={"csrf_token": t, "name": "Finance users", "path": "/directory?kind=user&q=fin"})
    c.post("/searches", data={"csrf_token": t, "name": "evil", "path": "//evil.example/x"})
    c.post("/searches", data={"csrf_token": t, "name": "evil2", "path": "https://evil.example/"})
    page = c.get("/directory").get_data(as_text=True)
    assert "Finance users" in page and "evil" not in page
    sid = database.tables.saved_searches
    with database.begin() as conn:
        [row] = conn.execute(sid.select()).all()
    o = make_web()
    login(o, "otto", "a-long-password-1")
    assert "Finance users" not in o.get("/directory").get_data(as_text=True)
    o.post(f"/searches/{row.id}/delete", data={"csrf_token": csrf(o, "/directory")})
    with database.begin() as conn:
        assert len(conn.execute(sid.select()).all()) == 1               # not otto's to delete
