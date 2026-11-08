"""Bulk import, change preview, time-limited access, mover workflow (batches)."""

import asyncio
import io
import time
from datetime import date, timedelta

import pytest

from app.directory import DirectoryRequest, TimedGrants, expire_grants, plan
from app.governance import Governance
from app.operator import OperatorRequests, approvals_needed
from app.sync import Store

from .test_directory import J, queued
from .test_web import add_user, csrf, login


def run(coro):
    return asyncio.run(coro)


def tomorrow(days: int = 1) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


@pytest.fixture
def otto(make_web, database):
    add_user(database, "otto", "operator")
    c = make_web()
    login(c, "otto", "a-long-password-1")
    return c


def test_end_date_rules():
    base = {**J, "via": "ad", "kind": "group", "op": "add_member", "name": "G", "member_kind": "user", "member": "E1"}
    assert DirectoryRequest.model_validate({**base, "expires_on": tomorrow()}).expires_on
    for bad in ("2020-01-01", tomorrow(400), "31/12/2030"):
        with pytest.raises(ValueError):
            DirectoryRequest.model_validate({**base, "expires_on": bad})
    with pytest.raises(ValueError):
        DirectoryRequest.model_validate({**base, "op": "remove_member", "expires_on": tomorrow()})


def test_timed_grant_is_recorded_and_removed_after_its_end(service, sync, database):
    run(service.handle({**J, "via": "ad", "kind": "group", "op": "add_member", "name": "VPN", "member_kind": "user",
                        "member": "E1", "expires_on": tomorrow(), "request_id": 7}))
    [grant] = TimedGrants(database).active()
    assert grant["request_id"] == 7
    assert expire_grants(database) == []                               # not yet
    [rid] = expire_grants(database, now=time.time() + 3 * 86400)
    removal = OperatorRequests(database).get(rid)
    assert removal["status"] == "pending"                              # runs without a new approval
    assert removal["decided_by"].startswith("system:expiry")
    assert removal["params"]["op"] == "remove_member" and removal["params"]["member"] == "E1"
    assert TimedGrants(database).active() == []
    run(service.handle(removal["params"]))                             # the service applies it
    assert [e["instructions"][0]["op"] for e in queued(sync)] == ["add_member", "remove_member"]


def test_batch_runs_rows_and_reports_each(service, sync):
    out = run(service.handle_batch({**J, "label": "t", "items": [
        {"via": "ad", "kind": "group", "op": "create", "name": "A"},
        {"via": "openiam", "kind": "group", "op": "delete", "name": "No-Such-Group"},   # fails
        {"via": "ad", "kind": "group", "op": "create", "name": "B"}]}))
    assert (out["ok"], out["failed"]) == (2, 1)
    assert not out["rows"][1]["ok"] and "not found" in out["rows"][1]["error"]
    assert len(queued(sync)) == 2


def test_batch_with_an_invalid_row_applies_nothing(service, sync):
    with pytest.raises(Exception, match="nothing applied"):
        run(service.handle_batch({**J, "items": [{"via": "ad", "kind": "group", "op": "create", "name": "A"},
                                                 {"via": "ad", "kind": "group", "op": "enable", "name": "B"}]}))
    assert queued(sync) == []


def test_large_or_destructive_batches_need_two_approvals():
    small = {"items": [{"op": "create"}] * 3}
    assert approvals_needed(small) == 1
    assert approvals_needed({"items": [{"op": "create"}] * 11}) == 2
    assert approvals_needed({"items": [{"op": "create"}, {"op": "delete"}]}) == 2


def test_preview_describes_without_saving(otto, database):
    r = otto.post("/directory/preview", data={"csrf_token": csrf(otto, "/directory"), "via": "ad", "kind": "group",
                                              "op": "create", "name": "GRP-X", "jira_ticket": "IAM-4",
                                              "reason": "preview for the test"})
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and "What will happen" in page and "OpenIAM: not changed" in page
    assert "AD: create group" in page and 'name="name" value="GRP-X"' in page
    assert OperatorRequests(database).page("producer") == []
    p = plan(DirectoryRequest.model_validate({**J, "via": "openiam", "kind": "group", "op": "delete", "name": "G"}))
    assert any("needs directories.group.delete_path" in s for s in p["steps"])


CSV = "employee_id,first_name,last_name,email,groups\nE10,Ada,Lovelace,ada@x.example,Staff;VPN\nE11,Alan,Turing,,Staff\n"


def test_bulk_import_previews_then_saves_one_request(otto, database):
    data = {"csrf_token": csrf(otto, "/directory/import"), "format": "user", "via": "ad",
            "jira_ticket": "IAM-9", "reason": "new branch opening in Lagos"}
    r = otto.post("/directory/import", data={**data, "file": (io.BytesIO(CSV.encode()), "users.csv")},
                  content_type="multipart/form-data")
    page = r.get_data(as_text=True)
    assert "Save 2 change(s) for approval" in page
    assert OperatorRequests(database).page("producer") == []           # preview only
    otto.post("/directory/import", data={**data, "csv": CSV, "step": "save"})
    [req] = OperatorRequests(database).page("producer")
    assert req["action"] == "directory_batch" and req["status"] == "awaiting_approval"
    assert [i["name"] for i in req["params"]["items"]] == ["E10", "E11"]
    assert req["params"]["items"][0]["groups"] == ["Staff", "VPN"] and req["params"]["jira_ticket"] == "IAM-9"


def test_bulk_import_with_bad_rows_saves_nothing(otto, database):
    bad = "employee_id,first_name,last_name\nE1,Ada,Lovelace\nE2,,Turing\n"
    r = otto.post("/directory/import", data={"csrf_token": csrf(otto, "/directory/import"), "format": "user",
                                             "via": "ad", "csv": bad, "step": "save", "jira_ticket": "IAM-9",
                                             "reason": "testing a broken file"})
    assert "first and last name are required" in r.get_data(as_text=True)
    assert OperatorRequests(database).page("producer") == []


def test_bulk_sod_considers_rows_together(otto, database):
    Governance(database).add_policy("Pay vs approve", ("group", "AP-Pay"), ("group", "AP-Approve"), "web:boss")
    csv_text = "op,kind,name,member_kind,member\nadd,group,AP-Pay,user,E5\nadd,group,AP-Approve,user,E5\n"
    r = otto.post("/directory/import", data={"csrf_token": csrf(otto, "/directory/import"), "format": "membership",
                                             "via": "ad", "csv": csv_text, "step": "save", "jira_ticket": "IAM-9",
                                             "reason": "two rows that clash together"})
    assert "Segregation of duties" in r.get_data(as_text=True)
    assert OperatorRequests(database).page("producer") == []


def test_mover_builds_one_batch(otto, database):
    store = Store(database)
    with store.connect() as conn:
        store.upsert_state(conn, "user", "u1", "h", {"id": "u1", "employeeId": "E1", "firstName": "Ada",
                                                     "lastName": "L", "domain": "corp", "groups": [{"name": "Sales"}]})
    assert "Sales" in otto.get("/directory/user/move?name=E1").get_data(as_text=True)
    data = {"csrf_token": csrf(otto, "/directory/user/move?name=E1"), "name": "E1", "remove": "group:Sales",
            "add_groups": "Finance", "title": "Analyst", "domain": "corp", "via": "openiam",
            "jira_ticket": "IAM-12", "reason": "moves from sales to finance"}
    r = otto.post("/directory/user/move", data=data)
    assert "Save 3 change(s) for approval" in r.get_data(as_text=True)
    otto.post("/directory/user/move", data={**data, "step": "save"})
    [req] = OperatorRequests(database).page("producer")
    ops = [(i["op"], i["kind"], i["name"]) for i in req["params"]["items"]]
    assert ops == [("update", "user", "E1"), ("remove_member", "group", "Sales"), ("add_member", "group", "Finance")]
    assert "batch" in otto.get("/directory/user/view?name=E1").get_data(as_text=True)
