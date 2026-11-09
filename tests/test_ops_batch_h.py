"""Readiness, metrics, key rotation, and the directory-request REST API."""

import pytest

from app import bundlesec
from app.cli import main as cli_main
from app.db import Database
from app.governance import Governance
from app.metrics import registry_for, render
from app.operator import OperatorRequests
from app.receipts import ReceiptImportConfig, ReceiptStore, ReceiptWriter, ReceiptWriterConfig, import_receipts
from app.security import ApiKeyStore

from .test_web import add_user, csrf, login


# ---- readiness -------------------------------------------------------------------------

def test_readyz_web_and_api(make_web, api, monkeypatch):
    c = make_web()
    assert c.get("/readyz").status_code == 200 and c.get("/readyz").json["schema"] == "current"
    assert api.get("/readyz").json()["ready"] is True
    monkeypatch.setattr(Database, "head_revision", staticmethod(lambda: "9999"))
    r = c.get("/readyz")
    assert r.status_code == 503 and "code needs 9999" in r.json["schema"]
    assert api.get("/readyz").status_code == 503


# ---- metrics ---------------------------------------------------------------------------

def test_new_metrics(database):
    OperatorRequests(database).create("producer", "directory", {"op": "create"}, "web:otto")
    text = render(registry_for(database, "producer")).decode()
    for name in ("backend_iam_approvals_waiting 1.0", "backend_iam_approvals_oldest_seconds",
                 'backend_iam_notifications{state="dead"}', "backend_iam_receipts_unsent",
                 "backend_iam_time_limited_access_active"):
        assert name in text, name


# ---- key rotation --------------------------------------------------------------------

RECEIPT = {"zip": "z", "zip_sha256": "s", "domain": "corp", "status": "applied",
           "instructions": [{"instruction_id": "i-1", "status": "applied"}]}


def test_receipts_trust_old_and_new_key_during_rotation(database, tmp_path):
    old = bundlesec.generate_signing_key(tmp_path / "old")
    new = bundlesec.generate_signing_key(tmp_path / "new")
    other = bundlesec.generate_signing_key(tmp_path / "other")
    folder = str(tmp_path / "receipts")
    cfg = ReceiptImportConfig(folder=folder, trusted={"site-b": [str(old[1]), str(new[1])]})
    for key, n in ((old, 1), (new, 1), (other, 0)):
        w = ReceiptWriter(ReceiptWriterConfig(folder=folder, site="site-b", signing_key_file=str(key[0])), database)
        w.outbox.add(RECEIPT)
        w.flush()
        assert import_receipts(database, cfg)["imported"] == n
    assert len(ReceiptStore(database).recent()) == 2


def test_keys_show_prints_ids_not_secrets(tmp_path, capsys):
    priv, pub = bundlesec.generate_signing_key(tmp_path / "k")
    recipient = bundlesec.generate_age_identity(tmp_path / "id.age")
    for f in (priv, pub, tmp_path / "id.age"):
        assert cli_main(["keys", "show", str(f)]) == 0
    out = capsys.readouterr().out
    kid = bundlesec.key_id(bundlesec.load_public_key(str(pub)))
    assert out.count(kid) == 2 and recipient in out
    assert "PRIVATE" not in out and "AGE-SECRET-KEY" not in out


# ---- REST API ------------------------------------------------------------------------

ONE = {"via": "ad", "kind": "group", "op": "create", "name": "GRP-Api", "jira_ticket": "iam-50",
       "reason": "requested by ServiceNow RITM0012"}


def test_api_creates_requests_that_still_need_approval(api, database):
    r = api.post("/directory/requests", json=ONE)
    assert r.status_code == 202, r.text
    rid = r.json()["request_id"]
    req = OperatorRequests(database).get(rid)
    assert req["status"] == "awaiting_approval" and req["requested_by"].startswith("api:")
    assert req["params"]["jira_ticket"] == "IAM-50"
    s = api.get(f"/directory/requests/{rid}").json()
    assert (s["status"], s["jira_ticket"], s["approvals"]) == ("awaiting_approval", "IAM-50", [])
    # A destructive batch needs two approvals.
    b = api.post("/directory/requests", json={"jira_ticket": "IAM-51", "reason": "decommission old groups",
                                              "items": [{"via": "ad", "kind": "group", "op": "delete", "name": "A"},
                                                        {"via": "ad", "kind": "group", "op": "delete", "name": "B"}]})
    assert b.status_code == 202 and b.json()["required_approvals"] == 2


def test_api_validates_and_enforces_sod(api, database):
    r = api.post("/directory/requests", json={**ONE, "jira_ticket": ""})
    assert r.status_code == 422 and "Jira" in str(r.json())
    assert api.post("/directory/requests", json={**ONE, "surprise": 1}).status_code == 422
    Governance(database).add_policy("Pay vs approve", ("group", "AP-Pay"), ("group", "AP-Approve"), "web:boss")
    pair = {"jira_ticket": "IAM-52", "reason": "two rows that clash together",
            "items": [{"via": "ad", "kind": "group", "op": "add_member", "name": n, "member_kind": "user",
                       "member": "E5"} for n in ("AP-Pay", "AP-Approve")]}
    r = api.post("/directory/requests", json=pair)
    assert r.status_code == 409 and r.json()["detail"]["policies"]
    assert OperatorRequests(database).page("producer") == []
    assert api.get("/directory/requests/999").status_code == 404


def test_api_scopes(api, database):
    key = ApiKeyStore(database).create("itsm-read", ["directory:read"], [], None, created_by="test")
    r = api.post("/directory/requests", json=ONE, headers={"X-API-Key": key})
    assert r.status_code == 403
    rid = api.post("/directory/requests", json=ONE).json()["request_id"]
    assert api.get(f"/directory/requests/{rid}", headers={"X-API-Key": key}).status_code == 200


def test_api_request_is_approved_in_the_web(api, database, make_web):
    rid = api.post("/directory/requests", json=ONE).json()["request_id"]
    add_user(database, "mia", "admin")
    w = make_web()
    login(w, "mia", "a-long-password-1")
    w.post(f"/approvals/{rid}/approve", data={"csrf_token": csrf(w, "/approvals")})
    assert OperatorRequests(database).get(rid)["status"] == "pending"


@pytest.mark.parametrize("path", ["/directory/requests/1"])
def test_api_needs_a_key(api, path):
    assert api.get(path, headers={"X-API-Key": "wrong"}).status_code == 401
