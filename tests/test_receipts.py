"""AD receipts: the consumer reports each instruction's fate; the producer verifies and shows it."""

import asyncio
import json

import pytest

from app import bundlesec
from app.consumer import Consumer, ConsumerConfig, ConsumerStore
from app.consumer.ad_target import AdApplier
from app.notify import Notifications
from app.receipts import (ReceiptImportConfig, ReceiptOutbox, ReceiptStore, ReceiptWriter,
                          ReceiptWriterConfig, from_plan, import_receipts, summarize_ad)
from app.sync.export import write_zip

from .ad_helpers import ad_cfg
from .test_directory import J, queued
from .test_web import add_user, csrf, login


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def keys(tmp_path):
    site_b = bundlesec.generate_signing_key(tmp_path / "keys" / "site-b")
    site_c = bundlesec.generate_signing_key(tmp_path / "keys" / "site-c")
    recipient = bundlesec.generate_age_identity(tmp_path / "keys" / "producer.age")
    return {"b": site_b, "c": site_c, "recipient": recipient, "identity": str(tmp_path / "keys" / "producer.age")}


def writer(database, tmp_path, keys, site="site-b", key="b", encrypt=False) -> ReceiptWriter:
    return ReceiptWriter(ReceiptWriterConfig(folder=str(tmp_path / "share" / "receipts"), site=site,
                                             signing_key_file=str(keys[key][0]),
                                             encrypt_to=[keys["recipient"]] if encrypt else []), database)


def importer(tmp_path, keys, **kw) -> ReceiptImportConfig:
    return ReceiptImportConfig(folder=str(tmp_path / "share" / "receipts"),
                               trusted={"site-b": str(keys["b"][1]), "site-c": str(keys["c"][1])},
                               age_identity_file=keys["identity"], **kw)


RECEIPT = {"zip": "openiam-corp-x.zip", "zip_sha256": "ab" * 32, "domain": "corp", "status": "applied",
           "target": "ad", "instructions": [{"instruction_id": "i-1", "op": "create", "status": "applied", "detail": "CN=x"},
                                            {"instruction_id": "i-2", "op": "add_member", "status": "failed",
                                             "detail": "member not found in AD"}]}


@pytest.mark.parametrize("encrypt", [False, True])
def test_signed_receipt_round_trip(database, tmp_path, keys, encrypt):
    w = writer(database, tmp_path, keys, encrypt=encrypt)
    w.outbox.add(RECEIPT)
    [name] = w.flush()
    assert name.endswith(".json.age" if encrypt else ".json")
    assert w.flush() == []                                         # written once
    counts = import_receipts(database, importer(tmp_path, keys))
    assert counts == {"imported": 1, "duplicate": 0, "rejected": 0}
    found = ReceiptStore(database).for_instructions(["i-1", "i-2"])
    assert found["i-1"][0]["status"] == "applied" and found["i-2"][0]["status"] == "failed"
    assert ReceiptStore(database).recent()[0]["signed_by"] == "site-b"
    [alert] = Notifications(database).recent()
    assert alert["event"] == "ad.failed" and "member not found" in alert["text"]
    assert (tmp_path / "share" / "receipts" / "imported" / name).exists()


def test_a_site_cannot_speak_for_another(database, tmp_path, keys):
    # Signed with site-c's key but claiming to be site-b.
    w = writer(database, tmp_path, keys, site="site-b", key="c")
    w.outbox.add(RECEIPT)
    [name] = w.flush()
    counts = import_receipts(database, importer(tmp_path, keys))
    assert counts["rejected"] == 1 and ReceiptStore(database).recent() == []
    assert (tmp_path / "share" / "receipts" / "rejected" / name).exists()


def test_tampered_unknown_or_unencrypted_receipts_are_rejected(database, tmp_path, keys):
    w = writer(database, tmp_path, keys)
    w.outbox.add(RECEIPT)
    [name] = w.flush()
    path = tmp_path / "share" / "receipts" / name
    env = json.loads(path.read_text())
    env["receipt"]["instructions"][1]["status"] = "applied"         # hide the failure
    path.write_text(json.dumps(env))
    assert import_receipts(database, importer(tmp_path, keys))["rejected"] == 1
    # A site nobody trusts.
    w2 = writer(database, tmp_path, keys, site="site-x")
    w2.outbox.add(RECEIPT)
    w2.flush()
    assert import_receipts(database, importer(tmp_path, keys))["rejected"] == 1
    # Encryption required, plain file sent.
    w3 = writer(database, tmp_path, keys)
    w3.outbox.add(RECEIPT)
    w3.flush()
    assert import_receipts(database, importer(tmp_path, keys, require_encryption=True))["rejected"] == 1
    assert ReceiptStore(database).recent() == []


def test_duplicates_ignored_and_newest_status_wins(database, tmp_path, keys):
    w = writer(database, tmp_path, keys)
    w.outbox.add({**RECEIPT, "status": "awaiting_approval",
                  "instructions": [{"instruction_id": "i-1", "status": "awaiting_approval"}]})
    w.outbox.add({**RECEIPT, "instructions": [{"instruction_id": "i-1", "status": "applied"}]})
    names = w.flush()
    receipts = tmp_path / "share" / "receipts"
    import shutil
    shutil.copy(receipts / names[1], receipts / ("receipt-copy-" + names[1].split("-", 1)[1]))
    counts = import_receipts(database, importer(tmp_path, keys))
    assert counts == {"imported": 2, "duplicate": 1, "rejected": 0}
    assert ReceiptStore(database).for_instructions(["i-1"])["i-1"][0]["status"] == "applied"


def test_summary_for_a_request():
    found = {"a": [{"site": "site-b", "status": "applied"}], "b": [{"site": "site-b", "status": "failed"}]}
    s = summarize_ad(["a", "b", "c"], found)
    assert (s["total"], s["reported"], s["failed"], s["sites"]) == (3, 2, 1, ["site-b"])


# ---- end to end: producer change -> zip -> consumer applies to AD -> receipt -> producer --------

def consumer(database, settings, tmp_path, ad, keys, mode="auto") -> Consumer:
    cfg = ConsumerConfig.model_validate({
        "inbox": str(tmp_path / "share" / "in"), "archive": str(tmp_path / "arc"), "failed": str(tmp_path / "bad"),
        "settle_seconds": 0,
        "receipts": {"folder": str(tmp_path / "share" / "receipts"), "site": "site-b",
                     "signing_key_file": str(keys["b"][0]), "encrypt_to": [keys["recipient"]]}})
    return Consumer(None, ConsumerStore(database), cfg, settings, target="ad",
                    ad=AdApplier(ad_cfg(mode=mode), conn_factory=lambda: ad))


def ship(sync, tmp_path) -> None:
    """Put the producer's queued AD instructions into a zip in the consumer's inbox."""
    lines = []
    for e in queued(sync):
        for ins in e["instructions"]:
            lines.append({"seq": e["seq"], "event_id": e["event_id"], "domain": "corp", "instruction": ins,
                          "why": ins.get("why")})
    dest = tmp_path / "share" / "in" / "corp"
    dest.mkdir(parents=True, exist_ok=True)
    write_zip(dest, "corp", {"user": []}, ["jsonl"], {}, lines)


def test_end_to_end_request_shows_what_ad_did(service, sync, database, settings, tmp_path, ad, keys, make_web):
    # The producer service applies an approved change (AD only): a group with a description.
    out = run(service.handle({**J, "via": "ad", "kind": "group", "op": "create", "name": "GRP-Receipts",
                              "description": "made by the e2e test", "request_id": 1}))
    ids = out["instruction_ids"]
    assert len(ids) == 1
    ship(sync, tmp_path)
    c = consumer(database, settings, tmp_path, ad, keys)
    result = run(c.scan())
    assert result["files"][0]["status"] == "applied" and result["receipts"] == 1
    assert import_receipts(database, importer(tmp_path, keys))["imported"] == 1
    [r] = ReceiptStore(database).for_instructions(ids)[ids[0]]
    assert (r["site"], r["status"]) == ("site-b", "applied") and "CN=GRP-Receipts" in r["detail"]

    # The web UI shows it on the request.
    from app.operator import OperatorRequests
    reqs = OperatorRequests(database)
    rid = reqs.create("producer", "directory", {**J, "via": "ad", "kind": "group", "op": "create",
                                                "name": "GRP-Receipts"}, "web:otto")
    reqs.decide(rid, True, "web:boss")
    with database.begin() as conn:
        t = database.tables.operator_requests
        conn.execute(t.update().where(t.c.id == rid).values(status="done", result=out))
    add_user(database, "mia", "admin")
    add_user(database, "otto", "operator")
    w = make_web()
    login(w, "mia", "a-long-password-1")
    page = w.get("/approvals").get_data(as_text=True)
    assert "AD:" in page and "applied 1" in page and "site-b" in page
    assert "GRP-Receipts" in w.get("/receipts").get_data(as_text=True)
    assert "site-b" in w.get("/outbox/1").get_data(as_text=True)


def test_held_plan_reports_waiting_then_applied(service, sync, database, settings, tmp_path, ad, keys):
    out = run(service.handle({**J, "via": "ad", "kind": "group", "op": "create", "name": "GRP-Held"}))
    iid = out["instruction_ids"][0]
    ship(sync, tmp_path)
    c = consumer(database, settings, tmp_path, ad, keys, mode="approve")
    [f] = run(c.scan())["files"]
    assert f["status"] == "awaiting_approval"
    import_receipts(database, importer(tmp_path, keys))
    assert ReceiptStore(database).for_instructions([iid])[iid][0]["status"] == "awaiting_approval"
    run(c.approve_plan(f["summary"]["plan_id"], "web:carol"))           # writes the follow-up receipt
    import_receipts(database, importer(tmp_path, keys))
    assert ReceiptStore(database).for_instructions([iid])[iid][0]["status"] == "applied"


def test_rejected_plan_from_the_oversight_web_is_reported(database, tmp_path, keys, make_web, settings, ad,
                                                           service, sync):
    out = run(service.handle({**J, "via": "ad", "kind": "group", "op": "create", "name": "GRP-No"}))
    iid = out["instruction_ids"][0]
    ship(sync, tmp_path)
    c = consumer(database, settings, tmp_path, ad, keys, mode="approve")
    [f] = run(c.scan())["files"]
    # The oversight web queues the receipt when this site has receipts configured.
    cfg_path = tmp_path / "consumer.yaml"
    cfg_path.write_text(json.dumps(c.cfg.model_dump(mode="json")))
    add_user(database, "carl", "operator")
    o = make_web("consumer", consumer_target="ad", consumer_config_path=str(cfg_path))
    login(o, "carl", "a-long-password-1")
    plan_id = f["summary"]["plan_id"]
    o.post(f"/ad/plans/{plan_id}/reject", data={"csrf_token": csrf(o, f"/ad/plans/{plan_id}")})
    assert [r["payload"]["status"] for r in ReceiptOutbox(database).pending()] == ["rejected"]
    c.flush_receipts()                                                 # the service signs and writes it
    import_receipts(database, importer(tmp_path, keys))
    assert ReceiptStore(database).for_instructions([iid])[iid][0]["status"] == "rejected"


def test_from_plan_statuses():
    plan = {"id": 1, "status": "applied", "file_sha256": "x", "domain": "d", "items": [
        {"instruction_id": "a", "ldap": "add", "ok": True}, {"instruction_id": "b", "ldap": "noop", "ok": True},
        {"instruction_id": "c", "ldap": "modify", "ok": False, "error": "busy"},
        {"instruction_id": "d", "ldap": "skipped", "ok": True}]}
    assert [i["status"] for i in from_plan(plan, "z")["instructions"]] == ["applied", "unchanged", "failed", "skipped"]
    held = from_plan({**plan, "status": "awaiting_approval"}, "z")
    assert {i["status"] for i in held["instructions"]} == {"awaiting_approval"}
