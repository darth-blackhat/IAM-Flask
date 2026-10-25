"""AD instructions with a `why`, from both the source of truth and OpenIAM admin changes,
written into the zip of the record's domain."""

import asyncio
import json
import time
import zipfile

import pytest

from app.producer import ProducerEvent, ProducerProcessor, ProducerStore
from app.sync import Store, SyncConfig, SyncService, build_target

from .test_producer import make_cfg as producer_cfg


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def site(fake, database, make_client, settings, tmp_path):
    fake.groups["g-staff"] = {"id": "g-staff", "name": "All Staff", "managedSysId": "AD-MANAGED-SYS",
                              "domain": "corp.example"}
    cfg = SyncConfig.model_validate({
        "entities": {
            "user": {"path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}],
                     "ignore_fields": ["userStatus"]},
            "group": {"path": "/webconsole/rest/api/groups/search", "queries": [{"name": "*"}]},
        },
        "target": {"type": "zip"},
        "export": {"folder": str(tmp_path / "out"), "after_sync": True,
                   "domains": {"by_field": {"user": "domain", "group": "domain"}}},
        "audit": {"search_path": "/webconsole/rest/api/auditlog/search"},
    })
    store = Store(database)
    sync = SyncService(make_client(), store, cfg, build_target(cfg))
    producer = ProducerProcessor(make_client(), ProducerStore(database), producer_cfg(), settings,
                                 ad=cfg.ad, outbox=store)
    sync.attributor = producer.store.attribution
    return sync, producer, tmp_path / "out"


def hire(**kw):
    return ProducerEvent.model_validate({
        "type": "hire", "employee_id": "E1", "event_id": "hr-1",
        "person": {"first_name": "Ada", "last_name": "L", "extra": {"domain": "corp.example"}},
        "groups": ["All Staff"], **kw})


def instructions_in(folder, domain):
    zips = sorted((folder / domain).glob("*.zip"))
    with zipfile.ZipFile(zips[-1]) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        lines = [json.loads(x) for x in zf.read("ad_instructions.jsonl").decode().splitlines()]
    assert manifest["ad_instructions"] == len(lines)
    return lines


def test_source_of_truth_instructions_go_into_the_domain_zip(fake, site):
    sync, producer, out = site
    run(sync.run(baseline=True))
    r = run(producer.process(hire(reason="new analyst")))
    assert r.ok and r.fields_set and "firstName" in r.fields_set

    result = run(sync.run())
    [corp] = [d for d in result["export"]["domains"] if d["domain"] == "corp.example"]
    assert corp["ad_instructions"] == 2

    lines = instructions_in(out, "corp.example")
    ops = [(x["instruction"]["op"], x["why"]["source"]) for x in lines]
    assert ops == [("create", "source-of-truth"), ("add_member", "source-of-truth")]
    create, member = lines
    assert create["why"]["summary"] == "HR hire: new person in the source of truth"
    assert create["why"]["reason"] == "new analyst" and create["why"]["event_id"] == "hr-1"
    assert create["data"]["firstName"] == "Ada"   # the payload travels with the instruction
    assert member["why"]["summary"] == "source of truth: in the HR group list"

    # Change detection saw the same new user, but it came from the source of truth:
    # no second "create".
    detected = [e for e in sync.store.events_after(0, 50) if e["type"] == "user.created"]
    assert detected and detected[0]["instructions"] == []
    assert detected[0]["why"]["source"] == "source-of-truth"
    assert sync.store.outbox_stats()["pending"] == 0   # delivered = written into the zip


def test_admin_change_in_openiam_is_explained_with_audit(fake, site):
    sync, producer, out = site
    run(sync.run(baseline=True))
    uid = run(producer.process(hire())).user_id
    run(sync.run())

    fake.users[uid]["title"] = "Lead Analyst"   # an admin edits the user in OpenIAM
    fake.audit.append({"id": "a-1", "timestamp": int(time.time() * 1000), "principal": "jsmith",
                       "action": "SAVE_USER", "result": "SUCCESS",
                       "targets": [{"targetId": uid, "targetType": "USER"}]})
    run(sync.run())

    [line] = instructions_in(out, "corp.example")
    assert line["instruction"]["op"] == "update"
    assert line["instruction"]["changes"] == [{"attribute": "title", "old": None, "new": "Lead Analyst"}]
    why = line["why"]
    assert why["source"] == "openiam-admin"
    assert why["summary"] == "changed directly in OpenIAM: title None -> 'Lead Analyst' (by jsmith)"
    assert why["audit"][0]["by"] == "jsmith" and why["audit"][0]["action"] == "SAVE_USER"


def test_mixed_change_keeps_only_the_admin_part(fake, site):
    sync, producer, out = site
    run(sync.run(baseline=True))
    uid = run(producer.process(hire())).user_id
    run(sync.run())

    # HR renames the person, and an admin changes the title in the same window.
    run(producer.process(hire(event_id="hr-2", person={
        "first_name": "Ada", "last_name": "Lovelace", "extra": {"domain": "corp.example"}})))
    fake.users[uid]["title"] = "Lead"
    run(sync.run())

    lines = instructions_in(out, "corp.example")
    by_source = {(x["why"]["source"], x["instruction"]["op"]) for x in lines}
    assert by_source == {("source-of-truth", "update"), ("openiam-admin", "update")}
    admin = next(x for x in lines if x["why"]["source"] == "openiam-admin")
    assert [c["attribute"] for c in admin["instruction"]["changes"]] == ["title"]
    assert "lastName" in admin["why"]["also_from_source_of_truth"]


def test_audit_unavailable_does_not_block(fake, site):
    sync, producer, out = site
    run(sync.run(baseline=True))
    uid = run(producer.process(hire())).user_id
    run(sync.run())
    fake.fail_paths.add("/webconsole/rest/api/auditlog/search")
    fake.users[uid]["title"] = "X"
    run(sync.run())
    [line] = instructions_in(out, "corp.example")
    assert "audit" not in line["why"] and line["why"]["source"] == "openiam-admin"


def test_instructions_follow_the_record_domain(fake, site):
    sync, producer, out = site
    run(sync.run(baseline=True))
    fake.users["x1"] = {"id": "x1", "firstName": "Lab", "lastName": "User", "domain": "lab.example"}
    run(sync.run())
    [line] = instructions_in(out, "lab.example")
    assert line["domain"] == "lab.example" and line["why"]["source"] == "openiam-admin"
    assert line["why"]["summary"] == "user created directly in OpenIAM"
    assert not (out / "corp.example").exists() or not any(
        x["entity_id"] == "x1" for x in instructions_in(out, "corp.example"))


def test_zip_target_requires_export_after_sync(tmp_path):
    with pytest.raises(ValueError, match="after_sync"):
        SyncConfig.model_validate({
            "entities": {"user": {"path": "/webconsole/rest/api/users/search", "queries": [{"a": 1}]}},
            "target": {"type": "zip"}, "export": {"folder": str(tmp_path)}})


def test_audit_time_criterion_cannot_clash_with_paging():
    with pytest.raises(ValueError, match="paging"):
        SyncConfig.model_validate({
            "entities": {"user": {"path": "/webconsole/rest/api/users/search", "queries": [{"a": 1}]}},
            "audit": {"since_criterion": "from"}})
