import asyncio

import pytest

from app.ad import AdMapping, from_change_event
from app.producer import ProducerEvent, ProducerProcessor, ProducerStore
from app.sync import Store, SyncConfig, SyncService, build_target

from .test_producer import AD_SYS, make_cfg as producer_cfg


def run(coro):
    return asyncio.run(coro)


def ev(action, data=None, previous=None, changes=None, entity="user"):
    return {"entity": entity, "entity_id": "oid-1", "action": action, "data": data,
            "previous": previous, "changes": changes}


def test_change_events_become_ad_instructions():
    m = AdMapping(user_status_field="status", user_disabled_values=["DISABLED"])
    user = {"id": "oid-1", "firstName": "Ada", "lastName": "L", "employeeId": "E1",
            "lastLogin": 5, "status": "ACTIVE"}

    [create], why = from_change_event(ev("created", data=user), m)
    assert why["source"] == "openiam-admin" and create["why"] == why
    assert create["op"] == "create" and create["object_class"] == "user"
    assert create["key"] == {"employeeID": "E1"}
    assert create["attributes"] == {"givenName": "Ada", "sn": "L", "employeeID": "E1"}

    changed = {**user, "lastName": "Lovelace", "status": "DISABLED"}
    (upd, dis), why = from_change_event(ev("updated", data=changed, changes={
        "lastName": {"old": "L", "new": "Lovelace"}, "status": {"old": "ACTIVE", "new": "DISABLED"}}), m)
    assert upd["changes"] == [{"attribute": "sn", "old": "L", "new": "Lovelace"}]
    assert dis["op"] == "disable"
    assert why["summary"] == "changed directly in OpenIAM: lastName 'L' -> 'Lovelace', status 'ACTIVE' -> 'DISABLED'"

    # Only unmapped fields changed: nothing for AD to do.
    assert from_change_event(ev("updated", data=user, changes={"lastLogin": {"old": 1, "new": 5}}), m)[0] == []

    [gone], _ = from_change_event(ev("deleted", previous=user), m)
    assert gone["op"] == "disable"  # users are disabled, not deleted, by default


def test_rename_is_keyed_by_old_name_and_unmapped_entity_is_skipped():
    m = AdMapping(classes={"user": "user", "group": "group", "role": None})
    [upd], _ = from_change_event(ev("updated", entity="group", data={"id": "g", "name": "New"},
                                 changes={"name": {"old": "Old", "new": "New"}}), m)
    assert upd["key"] == {"cn": "Old"} and upd["changes"][0]["new"] == "New"
    assert from_change_event(ev("created", entity="role", data={"name": "R"}), m)[0] == []


def test_missing_key_attribute_falls_back_to_openiam_id():
    [c], _ = from_change_event(ev("created", data={"firstName": "NoId"}), AdMapping())
    assert c["key"] == {"openiamId": "oid-1"}


def test_sync_events_carry_instructions(fake, database, make_client):
    fake.users["u1"] = {"id": "u1", "firstName": "A", "lastName": "B", "employeeId": "E1"}
    cfg = SyncConfig.model_validate({"entities": {"user": {
        "path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}]}}})
    svc = SyncService(make_client(), Store(database), cfg, build_target(cfg))
    run(svc.run())
    [event] = svc.store.events_after(0, 10)
    assert event["instructions"][0]["op"] == "create"


@pytest.fixture
def wired(fake, database, make_client, settings, tmp_path):
    fake.groups["g-staff"] = {"id": "g-staff", "name": "All Staff", "managedSysId": AD_SYS}
    fake.groups["g-ad"] = {"id": "g-ad", "name": "GRP-Finance-RW", "managedSysId": AD_SYS}
    fake.organizations["o-fin"] = {"id": "o-fin", "name": "Finance Dept"}
    out = tmp_path / "events.jsonl"
    scfg = SyncConfig.model_validate({
        "entities": {"user": {"path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}]}},
        "target": {"type": "file", "path": str(out)}})
    store = Store(database)
    sync = SyncService(make_client(), store, scfg, build_target(scfg))
    producer = ProducerProcessor(make_client(), ProducerStore(database), producer_cfg(), settings,
                                 ad=scfg.ad, outbox=store)
    return sync, producer


def pev(type_, **kw):
    return ProducerEvent.model_validate({"type": type_, "employee_id": "E1", **kw})


def test_producer_actions_are_queued_as_ad_instructions(wired):
    sync, producer = wired
    r = run(producer.process(pev("hire", event_id="m1",
                                 person={"first_name": "Ada", "last_name": "L",
                                         "emails": [{"email": "ada@x.example"}]},
                                 groups=["Finance", "All Staff"], organizations=["Finance Dept"])))
    ops = [(i["op"], i["object_class"], i["key"]) for i in r.instructions]
    assert ops[0] == ("create", "user", {"employeeID": "E1"})
    assert ("add_member", "group", {"cn": "GRP-Finance-RW"}) in ops
    assert ("add_member", "organizationalUnit", {"ou": "Finance Dept"}) in ops
    assert r.instructions[0]["attributes"]["mail"] == "ada@x.example"

    run(producer.process(pev("update", groups=["All Staff"])))
    run(producer.process(pev("terminate", reason="resigned")))

    events = sync.store.events_after(0, 50)
    assert [e["type"] for e in events] == ["producer.hire", "producer.update", "producer.terminate"]
    removal = events[1]["instructions"][0]
    assert removal["op"] == "remove_member" and removal["key"] == {"cn": "GRP-Finance-RW"}
    term = events[2]["instructions"]
    assert term[0]["op"] == "disable" and term[0]["lifecycle"] == "terminated"

    # A resent message is answered from the record and queues nothing new.
    again = run(producer.process(pev("hire", event_id="m1", person={"first_name": "Ada", "last_name": "L"})))
    assert again.duplicate and again.instructions == []
    assert len(sync.store.events_after(0, 50)) == 3

    assert run(sync.deliver())["sent"] == 3


def test_activity_log_records_every_outcome(wired):
    _, producer = wired
    run(producer.process_many([pev("terminate"), pev("status")]))  # unknown employee, then skipped
    run(producer.process(pev("hire", person={"first_name": "A", "last_name": "B"})))
    rows = producer.store.activity_page()
    assert [(r["event_type"], r["ok"]) for r in rows] == [("hire", True), ("status", False),
                                                          ("terminate", False)]
    assert "skipped" in rows[1]["error"]
    assert producer.store.activity_page(ok=False, limit=1)[0]["event_type"] == "status"
    detail = producer.store.activity_entry(rows[0]["id"])
    assert detail["result"]["instructions"][0]["op"] == "create"
