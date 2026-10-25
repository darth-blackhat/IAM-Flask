import asyncio
from datetime import date, timedelta

import pytest

from app.main import app
from app.producer import ProducerConfig, ProducerEvent, ProducerProcessor, ProducerStore

AD_SYS = "AD-MANAGED-SYS"


def run(coro):
    return asyncio.run(coro)


def make_cfg(**overrides) -> ProducerConfig:
    return ProducerConfig.model_validate({
        "directories": {
            "group": {"search_path": "/webconsole/rest/api/groups/search",
                      "aliases": {"Finance": "GRP-Finance-RW"},
                      "require": {"managedSysId": AD_SYS},
                      "create_path": "/webconsole/rest/api/groups/save",
                      "create_body": {"name": "{name}", "managedSysId": AD_SYS}},
        },
        "status_rules": {
            "compliance": {"non_compliant": {"hold": True}, "compliant": {}},
            "training": {"overdue": {"hold": True},
                         "complete": {"groups": ["VPN Users"], "roles": ["Remote Worker"]}},
        },
        **overrides,
    })


@pytest.fixture
def seeded(fake):
    # Two groups with the same name: only the AD-linked one may be used.
    fake.groups["g-ad"] = {"id": "g-ad", "name": "GRP-Finance-RW", "managedSysId": AD_SYS}
    fake.groups["g-local"] = {"id": "g-local", "name": "GRP-Finance-RW", "managedSysId": "OTHER"}
    fake.groups["g-staff"] = {"id": "g-staff", "name": "All Staff", "managedSysId": AD_SYS}
    fake.groups["g-vpn"] = {"id": "g-vpn", "name": "VPN Users", "managedSysId": AD_SYS}
    fake.roles["r-remote"] = {"id": "r-remote", "name": "Remote Worker"}
    fake.organizations["o-fin"] = {"id": "o-fin", "name": "Finance Dept"}
    return fake


@pytest.fixture
def producer(database, make_client, settings):
    def _make(cfg: ProducerConfig | None = None) -> ProducerProcessor:
        return ProducerProcessor(make_client(), ProducerStore(database), cfg or make_cfg(), settings)
    return _make


def hire(**kw) -> ProducerEvent:
    return ProducerEvent.model_validate({
        "type": "hire", "employee_id": "E1",
        "person": {"first_name": "Ada", "last_name": "Lovelace",
                   "emails": [{"email": "ada@example.com"}]},
        "groups": ["Finance", "All Staff"], "organizations": ["Finance Dept"], **kw})


def ev(type_: str, **kw) -> ProducerEvent:
    return ProducerEvent.model_validate({"type": type_, "employee_id": "E1", **kw})


def held(fake, uid, key):
    return fake.members.get(uid, {}).get(key, set())


def test_hire_creates_user_and_places_in_ad_groups_and_org(seeded, producer):
    p = producer()
    r = run(p.process(hire()))
    assert r.ok, r.error
    user = seeded.users[r.user_id]
    assert user["employeeId"] == "E1" and user["firstName"] == "Ada"
    # "Finance" -> alias "GRP-Finance-RW" -> the AD-linked one, not the local duplicate.
    assert held(seeded, r.user_id, "groupIds") == {"g-ad", "g-staff"}
    assert held(seeded, r.user_id, "organizationIds") == {"o-fin"}


def test_resend_and_rehire_do_not_duplicate(seeded, producer):
    p = producer()
    first = run(p.process(hire(event_id="m1")))
    again = run(p.process(hire(event_id="m1")))
    assert again.duplicate and again.user_id == first.user_id
    run(p.process(hire(event_id="m2")))  # new message, same person: an update
    assert len(seeded.users) == 1


def test_existing_openiam_user_is_matched_by_employee_id(seeded, producer):
    seeded.users["pre"] = {"id": "pre", "firstName": "Old", "lastName": "Name", "employeeId": "E1"}
    r = run(producer().process(hire()))
    assert r.user_id == "pre" and "user updated" in r.actions and len(seeded.users) == 1


def test_group_change_removes_only_what_producer_granted(seeded, producer):
    p = producer()
    uid = run(p.process(hire())).user_id
    seeded.members[uid]["groupIds"].add("g-admin-manual")  # assigned by an admin in OpenIAM
    r = run(p.process(ev("update", groups=["All Staff"])))
    assert r.ok and held(seeded, uid, "groupIds") == {"g-staff", "g-admin-manual"}
    # Organizations were not in the event, so they are left alone.
    assert held(seeded, uid, "organizationIds") == {"o-fin"}


def test_holds_stack_and_status_grants_access(seeded, producer):
    p = producer()
    uid = run(p.process(hire())).user_id
    run(p.process(ev("status", statuses={"compliance": "non_compliant", "training": "overdue"})))
    assert seeded.users[uid]["userStatus"] == "DISABLED"

    r = run(p.process(ev("status", statuses={"compliance": "compliant"})))
    assert seeded.users[uid]["userStatus"] == "DISABLED", "training hold still active"
    assert r.actions == []

    r = run(p.process(ev("status", statuses={"training": "complete"})))
    assert seeded.users[uid]["userStatus"] == "ACTIVE"
    assert "g-vpn" in held(seeded, uid, "groupIds")
    assert held(seeded, uid, "roleIds") == {"r-remote"}

    r = run(p.process(ev("status", statuses={"training": "unknown_value"})))
    assert r.ok and r.warnings and "g-vpn" not in held(seeded, uid, "groupIds")


def test_leave_and_return_respect_holds(seeded, producer):
    p = producer()
    uid = run(p.process(hire())).user_id
    run(p.process(ev("leave")))
    assert seeded.users[uid]["userStatus"] == "LEAVE"
    run(p.process(ev("status", statuses={"compliance": "non_compliant"})))
    assert seeded.users[uid]["userStatus"] == "LEAVE", "no enable/disable while on leave"
    run(p.process(ev("return")))
    assert seeded.users[uid]["userStatus"] == "DISABLED", "returns, but compliance hold applies"


def test_terminate_scheduled_removes_access_and_blocks_rehire(seeded, producer):
    p = producer()
    uid = run(p.process(hire())).user_id
    when = date.today() + timedelta(days=14)
    r = run(p.process(ev("terminate", effective_date=when.isoformat(), reason="resigned")))
    assert r.ok
    action, _, body = seeded.actions[-1]
    assert action == "terminateUser" and body["performNow"] is False
    assert body["performDataString"] == f"{when.isoformat()}T00:00:00.000Z"
    assert body["reason"] == "resigned"
    assert not held(seeded, uid, "groupIds") and not held(seeded, uid, "organizationIds")

    again = run(p.process(hire()))
    assert not again.ok and "rehire" in again.error


def test_unknown_group_is_created_as_ad_group(seeded, producer):
    p = producer()
    r = run(p.process(hire(groups=["Brand New Team"])))
    assert r.ok and "created group Brand New Team" in r.actions
    new = next(g for g in seeded.groups.values() if g["name"] == "Brand New Team")
    assert new["managedSysId"] == AD_SYS


def test_unknown_group_without_create_fails_before_any_change(seeded, producer):
    cfg = make_cfg()
    cfg.directories["group"].create_path = None
    p = producer(cfg)
    r = run(p.process(hire(groups=["Nope", "All Staff"])))
    assert not r.ok and "'Nope' not found" in r.error
    # The user exists (retry-safe), but no group was half-applied.
    assert held(seeded, r.user_id, "groupIds") == set()
    fixed = run(p.process(hire(groups=["All Staff"])))
    assert fixed.ok and fixed.user_id == r.user_id


def test_batch_skips_later_events_after_failure(seeded, producer):
    results = run(producer().process_many([ev("terminate"), hire(), ev("status")]))
    assert [r.ok for r in results] == [False, False, False]
    assert "send a hire first" in results[0].error and "skipped" in results[1].error


def test_http_routes(seeded, producer, api):
    app.state.producer = producer()
    r = api.post("/producer/events", json=[
        {"type": "hire", "employee_id": "E9", "person": {"first_name": "G", "last_name": "H"},
         "groups": ["All Staff"]},
        {"type": "status", "employee_id": "E9", "statuses": {"compliance": "non_compliant"}},
    ])
    assert r.status_code == 200 and all(x["ok"] for x in r.json())
    person = api.get("/producer/people/E9").json()
    assert person["enabled"] is False and person["applied"]["group"] == ["g-staff"]
    assert api.get("/producer/people/nobody").status_code == 404


def test_producer_routes_503_when_not_configured(api):
    assert api.post("/producer/events", json=[]).status_code == 503
