"""Consumer with CONSUMER_TARGET=ad (site without OpenIAM), against an in-memory LDAP server."""

import asyncio

import pytest
from ldap3 import SUBTREE

from app.consumer import Consumer, ConsumerConfig, ConsumerStore
from app.consumer.ad_target import AdApplier, AdError
from app.sync.export import write_zip

from .ad_helpers import BASE, USERS, ad_cfg



def run(coro):
    return asyncio.run(coro)


def line(seq, op, cls, key, why="test", **ins):
    return {"seq": seq, "event_id": f"e{seq}", "domain": "corp",
            "instruction": {"instruction_id": f"i{seq}", "op": op, "object_class": cls, "key": key, **ins},
            "why": {"summary": why}}


HIRE = [
    line(1, "create", "user", {"employeeID": "E1"}, "HR hire",
         attributes={"givenName": "Ada", "sn": "Lovelace", "mail": "ada@corp.example", "employeeID": "E1"}),
    line(2, "add_member", "group", {"cn": "All Staff"}, "in the HR group list",
         member={"object_class": "user", "key": {"employeeID": "E1"}}),
]


def drop(tmp_path, lines, n=0):
    dest = tmp_path / "in" / "corp"
    dest.mkdir(parents=True, exist_ok=True)
    path, _ = write_zip(dest, "corp", {"user": []}, ["jsonl"], {}, lines)
    return path


def find(ad, flt):
    ad.search(BASE, flt, SUBTREE, attributes=["*"])
    return [e for e in ad.response if e.get("type") == "searchResEntry"]


def test_auto_mode_creates_disabled_user_and_membership(make_ad_consumer, ad, tmp_path):
    drop(tmp_path, HIRE)
    [f] = run(make_ad_consumer().scan())["files"]
    assert f["status"] == "applied" and f["summary"]["add"] == 1 and f["summary"]["modify"] == 1
    [user] = find(ad, "(employeeID=E1)")
    assert user["dn"] == f"CN=Ada Lovelace,{USERS}"
    assert user["attributes"]["userAccountControl"] == 514          # created disabled
    assert user["attributes"]["userPrincipalName"] == "E1@corp.example"
    [group] = find(ad, "(cn=All Staff)")
    assert user["dn"] in group["attributes"]["member"]


def test_approve_mode_waits_then_applies(make_ad_consumer, ad, tmp_path):
    consumer = make_ad_consumer(mode="approve")
    drop(tmp_path, HIRE)
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "awaiting_approval" and not find(ad, "(employeeID=E1)")
    [plan] = consumer.store.plans_page()
    assert plan["status"] == "awaiting_approval" and plan["summary"]["changes"] == 2
    assert [i["ldap"] for i in plan["items"]] == ["add", "modify"]  # member of the user it creates

    result = run(consumer.approve_plan(plan["id"], "alice"))
    assert result["status"] == "applied" and find(ad, "(employeeID=E1)")
    assert consumer.store.plan(plan["id"])["decided_by"] == "alice"
    with pytest.raises(Exception, match="not awaiting"):
        run(consumer.approve_plan(plan["id"], "alice"))


def test_dry_run_changes_nothing(make_ad_consumer, ad, tmp_path):
    drop(tmp_path, HIRE)
    [f] = run(make_ad_consumer(mode="dry_run").scan())["files"]
    assert f["status"] == "planned" and not find(ad, "(employeeID=E1)")


def test_big_plan_needs_approval_even_in_auto(make_ad_consumer, ad, tmp_path):
    drop(tmp_path, HIRE)
    [f] = run(make_ad_consumer(max_changes_auto=1).scan())["files"]
    assert f["status"] == "awaiting_approval" and not find(ad, "(employeeID=E1)")


def test_protected_group_is_never_touched(make_ad_consumer, ad, tmp_path):
    drop(tmp_path, HIRE + [line(3, "add_member", "group", {"cn": "Domain Admins"},
                                member={"object_class": "user", "key": {"employeeID": "E1"}})])
    [f] = run(make_ad_consumer().scan())["files"]
    assert f["status"] == "partial"
    [da] = find(ad, "(cn=Domain Admins)")
    assert not da["attributes"].get("member")


def test_reapply_is_idempotent_and_updates_attributes(make_ad_consumer, ad, tmp_path):
    consumer = make_ad_consumer()
    drop(tmp_path, HIRE)
    run(consumer.scan())
    drop(tmp_path, [
        line(4, "update", "user", {"employeeID": "E1"}, "changed directly in OpenIAM (by jsmith)",
             changes=[{"attribute": "title", "old": None, "new": "Lead"}]),
        line(5, "create", "user", {"employeeID": "E1"},
             attributes={"givenName": "Ada", "sn": "Lovelace", "employeeID": "E1"}),
        line(6, "add_member", "group", {"cn": "All Staff"},
             member={"object_class": "user", "key": {"employeeID": "E1"}}),
    ])
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "applied"
    plan = consumer.store.plans_page()[0]
    assert [i["ldap"] for i in plan["items"]] == ["modify", "noop", "noop"]
    assert find(ad, "(employeeID=E1)")[0]["attributes"]["title"] == "Lead"


def test_delete_becomes_disable_and_enable_clears_the_bit(make_ad_consumer, ad, tmp_path):
    consumer = make_ad_consumer()
    drop(tmp_path, HIRE)
    run(consumer.scan())
    drop(tmp_path, [line(7, "enable", "user", {"employeeID": "E1"})])
    run(consumer.scan())
    assert find(ad, "(employeeID=E1)")[0]["attributes"]["userAccountControl"] == 512
    drop(tmp_path, [line(8, "delete", "user", {"employeeID": "E1"})])
    run(consumer.scan())
    [user] = find(ad, "(employeeID=E1)")                       # still there...
    assert user["attributes"]["userAccountControl"] == 514     # ...but disabled


def test_unreachable_ad_leaves_the_zip_for_retry(database, settings, tmp_path):
    def down():
        raise AdError("no AD server reachable")
    c = ConsumerConfig.model_validate({"inbox": str(tmp_path / "in"), "archive": str(tmp_path / "arc"), "settle_seconds": 0})
    consumer = Consumer(None, ConsumerStore(database), c, settings, target="ad",
                        ad=AdApplier(ad_cfg(), conn_factory=down))
    path = drop(tmp_path, HIRE)
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "retry" and path.exists()


def test_config_guard_rails():
    with pytest.raises(ValueError, match="under base_dn"):
        ad_cfg(users_ou="OU=Elsewhere,DC=other,DC=example")
    with pytest.raises(ValueError, match="clear"):
        ad_cfg(servers=["ldap://dc1.corp.example"])
    assert ad_cfg(servers=["ldap://dc1"], start_tls=True)


def test_ad_target_requires_config(database, settings, tmp_path):
    c = ConsumerConfig.model_validate({"inbox": str(tmp_path)})
    with pytest.raises(Exception, match="ad:"):
        Consumer(None, ConsumerStore(database), c, settings, target="ad")
