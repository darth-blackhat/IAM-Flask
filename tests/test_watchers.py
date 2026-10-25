"""Inbox watchdog, OpenIAM target carrying out instructions, AD change alerts."""

import asyncio
import os
import time

from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from app.consumer import Consumer, ConsumerConfig, ConsumerStore
from app.consumer.ad_target import AdApplier
from app.producer import ProducerEvent, ProducerProcessor, ProducerStore
from app.sync import Store, SyncConfig, SyncService, build_target
from app.sync.export import write_zip

from .ad_helpers import BASE, GROUPS, USERS, ad_cfg
from .test_ad_target import HIRE
from .test_producer import make_cfg as producer_cfg


def run(coro):
    return asyncio.run(coro)


# ---- watchdog -----------------------------------------------------------------

def test_zip_is_picked_up_on_arrival(database, settings, tmp_path, ad):
    inbox = tmp_path / "in"
    cfg = ConsumerConfig.model_validate({"inbox": str(inbox), "archive": str(tmp_path / "arc"),
                                         "interval_seconds": 300, "settle_seconds": 0.2})
    consumer = Consumer(None, ConsumerStore(database), cfg, settings, target="ad",
                        ad=AdApplier(ad_cfg(), conn_factory=lambda: ad))
    consumer.watcher = None   # only the inbox watchdog in this test

    async def scenario():
        task = asyncio.create_task(consumer.loop())
        await asyncio.sleep(1.0)                          # first (empty) scan done, now waiting
        start = time.monotonic()
        (inbox / "corp").mkdir(parents=True, exist_ok=True)
        write_zip(inbox / "corp", "corp", {"user": []}, ["jsonl"], {}, HIRE)   # .partial -> rename
        while time.monotonic() - start < 15 and not consumer.store.recent_files():
            await asyncio.sleep(0.2)
        task.cancel()
        return time.monotonic() - start
    took = run(scenario())
    [f] = consumer.store.recent_files()
    assert f["status"] == "applied" and took < 10   # not the 300 s timed scan


def test_file_still_being_written_is_left_for_later(database, settings, tmp_path):
    inbox = tmp_path / "in"
    (inbox / "corp").mkdir(parents=True)
    cfg = ConsumerConfig.model_validate({"inbox": str(inbox), "settle_seconds": 30})
    consumer = Consumer(None, ConsumerStore(database), cfg, settings, target="ad",
                        ad=AdApplier(ad_cfg(), conn_factory=lambda: None))
    p = inbox / "corp" / "openiam-corp-20260101T000000000000Z.zip"
    p.write_bytes(b"half a zip")
    assert consumer.find_bundles() == []
    old = time.time() - 60
    os.utime(p, (old, old))
    assert consumer.find_bundles() == [p]


# ---- OpenIAM target carries out instructions ------------------------------------

def test_remote_openiam_follows_instructions(fake, remote, database, make_client, settings, tmp_path):
    from app.openiam import OpenIAMClient

    from .fake_openiam import CLIENT_ID, CLIENT_SECRET
    fake.groups["g-staff"] = {"id": "g-staff", "name": "All Staff", "managedSysId": "AD-MANAGED-SYS",
                              "domain": "corp"}
    remote.groups["rg"] = {"id": "rg", "name": "All Staff"}
    scfg = SyncConfig.model_validate({
        "entities": {"user": {"path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}]}},
        "target": {"type": "zip"},
        "export": {"folder": str(tmp_path / "share"), "after_sync": True, "formats": ["jsonl"],
                   "domains": {"by_field": {"user": "domain"}}}})
    store = Store(database)
    sync = SyncService(make_client(), store, scfg, build_target(scfg))
    producer = ProducerProcessor(make_client(), ProducerStore(database), producer_cfg(), settings,
                                 ad=scfg.ad, outbox=store)
    sync.attributor = producer.store.attribution
    ccfg = ConsumerConfig.model_validate({"inbox": str(tmp_path / "share"), "settle_seconds": 0,
                                          "archive": str(tmp_path / "arc")})
    consumer = Consumer(OpenIAMClient("https://remote.test", CLIENT_ID, CLIENT_SECRET,
                                      transport=remote.transport()),
                        ConsumerStore(database), ccfg, settings)

    run(sync.run(baseline=True))
    run(producer.process(ProducerEvent.model_validate({
        "type": "hire", "employee_id": "E1", "person": {"first_name": "Ada", "last_name": "L",
                                                         "extra": {"domain": "corp"}},
        "groups": ["All Staff"]})))
    run(sync.run())
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "applied" and f["summary"]["instruction_add_member"] == 1
    ruser = next(u for u in remote.users.values() if u.get("employeeId") == "E1")
    assert remote.members[ruser["id"]]["groupIds"] == {"rg"}   # membership came from the instruction

    run(producer.process(ProducerEvent.model_validate({"type": "terminate", "employee_id": "E1"})))
    run(sync.run())
    [f] = run(consumer.scan())["files"]
    assert f["summary"]["instruction_disable"] == 1
    assert remote.users[ruser["id"]]["userStatus"] == "DISABLED"


# ---- AD change alerts -------------------------------------------------------------

def test_ad_changes_outside_the_consumer_raise_alerts(make_ad_consumer, ad, tmp_path):
    from .test_ad_target import drop
    c = make_ad_consumer()
    assert run(c.watch_ad())["alerts"] == 0          # baseline
    drop(tmp_path, HIRE)
    run(c.scan())                                    # the consumer's own writes...
    assert run(c.watch_ad())["alerts"] == 0          # ...never alert

    user_dn = f"CN=Ada Lovelace,{USERS}"
    ad.modify(user_dn, {"title": [(MODIFY_REPLACE, ["CEO"])]})                         # info
    ad.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, ["512"])]})            # warning
    ad.modify(f"CN=Domain Admins,CN=Users,{BASE}", {"member": [(MODIFY_ADD, [user_dn])]})  # critical
    ad.add(f"CN=Rogue,{USERS}", ["top", "person", "organizationalPerson", "user"], {"cn": "Rogue"})
    ad.delete(f"CN=All Staff,{GROUPS}")

    result = run(c.watch_ad())
    alerts = {(a["kind"], a["dn"].split(",")[0]): a for a in c.store.alerts_page()}
    assert result["by_severity"] == {"warning": 3, "critical": 1}
    da = alerts[("modified", "CN=Domain Admins")]
    assert da["severity"] == "critical" and da["changes"]["member"]["added"] == [user_dn.lower()]
    ada = alerts[("modified", "CN=Ada Lovelace")]
    assert ada["severity"] == "warning" and ada["changes"]["title"] == {"old": None, "new": "CEO"}
    assert ("appeared", "CN=Rogue") in alerts and ("disappeared", "CN=All Staff") in alerts
    assert run(c.watch_ad())["alerts"] == 0          # reported once, not on every poll

    first = c.store.alerts_page(open_only=True)[0]
    assert c.store.acknowledge(first["id"], "web:alice", "checked with the AD team")
    assert len(c.store.alerts_page(open_only=True)) == 3
