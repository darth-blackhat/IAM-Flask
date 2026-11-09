"""Notifications for change detection problems and for the consumer site's own events."""

import asyncio

import pytest

from app.notify import EVENTS, Notifications, Notifier, NotifyConfig, Webhook
from app.sync import Store
from app.sync.engine import MassDeleteError, run_sync

from .test_ad_target import HIRE
from .test_receipts import consumer


def run(coro):
    return asyncio.run(coro)


def events(database):
    return [n["event"] for n in Notifications(database).recent()]


def test_every_emitted_event_is_known():
    for e in ("sync.failed", "sync.mass_delete_blocked", "instructions.dead", "zip.rejected", "zip.partial",
              "ad.plan_waiting", "ad.changed_outside", "ad.protected_group_changed", "drift.found"):
        assert e in EVENTS


def test_failed_and_mass_delete_runs_notify(exporter, site_a, database):
    exporter.cfg.mass_delete_min = 1                          # the fixture has only 3 users
    run(exporter.run(baseline=True))
    site_a.users.clear()                                     # everyone vanished: refused
    with pytest.raises(MassDeleteError):
        run(run_sync(exporter.client, exporter.store, exporter.cfg))
    site_a.fail_paths.add("/webconsole/rest/api/users/search")
    with pytest.raises(Exception):
        run(run_sync(exporter.client, exporter.store, exporter.cfg))
    assert events(database) == ["sync.failed", "sync.mass_delete_blocked"]


def test_dead_instructions_notify_once(database):
    store = Store(database)
    with store.connect() as conn:
        store.add_events(conn, [{"event_id": "e1", "type": "t", "entity": "user", "instructions": []}])
    [seq] = [e["seq"] for e in store.pending_all()]
    for _ in range(5):
        store.mark_failed([seq], "HTTP 503", max_attempts=3)
    assert events(database) == ["instructions.dead"]


def test_consumer_events_and_its_own_delivery(database, settings, tmp_path, ad, keys):
    c = consumer(database, settings, tmp_path, ad, keys, mode="approve")
    dest = tmp_path / "share" / "in" / "corp"
    dest.mkdir(parents=True)
    (dest / "openiam-corp-20260101T000000000000Z.zip").write_bytes(b"not a zip")
    run(c.scan())
    from app.sync.export import write_zip
    write_zip(dest, "corp", {"user": []}, ["jsonl"], {}, HIRE)
    run(c.scan())
    assert events(database) == ["ad.plan_waiting", "zip.rejected"]
    got = []
    import httpx
    c.notifier = Notifier(database, NotifyConfig(webhooks=[Webhook(name="site-b", url="https://10.0.0.9/h",
                                                                   allow_private=True)]),
                          env={}, transport=httpx.MockTransport(lambda r: got.append(r) or httpx.Response(200)))
    assert run(c.notifier.run_pending()) == 2 and len(got) == 2


def test_protected_group_change_is_its_own_event(database, settings, tmp_path, ad, keys):
    c = consumer(database, settings, tmp_path, ad, keys)

    class FakeWatcher:
        def poll(self):
            return [{"severity": "critical", "kind": "modified", "object_class": "group",
                     "dn": "CN=Domain Admins,CN=Users,DC=corp"},
                    {"severity": "warning", "kind": "appeared", "object_class": "user", "dn": "CN=x"}]
    c.watcher = FakeWatcher()
    run(c.watch_ad())
    assert sorted(events(database)) == ["ad.changed_outside", "ad.protected_group_changed"]
