import asyncio
import hashlib
import hmac
import json

import httpx
import pytest
from sqlalchemy import update

from app.main import app
from app.sync import MassDeleteError, Store, SyncConfig, SyncError, SyncService, build_target

SECRET = "hook-secret"


def run(coro):
    return asyncio.run(coro)


def make_cfg(target: dict | None = None, **overrides) -> SyncConfig:
    return SyncConfig.model_validate({
        "entities": {
            "user": {"path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}],
                     "page_size": 3, "ignore_fields": ["lastLogin"]},
            "group": {"path": "/webconsole/rest/api/groups/search", "queries": [{"name": "*"}]},
        },
        "target": target or {"type": "none"},
        **overrides,
    })


def seed(fake, n_users: int = 4) -> None:
    for i in range(n_users):
        fake.users[f"u{i}"] = {"id": f"u{i}", "firstName": f"F{i}", "lastName": "L", "lastLogin": 0}
    fake.groups["g1"] = {"id": "g1", "name": "Staff"}


@pytest.fixture
def service(database, make_client):
    def _make(cfg: SyncConfig, transport=None) -> SyncService:
        return SyncService(make_client(), Store(database), cfg, build_target(cfg, transport))
    return _make


def kinds(events):
    return sorted((e["type"], e["entity_id"]) for e in events)


def test_detects_create_update_delete_and_ignores_noise(fake, service, tmp_path):
    seed(fake)
    out = tmp_path / "events.jsonl"
    svc = service(make_cfg({"type": "file", "path": str(out)}))

    first = run(svc.run())
    assert first["entities"]["user"]["created"] == 4 and first["entities"]["group"]["created"] == 1
    assert first["delivery"] == {"sent": 5}

    assert run(svc.run())["delivery"] == {"sent": 0}  # nothing changed

    fake.users["u0"]["lastLogin"] = 999          # ignored field
    fake.users["u1"]["firstName"] = "Renamed"    # real change
    fake.groups["g2"] = {"id": "g2", "name": "Ops"}
    del fake.users["u3"]
    third = run(svc.run())
    assert third["entities"]["user"] == {"created": 0, "updated": 1, "deleted": 1, "unchanged": 2}

    events = [json.loads(line) for line in out.read_text().splitlines()]
    new = events[5:]
    assert kinds(new) == [("group.created", "g2"), ("user.deleted", "u3"), ("user.updated", "u1")]
    upd = next(e for e in new if e["type"] == "user.updated")
    assert upd["changes"] == {"firstName": {"old": "F1", "new": "Renamed"}}
    gone = next(e for e in new if e["type"] == "user.deleted")
    assert gone["data"] is None and gone["previous"]["firstName"] == "F3"
    assert len({e["event_id"] for e in events}) == len(events)


def test_baseline_records_state_without_events(fake, service):
    seed(fake)
    svc = service(make_cfg())
    run(svc.run(baseline=True))
    assert svc.store.counts() == {"user": 4, "group": 1}
    assert svc.store.events_after(0, 100) == []


def test_mass_delete_is_blocked_and_nothing_recorded(fake, service):
    seed(fake, n_users=10)
    svc = service(make_cfg())
    run(svc.run())
    for i in range(6):
        del fake.users[f"u{i}"]
    fake.groups["g9"] = {"id": "g9", "name": "New"}
    with pytest.raises(MassDeleteError):
        run(svc.run())
    # All-or-nothing: the group change from the same run was not recorded either.
    assert svc.store.counts() == {"user": 10, "group": 1}
    assert svc.store.recent_runs(1)[0]["status"] == "failed"

    result = run(svc.run(allow_mass_delete=True))
    assert result["entities"]["user"]["deleted"] == 6


def test_failed_fetch_records_nothing(fake, service):
    seed(fake)
    svc = service(make_cfg())
    run(svc.run())
    fake.users["u0"]["firstName"] = "Changed"
    fake.fail_paths.add("/webconsole/rest/api/groups/search")
    with pytest.raises(Exception):
        run(svc.run())
    assert svc.store.snapshot("user")[0]["firstName"] == "F0"
    fake.fail_paths.clear()
    assert run(svc.run())["entities"]["user"]["updated"] == 1


def test_paging_that_ignores_offset_is_an_error(fake, service):
    cfg = SyncConfig.model_validate({"entities": {"x": {
        "path": "/webconsole/rest/api/broken/search", "queries": [{"a": 1}], "page_size": 5}}})
    with pytest.raises(SyncError, match="no new records"):
        run(service(cfg).run())


class Receiver:
    """The other site: verifies signatures, can be told to fail."""

    def __init__(self):
        self.batches: list[list[dict]] = []
        self.fail = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            return httpx.Response(503)
        ts, sig = request.headers["X-IAM-Timestamp"], request.headers["X-IAM-Signature"]
        expected = hmac.new(SECRET.encode(), ts.encode() + b"." + request.content,
                            hashlib.sha256).hexdigest()
        assert sig == f"sha256={expected}"
        self.batches.append(json.loads(request.content)["events"])
        return httpx.Response(200)


def test_webhook_signed_ordered_and_retried(fake, service, monkeypatch):
    monkeypatch.setenv("SYNC_WEBHOOK_SECRET", SECRET)
    seed(fake)
    recv = Receiver()
    svc = service(make_cfg({"type": "webhook", "url": "https://other.site/hook"}, batch_size=2),
                  httpx.MockTransport(recv))

    recv.fail = True
    result = run(svc.run())
    assert result["delivery"]["sent"] == 0 and "503" in result["delivery"]["error"]
    stats = svc.store.outbox_stats()
    assert stats["pending"] == 5 and "503" in stats["last_error"]

    recv.fail = False
    assert run(svc.deliver()) == {"sent": 0}  # still in backoff
    with svc.store.connect() as conn:
        conn.execute(update(svc.store.outbox).values(next_attempt=0))
    assert run(svc.deliver()) == {"sent": 5}
    seqs = [e["event_id"] for b in recv.batches for e in b]
    assert len(seqs) == 5 and [len(b) for b in recv.batches] == [2, 2, 1]
    assert svc.store.outbox_stats()["pending"] == 0


def test_webhook_without_secret_refuses_to_start(monkeypatch):
    monkeypatch.delenv("SYNC_WEBHOOK_SECRET", raising=False)
    with pytest.raises(ValueError, match="SYNC_WEBHOOK_SECRET"):
        build_target(make_cfg({"type": "webhook", "url": "https://x.example"}))


@pytest.fixture
def sync_api(fake, service, request):
    seed(fake)
    app.state.sync = service(make_cfg())
    yield request.getfixturevalue("api")


def test_sync_http_routes(sync_api, fake):
    api = sync_api
    r = api.post("/sync/run")
    assert r.status_code == 200 and r.json()["delivery"] == {"mode": "pull", "sent": 0}

    feed = api.get("/sync/events").json()
    assert len(feed["events"]) == 5
    fake.users["u2"]["firstName"] = "Z"
    api.post("/sync/run")
    newer = api.get(f"/sync/events?after={feed['next_after']}").json()
    assert [e["type"] for e in newer["events"]] == ["user.updated"]

    snap = api.get("/sync/snapshot/user").json()["items"]
    assert [u["id"] for u in snap] == ["u0", "u1", "u2", "u3"]
    assert api.get("/sync/snapshot/nope").status_code == 404
    status = api.get("/sync/status").json()
    assert status["tracked"] == {"user": 4, "group": 1} and status["runs"][0]["status"] == "ok"

    for i in range(4):
        del fake.users[f"u{i}"]
    for i in range(10, 16):
        fake.users[f"u{i}"] = {"id": f"u{i}", "lastName": "L"}
    api.post("/sync/run")  # 6 users now
    for i in range(10, 16):
        del fake.users[f"u{i}"]
    assert api.post("/sync/run").status_code == 409


def test_sync_routes_503_when_not_configured(api):
    assert api.get("/sync/status").status_code == 503
