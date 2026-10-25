import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.config import get_settings
from app.main import app
from app.security import ApiKeyStore, Authenticator, client_ip, parse_networks


@pytest.fixture
def make_api(fake, settings, make_client, database):
    """Start the app with adjusted settings; yields (client without default key, store)."""
    clients = []

    def _make(**overrides):
        for k, v in overrides.items():
            setattr(settings, k, v)
        app.state.openiam = make_client()
        app.state.db = database
        app.state.sync = None
        app.state.producer = None
        app.dependency_overrides[get_settings] = lambda: settings
        c = TestClient(app)
        c.__enter__()
        clients.append(c)
        return c, ApiKeyStore(database)
    yield _make
    for c in clients:
        c.__exit__(None, None, None)
    app.dependency_overrides.clear()
    for name in ("openiam", "db", "sync", "producer"):
        if hasattr(app.state, name):
            delattr(app.state, name)


def h(key):
    return {"X-API-Key": key}


def test_scopes_limit_what_a_key_can_do(make_api):
    api, store = make_api()
    hr = store.create("hr-system", ["producer:write"])
    # Auth passes (producer intake not configured here -> 503), other areas are refused.
    assert api.post("/producer/events", json=[], headers=h(hr)).status_code == 503
    r = api.get("/sync/status", headers=h(hr))
    assert r.status_code == 403 and "lacks scope sync:read" in r.json()["detail"]
    assert api.post("/users/search", json={"criteria": {"a": 1}}, headers=h(hr)).status_code == 403
    # Bearer works too.
    assert api.post("/producer/events", json=[],
                    headers={"Authorization": f"Bearer {hr}"}).status_code == 503


def test_revoked_expired_unknown_and_missing_keys(make_api, database):
    api, store = make_api()
    key = store.create("tmp", ["sync:read"])
    assert api.get("/sync/status", headers=h(key)).status_code == 503   # authenticated
    store.revoke("tmp")
    assert "revoked" in api.get("/sync/status", headers=h(key)).json()["detail"]

    old = store.create("old", ["sync:read"], expires_days=1)
    with database.begin() as conn:
        conn.execute(update(database.tables.api_keys).where(database.tables.api_keys.c.name == "old")
                     .values(expires_at=time.time() - 1))
    assert "expired" in api.get("/sync/status", headers=h(old)).json()["detail"]
    assert api.get("/sync/status", headers=h("biam_x_nope")).status_code == 401
    assert api.get("/sync/status").status_code == 401


def test_key_bound_to_a_network(make_api):
    api, store = make_api()
    key = store.create("dc-only", ["sync:read"], cidrs=["10.20.0.0/16"])
    r = api.get("/sync/status", headers=h(key))   # TestClient is not in 10.20/16
    assert r.status_code == 401 and "not allowed from" in r.json()["detail"]


def test_only_hash_is_stored(make_api, database):
    _, store = make_api()
    key = store.create("hashed", ["sync:read"])
    with database.engine.connect() as conn:
        row = conn.execute(select(database.tables.api_keys)).first()
    assert key not in str(dict(row._mapping)) and row.key_hash != key
    assert "key_hash" not in store.list()[0]


def test_rate_limit_and_body_limit(make_api):
    api, store = make_api(api_rate_per_minute=2, max_request_bytes=100)
    key = store.create("busy", ["sync:read", "producer:write"])
    codes = [api.get("/sync/status", headers=h(key)).status_code for _ in range(3)]
    assert codes[:2] == [503, 503] and codes[2] == 429
    big = api.post("/producer/events", content=b"[" + b" " * 500 + b"]",
                   headers={**h(key), "content-type": "application/json"})
    assert big.status_code == 413


def test_writes_and_refusals_are_audited_and_headers_set(make_api, database):
    api, store = make_api()
    key = store.create("auditor", ["producer:write"])
    r = api.post("/producer/events", json=[], headers=h(key))
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["Cache-Control"] == "no-store"
    api.get("/sync/status", headers=h(key))      # refused: scope
    api.get("/sync/status", headers=h("bad"))    # refused: invalid
    with database.engine.connect() as conn:
        rows = conn.execute(select(database.tables.audit_trail).order_by(database.tables.audit_trail.c.id)).all()
    assert [(r.actor, r.action, r.ok) for r in rows] == [
        ("api:auditor", "POST /producer/events", False),     # 503 -> not ok
        ("api:auditor", "GET /sync/status", False),
        ("unknown", "GET /sync/status", False)]
    assert "missing scope" in rows[1].detail and "invalid" in rows[2].detail


def test_global_allowlist_and_forwarded_for():
    trusted = parse_networks(["10.0.0.5/32"])
    # Direct peer is the trusted proxy: believe the hop before it.
    assert client_ip("10.0.0.5", "203.0.113.9", trusted) == "203.0.113.9"
    # A client cannot spoof by sending its own header when it is not the proxy.
    assert client_ip("198.51.100.7", "10.1.1.1", trusted) == "198.51.100.7"
    # Spoofed extra hops in front are ignored: take the last untrusted hop.
    assert client_ip("10.0.0.5", "1.2.3.4, 203.0.113.9", trusted) == "203.0.113.9"

    auth = Authenticator(None, "boot", ["192.168.0.0/16"])
    assert auth.authenticate("boot", "192.168.1.2")[0] is not None
    assert auth.authenticate("boot", "8.8.8.8") == (None, "source address not allowed")


def test_unknown_scope_is_refused(make_api):
    _, store = make_api()
    with pytest.raises(ValueError, match="unknown"):
        store.create("x", ["everything"])
