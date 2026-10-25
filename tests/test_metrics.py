import time
import urllib.request

from app.metrics import registry_for, render, serve
from app.security import ApiKeyStore


def test_metrics_reflect_the_database(database):
    t = database.tables
    with database.begin() as conn:
        conn.execute(t.sync_outbox.insert(), [
            {"event_id": "a", "payload": {}, "created_at": time.time() - 100, "delivered_at": None, "dead": False},
            {"event_id": "b", "payload": {}, "created_at": 0.0, "delivered_at": None, "dead": True}])
        conn.execute(t.consumer_domains.insert().values(domain="corp", last_generated_at="x",
                                                        last_file="f", records=1, updated_at=time.time() - 50))
        conn.execute(t.sync_runs.insert().values(started_at=1.0, finished_at=2.0, status="failed",
                                                 error="MassDeleteError: user: 9 of 10 disappeared"))
    text = render(registry_for(database, "producer")).decode()
    assert 'backend_iam_outbox_events{state="pending"} 1.0' in text
    assert 'backend_iam_outbox_events{state="dead"} 1.0' in text
    assert "backend_iam_sync_mass_delete_blocked 1.0" in text
    assert 'backend_iam_consumer_domain_applied_age_seconds{domain="corp"}' in text
    assert 'backend_iam_up{role="producer"} 1.0' in text


def test_metrics_endpoint_needs_scope(api, database):
    assert api.get("/metrics", headers={"X-API-Key": "nope"}).status_code == 401
    scraper = ApiKeyStore(database).create("prometheus", ["metrics:read"])
    r = api.get("/metrics", headers={"Authorization": f"Bearer {scraper}"})
    assert r.status_code == 200 and "backend_iam_up" in r.text
    assert api.get("/sync/status", headers={"X-API-Key": scraper}).status_code == 403


def test_consumer_listener(database):
    serve(database, "consumer", "127.0.0.1", 19102)
    body = urllib.request.urlopen("http://127.0.0.1:19102/metrics", timeout=5).read().decode()
    assert 'backend_iam_up{role="consumer"} 1.0' in body
