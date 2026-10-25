import os
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server

from app.config import Settings, get_settings
from app.consumer import Consumer, ConsumerConfig, ConsumerStore
from app.consumer.ad_target import AdApplier
from app.sync import Store, SyncConfig, SyncService, build_target
from app.db import Database
from app.main import app
from app.openiam import OpenIAMClient

from .ad_helpers import BASE, GROUPS, USERS, ad_cfg
from .fake_openiam import CLIENT_ID, CLIENT_SECRET, FakeOpenIAM

API_KEY = "k3y"


@pytest.fixture
def database(tmp_path):
    """SQLite by default; a fresh PostgreSQL schema per test when TEST_DATABASE_URL is set."""
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        db = Database(f"sqlite:///{(tmp_path / 'backend.db').as_posix()}")
        db.migrate()
        yield db
        db.engine.dispose()
        return
    schema = f"test_{uuid.uuid4().hex[:12]}"
    db = Database(url, schema)
    db.migrate()
    yield db
    with db.engine.begin() as conn:
        conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    db.engine.dispose()


@pytest.fixture
def fake() -> FakeOpenIAM:
    return FakeOpenIAM()


@pytest.fixture
def settings() -> Settings:
    return Settings(_env_file=None, openiam_base_url="https://iam.test",
                    openiam_client_id=CLIENT_ID, openiam_client_secret=CLIENT_SECRET,
                    default_user_metadata_type_id="DEFAULT_USER", default_email_type_id="PRIMARY_EMAIL",
                    backend_api_key=API_KEY)


@pytest.fixture
def make_client(fake):
    def _make(secret: str = CLIENT_SECRET) -> OpenIAMClient:
        return OpenIAMClient("https://iam.test", CLIENT_ID, secret, transport=fake.transport())
    return _make


@pytest.fixture
def api(fake, settings, make_client, database):
    app.state.openiam = make_client()
    app.state.db = database
    if not hasattr(app.state, "sync"):  # sync tests set their own first
        app.state.sync = None
    app.state.producer = None
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        yield c
    app.dependency_overrides.clear()
    del app.state.openiam
    del app.state.db
    del app.state.sync
    del app.state.producer


# ---- two-site fixtures (producer side exports, consumer side applies) -----------------

@pytest.fixture
def site_a(fake):
    """The producer side's OpenIAM."""
    fake.users.update({
        "a1": {"id": "a1", "firstName": "Ada", "lastName": "Lovelace", "employeeId": "E1",
               "email": "ada@corp.example", "domain": "corp.example", "groups": [{"name": "Staff"}]},
        "a2": {"id": "a2", "firstName": "Alan", "lastName": "Turing", "employeeId": "E2",
               "domain": "corp.example", "groups": []},
        "a3": {"id": "a3", "firstName": "Grace", "lastName": "Hopper", "employeeId": "E3",
               "domain": "lab.example", "groups": [{"name": "Lab"}]},
    })
    fake.groups.update({"g1": {"id": "g1", "name": "Staff", "domain": "corp.example"},
                        "g2": {"id": "g2", "name": "Lab", "domain": "lab.example"}})
    return fake


@pytest.fixture
def remote():
    """The remote site's OpenIAM, a separate instance."""
    return FakeOpenIAM()


@pytest.fixture
def exporter(site_a, database, make_client, tmp_path):
    cfg = SyncConfig.model_validate({
        "entities": {
            "user": {"path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}]},
            "group": {"path": "/webconsole/rest/api/groups/search", "queries": [{"name": "*"}]},
        },
        "export": {"folder": str(tmp_path / "share"), "formats": ["jsonl", "csv"],
                   "domains": {"by_field": {"user": "domain", "group": "domain"}}},
    })
    return SyncService(make_client(), Store(database), cfg, build_target(cfg))


@pytest.fixture
def consumer(remote, database, settings, tmp_path):
    cfg = ConsumerConfig.model_validate({
        "inbox": str(tmp_path / "share"), "settle_seconds": 0,
        "archive": str(tmp_path / "archive"), "failed": str(tmp_path / "failed"),
        "user": {"memberships": {"group": "groups.name"}},
        "directories": {"group": {"search_path": "/webconsole/rest/api/groups/search",
                                  "create_path": "/webconsole/rest/api/groups/save"}},
    })
    client = OpenIAMClient("https://remote.test", CLIENT_ID, CLIENT_SECRET, transport=remote.transport())
    return Consumer(client, ConsumerStore(database), cfg, settings)


# ---- AD target fixtures -----------------------------------------------------------------

@pytest.fixture
def ad():
    """A shared in-memory AD; every 'connection' the applier opens is this one."""
    conn = Connection(Server("mock", get_info=OFFLINE_AD_2012_R2), user=f"CN=svc,{BASE}",
                      password="x", client_strategy=MOCK_SYNC)
    conn.strategy.add_entry(f"CN=svc,{BASE}", {"userPassword": "x", "objectClass": ["user"]})
    conn.bind()
    for dn, oc, attrs in [
        (f"OU=IAM,{BASE}", ["organizationalUnit"], {"ou": "IAM"}),
        (USERS, ["organizationalUnit"], {"ou": "Users"}),
        (GROUPS, ["organizationalUnit"], {"ou": "Groups"}),
        (f"CN=All Staff,{GROUPS}", ["top", "group"], {"cn": "All Staff"}),
        (f"CN=Domain Admins,CN=Users,{BASE}", ["top", "group"], {"cn": "Domain Admins"}),
    ]:
        conn.add(dn, oc, attrs)
    conn.unbind = lambda: None   # keep the shared mock open between plan/apply
    return conn


@pytest.fixture
def make_ad_consumer(database, settings, tmp_path, ad):
    def _make(**cfg):
        c = ConsumerConfig.model_validate({"inbox": str(tmp_path / "in"), "archive": str(tmp_path / "arc"), "settle_seconds": 0,
                                           "failed": str(tmp_path / "bad")})
        applier = AdApplier(ad_cfg(**cfg), conn_factory=lambda: ad)
        return Consumer(None, ConsumerStore(database), c, settings, target="ad", ad=applier)
    return _make
