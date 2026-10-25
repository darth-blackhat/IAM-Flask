"""Signed and encrypted zips, end to end: producer export -> consumer."""

import asyncio
import hashlib
import json
import subprocess
import sys
import zipfile

import pytest

from app import bundlesec
from app.consumer import Consumer, ConsumerConfig, ConsumerStore
from app.openiam import OpenIAMClient
from app.sync import Store, SyncConfig, SyncService, build_target

from .fake_openiam import CLIENT_ID, CLIENT_SECRET, FakeOpenIAM


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def keys(tmp_path):
    k = tmp_path / "keys"
    priv, pub = bundlesec.generate_signing_key(k / "producer")
    other_priv, _ = bundlesec.generate_signing_key(k / "intruder")
    recipient = bundlesec.generate_age_identity(k / "site-b.age")
    other_recipient = bundlesec.generate_age_identity(k / "site-c.age")
    return {"priv": priv, "pub": pub, "other_priv": other_priv, "age_id": k / "site-b.age",
            "recipient": recipient, "other_recipient": other_recipient}


@pytest.fixture
def make_exporter(fake, database, make_client, tmp_path):
    fake.users["u1"] = {"id": "u1", "firstName": "Ada", "lastName": "L", "employeeId": "E1",
                        "domain": "corp"}

    def _make(**export):
        cfg = SyncConfig.model_validate({
            "entities": {"user": {"path": "/webconsole/rest/api/users/search",
                                  "queries": [{"lastName": "*"}]}},
            "export": {"folder": str(tmp_path / "share"), "formats": ["jsonl"],
                       "domains": {"by_field": {"user": "domain"}}, **export}})
        return SyncService(make_client(), Store(database), cfg, build_target(cfg))
    return _make


@pytest.fixture
def make_consumer(database, settings, tmp_path):
    def _make(**cfg):
        remote = FakeOpenIAM()
        c = ConsumerConfig.model_validate({"inbox": str(tmp_path / "share"), "settle_seconds": 0,
                                           "archive": str(tmp_path / "archive"),
                                           "failed": str(tmp_path / "failed"), **cfg})
        client = OpenIAMClient("https://remote.test", CLIENT_ID, CLIENT_SECRET,
                               transport=remote.transport())
        return Consumer(client, ConsumerStore(database), c, settings), remote
    return _make


def only_zip(tmp_path):
    [p] = list((tmp_path / "share").rglob("openiam-*"))
    return p


def clear_share(tmp_path):
    for p in (tmp_path / "share").rglob("openiam-*"):
        p.unlink()


def test_signed_and_encrypted_roundtrip(keys, make_exporter, make_consumer, tmp_path):
    run(make_exporter(signing_key_file=str(keys["priv"]), encrypt_to=[keys["recipient"]]).export())
    z = only_zip(tmp_path)
    assert z.name.endswith(".zip.age")
    with pytest.raises(zipfile.BadZipFile):   # unreadable without the identity
        zipfile.ZipFile(z)

    consumer, remote = make_consumer(trusted_signing_keys=[str(keys["pub"])], require_signature=True,
                                     age_identity_file=str(keys["age_id"]), require_encryption=True)
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "applied"
    assert any(u.get("employeeId") == "E1" for u in remote.users.values())


def test_unsigned_or_wrongly_signed_zip_is_rejected(keys, make_exporter, make_consumer, tmp_path):
    run(make_exporter().export())   # not signed
    consumer, remote = make_consumer(trusted_signing_keys=[str(keys["pub"])], require_signature=True)
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "failed" and "not signed" in f["error"] and not remote.users

    run(make_exporter(signing_key_file=str(keys["other_priv"])).export(force=True))
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "failed" and "trusted" in f["error"]


def test_attacker_who_fixes_checksums_still_fails_the_signature(keys, make_exporter, make_consumer,
                                                                 tmp_path):
    run(make_exporter(signing_key_file=str(keys["priv"])).export())
    z = only_zip(tmp_path)
    forged = tmp_path / "forged.zip"
    with zipfile.ZipFile(z) as src, zipfile.ZipFile(forged, "w") as dst:
        manifest = json.loads(src.read("manifest.json"))
        users = src.read("user.jsonl").replace(b"Ada", b"Eve")
        for f in manifest["files"]:
            if f["name"] == "user.jsonl":
                f["sha256"] = hashlib.sha256(users).hexdigest()   # checksum fixed up...
        dst.writestr("user.jsonl", users)
        dst.writestr("manifest.json", json.dumps(manifest))
        dst.writestr("manifest.sig", src.read("manifest.sig"))   # ...but it cannot re-sign
    z.write_bytes(forged.read_bytes())
    consumer, remote = make_consumer(trusted_signing_keys=[str(keys["pub"])], require_signature=True)
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "failed" and "trusted" in f["error"] and not remote.users


def test_wrong_identity_and_plaintext_policy(keys, make_exporter, make_consumer, tmp_path):
    run(make_exporter(encrypt_to=[keys["other_recipient"]]).export())   # for another site
    consumer, _ = make_consumer(age_identity_file=str(keys["age_id"]))
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "failed" and "decrypt" in f["error"]

    run(make_exporter().export(force=True))   # plaintext
    consumer, _ = make_consumer(age_identity_file=str(keys["age_id"]), require_encryption=True)
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "failed" and "not encrypted" in f["error"]


def test_present_signature_is_checked_even_when_not_required(keys, make_exporter, make_consumer):
    run(make_exporter(signing_key_file=str(keys["other_priv"])).export())
    consumer, _ = make_consumer(trusted_signing_keys=[str(keys["pub"])])
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "failed"


def test_config_needs_keys_for_requirements():
    with pytest.raises(ValueError, match="trusted_signing_keys"):
        ConsumerConfig.model_validate({"inbox": "x", "require_signature": True})
    with pytest.raises(ValueError, match="age_identity_file"):
        ConsumerConfig.model_validate({"inbox": "x", "require_encryption": True})


def test_keys_cli(tmp_path):
    out = subprocess.run([sys.executable, "-m", "app.cli", "keys", "signing", str(tmp_path / "s")],
                         capture_output=True, text=True, check=True).stdout
    assert "key id:" in out and (tmp_path / "s.key").exists() and (tmp_path / "s.pub").exists()
    out = subprocess.run([sys.executable, "-m", "app.cli", "keys", "age", str(tmp_path / "b.age")],
                         capture_output=True, text=True, check=True).stdout
    assert "age1" in out and "AGE-SECRET-KEY-" in (tmp_path / "b.age").read_text()
