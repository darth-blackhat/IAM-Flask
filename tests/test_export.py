import asyncio
import hashlib
import json
import zipfile

import pytest

from app.sync import Store, SyncConfig, SyncService, build_target
from app.sync.export import extract, safe_name, split_domains
from app.sync.config import DomainSplit


def run(coro):
    return asyncio.run(coro)


def make_cfg(folder, **export) -> SyncConfig:
    return SyncConfig.model_validate({
        "entities": {
            "user": {"path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}]},
            "group": {"path": "/webconsole/rest/api/groups/search", "queries": [{"name": "*"}]},
            "role": {"path": "/webconsole/rest/api/roles/search", "queries": [{"name": "*"}]},
        },
        "export": {"folder": str(folder),
                   "domains": {"by_field": {"user": "domain", "group": "domain"}, "shared": ["role"]},
                   **export},
    })


@pytest.fixture
def seeded(fake):
    fake.users.update({
        "u1": {"id": "u1", "lastName": "A", "domain": "corp.example"},
        "u2": {"id": "u2", "lastName": "B", "domain": "corp.example"},
        "u3": {"id": "u3", "lastName": "C", "domain": "lab.example"},
        "u4": {"id": "u4", "lastName": "D"},  # no domain
    })
    fake.groups.update({"g1": {"id": "g1", "name": "Staff", "domain": "corp.example"}})
    return fake


@pytest.fixture
def service(database, make_client):
    def _make(cfg):
        return SyncService(make_client(), Store(database), cfg, build_target(cfg))
    return _make


def zips(folder):
    return sorted(p for p in folder.rglob("*.zip"))


def read_zip(path):
    with zipfile.ZipFile(path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        for f in manifest["files"]:
            assert hashlib.sha256(zf.read(f["name"])).hexdigest() == f["sha256"]
        users = [json.loads(line) for line in zf.read("user.jsonl").decode().splitlines()]
        return manifest, users, zf.namelist()


def test_one_zip_per_domain_with_shared_roles(seeded, service, tmp_path):
    out = tmp_path / "exports"
    result = run(service(make_cfg(out)).export())
    statuses = {d["domain"]: d["status"] for d in result["domains"]}
    assert statuses == {"corp.example": "exported", "lab.example": "exported", "_unassigned": "exported"}

    corp = next(p for p in zips(out) if p.parent.name == "corp.example")
    manifest, users, names = read_zip(corp)
    assert manifest["domain"] == "corp.example" and manifest["counts"] == {"user": 2, "group": 1, "role": 1}
    assert {u["id"] for u in users} == {"u1", "u2"}
    assert {"user.jsonl", "user.csv", "group.jsonl", "role.jsonl", "manifest.json"} <= set(names)
    assert not list(out.rglob("*.partial"))


def test_only_changed_and_new_domains_are_reexported(seeded, service, tmp_path):
    out = tmp_path / "exports"
    svc = service(make_cfg(out))
    run(svc.export())
    assert {d["status"] for d in run(svc.export())["domains"]} == {"unchanged"}

    seeded.users["u3"]["lastName"] = "Changed"
    seeded.users["u5"] = {"id": "u5", "lastName": "E", "domain": "new.example"}  # brand-new domain
    statuses = {d["domain"]: d["status"] for d in run(svc.export())["domains"]}
    assert statuses == {"corp.example": "unchanged", "lab.example": "exported",
                        "new.example": "exported", "_unassigned": "unchanged"}
    assert len(zips(out / "lab.example")) == 2

    assert all(d["status"] == "exported" for d in run(svc.export(force=True))["domains"])


def test_vanished_domain_gets_final_removed_zip(seeded, service, tmp_path):
    out = tmp_path / "exports"
    svc = service(make_cfg(out))
    run(svc.export())
    del seeded.users["u3"]
    statuses = {d["domain"]: d["status"] for d in run(svc.export())["domains"]}
    assert statuses["lab.example"] == "removed"
    manifest, users, _ = read_zip(zips(out / "lab.example")[-1])
    assert manifest["removed"] is True and users == []


def test_keep_prunes_only_that_domains_zips(seeded, service, tmp_path):
    out = tmp_path / "exports"
    (out / "corp.example").mkdir(parents=True)
    stranger = out / "corp.example" / "notes.txt"
    stranger.write_text("not ours")
    svc = service(make_cfg(out, keep=2))
    for _ in range(4):
        run(svc.export(force=True))
    assert len(zips(out / "corp.example")) == 2 and stranger.exists()


def test_after_sync_exports_from_snapshot(seeded, service, tmp_path):
    out = tmp_path / "exports"
    svc = service(make_cfg(out, after_sync=True))
    result = run(svc.run())
    assert {d["status"] for d in result["export"]["domains"]} == {"exported"}
    assert {d["status"] for d in run(svc.run())["export"]["domains"]} == {"unchanged"}


def test_no_export_section_is_an_error(seeded, service, tmp_path, database, make_client):
    cfg = make_cfg(tmp_path)
    cfg.export = None
    with pytest.raises(Exception, match="no `export`"):
        run(service(cfg).export())


def test_extract_and_split_helpers():
    rec = {"orgs": [{"name": "A"}, {"name": "B"}, {"name": None}], "d": "x"}
    assert extract(rec, "orgs.name") == ["A", "B"]
    assert extract(rec, "d") == ["x"] and extract(rec, "missing") == []
    split = split_domains({"user": [rec]}, DomainSplit(by_field={"user": "orgs.name"}))
    assert set(split) == {"A", "B"}
    assert split_domains({"user": [rec]}, DomainSplit())["all"]["user"] == [rec]


@pytest.mark.parametrize("domain", ["corp.example", "a/b\\c", "CON", "..", "Ünïcode Dept"])
def test_safe_name_is_filesystem_safe_and_unique(domain):
    name = safe_name(domain)
    assert name and all(c.isalnum() or c in "._-" for c in name)
    assert name.upper() != "CON" and not name.startswith(".")
    assert safe_name("a/b") != safe_name("a_b")


def test_config_rejects_unsplit_entities(tmp_path):
    with pytest.raises(ValueError, match="role"):
        SyncConfig.model_validate({
            "entities": {"user": {"path": "/webconsole/rest/api/users/search", "queries": [{"a": 1}]},
                         "role": {"path": "/webconsole/rest/api/roles/search", "queries": [{"a": 1}]}},
            "export": {"folder": str(tmp_path), "domains": {"by_field": {"user": "domain"}}}})
