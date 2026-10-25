import asyncio
import pathlib
import shutil
import zipfile





def run(coro):
    return asyncio.run(coro)


def by_emp(remote, emp):
    return next(u for u in remote.users.values() if u.get("employeeId") == emp)


def statuses(result):
    return sorted((f["domain"], f["status"]) for f in result["files"])


def test_zips_are_applied_to_remote_openiam(site_a, remote, exporter, consumer, tmp_path):
    run(exporter.export())
    result = run(consumer.scan())
    assert statuses(result) == [("corp.example", "applied"), ("lab.example", "applied")]

    ada = by_emp(remote, "E1")
    assert ada["firstName"] == "Ada" and ada["emailAddresses"][0]["email"] == "ada@corp.example"
    staff = next(g for g in remote.groups.values() if g["name"] == "Staff")
    assert remote.members[ada["id"]]["groupIds"] == {staff["id"]}
    assert {g["name"] for g in remote.groups.values()} == {"Staff", "Lab"}

    # Zips moved out of the inbox, into archive/<domain>/.
    assert not list((tmp_path / "share").rglob("*.zip"))
    assert len(list((tmp_path / "archive" / "corp.example").glob("*.zip"))) == 1


def test_changes_flow_through_and_only_changes_are_applied(site_a, remote, exporter, consumer):
    run(exporter.export())
    run(consumer.scan())
    saves_before = sum(1 for m, p in remote.requests if p.endswith("/prov/saveUser"))

    site_a.users["a2"]["lastName"] = "Turing-Changed"
    site_a.users["a4"] = {"id": "a4", "firstName": "New", "lastName": "Hire", "employeeId": "E4",
                          "domain": "corp.example", "groups": [{"name": "Staff"}]}
    run(exporter.export())  # only corp.example changed
    result = run(consumer.scan())
    [corp] = result["files"]
    assert corp["domain"] == "corp.example" and corp["status"] == "applied"
    assert corp["summary"] == {"unchanged": 2, "updated": 1, "created": 1}
    assert by_emp(remote, "E2")["lastName"] == "Turing-Changed" and by_emp(remote, "E4")
    saves = sum(1 for m, p in remote.requests if p.endswith("/prov/saveUser")) - saves_before
    assert saves == 2  # Ada was not re-sent


def test_user_removed_from_domain_is_disabled(site_a, remote, exporter, consumer):
    run(exporter.export())
    run(consumer.scan())
    del site_a.users["a2"]
    run(exporter.export())
    [corp] = run(consumer.scan())["files"]
    assert corp["summary"]["disabled"] == 1
    assert by_emp(remote, "E2")["userStatus"] == "DISABLED"


def test_user_in_two_domains_is_not_disabled_when_leaving_one(site_a, remote, exporter, consumer):
    exporter.cfg.export.domains.by_field["user"] = "domains"
    for u in site_a.users.values():
        u["domains"] = [u["domain"]]
    site_a.users["a1"]["domains"] = ["corp.example", "lab.example"]
    run(exporter.export())
    run(consumer.scan())
    site_a.users["a1"]["domains"] = ["corp.example"]
    run(exporter.export())
    result = run(consumer.scan())
    lab = next(f for f in result["files"] if f["domain"] == "lab.example")
    assert lab["summary"].get("missing") == 1 and "disabled" not in lab["summary"]
    assert by_emp(remote, "E1")["userStatus"] != "DISABLED"


def test_out_of_order_duplicate_and_tampered_zips(site_a, remote, exporter, consumer, tmp_path):
    share, held = tmp_path / "share", tmp_path / "held-back"
    held.mkdir()
    run(exporter.export())
    run(consumer.scan())

    # Two newer lab.example zips; the first one is delayed in transit.
    site_a.users["a3"]["lastName"] = "Hopper-2"
    run(exporter.export())
    [older] = list((share / "lab.example").glob("*.zip"))
    delayed = shutil.move(older, held / older.name)
    site_a.users["a3"]["lastName"] = "Hopper-3"
    run(exporter.export())
    assert statuses(run(consumer.scan())) == [("lab.example", "applied")]

    # The delayed (older) zip arrives late: it must not roll the data back.
    shutil.copy(delayed, share / "lab.example" / pathlib.Path(delayed).name)
    assert statuses(run(consumer.scan())) == [("lab.example", "stale")]
    assert by_emp(remote, "E3")["lastName"] == "Hopper-3"

    # Exactly the same bytes again: recognised as a duplicate.
    shutil.copy(delayed, share / "lab.example" / pathlib.Path(delayed).name)
    assert statuses(run(consumer.scan())) == [("lab.example", "duplicate")]

    # A zip whose content no longer matches its manifest is rejected.
    bad = share / "lab.example" / "openiam-lab.example-29990101T000000000000Z.zip"
    with zipfile.ZipFile(delayed) as src, zipfile.ZipFile(bad, "w") as dst:
        for item in src.namelist():
            data = src.read(item)
            dst.writestr(item, data.replace(b"Grace", b"Mallory") if item == "user.jsonl" else data)
    [f] = run(consumer.scan())["files"]
    assert f["status"] == "failed" and "checksum" in f["error"]
    assert list((tmp_path / "failed").rglob("*.zip"))
    assert by_emp(remote, "E3")["firstName"] == "Grace"


def test_half_written_and_foreign_files_are_ignored(consumer, tmp_path):
    share = tmp_path / "share"
    share.mkdir()
    (share / ".openiam-x-20260101T000000000000Z.zip.partial").write_bytes(b"...")
    (share / "notes.zip").write_bytes(b"...")
    assert run(consumer.scan()) == {"files": []}


def test_missing_group_without_create_is_reported_and_retried(site_a, remote, exporter, consumer):
    consumer.cfg.directories["group"].create_path = None
    run(exporter.export())
    result = run(consumer.scan())
    assert {f["status"] for f in result["files"]} == {"partial"}
    failed = consumer.store.actions_page(ok=False)
    assert any("not in the remote OpenIAM" in a["detail"] for a in failed)

    # Fixed on the remote side; the next zip for the domain retries the failed records.
    remote.groups["r1"] = {"id": "r1", "name": "Staff"}
    remote.groups["r2"] = {"id": "r2", "name": "Lab"}
    run(exporter.export(force=True))
    assert {f["status"] for f in run(consumer.scan())["files"]} == {"applied"}


def test_unwritable_archive_does_not_stop_the_scan(site_a, remote, exporter, consumer, tmp_path):
    blocker = tmp_path / "archive-is-a-file"
    blocker.write_text("not a directory")
    consumer.cfg.archive = str(blocker)
    run(exporter.export())
    result = run(consumer.scan())
    assert {f["status"] for f in result["files"]} == {"applied"}
    assert by_emp(remote, "E1")
    # Left in the inbox; the next scan recognises it and does not re-apply it.
    assert {f["status"] for f in run(consumer.scan())["files"]} == {"duplicate"}
