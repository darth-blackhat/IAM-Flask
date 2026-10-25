import asyncio
import json
import zipfile

from app.logs import redact
from app.sync import Store, SyncConfig, SyncService, build_target


def test_only_allowed_fields_leave_the_site(fake, database, make_client, tmp_path):
    fake.users["u1"] = {"id": "u1", "firstName": "Ada", "lastName": "L", "employeeId": "E1",
                        "domain": "corp", "ssn": "123-45-6789", "salary": 99000, "homeAddress": "x"}
    cfg = SyncConfig.model_validate({
        "entities": {"user": {"path": "/webconsole/rest/api/users/search", "queries": [{"lastName": "*"}]}},
        "target": {"type": "zip"},
        "export": {"folder": str(tmp_path / "out"), "after_sync": True, "formats": ["jsonl", "csv"],
                   "domains": {"by_field": {"user": "domain"}},
                   "fields": {"user": ["firstName", "lastName", "employeeId"]}}})
    svc = SyncService(make_client(), Store(database), cfg, build_target(cfg))
    asyncio.run(svc.run())
    [z] = list((tmp_path / "out").rglob("*.zip"))
    with zipfile.ZipFile(z) as zf:
        [user] = [json.loads(x) for x in zf.read("user.jsonl").decode().splitlines()]
        line = json.loads(zf.read("ad_instructions.jsonl").decode().splitlines()[0])
        csv = zf.read("user.csv").decode()
    assert set(user) == {"id", "domain", "firstName", "lastName", "employeeId"}
    assert "ssn" not in line["data"] and "salary" not in line["data"]
    assert "123-45-6789" not in csv and "99000" not in csv


def test_log_redaction():
    assert redact("sent to ada.lovelace@corp.example ok") == "sent to a***@corp.example ok"
    assert redact("call +1 (555) 123-4567 now") == "call ***67 now"
    assert redact("employee E1001 run 42 at 2026-10-25") == "employee E1001 run 42 at 2026-10-25"


def test_redaction_leaves_dates_and_ids_alone():
    assert redact("from 2026-10-25T12:00:00Z, run 1234567, E1001") == "from 2026-10-25T12:00:00Z, run 1234567, E1001"
    assert redact("tel (020) 7946 0958 or 555-123-4567") == "tel ***58 or ***67"
