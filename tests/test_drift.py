import asyncio

from app.consumer.drift import drift_page, drift_report

from .test_ad_target import HIRE, drop
from .test_consumer import by_emp


def run(coro):
    return asyncio.run(coro)


def test_openiam_drift_finds_missing_and_changed(site_a, remote, exporter, consumer):
    run(exporter.export())
    run(consumer.scan())
    clean = run(drift_report(consumer, "corp.example", "alice"))
    assert clean["status"] == "clean" and clean["checked"] == 3   # 2 users + 1 group

    by_emp(remote, "E1")["firstName"] = "Changed-by-hand"
    remote.users.pop(by_emp(remote, "E2")["id"])
    report = run(drift_report(consumer, "corp.example", "alice"))
    assert report["status"] == "drift" and report["different"] == 1 and report["missing"] == 1
    [stored] = [r for r in drift_page(consumer) if r["id"] == report["report_id"]]
    assert {i["issue"] for i in stored["items"]} == {"different", "missing"}
    assert "Changed-by-hand" in next(i for i in stored["items"] if i["issue"] == "different")["detail"]


def test_ad_drift_replans_the_last_zip(make_ad_consumer, ad, tmp_path):
    c = make_ad_consumer()
    drop(tmp_path, HIRE)
    run(c.scan())
    assert run(drift_report(c, "corp", "bob"))["status"] == "clean"
    # Someone removes the user from the group directly in AD.
    from ldap3 import MODIFY_DELETE
    [user] = [e for e in (ad.search("DC=corp,DC=example", "(employeeID=E1)", attributes=["*"]) and ad.response)
              if e.get("type") == "searchResEntry"]
    ad.modify("CN=All Staff,OU=Groups,OU=IAM,DC=corp,DC=example", {"member": [(MODIFY_DELETE, [user["dn"]])]})
    report = run(drift_report(c, "corp", "bob"))
    assert report["status"] == "drift" and report["modify"] == 1


def test_drift_via_operator_request(site_a, remote, exporter, consumer):
    run(exporter.export())
    run(consumer.scan())
    result = run(consumer.operator_handlers()["drift"]({"by": "carol"}))
    assert {r["domain"] for r in result["reports"]} == {"corp.example", "lab.example"}
