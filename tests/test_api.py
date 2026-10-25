from fastapi.testclient import TestClient

from app.main import app


def test_api_key_required(api):
    with TestClient(app) as anon:
        assert anon.get("/health").status_code == 200
        assert anon.post("/users/search", json={"criteria": {"lastName": "x"}}).status_code == 401


def test_create_user_with_roles_then_pull_it_back(api, fake):
    r = api.post("/users", json={
        "first_name": "Ada", "last_name": "Lovelace",
        "emails": [{"email": "ada@example.com"}], "role_ids": ["role-1"],
        "extra": {"login": "ada"},
    })
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["ok"] and res["created"] and res["entitled"]
    assert res["account_states"] == "OpenIAM: PENDING_CREATE"

    stored = fake.users[res["user_id"]]
    assert stored["metadataTypeId"] == "DEFAULT_USER"
    assert stored["emailAddresses"] == [{"email": "ada@example.com", "typeId": "PRIMARY_EMAIL",
                                         "published": False}]
    assert stored["login"] == "ada" and stored["notifyUserViaEmail"] is False
    assert fake.entitlements[res["user_id"]]["roleIds"] == ["role-1"]

    page = api.post("/users/search", json={"criteria": {"lastName": "Lovelace"}}).json()
    assert [u["id"] for u in page["beans"]] == [res["user_id"]]


def test_update_unknown_user_maps_to_404_body(api):
    r = api.post("/users", json={"id": "missing", "first_name": "A", "last_name": "B"})
    assert r.status_code == 400
    assert "USER_NOT_FOUND" in r.text


def test_partial_failure_is_reported(api, fake):
    r = api.post("/users", json={"first_name": "A", "last_name": "B", "role_ids": ["forbidden-role"]})
    res = r.json()
    assert r.status_code == 200 and res["ok"] is False and res["entitled"] is False
    assert res["user_id"] in fake.users  # the user was created; caller must know that


def test_dry_run_sends_nothing(api, fake):
    r = api.post("/users/bulk?dry_run=true", json=[{"first_name": "A", "last_name": "B"}] * 3)
    assert r.json()["succeeded"] == 3
    assert fake.users == {} and fake.tokens_issued == 0


def test_csv_import_and_csv_export(api, fake):
    csv_text = ("first_name,last_name,email,role_ids,employeeId\n"
                "Grace,Hopper,grace@example.com,r1;r2,E1\n"
                "Alan,Hopper,,,E2\n")
    r = api.post("/users/import", files={"file": ("users.csv", csv_text, "text/csv")})
    body = r.json()
    assert body["total"] == 2 and body["failed"] == 0, body
    grace = next(u for u in fake.users.values() if u["firstName"] == "Grace")
    assert grace["employeeId"] == "E1"
    assert fake.entitlements[grace["id"]]["roleIds"] == ["r1", "r2"]

    exp = api.post("/users/export?format=csv", json={"criteria": {"lastName": "Hopper"}})
    assert exp.headers["content-type"].startswith("text/csv")
    lines = exp.text.strip().splitlines()
    assert len(lines) == 3 and "firstName" in lines[0]


def test_import_reports_bad_rows(api):
    csv_text = "first_name,last_name\nOnly,\n"
    r = api.post("/users/import", files={"file": ("users.csv", csv_text, "text/csv")})
    assert r.status_code == 422
    assert "2" in r.json()["detail"]["row_errors"]


def test_lifecycle_actions(api, fake):
    uid = api.post("/users", json={"first_name": "T", "last_name": "Mp"}).json()["user_id"]
    assert api.post(f"/users/{uid}/actions/disable", json={"reason": "test"}).status_code == 200
    assert fake.users[uid]["userStatus"] == "DISABLED"
    assert api.post(f"/users/{uid}/actions/remove").status_code == 200
    assert uid not in fake.users
    assert api.post(f"/users/{uid}/actions/remove").status_code == 404
    assert api.post(f"/users/{uid}/actions/explode").status_code == 404


def test_raw_and_api_docs(api):
    r = api.post("/openiam/raw", json={"method": "POST", "path": "/webconsole/rest/api/roles/search",
                                       "body": {"name": "Admin"}})
    assert r.json()["beans"][0]["name"] == "Admin"
    assert api.post("/openiam/raw", json={"path": "/idp/oauth2/token"}).status_code == 400
    assert api.get("/openiam/api-docs").json()["openapi"].startswith("3")


def test_bad_openiam_credentials_give_502(api, make_client):
    app.state.openiam = make_client(secret="wrong")
    r = api.get("/openiam/ping")
    assert r.status_code == 502 and "Bad client credentials" in r.json()["detail"]
