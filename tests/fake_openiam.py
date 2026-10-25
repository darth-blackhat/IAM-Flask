"""In-memory stand-in for OpenIAM, mimicking the documented wire behaviour."""

import base64
import json
import uuid

import httpx

CLIENT_ID, CLIENT_SECRET = "test-client", "test-secret"

USER_STATUS = {"disableUser": "DISABLED", "enableUser": "ACTIVE", "removeUser": "DELETED",
               "terminateUser": "TERMINATED", "leaveOfAbsence": "LEAVE"}


class FakeOpenIAM:
    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        self.roles: dict[str, dict] = {"r1": {"id": "r1", "name": "Admin"}}
        self.organizations: dict[str, dict] = {}
        self.entitlements: dict[str, dict] = {}
        # user id -> {"groupIds"|"roleIds"|"organizationIds": set of ids}
        self.members: dict[str, dict[str, set]] = {}
        self.actions: list[tuple[str, str, dict]] = []
        self.fail_paths: set[str] = set()
        self.audit: list[dict] = []  # entries with "timestamp" (epoch ms) and "targets"
        self.tokens_issued = 0
        self.valid_tokens: set[str] = set()
        self.requests: list[tuple[str, str]] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def expire_tokens(self) -> None:
        self.valid_tokens.clear()

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append((request.method, path))
        if path == "/idp/oauth2/token":
            return self._token(request)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.valid_tokens:
            return httpx.Response(401)
        body = json.loads(request.content) if request.content else {}
        if path in self.fail_paths:
            return httpx.Response(500)
        if path == "/webconsole/rest/api/users/search":
            return self._search(body)
        if path == "/webconsole/rest/api/groups/search":
            return self._search(body, self.groups)
        if path == "/webconsole/rest/api/roles/search":
            return self._search(body, self.roles)
        if path == "/webconsole/rest/api/organizations/search":
            return self._search(body, self.organizations)
        if path == "/webconsole/rest/api/groups/save":
            gid = f"g-{len(self.groups) + 1}"
            self.groups[gid] = {"id": gid, **body}
            return _ajax(200)
        if path == "/webconsole/rest/api/auditlog/search":
            rows = [a for a in self.audit if a["timestamp"] >= body.get("fromDate", 0)]
            start = body.get("from", 0)
            return httpx.Response(200, json={"beans": rows[start:start + body.get("size", 50)]})
        if path == "/webconsole/rest/api/broken/search":
            # Ignores `from`: always the same full page.
            return httpx.Response(200, json={"beans": [{"id": str(i)} for i in range(body["size"])]})
        if path == "/webconsole/rest/api/prov/saveUser":
            return self._save(body)
        if path == "/webconsole/rest/api/prov/entitle":
            return self._entitle(body)
        if path.rsplit("/", 1)[1] in USER_STATUS:
            return self._action(path.rsplit("/", 1)[1], body)
        if path == "/webconsole/api-docs":
            return httpx.Response(200, json={"openapi": "3.0.1", "paths": {}})
        return httpx.Response(404)

    def _token(self, request: httpx.Request) -> httpx.Response:
        expected = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        if request.headers.get("Authorization") != f"Basic {expected}":
            # OpenIAM can answer token failures with HTTP 200 and no access_token.
            return httpx.Response(200, json={"error": "invalid_client",
                                             "error_description": "Bad client credentials"})
        self.tokens_issued += 1
        token = f"tok-{self.tokens_issued}"
        self.valid_tokens.add(token)
        return httpx.Response(200, json={"access_token": token, "token_type": "Bearer",
                                         "expires_in": 3600})

    def _search(self, body: dict, table: dict | None = None) -> httpx.Response:
        table = self.users if table is None else table
        criteria = {k: v for k, v in body.items() if k not in ("from", "size")}
        if not criteria:
            return httpx.Response(200, json={"beans": [], "emptySearchBean": True})
        matches = [u for u in sorted(table.values(), key=lambda u: u["id"])
                   if all(v == "*" or u.get(k) == v for k, v in criteria.items())]
        start, size = body.get("from", 0), body.get("size", 50)
        return httpx.Response(200, json={"beans": matches[start:start + size],
                                         "from": start, "size": len(matches),
                                         "emptySearchBean": False, "error": None})

    def _save(self, body: dict) -> httpx.Response:
        if not body.get("lastName"):
            return _ajax(400, errors=[{"error": "REQUIRED", "validationError": "lastName"}])
        user_id = body.get("id")
        if user_id and user_id not in self.users:
            return _ajax(404, errors=[{"error": "USER_NOT_FOUND"}])
        user_id = user_id or uuid.uuid4().hex
        self.users[user_id] = {**self.users.get(user_id, {}), **body, "id": user_id,
                               "userStatus": "PENDING_INITIAL_LOGIN"}
        return _ajax(200, context={"userId": user_id, "checkStatusInProgress": True},
                     success="OpenIAM: PENDING_CREATE")

    def _entitle(self, body: dict) -> httpx.Response:
        if body.get("userId") not in self.users:
            return _ajax(404, errors=[{"error": "USER_NOT_FOUND"}])
        if "forbidden-role" in (body.get("roleIds") or []):
            return _ajax(401, errors=[{"error": "ACCESS_DENIED"}])
        self.entitlements[body["userId"]] = body
        held = self.members.setdefault(body["userId"], {})
        for key in ("groupIds", "roleIds", "organizationIds"):
            ids = set(body.get(key) or [])
            if body["operation"] == "ADD":
                held.setdefault(key, set()).update(ids)
            elif body["operation"] == "DELETE":
                held.setdefault(key, set()).difference_update(ids)
        return _ajax(200)

    def _action(self, action: str, body: dict) -> httpx.Response:
        user_id = body.get("userId")
        if user_id not in self.users:
            return _ajax(404, errors=[{"error": "USER_NOT_FOUND"}])
        self.actions.append((action, user_id, body))
        if action == "removeUser":
            del self.users[user_id]
        else:
            self.users[user_id]["userStatus"] = USER_STATUS[action]
        return _ajax(200)


def _ajax(status: int, *, errors=None, context=None, success=None) -> httpx.Response:
    # HTTP is always 200; the outcome is in the body.
    return httpx.Response(200, json={"status": status, "errorList": errors or [],
                                     "contextValues": context or {}, "successMessage": success,
                                     "primaryKey": None})
