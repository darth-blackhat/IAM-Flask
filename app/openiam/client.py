"""Async client for the OpenIAM REST API.

Endpoints and response shapes follow the OpenIAM developer guide:
  - token:   POST /idp/oauth2/token (form, Basic auth, grant_type=client_credentials)
  - search:  POST /webconsole/rest/api/users/search      -> BeanResponse
  - writes:  POST /webconsole/rest/api/prov/<operation>  -> BasicAjaxResponse

OpenIAM returns HTTP 200 for refused operations; the real outcome is the integer
`status` in the body, so every write goes through `_check_ajax`.
"""

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx

from ..logs import logger
from .errors import OpenIAMAuthError, OpenIAMError

API_PREFIX = "/webconsole/rest/api"
TOKEN_PATH = "/idp/oauth2/token"

# Lifecycle actions that take an ActionUserModel body.
USER_ACTIONS = {
    "activate": "activateUser",
    "deactivate": "deactivate-user",
    "enable": "enableUser",
    "disable": "disableUser",
    "remove": "removeUser",
    "reset": "resetUser",
    "terminate": "terminateUser",
    "deceased": "deceasedUser",
    "leave-with-pay": "leaveWithPay",
    "leave-of-absence": "leaveOfAbsence",
}

# Front ends whose REST API the raw passthrough may reach.
RAW_ALLOWED_PREFIXES = ("/webconsole/rest/api/", "/selfservice/rest/api/", "/idp/rest/api/")

# Refresh the token this many seconds before OpenIAM says it expires.
TOKEN_EXPIRY_MARGIN = 30


class OpenIAMClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str, *,
                 verify_tls: bool = True, timeout: float = 30.0,
                 transport: httpx.AsyncBaseTransport | None = None):
        self._client_id = client_id
        self._client_secret = client_secret
        self._http = httpx.AsyncClient(base_url=base_url.rstrip("/"), verify=verify_tls,
                                       timeout=timeout, transport=transport)
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._token_lock = asyncio.Lock()

    @property
    def base_url(self) -> str:
        return str(self._http.base_url).rstrip("/")

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "OpenIAMClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    # ---- auth ---------------------------------------------------------------

    async def _get_token(self, force: bool = False) -> str:
        async with self._token_lock:
            if not force and self._token and time.monotonic() < self._token_expires_at:
                return self._token
            if not self._client_id or not self._client_secret:
                raise OpenIAMAuthError("OPENIAM_CLIENT_ID / OPENIAM_CLIENT_SECRET are not set")
            try:
                r = await self._http.post(TOKEN_PATH, auth=(self._client_id, self._client_secret),
                                          data={"grant_type": "client_credentials"})
            except httpx.HTTPError as e:
                raise OpenIAMAuthError(f"token request failed: {e}") from e
            try:
                body = r.json()
            except ValueError:
                body = {}
            # Some token failures come back as HTTP 200 with `error` and no token.
            token = body.get("access_token") if isinstance(body, dict) else None
            if r.status_code != 200 or not token:
                detail = body.get("error_description") or body.get("error") if isinstance(body, dict) else None
                raise OpenIAMAuthError(f"could not obtain token: {detail or r.text[:200]}",
                                       status=r.status_code, body=body)
            self._token = token
            logger.debug("obtained OpenIAM token (expires in {}s)", body.get("expires_in"))
            expires_in = body.get("expires_in") or 300
            self._token_expires_at = time.monotonic() + max(int(expires_in) - TOKEN_EXPIRY_MARGIN, 0)
            return token

    async def check_auth(self) -> None:
        """Fetch a fresh token; raises OpenIAMAuthError if the client can't sign in."""
        await self._get_token(force=True)

    async def _request(self, method: str, path: str, *, json: Any = None,
                       params: dict[str, Any] | None = None) -> httpx.Response:
        """Send an authenticated request; on HTTP 401 fetch a new token and retry once."""
        for attempt in range(2):
            token = await self._get_token(force=attempt > 0)
            try:
                r = await self._http.request(method, path, json=json, params=params,
                                             headers={"Authorization": f"Bearer {token}"})
            except httpx.HTTPError as e:
                raise OpenIAMError(f"{method} {path} failed: {e}") from e
            if r.status_code != 401:
                break
            if attempt == 0:
                logger.info("OpenIAM returned 401 for {} {}; refreshing token", method, path)
        if r.status_code >= 400:
            raise OpenIAMError(f"{method} {path} returned HTTP {r.status_code}",
                               status=r.status_code, body=_safe_json(r))
        return r

    async def _post_ajax(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        r = await self._request("POST", API_PREFIX + path, json=payload)
        return _check_ajax(path, _safe_json(r))

    # ---- users: read --------------------------------------------------------

    async def search(self, path: str, criteria: dict[str, Any], from_: int = 0,
                     size: int = 50) -> dict[str, Any]:
        """One page of any BeanResponse search (users, groups, roles, ...)."""
        if not path.startswith(RAW_ALLOWED_PREFIXES) or ".." in path:
            raise ValueError(f"path must start with one of {RAW_ALLOWED_PREFIXES}")
        r = await self._request("POST", path, json={**criteria, "from": from_, "size": size})
        body = _safe_json(r)
        if not isinstance(body, dict):
            raise OpenIAMError(f"{path}: unexpected search response", body=body)
        # emptySearchBean means no criteria were applied, so an empty list is meaningless.
        if body.get("emptySearchBean"):
            raise OpenIAMError(f"{path}: no search criteria were applied; supply at least one field",
                               status=400, body=body)
        if body.get("error"):
            raise OpenIAMError(f"{path}: search failed: {body['error']}", body=body)
        if not isinstance(body.get("beans", []), list):
            raise OpenIAMError(f"{path}: `beans` is not a list", body=body)
        body.setdefault("beans", [])
        return body

    async def iter_search(self, path: str, criteria: dict[str, Any], page_size: int = 100,
                          limit: int | None = None) -> AsyncIterator[dict[str, Any]]:
        offset = yielded = 0
        while True:
            beans = (await self.search(path, criteria, offset, page_size))["beans"]
            for bean in beans:
                yield bean
                yielded += 1
                if limit is not None and yielded >= limit:
                    return
            if len(beans) < page_size:
                return
            offset += page_size

    async def search_users(self, criteria: dict[str, Any], from_: int = 0,
                           size: int = 50) -> dict[str, Any]:
        """One page of user search. `criteria` needs at least one field (e.g. lastName)."""
        return await self.search(f"{API_PREFIX}/users/search", criteria, from_, size)

    def iter_users(self, criteria: dict[str, Any], page_size: int = 100,
                   limit: int | None = None) -> AsyncIterator[dict[str, Any]]:
        return self.iter_search(f"{API_PREFIX}/users/search", criteria, page_size, limit)

    # ---- users: write -------------------------------------------------------

    async def save_user(self, user: dict[str, Any]) -> dict[str, Any]:
        """Create (no `id`) or update (with `id`) a user. Returns the BasicAjaxResponse.

        The new user's id is in `contextValues.userId`, not `primaryKey`.
        """
        return await self._post_ajax("/prov/saveUser", user)

    async def entitle(self, user_id: str, *, operation: str = "ADD",
                      role_ids: list[str] | None = None, group_ids: list[str] | None = None,
                      resource_ids: list[str] | None = None,
                      organization_ids: list[str] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"userId": user_id, "operation": operation}
        for key, value in (("roleIds", role_ids), ("groupIds", group_ids),
                           ("resourceIds", resource_ids), ("organizationIds", organization_ids)):
            if value:
                payload[key] = value
        return await self._post_ajax("/prov/entitle", payload)

    async def user_action(self, action: str, user_id: str, *, reason: str | None = None,
                          perform_now: bool = True, perform_date: str | None = None,
                          description: str | None = None) -> dict[str, Any]:
        """Lifecycle action (enable, disable, remove, ...). See USER_ACTIONS.

        `perform_date` is UTC in yyyy-MM-dd'T'HH:mm:ss.SSS'Z' and implies perform_now=False.
        """
        try:
            endpoint = USER_ACTIONS[action]
        except KeyError:
            raise ValueError(f"unknown action {action!r}; expected one of {sorted(USER_ACTIONS)}")
        payload: dict[str, Any] = {"userId": user_id, "performNow": perform_now and not perform_date}
        if perform_date:
            payload["performDataString"] = perform_date
        if reason:
            payload["reason"] = reason
        if description:
            payload["description"] = description
        return await self._post_ajax(f"/prov/{endpoint}", payload)

    # ---- generic ------------------------------------------------------------

    async def raw(self, method: str, path: str, *, json: Any = None,
                  params: dict[str, Any] | None = None) -> Any:
        """Call any OpenIAM REST endpoint, for data this client has no wrapper for.

        `path` must start with one of RAW_ALLOWED_PREFIXES. The body is returned as-is;
        callers must check BasicAjaxResponse `status` themselves.
        """
        if not path.startswith("/"):
            path = "/" + path
        if ".." in path or not path.startswith(RAW_ALLOWED_PREFIXES):
            raise ValueError(f"path must start with one of {RAW_ALLOWED_PREFIXES}")
        r = await self._request(method.upper(), path, json=json, params=params)
        return _safe_json(r)

    async def call_ajax(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        """POST to any endpoint answering a BasicAjaxResponse, raising unless status is 200."""
        body = await self.raw("POST", path, json=payload)
        return _check_ajax(path, body)

    async def api_docs(self, front_end: str = "webconsole") -> Any:
        """The deployment's own OpenAPI spec: the authoritative list of endpoints and schemas."""
        if front_end not in ("webconsole", "selfservice", "idp"):
            raise ValueError("front_end must be webconsole, selfservice or idp")
        r = await self._request("GET", f"/{front_end}/api-docs")
        return _safe_json(r)


def _safe_json(r: httpx.Response) -> Any:
    try:
        return r.json()
    except ValueError:
        return r.text


def _check_ajax(path: str, body: Any) -> dict[str, Any]:
    if not isinstance(body, dict) or "status" not in body:
        raise OpenIAMError(f"{path}: unexpected response", body=body)
    status = body.get("status")
    if status != 200:
        errors = body.get("errorList") or []
        codes = ", ".join(str(e.get("error") or e.get("validationError") or e)
                          if isinstance(e, dict) else str(e) for e in errors)
        raise OpenIAMError(f"{path}: OpenIAM returned status {status}" + (f" ({codes})" if codes else ""),
                           status=status if isinstance(status, int) else None,
                           errors=errors, body=body)
    return body
