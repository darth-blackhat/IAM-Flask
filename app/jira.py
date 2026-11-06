"""Jira: check the ticket a directory change names, and comment on it afterwards.

Used only by the producer service (it holds the API token; the web UI never does).

JIRA_CHECK:
  off      no calls to Jira (the key format is still checked)
  warn     look the ticket up; a missing / unapproved ticket is reported but the change runs
  enforce  the change runs only if the ticket exists and its status is in JIRA_ALLOWED_STATUSES
Comments: when JIRA_COMMENT=true, the outcome is added as a comment on the ticket.
"""

from typing import Any

import httpx

from .config import Settings
from .directory import JIRA_KEY


class JiraError(Exception):
    pass


class Jira:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.base = settings.jira_base_url.strip().rstrip("/")
        self.mode = (settings.jira_check or "off").lower()
        self.allowed = {s.strip().lower() for s in settings.jira_allowed_statuses.split(",") if s.strip()}
        self.comment_enabled = settings.jira_comment
        self.user = settings.jira_user
        self.token = settings.jira_api_token.get_secret_value()
        self.transport = transport
        if self.mode not in ("off", "warn", "enforce"):
            raise ValueError("JIRA_CHECK must be off, warn or enforce")
        if self.mode != "off" and not (self.base.startswith("https://") and self.token):
            raise ValueError("JIRA_CHECK needs an https JIRA_BASE_URL and JIRA_API_TOKEN")

    @property
    def active(self) -> bool:
        return self.mode != "off"

    def _client(self) -> httpx.AsyncClient:
        # Jira Cloud: email + API token (basic); Server/DC: personal access token (bearer).
        auth = (self.user, self.token) if self.user else None
        headers = {} if self.user else {"Authorization": f"Bearer {self.token}"}
        return httpx.AsyncClient(base_url=self.base, auth=auth, headers={"Accept": "application/json", **headers},
                                 timeout=15, follow_redirects=False, transport=self.transport)

    async def check(self, key: str) -> dict[str, Any]:
        """{"ok", "status", "summary", "problem"}; raises JiraError only when enforce says stop."""
        if not JIRA_KEY.match(key or ""):
            raise JiraError(f"{key!r} is not a Jira issue key")
        if not self.active:
            return {"ok": True, "status": None, "problem": None}
        try:
            async with self._client() as c:
                r = await c.get(f"/rest/api/2/issue/{key}", params={"fields": "status,summary"})
        except httpx.HTTPError as e:
            problem = f"Jira unreachable: {type(e).__name__}"
        else:
            if r.status_code == 404:
                problem = f"Jira ticket {key} does not exist (or is not visible to the service account)"
            elif r.status_code >= 300:
                problem = f"Jira answered HTTP {r.status_code} for {key}"
            else:
                fields = (r.json() or {}).get("fields") or {}
                status = ((fields.get("status") or {}).get("name") or "").strip()
                if self.allowed and status.lower() not in self.allowed:
                    problem = f"Jira ticket {key} is '{status}', not one of: {', '.join(sorted(self.allowed))}"
                else:
                    return {"ok": True, "status": status, "summary": fields.get("summary"), "problem": None}
        if self.mode == "enforce":
            raise JiraError(problem)
        return {"ok": False, "status": None, "problem": problem}

    async def comment(self, key: str, text: str) -> None:
        if not (self.active and self.comment_enabled and JIRA_KEY.match(key or "")):
            return
        async with self._client() as c:
            r = await c.post(f"/rest/api/2/issue/{key}/comment", json={"body": text[:30000]})
            if r.status_code >= 300:
                raise JiraError(f"comment on {key}: HTTP {r.status_code}")
