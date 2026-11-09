"""Notifications: email and webhook templates (Teams, Slack, ServiceNow, Jira, anything HTTP).

Anything (the web UI, the services) adds an event to the `notifications` outbox. Only the
producer service (`iam serve`) delivers them, so SMTP passwords and webhook secrets never
reach the web UI. Delivery is retried; each event is sent to every channel that wants it.

Webhooks are guarded: https only (unless `allow_http`), every resolved address must be
public unless `allow_private` (a deliberate opt-in for an internal ITSM), no redirects,
a timeout and a response cap. Bodies are filled from templates with ${field} placeholders
(string.Template: no code runs), each value JSON-escaped. Each request is signed:
X-Signature: sha256=<hmac of the body with the webhook's secret>.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage
from pathlib import Path
from string import Template
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml
from pydantic import BaseModel, Field
from sqlalchemy import insert, select, update

from .db import Database
from .logs import logger

# Events this system emits (webhooks / email subscribe to a subset; "*" = all).
EVENTS = {
    "request.awaiting_approval": "A directory change waits for approval",
    "request.approved": "A directory change was approved (it runs now)",
    "request.rejected": "A directory change was rejected",
    "request.done": "A directory change was applied",
    "request.failed": "A directory change failed",
    "sod.blocked": "A request was refused: segregation of duties",
    "campaign.started": "An access certification campaign started",
    "campaign.overdue": "A certification campaign is past its due date",
    "access.expired": "Time-limited access ended and was removed",
    "audit.tampered": "The audit trail's hash chain is broken",
    "report.scheduled": "A scheduled report was written",
    "ad.failed": "A consumer site reported AD instructions that failed",
}
MAX_ATTEMPTS = 10
PRESETS = {
    # Microsoft Teams (incoming webhook / workflow) and Slack: a text message.
    "teams": {"text": "**${title}**\n\n${text}"},
    "slack": {"text": "*${title}*\n${text}"},
    # Plain JSON with everything (ServiceNow scripted REST, SIEM, ...).
    "json": {"event": "${event}", "title": "${title}", "text": "${text}", "data": "${data}"},
}


class Webhook(BaseModel):
    name: str
    url: str
    events: list[str] = ["*"]
    # Body template (dict / list / str with ${event} ${title} ${text} ${data} ${<field>}) or a preset name.
    template: Any = "json"
    secret_env: str | None = None          # env var holding the HMAC secret
    headers: dict[str, str] = {}
    allow_http: bool = False
    allow_private: bool = False            # internal ITSM on a private address: explicit opt-in
    timeout_seconds: float = Field(10.0, gt=0, le=60)


class EmailChannel(BaseModel):
    host: str
    port: int = 587
    security: str = "starttls"             # starttls | tls | none (none: only with allow_plain)
    allow_plain: bool = False
    username: str | None = None
    password_env: str | None = None
    sender: str = Field(..., alias="from")
    to: list[str]
    events: list[str] = ["*"]

    model_config = {"populate_by_name": True}


class NotifyConfig(BaseModel):
    email: EmailChannel | None = None
    webhooks: list[Webhook] = []


def load_notify_config(path: str) -> NotifyConfig | None:
    if not Path(path).is_file():
        return None
    with open(path, encoding="utf-8") as f:
        return NotifyConfig.model_validate(yaml.safe_load(f) or {})


def wants(events: list[str], event: str) -> bool:
    return "*" in events or event in events or any(e.endswith(".*") and event.startswith(e[:-1]) for e in events)


# ---- outbox -------------------------------------------------------------------------------

class Notifications:
    def __init__(self, db: Database):
        self.db, self.t = db, db.tables.notifications

    def add(self, event: str, title: str, text: str, data: dict[str, Any] | None = None) -> int:
        if event not in EVENTS:
            raise ValueError(f"unknown event {event}")
        with self.db.begin() as conn:
            return conn.execute(insert(self.t).values(
                at=time.time(), event=event, title=title[:300], text=text[:4000], data=data or {},
                status="pending", attempts=0)).inserted_primary_key[0]

    def pending(self, limit: int = 50) -> list[dict[str, Any]]:
        c = self.t.c
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(self.t).where(c.status == "pending").order_by(c.id).limit(limit))]

    def finish(self, nid: int, ok: bool, error: str | None, attempts: int) -> None:
        status = "sent" if ok else ("dead" if attempts >= MAX_ATTEMPTS else "pending")
        with self.db.begin() as conn:
            conn.execute(update(self.t).where(self.t.c.id == nid).values(
                status=status, attempts=attempts, last_error=(error or "")[:1000] or None,
                sent_at=time.time() if ok else None))

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(self.t).order_by(self.t.c.id.desc()).limit(limit))]


# ---- rendering + guards -------------------------------------------------------------------

def render_template(template: Any, values: dict[str, Any]) -> Any:
    """Fill ${field} placeholders; values are JSON-escaped strings (no code runs)."""
    if isinstance(template, str) and template in PRESETS:
        template = PRESETS[template]
    flat = {k: v if isinstance(v, str) else json.dumps(v, default=str) for k, v in values.items()}

    def fill(t: Any) -> Any:
        if isinstance(t, str):
            return Template(t).safe_substitute(flat)
        if isinstance(t, dict):
            return {k: fill(v) for k, v in t.items()}
        if isinstance(t, list):
            return [fill(v) for v in t]
        return t
    return fill(template)


class UnsafeTarget(ValueError):
    pass


def check_target(url: str, *, allow_http: bool = False, allow_private: bool = False) -> None:
    """Refuse URLs that could reach internal systems (SSRF)."""
    u = urlparse(url)
    if u.scheme not in (("https", "http") if allow_http else ("https",)):
        raise UnsafeTarget(f"{url}: https only")
    if not u.hostname or u.username or u.password:
        raise UnsafeTarget(f"{url}: needs a host and no credentials in the URL")
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80),
                                   proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeTarget(f"{u.hostname}: cannot resolve ({e})") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise UnsafeTarget(f"{u.hostname} resolves to non-public {ip}; set allow_private to permit it")


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ---- delivery ---------------------------------------------------------------------------

class Notifier:
    def __init__(self, db: Database, cfg: NotifyConfig, env: dict[str, str] | None = None,
                 transport: httpx.AsyncBaseTransport | None = None, smtp_factory=None):
        import os
        self.outbox, self.cfg = Notifications(db), cfg
        self.env = env if env is not None else dict(os.environ)
        self.transport, self.smtp_factory = transport, smtp_factory

    async def run_pending(self) -> int:
        sent = 0
        for n in self.outbox.pending():
            errors = []
            values = {"event": n["event"], "title": n["title"], "text": n["text"], "data": n["data"] or {},
                      **{k: v for k, v in (n["data"] or {}).items() if isinstance(k, str)}}
            for hook in self.cfg.webhooks:
                if wants(hook.events, n["event"]):
                    try:
                        await self._post(hook, values)
                    except Exception as e:
                        errors.append(f"{hook.name}: {e}")
            if self.cfg.email and wants(self.cfg.email.events, n["event"]):
                try:
                    await asyncio.to_thread(self._mail, n)
                except Exception as e:
                    errors.append(f"email: {e}")
            self.outbox.finish(n["id"], not errors, "; ".join(errors), n["attempts"] + 1)
            if errors:
                logger.warning("notification {} ({}) not delivered: {}", n["id"], n["event"], "; ".join(errors))
            else:
                sent += 1
        return sent

    async def _post(self, hook: Webhook, values: dict[str, Any]) -> None:
        check_target(hook.url, allow_http=hook.allow_http, allow_private=hook.allow_private)
        payload = render_template(hook.template, values)
        body = (payload if isinstance(payload, str) else json.dumps(payload)).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "backend-iam-notify", **hook.headers}
        if hook.secret_env:
            secret = self.env.get(hook.secret_env)
            if not secret:
                raise RuntimeError(f"env {hook.secret_env} is empty")
            headers["X-Signature"] = sign(body, secret)
        async with httpx.AsyncClient(timeout=hook.timeout_seconds, follow_redirects=False,
                                     transport=self.transport) as client:
            async with client.stream("POST", hook.url, content=body, headers=headers) as r:
                read = 0
                async for chunk in r.aiter_bytes():     # drain at most 64 KB, never more
                    read += len(chunk)
                    if read > 65536:
                        break
                if r.status_code >= 300:
                    raise RuntimeError(f"HTTP {r.status_code}")

    def _mail(self, n: dict[str, Any]) -> None:
        e = self.cfg.email
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = f"[backend-iam] {n['title']}", e.sender, ", ".join(e.to)
        msg.set_content(f"{n['text']}\n\nEvent: {n['event']}\n")
        ctx = ssl.create_default_context()
        if e.security == "none" and not e.allow_plain:
            raise RuntimeError("plain SMTP refused (security: none needs allow_plain: true)")
        factory = self.smtp_factory or (smtplib.SMTP_SSL if e.security == "tls" else smtplib.SMTP)
        kwargs = {"context": ctx} if e.security == "tls" and not self.smtp_factory else {}
        with factory(e.host, e.port, timeout=20, **kwargs) as s:
            if e.security == "starttls":
                s.starttls(context=ctx)
            if e.username:
                s.login(e.username, self.env.get(e.password_env or "", ""))
            s.send_message(msg)
