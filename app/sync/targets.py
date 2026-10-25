"""Where change events go: the other site. OpenIAM and AD are not involved."""

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Protocol

import httpx

from .config import FileTarget, NoTarget, SyncConfig, WebhookTarget, ZipTarget


class Target(Protocol):
    async def send(self, events: list[dict[str, Any]]) -> None: ...
    async def aclose(self) -> None: ...


class WebhookSender:
    """POSTs {"events": [...]} as JSON.

    With a secret, adds X-IAM-Timestamp and X-IAM-Signature: sha256=HMAC(secret,
    "<timestamp>.<body>"). The receiver should verify both, and use `event_id` to
    drop duplicates: delivery is at-least-once.
    """

    def __init__(self, cfg: WebhookTarget, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        self.secret: bytes | None = None
        if cfg.secret_env:
            secret = os.environ.get(cfg.secret_env, "")
            if not secret:
                raise ValueError(f"webhook target needs env var {cfg.secret_env} "
                                 "(or set secret_env: null to send unsigned)")
            self.secret = secret.encode()
        self.http = httpx.AsyncClient(timeout=cfg.timeout_seconds, verify=cfg.verify_tls,
                                      transport=transport)

    async def send(self, events: list[dict[str, Any]]) -> None:
        body = json.dumps({"events": events}, sort_keys=True).encode()
        headers = {**self.cfg.headers, "Content-Type": "application/json",
                   "X-IAM-Event-Count": str(len(events))}
        if self.secret:
            ts = str(int(time.time()))
            sig = hmac.new(self.secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
            headers |= {"X-IAM-Timestamp": ts, "X-IAM-Signature": f"sha256={sig}"}
        r = await self.http.post(self.cfg.url, content=body, headers=headers)
        if not 200 <= r.status_code < 300:
            raise RuntimeError(f"target returned HTTP {r.status_code}: {r.text[:300]}")

    async def aclose(self) -> None:
        await self.http.aclose()


class FileSender:
    def __init__(self, cfg: FileTarget):
        self.path = Path(cfg.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def send(self, events: list[dict[str, Any]]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e, sort_keys=True) + "\n")

    async def aclose(self) -> None:
        pass


def build_target(cfg: SyncConfig, transport: httpx.AsyncBaseTransport | None = None) -> Target | None:
    """None means pull mode: events stay in the outbox for GET /sync/events."""
    t = cfg.target
    if isinstance(t, WebhookTarget):
        return WebhookSender(t, transport)
    if isinstance(t, FileTarget):
        return FileSender(t)
    assert isinstance(t, (NoTarget, ZipTarget))
    return None
