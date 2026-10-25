"""API keys, client addresses, rate limiting and the audit trail.

API keys look like  biam_<prefix>_<secret>.  Only the sha256 of the whole key is stored;
the key is shown once, when created. Each key has scopes, optional source CIDRs and an
optional expiry. BACKEND_API_KEY (env) still works as a bootstrap key with every scope.
"""

import hashlib
import hmac
import ipaddress
import secrets
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import insert, select, update

from .db import Database

SCOPES = {
    "producer:write": "POST /producer/events (source of truth)",
    "producer:read": "GET /producer/people/...",
    "users:write": "create/update users, entitlements, lifecycle actions",
    "users:read": "search and export users",
    "sync:read": "sync status, events feed, snapshots",
    "sync:run": "run sync / deliver / export / retry dead",
    "openiam:raw": "raw OpenIAM calls, api-docs, ping",
    "metrics:read": "GET /metrics",
    "admin": "everything",
}
KEY_PREFIX = "biam"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def parse_networks(values: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(v.strip(), strict=False) for v in values if v and v.strip()]


def ip_allowed(ip: str | None, networks: list) -> bool:
    if not networks:
        return True
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in networks)


def client_ip(peer: str | None, forwarded_for: str | None, trusted_proxies: list) -> str | None:
    """The real client address. X-Forwarded-For is believed only when the direct peer is a
    trusted proxy, and then only up to the first hop that is not itself a trusted proxy."""
    if not peer or not forwarded_for or not ip_allowed(peer, trusted_proxies) or not trusted_proxies:
        return peer
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    for hop in reversed(hops):
        if not ip_allowed(hop, trusted_proxies):
            return hop
    return hops[0] if hops else peer


@dataclass
class Principal:
    name: str
    scopes: frozenset[str]
    key_id: int | None   # None: the bootstrap key

    def allows(self, scope: str) -> bool:
        return "admin" in self.scopes or scope in self.scopes


class ApiKeyStore:
    def __init__(self, db: Database):
        self.db, self.t = db, db.tables.api_keys

    def create(self, name: str, scopes: list[str], cidrs: list[str] | None = None,
               expires_days: int | None = None, created_by: str | None = None) -> str:
        unknown = set(scopes) - set(SCOPES)
        if unknown or not scopes:
            raise ValueError(f"unknown or missing scopes {sorted(unknown)}; choose from {sorted(SCOPES)}")
        parse_networks(cidrs or [])   # validate
        prefix = secrets.token_hex(4)
        key = f"{KEY_PREFIX}_{prefix}_{secrets.token_urlsafe(32)}"
        now = time.time()
        with self.db.begin() as conn:
            conn.execute(insert(self.t).values(
                name=name, key_prefix=prefix, key_hash=hash_key(key), scopes=sorted(scopes),
                allowed_cidrs=list(cidrs or []), created_at=now, created_by=created_by,
                expires_at=now + expires_days * 86400 if expires_days else None))
        return key

    def revoke(self, name: str) -> bool:
        with self.db.begin() as conn:
            return conn.execute(update(self.t).where(self.t.c.name == name, self.t.c.revoked_at.is_(None))
                                .values(revoked_at=time.time())).rowcount > 0

    def list(self) -> list[dict[str, Any]]:
        with self.db.begin() as conn:
            rows = conn.execute(select(self.t).order_by(self.t.c.name))
            return [{k: v for k, v in r._mapping.items() if k != "key_hash"} for r in rows]

    def lookup(self, key: str) -> dict[str, Any] | None:
        if not key.startswith(KEY_PREFIX + "_"):
            return None
        with self.db.begin() as conn:
            r = conn.execute(select(self.t).where(self.t.c.key_hash == hash_key(key))).first()
            return dict(r._mapping) if r else None

    def touch(self, key_id: int) -> None:
        with self.db.begin() as conn:
            conn.execute(update(self.t).where(self.t.c.id == key_id).values(last_used_at=time.time()))


class Authenticator:
    """Turns a presented key + client address into a Principal, or a reason to refuse."""

    def __init__(self, store: ApiKeyStore | None, bootstrap_key: str = "",
                 global_cidrs: list[str] | None = None):
        self.store = store
        self.bootstrap_key = bootstrap_key
        self.global_networks = parse_networks(global_cidrs or [])
        self._touched: dict[int, float] = {}

    def authenticate(self, key: str | None, ip: str | None) -> tuple[Principal | None, str]:
        if not ip_allowed(ip, self.global_networks):
            return None, "source address not allowed"
        if not key:
            return None, "missing API key"
        if self.bootstrap_key and hmac.compare_digest(key.encode(), self.bootstrap_key.encode()):
            return Principal("bootstrap", frozenset({"admin"}), None), ""
        row = self.store.lookup(key) if self.store else None
        if row is None:
            return None, "invalid API key"
        if row["revoked_at"]:
            return None, f"API key {row['name']} is revoked"
        if row["expires_at"] and row["expires_at"] < time.time():
            return None, f"API key {row['name']} has expired"
        if not ip_allowed(ip, parse_networks(row["allowed_cidrs"])):
            return None, f"API key {row['name']} is not allowed from {ip}"
        # last_used_at at most once a minute per key, not on every request.
        if time.time() - self._touched.get(row["id"], 0) > 60:
            self._touched[row["id"]] = time.time()
            self.store.touch(row["id"])
        return Principal(row["name"], frozenset(row["scopes"]), row["id"]), ""


class RateLimiter:
    """Token bucket per principal, per process."""

    def __init__(self, per_minute: int):
        self.rate = per_minute / 60.0
        self.capacity = max(per_minute, 1)
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, who: str) -> tuple[bool, float]:
        if self.rate <= 0:
            return True, 0.0
        now = time.monotonic()
        tokens, last = self._buckets.get(who, (float(self.capacity), now))
        tokens = min(self.capacity, tokens + (now - last) * self.rate)
        if tokens < 1:
            self._buckets[who] = (tokens, now)
            return False, (1 - tokens) / self.rate
        self._buckets[who] = (tokens - 1, now)
        return True, 0.0


class AuditTrail:
    def __init__(self, db: Database):
        self.db, self.t = db, db.tables.audit_trail

    def record(self, channel: str, actor: str, action: str, *, ok: bool, ip: str | None = None,
               target: str | None = None, detail: str | None = None) -> None:
        with self.db.begin() as conn:
            conn.execute(insert(self.t).values(at=time.time(), channel=channel, actor=actor[:120],
                                               ip=ip, action=action[:60], target=target, ok=ok,
                                               detail=(detail or "")[:2000] or None))

    def page(self, *, actor: str | None = None, channel: str | None = None, ok: bool | None = None,
             limit: int = 200, before_id: int | None = None) -> list[dict[str, Any]]:
        q = select(self.t).order_by(self.t.c.id.desc()).limit(limit)
        if actor:
            q = q.where(self.t.c.actor == actor)
        if channel:
            q = q.where(self.t.c.channel == channel)
        if ok is not None:
            q = q.where(self.t.c.ok.is_(ok))
        if before_id:
            q = q.where(self.t.c.id < before_id)
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(q)]
