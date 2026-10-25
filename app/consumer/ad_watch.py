"""Alert when Active Directory is changed without the consumer's AD instructions.

The watcher keeps the last-seen value of selected attributes of every user, group and OU
in the managed OUs, plus the membership of protected groups (Domain Admins, ...) wherever
they are. Each poll compares AD with that state:
  - the consumer's own writes update the state as they are made, so they never alert;
  - anything else that differs is an alert: an object modified, appeared or disappeared.
LDAP cannot say *who* changed an object; that is in the domain controllers' security
event log (e.g. events 4720/4728/4738). The alert says what changed and when it was seen.
"""

import hashlib
import json
import time
from typing import Any

from ldap3 import SUBTREE, Connection
from ldap3.utils.conv import escape_filter_chars
from pydantic import BaseModel, Field

from ..logs import logger

DEFAULT_ATTRIBUTES = ["cn", "givenName", "sn", "displayName", "mail", "title", "department",
                      "employeeID", "sAMAccountName", "userPrincipalName", "userAccountControl",
                      "telephoneNumber", "manager", "description", "member"]
OBJECTS = "(|(&(objectClass=user)(!(objectClass=computer)))(objectClass=group)(objectClass=organizationalUnit))"


class AdWatchConfig(BaseModel):
    enabled: bool = True
    interval_minutes: int = Field(10, ge=1)
    attributes: list[str] = DEFAULT_ATTRIBUTES
    # Also watch protected groups' membership anywhere under base_dn (critical alerts).
    protected_groups: bool = True


def _norm(attrs: dict[str, Any], watched: list[str]) -> dict[str, Any]:
    out = {}
    for a in watched:
        v = attrs.get(a)
        if v in (None, [], ""):
            continue
        vals = v if isinstance(v, list) else [v]
        vals = [str(x) for x in vals]
        out[a] = sorted(x.lower() for x in vals) if a == "member" else (vals[0] if len(vals) == 1 else sorted(vals))
    return out


def _hash(attrs: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(attrs, sort_keys=True).encode()).hexdigest()


def _class_of(entry_classes: Any) -> str:
    classes = {str(c).lower() for c in (entry_classes or [])}
    if "organizationalunit" in classes:
        return "organizationalUnit"
    if "group" in classes:
        return "group"
    return "user"


class AdWatcher:
    def __init__(self, applier, store, cfg: AdWatchConfig):
        self.applier, self.store, self.cfg = applier, store, cfg
        self.protected = {g.lower() for g in applier.cfg.protected_groups}
        self._last_poll = 0.0

    # ---- reading AD ---------------------------------------------------------

    def _scopes(self) -> list[str]:
        c = self.applier.cfg
        scopes = []
        for s in (c.users_ou, c.groups_ou, c.ous_base):   # avoid double-counting nested scopes
            if not any(s.lower().endswith(o.lower()) for o in scopes):
                scopes = [o for o in scopes if not o.lower().endswith(s.lower())] + [s]
        return scopes

    def snapshot(self, conn: Connection) -> dict[str, tuple[str, str, dict]]:
        attrs = list(dict.fromkeys(self.cfg.attributes + ["objectClass"]))
        found: dict[str, tuple[str, str, dict]] = {}

        def add(entries):
            for e in entries:
                if e.get("type") != "searchResEntry":
                    continue
                cls = _class_of(e["attributes"].get("objectClass"))
                found[e["dn"].lower()] = (e["dn"], cls, _norm(e["attributes"], self.cfg.attributes))

        for scope in self._scopes():
            conn.search(scope, OBJECTS, SUBTREE, attributes=attrs)
            add(conn.response)
        if self.cfg.protected_groups and self.protected:
            ors = "".join(f"(cn={escape_filter_chars(g)})" for g in self.applier.cfg.protected_groups)
            conn.search(self.applier.cfg.base_dn, f"(&(objectClass=group)(|{ors}))", SUBTREE,
                        attributes=["member", "cn", "objectClass"])
            add(conn.response)
        return found

    def _severity(self, cls: str, dn: str, changes: dict, kind: str) -> str:
        cn = dn.split(",", 1)[0].split("=", 1)[-1].lower()
        if cls == "group" and cn in self.protected:
            return "critical"
        if kind != "modified" or "userAccountControl" in changes or "member" in changes:
            return "warning"
        return "info"

    # ---- polling ------------------------------------------------------------

    def poll(self, conn: Connection | None = None) -> list[dict[str, Any]]:
        own = conn is None
        conn = conn or self.applier._factory()
        try:
            current = self.snapshot(conn)
        finally:
            if own:
                conn.unbind()
        self._last_poll = time.time()
        known = self.store.watch_state()
        if not known:   # first poll: baseline only
            self.store.watch_put([(dn, cls, a, _hash(a), "poll") for dn, cls, a in current.values()])
            logger.info("AD watch baseline: {} objects", len(current))
            return []
        alerts, updates = [], []
        for key, (dn, cls, attrs) in current.items():
            old = known.get(key)
            h = _hash(attrs)
            if old is None:
                alerts.append(self._alert(dn, cls, "appeared", {a: {"old": None, "new": v} for a, v in attrs.items()}))
            elif old["hash"] != h:
                before = old["attrs"]
                changes = {a: {"old": before.get(a), "new": attrs.get(a)}
                           for a in sorted(set(before) | set(attrs)) if before.get(a) != attrs.get(a)}
                if "member" in changes:   # show who was added / removed, not two long lists
                    o, n = set(before.get("member") or []), set(attrs.get("member") or [])
                    changes["member"] = {"added": sorted(n - o), "removed": sorted(o - n)}
                alerts.append(self._alert(dn, cls, "modified", changes))
            else:
                continue
            updates.append((dn, cls, attrs, h, "poll"))
        gone = set(known) - set(current)
        for key in gone:
            k = known[key]
            alerts.append(self._alert(k["dn"], k["object_class"], "disappeared",
                                      {a: {"old": v, "new": None} for a, v in k["attrs"].items()}))
        self.store.watch_put(updates)
        self.store.watch_delete([known[k]["dn"] for k in gone])
        if alerts:
            self.store.add_alerts(alerts)
            for a in alerts:
                logger.bind(dn=a["dn"], severity=a["severity"]).warning(
                    "AD changed outside the consumer: {} {} ({})", a["kind"], a["dn"], a["severity"])
        return alerts

    def _alert(self, dn: str, cls: str, kind: str, changes: dict) -> dict[str, Any]:
        return {"dn": dn, "object_class": cls, "kind": kind,
                "severity": self._severity(cls, dn, changes, kind), "changes": changes}

    def due(self) -> bool:
        return time.time() - self._last_poll >= self.cfg.interval_minutes * 60

    def record_own(self, dns: list[str]) -> None:
        """After the consumer wrote to AD: take those objects as the new expected state."""
        dns = [d for d in dict.fromkeys(dns) if d]
        if not dns or not self.store.watch_state():   # no baseline yet: the first poll makes it
            return
        conn = self.applier._factory()
        try:
            current = self.snapshot(conn)
        finally:
            conn.unbind()
        rows = [(dn, cls, a, _hash(a), "consumer") for key, (dn, cls, a) in current.items()
                if key in {d.lower() for d in dns}]
        self.store.watch_put(rows)
