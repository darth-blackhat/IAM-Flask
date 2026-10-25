"""Apply the zip's AD instructions to Active Directory (sites without OpenIAM only).

Enabled with CONSUMER_TARGET=ad and the `ad:` section of consumer.yaml. Every zip becomes
a *plan*: each instruction is reconciled against what AD holds now, giving the exact LDAP
change (or "noop"). Depending on `mode` the plan is only shown (dry_run), waits for an
operator's approval in the oversight web (approve), or is applied (auto, up to
max_changes_auto). Applying re-plans first, so an approved plan is still correct.

Guard rails: LDAPS / StartTLS with certificate validation (plain LDAP refused unless
allow_insecure), nothing outside base_dn, protected groups never touched, deletes become
disables unless allow_delete, new users are created disabled (no password handling here).
"""

import os
import ssl
from typing import Any, Literal

from ldap3 import (ALL_ATTRIBUTES, BASE, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE,
                   Connection, Server, Tls)
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn
from pydantic import BaseModel, Field, model_validator

from .ad_watch import AdWatchConfig

UF_ACCOUNTDISABLE = 0x2
NORMAL_ACCOUNT = 0x200
GLOBAL_SECURITY_GROUP = -2147483646
DEFAULT_PROTECTED = [
    "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators",
    "Backup Operators", "Server Operators", "Print Operators", "Group Policy Creator Owners",
    "Cert Publishers", "Key Admins", "Enterprise Key Admins", "DnsAdmins", "Domain Controllers",
    "Read-only Domain Controllers", "Protected Users"]
CLASS_FILTER = {"user": "(&(objectClass=user)(!(objectClass=computer)))",
                "group": "(objectClass=group)", "organizationalUnit": "(objectClass=organizationalUnit)"}


class AdConfig(BaseModel):
    servers: list[str] = Field(..., min_length=1)   # ldaps://dc1.corp.example:636, ...
    bind_dn: str
    bind_password_env: str = "AD_BIND_PASSWORD"
    ca_cert_file: str | None = None
    start_tls: bool = False
    allow_insecure: bool = False
    base_dn: str
    users_ou: str
    groups_ou: str
    ous_base: str
    upn_suffix: str | None = None
    mode: Literal["dry_run", "approve", "auto"] = "approve"
    max_changes_auto: int = Field(100, ge=0)
    allow_delete: bool = False
    protected_groups: list[str] = DEFAULT_PROTECTED
    timeout_seconds: int = 15
    # Alert on changes made in AD without the consumer (see ad_watch.py).
    watch: "AdWatchConfig" = Field(default_factory=lambda: AdWatchConfig())

    @model_validator(mode="after")
    def _check(self) -> "AdConfig":
        base = self.base_dn.lower()
        for name in ("users_ou", "groups_ou", "ous_base"):
            if not getattr(self, name).lower().endswith(base):
                raise ValueError(f"ad.{name} must be under base_dn")
        for s in self.servers:
            if s.lower().startswith("ldap://") and not (self.start_tls or self.allow_insecure):
                raise ValueError(f"{s}: plain LDAP sends the password in clear; use ldaps://, "
                                 "start_tls: true, or (lab only) allow_insecure: true")
        return self


class AdError(Exception):
    pass


def connect(cfg: AdConfig) -> Connection:
    password = os.environ.get(cfg.bind_password_env, "")
    if not password:
        raise AdError(f"env var {cfg.bind_password_env} (AD bind password) is not set")
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=cfg.ca_cert_file,
              version=ssl.PROTOCOL_TLS_CLIENT)
    last = None
    for uri in cfg.servers:   # first reachable server wins
        server = Server(uri, use_ssl=uri.lower().startswith("ldaps://"), tls=tls,
                        connect_timeout=cfg.timeout_seconds)
        conn = Connection(server, user=cfg.bind_dn, password=password,
                          receive_timeout=cfg.timeout_seconds, raise_exceptions=False)
        try:
            conn.open()
            if cfg.start_tls and not uri.lower().startswith("ldaps://"):
                conn.start_tls()
            if conn.bind():
                return conn
            last = f"{uri}: bind failed: {conn.result.get('description')}"
        except Exception as e:  # unreachable DC: try the next one
            last = f"{uri}: {e}"
    raise AdError(f"no AD server reachable: {last}")


class AdApplier:
    def __init__(self, cfg: AdConfig, conn_factory=None):
        self.cfg = cfg
        self._factory = conn_factory or (lambda: connect(cfg))
        self.protected = {g.lower() for g in cfg.protected_groups}

    # ---- lookups ------------------------------------------------------------

    def _under_base(self, dn: str) -> bool:
        return dn.lower().endswith(self.cfg.base_dn.lower())

    def _find(self, conn: Connection, object_class: str, key: dict[str, Any]) -> dict | None:
        (attr, value), = key.items()
        if attr == "openiamId":
            return None   # the receiving AD has no OpenIAM ids
        flt = f"(&{CLASS_FILTER[object_class]}({attr}={escape_filter_chars(str(value))}))"
        conn.search(self.cfg.base_dn, flt, SUBTREE, attributes=ALL_ATTRIBUTES)
        hits = [e for e in conn.response if e.get("type") == "searchResEntry"]
        if len(hits) > 1:
            raise AdError(f"{len(hits)} AD objects match {attr}={value}")
        if not hits:
            return None
        return {"dn": hits[0]["dn"], "attrs": hits[0]["attributes"]}

    @staticmethod
    def _first(attrs: dict, name: str) -> Any:
        v = attrs.get(name)
        if isinstance(v, list):
            return v[0] if v else None
        return v

    def _uac(self, obj: dict) -> int:
        return int(self._first(obj["attrs"], "userAccountControl") or NORMAL_ACCOUNT)

    def _members(self, obj: dict) -> set[str]:
        v = obj["attrs"].get("member") or []
        return {m.lower() for m in (v if isinstance(v, list) else [v])}

    # ---- planning -----------------------------------------------------------

    def plan(self, lines: list[dict[str, Any]], conn: Connection | None = None) -> list[dict[str, Any]]:
        own = conn is None
        conn = conn or self._factory()
        try:
            # Objects this plan will create, so later lines can refer to them.
            pending: dict[tuple[str, str], str] = {}
            items = []
            for line in lines:
                item = self._plan_one(conn, line, pending)
                if item["ldap"] == "add":
                    (k, v), = (item["key"] or {"": ""}).items()
                    pending[(item["object_class"], f"{k}={v}".lower())] = item["dn"]
                items.append(item)
            return items
        finally:
            if own:
                conn.unbind()

    def _item(self, line: dict, **kw: Any) -> dict[str, Any]:
        ins = line["instruction"]
        return {"seq": line.get("seq"), "instruction_id": ins.get("instruction_id"),
                "op": ins["op"], "object_class": ins["object_class"], "key": ins.get("key"),
                "why": (line.get("why") or {}).get("summary"), "instruction": ins, **kw}

    def _plan_one(self, conn: Connection, line: dict,
                  pending: dict[tuple[str, str], str] | None = None) -> dict[str, Any]:
        ins = line["instruction"]
        op, cls, key = ins["op"], ins["object_class"], ins.get("key") or {}
        try:
            if cls not in CLASS_FILTER:
                return self._item(line, ldap="error", error=f"unsupported object class {cls}")
            if cls == "group" and str(next(iter(key.values()), "")).lower() in self.protected:
                return self._item(line, ldap="error", error="protected group: never changed")
            obj = self._find(conn, cls, key)
            if obj and not self._under_base(obj["dn"]):
                return self._item(line, ldap="error", error=f"{obj['dn']} is outside base_dn")

            if op == "create":
                if obj:
                    return self._modify_attrs(line, obj, ins.get("attributes") or {})
                return self._plan_create(line, cls, key, ins.get("attributes") or {}, conn)
            if obj is None:
                return self._item(line, ldap="error", error=f"not found in AD: {key}")
            if op == "update":
                new = {c["attribute"]: c["new"] for c in ins.get("changes") or []}
                return self._modify_attrs(line, obj, new)
            if op in ("enable", "disable"):
                if cls != "user":
                    return self._item(line, ldap="error", error=f"{op} applies to users only")
                uac = self._uac(obj)
                want = (uac | UF_ACCOUNTDISABLE) if op == "disable" else (uac & ~UF_ACCOUNTDISABLE)
                if want == uac:
                    return self._item(line, ldap="noop", dn=obj["dn"])
                return self._item(line, ldap="modify", dn=obj["dn"],
                                  changes={"userAccountControl": [(MODIFY_REPLACE, [str(want)])]})
            if op in ("add_member", "remove_member"):
                return self._plan_member(conn, line, obj, pending or {})
            if op == "delete":
                if cls == "user" and not self.cfg.allow_delete:
                    uac = self._uac(obj)
                    if uac & UF_ACCOUNTDISABLE:
                        return self._item(line, ldap="noop", dn=obj["dn"], note="delete -> disable")
                    return self._item(line, ldap="modify", dn=obj["dn"], note="delete -> disable",
                                      changes={"userAccountControl": [(MODIFY_REPLACE,
                                                                       [str(uac | UF_ACCOUNTDISABLE)])]})
                if not self.cfg.allow_delete:
                    return self._item(line, ldap="skipped", dn=obj["dn"], note="allow_delete is off")
                return self._item(line, ldap="delete", dn=obj["dn"])
            return self._item(line, ldap="error", error=f"unknown op {op}")
        except AdError as e:
            return self._item(line, ldap="error", error=str(e))

    def _modify_attrs(self, line: dict, obj: dict, wanted: dict[str, Any]) -> dict[str, Any]:
        changes = {}
        for attr, value in wanted.items():
            if attr.lower() in ("cn", "ou", "distinguishedname", "objectclass"):
                continue   # renames are not done automatically
            current = self._first(obj["attrs"], attr)
            if value in (None, ""):
                if current not in (None, ""):
                    changes[attr] = [(MODIFY_DELETE, [])]
            elif str(current) != str(value):
                changes[attr] = [(MODIFY_REPLACE, [str(value)])]
        if not changes:
            return self._item(line, ldap="noop", dn=obj["dn"])
        return self._item(line, ldap="modify", dn=obj["dn"], changes=changes)

    def _plan_create(self, line: dict, cls: str, key: dict, attrs: dict, conn: Connection) -> dict:
        (key_attr, key_value), = key.items()
        if key_attr == "openiamId":
            return self._item(line, ldap="error", error="no AD key attribute in the instruction")
        attrs = {k: v for k, v in attrs.items() if v not in (None, "")}
        attrs[key_attr] = key_value
        if cls == "user":
            given, sn = attrs.get("givenName", ""), attrs.get("sn", "")
            cn = attrs.get("displayName") or f"{given} {sn}".strip() or str(key_value)
            dn = f"CN={escape_rdn(cn)},{self.cfg.users_ou}"
            conn.search(dn, "(objectClass=*)", BASE, attributes=["cn"])
            if conn.response and any(e.get("type") == "searchResEntry" for e in conn.response):
                dn = f"CN={escape_rdn(f'{cn} ({key_value})')},{self.cfg.users_ou}"   # name clash
            sam = str(attrs.get("sAMAccountName") or key_value)[:20]
            attrs.update({"cn": cn, "sAMAccountName": sam,
                          # Created disabled: AD cannot enable an account without a password.
                          "userAccountControl": str(NORMAL_ACCOUNT | UF_ACCOUNTDISABLE)})
            if self.cfg.upn_suffix:
                attrs.setdefault("userPrincipalName", f"{sam}@{self.cfg.upn_suffix}")
            object_class = ["top", "person", "organizationalPerson", "user"]
        elif cls == "group":
            cn = str(key_value)
            dn = f"CN={escape_rdn(cn)},{self.cfg.groups_ou}"
            attrs.update({"cn": cn, "sAMAccountName": cn[:256], "groupType": str(GLOBAL_SECURITY_GROUP)})
            object_class = ["top", "group"]
        else:
            dn = f"OU={escape_rdn(str(key_value))},{self.cfg.ous_base}"
            object_class = ["top", "organizationalUnit"]
        return self._item(line, ldap="add", dn=dn, object_class_values=object_class,
                          attributes={k: str(v) for k, v in attrs.items()})

    def _plan_member(self, conn: Connection, line: dict, group: dict,
                     pending: dict[tuple[str, str], str]) -> dict:
        ins = line["instruction"]
        if ins["object_class"] != "group":
            return self._item(line, ldap="skipped", dn=group["dn"],
                              note=f"membership of {ins['object_class']} is not an AD group membership")
        if (self._first(group["attrs"], "cn") or "").lower() in self.protected:
            return self._item(line, ldap="error", error="protected group: never changed")
        member = ins.get("member") or {}
        member_cls = member.get("object_class") or "user"
        user = self._find(conn, member_cls, member.get("key") or {})
        if user is None and member.get("key"):
            (k, v), = member["key"].items()
            if dn := pending.get((member_cls, f"{k}={v}".lower())):
                user = {"dn": dn, "attrs": {}}   # created earlier in this plan
        if user is None:
            return self._item(line, ldap="error", dn=group["dn"],
                              error=f"member not found in AD: {member.get('key')}")
        has = user["dn"].lower() in self._members(group)
        if (ins["op"] == "add_member") == has:
            return self._item(line, ldap="noop", dn=group["dn"])
        mode = MODIFY_ADD if ins["op"] == "add_member" else MODIFY_DELETE
        return self._item(line, ldap="modify", dn=group["dn"], member_dn=user["dn"],
                          changes={"member": [(mode, [user["dn"]])]})

    # ---- applying -----------------------------------------------------------

    def apply(self, lines: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Re-plan against current AD, then execute. Returns items with ok / error."""
        conn = self._factory()
        try:
            items = []
            for line in lines:
                item = self._plan_one(conn, line)
                kind = item["ldap"]
                ok = kind in ("noop", "skipped")
                if kind == "add":
                    ok = conn.add(item["dn"], item["object_class_values"], item["attributes"])
                elif kind == "modify":
                    ok = conn.modify(item["dn"], item["changes"])
                elif kind == "delete":
                    ok = conn.delete(item["dn"])
                if kind in ("add", "modify", "delete") and not ok:
                    item["error"] = f"{conn.result.get('description')}: {conn.result.get('message')}"
                item["ok"] = bool(ok) and kind != "error"
                items.append(item)
            return items
        finally:
            conn.unbind()


def summarize(items: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[i["ldap"]] = out.get(i["ldap"], 0) + 1
    return out


def change_count(items: list[dict[str, Any]]) -> int:
    return sum(1 for i in items if i["ldap"] in ("add", "modify", "delete"))
