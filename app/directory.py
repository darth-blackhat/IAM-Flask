"""Create / edit / delete users, groups, organizations (OUs) and roles from the web UI.

The web UI queues a `directory` operator request; the producer service (`iam serve`) runs it
here. Each request says where it goes:

  via=openiam  write OpenIAM (the producer site's source of truth) and queue the matching
               AD instructions at once. Instructions are idempotent, so change detection
               sending the same change again later is harmless.
  via=ad       queue AD instructions only. OpenIAM is not touched, so it no longer matches
               AD for that object (drift reports on the consumer site will show it).

Either way this backend never talks to AD: the instructions travel in the per-domain zips
and the consumer site applies them.

Users written via OpenIAM go through the producer engine (hire / update / leave / return /
terminate), so its record of each person stays right and HR events keep working.
"""

import re
import uuid
from contextlib import suppress
from datetime import date, datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, field_validator, model_validator

from .ad import AdMapping, instruction
from .logs import logger
from .openiam import OpenIAMClient
from .producer.config import DirectoryConfig, ProducerConfig
from .producer.schemas import ProducerEvent, ProducerPerson
from .schemas import EmailIn

Kind = Literal["user", "group", "organization", "role"]
Op = Literal["create", "update", "delete", "enable", "disable", "add_member", "remove_member"]
KINDS: tuple[str, ...] = ("user", "group", "organization", "role")
CONTAINERS = ("group", "organization", "role")
ENTITLE_ARG = {"group": "group_ids", "role": "role_ids", "organization": "organization_ids"}
# Organization types offered in the web UI. Key -> label. The label is written to AD
# (businessCategory on the OU); OpenIAM gets the id from producer config
# `organization_type_ids` (key -> OpenIAM organizationTypeId), else the key itself.
ORG_TYPES: dict[str, str] = {
    "organization": "Organization", "company": "Company", "division": "Division",
    "business_unit": "Business unit", "department": "Department", "region": "Region",
    "office": "Office", "branch": "Branch", "location": "Location", "team": "Team",
    "cost_center": "Cost center", "project": "Project",
}
USER_EVENT = {"create": "hire", "update": "update", "disable": "leave", "enable": "return",
              "delete": "terminate"}


MAX_LEN = 256                                   # names, ids, attributes
LONG_FIELDS = {"description": 1024, "reason": 1024, "login": 20}  # sAMAccountName: 20
MAX_LIST = 100
# Jira issue key: project key (letter, then letters / digits / _), dash, number.
JIRA_KEY = re.compile(r"^[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]{0,8}$")
MIN_JUSTIFICATION = 10
MAX_GRANT_DAYS = 366


class DirectoryError(Exception):
    pass


class DirectoryRequest(BaseModel):
    via: Literal["openiam", "ad"]
    kind: Kind
    op: Op
    # Employee id for a user; the object's name otherwise.
    name: str
    new_name: str | None = None          # rename (OpenIAM only)
    description: str | None = None
    org_type: str | None = None          # organizations only: a key of ORG_TYPES
    # Users: more AD attributes. manager = the manager's employee id.
    department: str | None = None
    company: str | None = None
    manager: str | None = None
    account_expires: str | None = None   # YYYY-MM-DD (the account works through that day) or "never"
    # Groups: AD scope and type.
    group_scope: Literal["global", "domain_local", "universal"] | None = None
    group_type: Literal["security", "distribution"] | None = None
    first_name: str | None = None
    last_name: str | None = None
    email: str | None = None
    login: str | None = None
    title: str | None = None
    # Domain the change belongs to: picks the zip; set on the user in OpenIAM.
    domain: str | None = None
    # add_member / remove_member: who joins (or leaves) the group / role / organization `name`.
    member_kind: Literal["user", "group"] | None = None
    member: str | None = None
    # Starting memberships for a new user.
    groups: list[str] = []
    roles: list[str] = []
    organizations: list[str] = []
    # Every change names its Jira ticket and says why (the justification).
    jira_ticket: str | None = None       # required: checked in _check for a clear message
    reason: str | None = None            # the justification; required likewise
    requested_by: str | None = None
    # add_member only: the membership ends on this day (YYYY-MM-DD) and is removed automatically.
    expires_on: str | None = None
    request_id: int | None = None        # set by the service: the approved request

    model_config = {"extra": "forbid"}

    @field_validator("*", mode="before")
    @classmethod
    def _clean(cls, v: Any, info: Any) -> Any:
        """Trim; blank means unset; refuse control characters and oversized values."""
        limit = LONG_FIELDS.get(info.field_name, MAX_LEN)

        def one(s: str) -> str | None:
            s = s.strip()
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in s):
                raise ValueError(f"{info.field_name}: control characters are not allowed")
            if len(s) > limit:
                raise ValueError(f"{info.field_name}: at most {limit} characters")
            return s or None
        if isinstance(v, str):
            return one(v)
        if isinstance(v, list):
            items = [x for x in (one(s) for s in v if isinstance(s, str)) if x]
            if len(items) > MAX_LIST:
                raise ValueError(f"{info.field_name}: at most {MAX_LIST} names")
            return items
        return v

    @model_validator(mode="after")
    def _check(self) -> "DirectoryRequest":
        if not self.name:
            raise ValueError("a name (employee id for a user) is required")
        self.jira_ticket = (self.jira_ticket or "").upper()
        if not JIRA_KEY.match(self.jira_ticket):
            raise ValueError("a Jira ticket key is required, e.g. IAM-123")
        if len(self.reason or "") < MIN_JUSTIFICATION:
            raise ValueError(f"a justification of at least {MIN_JUSTIFICATION} characters is required")
        if self.op in ("enable", "disable") and self.kind != "user":
            raise ValueError(f"{self.op} applies to users only")
        if self.op in ("add_member", "remove_member"):
            if self.kind not in CONTAINERS:
                raise ValueError("members are added to a group, role or organization")
            if not self.member or not self.member_kind:
                raise ValueError("say who the member is (a user's employee id or a group name)")
            if self.member_kind == "group" and self.kind != "group":
                raise ValueError("only a group can be a member of another group")
            if self.member_kind == "group" and self.member == self.name:
                raise ValueError("a group cannot be a member of itself")
        if self.kind == "user" and self.op in ("create", "update"):
            if not (self.first_name and self.last_name):
                raise ValueError("first and last name are required")
        if self.org_type is not None:
            if self.kind != "organization":
                raise ValueError("a type applies to organizations only")
            if self.org_type not in ORG_TYPES:
                raise ValueError(f"unknown organization type; one of {', '.join(ORG_TYPES)}")
        if self.expires_on is not None:
            if self.op != "add_member":
                raise ValueError("an end date applies to adding a member only")
            try:
                end = date.fromisoformat(self.expires_on)
            except ValueError:
                raise ValueError("end date must be YYYY-MM-DD") from None
            today = datetime.now(timezone.utc).date()
            if not today <= end <= today + timedelta(days=MAX_GRANT_DAYS):
                raise ValueError(f"end date must be today or later, within {MAX_GRANT_DAYS} days")
        if self.new_name == self.name:
            self.new_name = None
        if self.new_name:
            if self.kind == "user" or self.op != "update":
                raise ValueError("only a group, role or organization can be renamed (with update)")
        if self.kind != "user" and any((self.department, self.company, self.manager, self.account_expires)):
            raise ValueError("department, company, manager and account expiry are user attributes")
        if self.kind not in ("group", "role") and (self.group_scope or self.group_type):
            raise ValueError("scope and type apply to groups")
        if self.account_expires and self.account_expires != "never":
            try:
                date.fromisoformat(self.account_expires)
            except ValueError:
                raise ValueError("account expiry must be YYYY-MM-DD or never") from None
        if self.manager and self.manager == self.name:
            raise ValueError("a user cannot be their own manager")
        return self


def render(template: Any, values: dict[str, Any]) -> Any:
    """Fill {placeholders}; a value that is only a placeholder keeps its type (None stays None)."""
    if isinstance(template, str):
        for k, v in values.items():
            if template == "{" + k + "}":
                return v
        for k, v in values.items():
            template = template.replace("{" + k + "}", "" if v is None else str(v))
        return template
    if isinstance(template, dict):
        return {k: render(v, values) for k, v in template.items()}
    if isinstance(template, list):
        return [render(v, values) for v in template]
    return template


def _set_path(record: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    for part in parts[:-1]:
        record = record.setdefault(part, {})
    record[parts[-1]] = value


class DirectoryService:
    def __init__(self, client: OpenIAMClient, *, producer: Any = None, sync: Any = None,
                 producer_cfg: ProducerConfig | None = None, jira: Any = None, db: Any = None):
        """`producer` is the ProducerProcessor and `sync` the SyncService (either may be None);
        `jira` an app.jira.Jira; `db` enables notifications (request.done / request.failed)."""
        self.client, self.producer, self.sync, self.jira = client, producer, sync, jira
        db = db or (producer.store.db if producer is not None else sync.store.db if sync is not None else None)
        from .notify import Notifications
        self.notes = Notifications(db) if db is not None else None
        self.grants = TimedGrants(db) if db is not None else None
        self.cfg = producer.cfg if producer is not None else (producer_cfg or ProducerConfig())
        self.ad: AdMapping = sync.cfg.ad if sync is not None else AdMapping()
        self.cache = producer.store if producer is not None else None

    def operator_handlers(self) -> dict:
        async def directory(params: dict) -> dict:
            return await self.handle(params)
        async def directory_batch(params: dict) -> dict:
            return await self.handle_batch(params)
        return {"directory": directory, "directory_batch": directory_batch}

    def _domain_path(self, kind: str) -> str | None:
        export = getattr(self.sync.cfg, "export", None) if self.sync is not None else None
        if export is not None and export.domains.by_field:
            return export.domains.by_field.get(kind)
        return "domain" if kind == "user" else None

    # ---- entry point ---------------------------------------------------------

    async def handle_batch(self, params: dict[str, Any]) -> dict[str, Any]:
        """Many changes approved together (bulk import, mover). Every row is validated before
        anything runs; the Jira ticket is checked once; each row is then applied in order and
        its outcome reported. One summary notification / Jira comment."""
        items = params.get("items") or []
        common = {k: params.get(k) for k in ("jira_ticket", "reason", "requested_by")}
        if not items:
            raise DirectoryError("empty batch")
        try:
            reqs = [DirectoryRequest.model_validate({**item, **common, "request_id": params.get("request_id")})
                    for item in items]
        except ValueError as e:
            raise DirectoryError(f"batch refused, nothing applied: {e}") from None
        head = reqs[0]
        out: dict[str, Any] = {"label": params.get("label"), "jira_ticket": head.jira_ticket,
                               "rows": [], "ok": 0, "failed": 0, "warnings": [], "actions": []}
        try:
            await self._check_jira(head, out)
        except DirectoryError as e:
            await self._after(head, out, error=str(e), what=f"batch {params.get('label') or ''}".strip())
            raise
        for i, req in enumerate(reqs, 1):
            try:
                row = await self.handle(req.model_dump(), batch=True)
                out["rows"].append({"row": i, "ok": True, "name": req.name, "op": req.op, "actions": row["actions"]})
                out.setdefault("instruction_ids", []).extend(row.get("instruction_ids") or [])
                out["ok"] += 1
            except Exception as e:
                out["rows"].append({"row": i, "ok": False, "name": req.name, "op": req.op, "error": str(e)})
                out["failed"] += 1
        out["actions"] = [f"{out['ok']} applied, {out['failed']} failed"]
        await self._after(head, out, error=f"{out['failed']} of {len(reqs)} row(s) failed" if out["failed"] else None,
                          what=f"batch {params.get('label') or ''} ({len(reqs)} changes)".strip())
        return out

    async def _check_jira(self, req: "DirectoryRequest", out: dict[str, Any]) -> None:
        if self.jira is None or not self.jira.active:
            return
        from .jira import JiraError
        try:   # enforce: nothing is changed unless the ticket is in an allowed status
            info = await self.jira.check(req.jira_ticket)
        except JiraError as e:
            raise DirectoryError(f"Jira: {e}") from None
        out["jira_status"] = info.get("status")
        if not info["ok"]:
            out["warnings"].append(info["problem"])

    async def handle(self, params: dict[str, Any], *, batch: bool = False) -> dict[str, Any]:
        try:
            req = DirectoryRequest.model_validate(params)
        except ValueError as e:
            raise DirectoryError(str(e)) from None
        out: dict[str, Any] = {"via": req.via, "kind": req.kind, "op": req.op, "name": req.name,
                               "jira_ticket": req.jira_ticket,
                               "actions": [], "warnings": [], "instructions": 0}
        try:
            if req.via == "ad" and self.sync is None:
                raise DirectoryError("no sync config: AD instructions have nowhere to go")
            if not batch:
                await self._check_jira(req, out)
            if req.kind == "user" and req.via == "openiam" and req.op in USER_EVENT:
                await self._user_via_producer(req, out)
            else:
                ids: dict[str, str | None] = {"object": None, "member": None}
                if req.via == "openiam":
                    await self._openiam(req, out, ids)
                self._queue(req, out, self._instructions(req, ids, out), ids["object"])
        except Exception as e:
            if not batch:
                await self._after(req, out, error=str(e))
            raise
        if req.expires_on and self.grants is not None:
            # Access lasts through the whole end day (UTC), then it is removed.
            end = datetime.combine(date.fromisoformat(req.expires_on) + timedelta(days=1),
                                   datetime.min.time(), timezone.utc)
            self.grants.add(req.request_id, req.model_dump(exclude_none=True), end.timestamp())
            out["actions"].append(f"access ends {req.expires_on}")
        if not batch:
            await self._after(req, out)
        logger.bind(requested_by=req.requested_by).info(
            "directory {} {} {} via {} ({}): {}", req.op, req.kind, req.name, req.via, req.jira_ticket,
            "; ".join(out["actions"]) or "no change")
        return out

    async def _after(self, req: DirectoryRequest, out: dict[str, Any], error: str | None = None,
                     what: str | None = None) -> None:
        """Tell people: notification + Jira comment. Never fails the change itself."""
        what = what or f"{req.op} {req.kind} {req.name}" + (f" ({req.member_kind} {req.member})" if req.member else "")
        text = (f"{req.jira_ticket}: {what} via {'OpenIAM + AD' if req.via == 'openiam' else 'AD only'}"
                f" requested by {req.requested_by}.\nJustification: {req.reason}\n"
                + (f"FAILED: {error}" if error else "Done: " + ("; ".join(out["actions"]) or "no change")))
        if self.notes is not None:
            try:
                self.notes.add("request.failed" if error else "request.done",
                               f"{'Failed' if error else 'Applied'}: {what}", text,
                               {"jira_ticket": req.jira_ticket, "kind": req.kind, "op": req.op,
                                "name": req.name, "via": req.via, "error": error})
            except Exception as e:
                logger.error("could not queue notification: {}", e)
        if self.jira is not None and self.jira.active:
            try:
                await self.jira.comment(req.jira_ticket, "[backend-iam] " + text)
            except Exception as e:
                out["warnings"].append(f"Jira comment failed: {e}")

    # ---- OpenIAM: users (through the producer engine) -------------------------

    async def _user_via_producer(self, req: DirectoryRequest, out: dict[str, Any]) -> None:
        if self.producer is None:
            raise DirectoryError("producer intake is not configured (no producer config file); "
                                 "users are written to OpenIAM through it")
        person = None
        if req.op in ("create", "update"):
            extra = {k: v for k, v in (("login", req.login), ("title", req.title)) if v}
            if req.domain and (path := self._domain_path("user")):
                _set_path(extra, path, req.domain)
            person = ProducerPerson(first_name=req.first_name, last_name=req.last_name,
                                    emails=[EmailIn(email=req.email)] if req.email else [],
                                    extra=extra)
        is_hire = req.op == "create"
        ev = ProducerEvent(type=USER_EVENT[req.op], employee_id=req.name,
                           event_id=f"web-{uuid.uuid4()}", person=person,
                           groups=(req.groups or None) if is_hire else None,
                           roles=(req.roles or None) if is_hire else None,
                           organizations=(req.organizations or None) if is_hire else None,
                           reason=f"{req.jira_ticket}: {req.reason}")
        r = await self.producer.process(ev)
        extra_ad = {k: v for k, v in (("department", req.department), ("company", req.company),
                                      ("manager", req.manager), ("accountExpires", req.account_expires)) if v}
        if r.ok and extra_ad and req.op in ("create", "update"):
            # OpenIAM has no place for these: they go to AD as an update after the user record.
            cls = self.ad.classes.get("user")
            mapped = self.ad.map("user", extra_ad)
            if cls and mapped:
                ins = instruction("update", cls, self._key("user", req.name, r.user_id), r.user_id,
                                  changes=[{"attribute": a, "old": None, "new": v} for a, v in mapped.items()],
                                  source="web", why={"source": "web-operator", "summary": f"{req.jira_ticket}: AD attributes"})
                self._queue(req, out, [ins], r.user_id)
                r.instructions.append(ins)
        out.update(actions=r.actions, warnings=r.warnings, instructions=len(r.instructions),
                   instruction_ids=[i["instruction_id"] for i in r.instructions],
                   user_id=r.user_id, producer_event=ev.event_id)
        if not r.ok:
            raise DirectoryError(r.error or "producer event failed")
        await self._deliver(r.instructions)

    # ---- OpenIAM: groups / roles / organizations, memberships ------------------

    def _dir(self, kind: str) -> DirectoryConfig:
        return self.cfg.directories[kind]

    def _need(self, kind: str, attr: str) -> str:
        path = getattr(self._dir(kind), attr)
        if not path:
            raise DirectoryError(f"set directories.{kind}.{attr} in the producer config "
                                 "(find the endpoint with `iam api-docs`) to do this via OpenIAM")
        return path

    async def _find(self, kind: str, name: str) -> str | None:
        if kind == "user":
            field = self.cfg.employee_id_field
            page = await self.client.search(self.cfg.user_search_path, {field: name}, 0, 5)
            matches = [b for b in page["beans"] if str(b.get(field)) == name]
            if len(matches) > 1:
                raise DirectoryError(f"{len(matches)} OpenIAM users have {field}={name}")
            return str(matches[0]["id"]) if matches else None
        d = self._dir(kind)
        page = await self.client.search(d.search_path, {**d.search_extra, d.name_field: name}, 0, 50)
        matches = [b for b in page["beans"] if b.get(d.name_field) == name
                   and all(b.get(k) == v for k, v in d.require.items())]
        if len(matches) > 1:
            raise DirectoryError(f"{len(matches)} OpenIAM {kind}s are named {name!r}; "
                                 f"narrow it with directories.{kind}.require")
        return str(matches[0][d.id_field]) if matches else None

    async def _must_find(self, kind: str, name: str) -> str:
        object_id = await self._find(kind, name)
        if object_id is None:
            raise DirectoryError(f"{kind} {name!r} not found in OpenIAM")
        return object_id

    async def _openiam(self, req: DirectoryRequest, out: dict[str, Any],
                       ids: dict[str, str | None]) -> None:
        kind, name, d = req.kind, req.name, self._dir(req.kind)
        values = {"name": name, "new_name": req.new_name or name, "description": req.description,
                  "type": ORG_TYPES.get(req.org_type or ""),
                  "type_id": self.cfg.organization_type_ids.get(req.org_type, req.org_type)
                  if req.org_type else None}
        if req.op == "create":
            ids["object"] = await self._find(kind, name)
            if ids["object"]:
                out["actions"].append(f"{kind} {name} already in OpenIAM")
                return
            await self.client.call_ajax(self._need(kind, "create_path"), render(d.create_body, values))
            ids["object"] = await self._find(kind, name)
            out["actions"].append(f"created {kind} {name} in OpenIAM")
            if ids["object"] and self.cache:
                self.cache.remember(kind, name, ids["object"])
            return

        ids["object"] = await self._must_find(kind, name)
        values["id"] = ids["object"]
        if req.op == "update":
            await self.client.call_ajax(self._need(kind, "update_path"), render(d.update_body, values))
            out["actions"].append(f"updated {kind} {name} in OpenIAM"
                                  + (f" (renamed to {req.new_name})" if req.new_name else ""))
            if req.new_name and self.cache:
                self.cache.forget(kind, name)
                self.cache.remember(kind, req.new_name, ids["object"])
        elif req.op == "delete":
            await self.client.call_ajax(self._need(kind, "delete_path"), render(d.delete_body, values))
            out["actions"].append(f"deleted {kind} {name} in OpenIAM")
            if self.cache:
                self.cache.forget(kind, name)
        else:  # add_member / remove_member
            adding = req.op == "add_member"
            if req.member_kind == "user":
                ids["member"] = await self._must_find("user", req.member)
                await self.client.entitle(ids["member"], operation="ADD" if adding else "DELETE",
                                          **{ENTITLE_ARG[kind]: [ids["object"]]})
            else:
                ids["member"] = await self._must_find("group", req.member)
                attr = "add_child_path" if adding else "remove_child_path"
                body = d.add_child_body if adding else d.remove_child_body
                await self.client.call_ajax(self._need("group", attr),
                                            render(body, {**values, "parent_id": ids["object"],
                                                          "child_id": ids["member"]}))
            out["actions"].append(f"{'added' if adding else 'removed'} {req.member_kind} "
                                  f"{req.member} {'to' if adding else 'from'} {kind} {name} in OpenIAM")

    # ---- AD instructions ---------------------------------------------------

    def _flat(self, req: DirectoryRequest) -> dict[str, Any]:
        """The request as OpenIAM-style fields, for the AD attribute mapping."""
        if req.kind == "user":
            flat = {"employeeId": req.name, "firstName": req.first_name, "lastName": req.last_name,
                    "email": req.email, "login": req.login, "title": req.title,
                    "department": req.department, "company": req.company, "manager": req.manager,
                    "accountExpires": req.account_expires}
        else:
            flat = {"name": req.name, "description": req.description,
                    "organizationType": ORG_TYPES.get(req.org_type or ""),
                    "groupScope": req.group_scope, "groupCategory": req.group_type}
        return {k: v for k, v in flat.items() if v not in (None, "")}

    def _key(self, kind: str, name: str, openiam_id: str | None) -> dict[str, Any]:
        attr = self.ad.keys.get(kind)
        return {attr: name} if attr else {"openiamId": openiam_id}

    def _instructions(self, req: DirectoryRequest, ids: dict[str, str | None],
                      out: dict[str, Any]) -> list[dict[str, Any]]:
        cls = self.ad.classes.get(req.kind)
        if not cls:
            out["warnings"].append(f"{req.kind} is not mapped to AD (sync ad.classes): no AD instructions")
            return []
        why = {"source": "web-operator", "via": req.via, "by": req.requested_by,
               "jira_ticket": req.jira_ticket, "reason": req.reason,
               "summary": f"{req.jira_ticket}: {req.op} {req.kind} {req.name} from the web UI"
                          + (" (AD only)" if req.via == "ad" else "")}
        why = {k: v for k, v in why.items() if v}
        key, oid, flat = self._key(req.kind, req.name, ids["object"]), ids["object"], self._flat(req)
        common = {"source": "web", "why": why, "reason": f"{req.jira_ticket}: {req.reason}"}
        if req.op == "create":
            return [instruction("create", cls, key, oid, attributes=self.ad.map(req.kind, flat), **common)]
        if req.op == "update":
            key_attr = next(iter(key))
            changes = [{"attribute": a, "old": None, "new": v}
                       for a, v in self.ad.map(req.kind, flat).items() if a != key_attr]
            out_ins = [instruction("update", cls, key, oid, changes=changes, **common)] if changes else []
            if req.kind == "user" and req.domain:
                # The consumer moves the account to the OU it places this domain in (no-op if there).
                out_ins.append(instruction("move", cls, key, oid, domain=req.domain, **common))
            if req.new_name:
                # Last: the object is found by its old name, then renamed.
                out_ins.append(instruction("rename", cls, key, oid, new_name=req.new_name, **common))
            return out_ins
        if req.op == "delete":
            op = self.ad.on_user_delete if req.kind == "user" else "delete"
            return [instruction(op, cls, key, oid, **common)]
        if req.op in ("enable", "disable"):
            return [instruction(req.op, cls, key, oid, **common)]
        member = {"object_class": self.ad.classes.get(req.member_kind) or req.member_kind,
                  "key": self._key(req.member_kind, req.member, ids["member"]),
                  "openiam_id": ids["member"]}
        if req.kind == "organization":
            out["warnings"].append("AD has no OU membership: the consumer will skip this instruction")
        return [instruction(req.op, cls, key, oid, member=member, **common)]

    def _queue(self, req: DirectoryRequest, out: dict[str, Any], instructions: list[dict[str, Any]],
               openiam_id: str | None) -> None:
        if not instructions:
            return
        if self.sync is None:
            out["warnings"].append("no sync config: AD instructions were not queued")
            return
        data = self._flat(req)
        if req.domain and (path := self._domain_path(req.kind)):
            _set_path(data, path, req.domain)
        event = {"event_id": str(uuid.uuid4()), "type": f"web.{req.kind}.{req.op}",
                 "entity": req.kind, "entity_id": openiam_id, "action": req.op,
                 "employee_id": req.name if req.kind == "user" else None,
                 "detected_at": datetime.now(timezone.utc).isoformat(),
                 "data": data, "previous": None, "changes": None,
                 "why": instructions[0]["why"], "instructions": instructions}
        with self.sync.store.connect() as conn:
            self.sync.store.add_events(conn, [event])
        out["instructions"] = len(instructions)
        out["instruction_ids"] = [i["instruction_id"] for i in instructions]
        out["actions"].append(f"queued {len(instructions)} AD instruction(s)")

    async def _deliver(self, instructions: list[dict[str, Any]]) -> None:
        if self.sync is None or not instructions:
            return
        from .sync.service import SyncBusy
        with suppress(SyncBusy):  # a running cycle delivers them anyway
            await self.sync.deliver()


# ---- time-limited access ------------------------------------------------------------------

class TimedGrants:
    def __init__(self, db: Any):
        self.db, self.t = db, db.tables.timed_grants

    def add(self, request_id: int | None, params: dict[str, Any], expires_at: float) -> int:
        import time
        from sqlalchemy import insert
        with self.db.begin() as conn:
            return conn.execute(insert(self.t).values(
                request_id=request_id, params=params, expires_at=expires_at, status="active",
                created_at=time.time())).inserted_primary_key[0]

    def due(self, now: float) -> list[dict[str, Any]]:
        from sqlalchemy import select
        c = self.t.c
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(self.t).where(c.status == "active", c.expires_at <= now).order_by(c.id))]

    def mark(self, grant_id: int, status: str, removal_request_id: int | None = None) -> None:
        from sqlalchemy import update
        with self.db.begin() as conn:
            conn.execute(update(self.t).where(self.t.c.id == grant_id).values(
                status=status, removal_request_id=removal_request_id))

    def active(self) -> list[dict[str, Any]]:
        from sqlalchemy import select
        c = self.t.c
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(self.t).where(c.status == "active").order_by(c.expires_at))]


def expire_grants(db: Any, now: float | None = None) -> list[int]:
    """Queue the removal of every grant past its end date. The removal was approved with the
    grant, so it runs without a new approval. Returns the removal request ids."""
    import time
    from .notify import Notifications
    from .operator import OperatorRequests
    grants, reqs, notes = TimedGrants(db), OperatorRequests(db), Notifications(db)
    out = []
    for g in grants.due(now or time.time()):
        p = dict(g["params"])
        removal = {k: v for k, v in p.items() if k not in ("expires_on", "request_id", "new_name")}
        removal.update(op="remove_member",
                       reason=f"time-limited access ended on {p.get('expires_on')} (granted by request "
                              f"{g['request_id']}): {p.get('reason', '')}"[:1024])
        rid = reqs.create("producer", "directory", removal, "system:expiry",
                          preapproved_by=f"system:expiry (approved with request {g['request_id']})")
        grants.mark(g["id"], "expired", rid)
        notes.add("access.expired", f"Access ended: {p.get('member')} from {p.get('kind')} {p.get('name')}",
                  f"Time-limited access ({p.get('jira_ticket')}) ended on {p.get('expires_on')}; "
                  f"removal queued as request {rid}.", {"request_id": rid, "jira_ticket": p.get("jira_ticket")})
        out.append(rid)
    return out


# ---- preview -------------------------------------------------------------------------------

def plan(req: DirectoryRequest, ad: AdMapping | None = None, cfg: ProducerConfig | None = None) -> dict[str, Any]:
    """What a change will do, without contacting anything: OpenIAM steps and AD instructions."""
    svc = DirectoryService.__new__(DirectoryService)
    svc.ad, svc.cfg = ad or AdMapping(), cfg or ProducerConfig()
    steps: list[str] = []
    if req.via == "openiam":
        if req.kind == "user" and req.op in USER_EVENT:
            steps.append(f"OpenIAM: producer '{USER_EVENT[req.op]}' event for employee {req.name}"
                         + (" (creates or updates the user record)" if req.op in ("create", "update") else ""))
        elif req.op in ("add_member", "remove_member"):
            if req.member_kind == "user":
                steps.append(f"OpenIAM: entitle user {req.member} {'ADD' if req.op == 'add_member' else 'DELETE'} "
                             f"{req.kind} {req.name}")
            else:
                steps.append(f"OpenIAM: {'add' if req.op == 'add_member' else 'remove'} group {req.member} "
                             f"{'to' if req.op == 'add_member' else 'from'} group {req.name} (nesting endpoint)")
        else:
            path = {"create": "create_path", "update": "update_path", "delete": "delete_path"}.get(req.op)
            configured = bool(path and getattr(svc.cfg.directories[req.kind], path, None)) if req.kind != "user" else True
            steps.append(f"OpenIAM: {req.op} {req.kind} {req.name}"
                         + ("" if configured else f" (needs directories.{req.kind}.{path} in producer config)"))
    else:
        steps.append("OpenIAM: not changed (AD instructions only)")
    out: dict[str, Any] = {"warnings": []}
    if req.kind == "user" and req.via == "openiam" and req.op in USER_EVENT:
        ad_lines = ["AD: the producer engine emits the user's instructions (create / update / disable ...)"]
        instructions = []
    else:
        instructions = svc._instructions(req, {"object": None, "member": None}, out)
        ad_lines = [f"AD: {i['op']} {i['object_class']} {i['key']}"
                    + (f" member {i['member']['key']}" if i.get("member") else "") for i in instructions]
    if req.expires_on:
        steps.append(f"Ends {req.expires_on}: removed automatically then (already approved with this request)")
    return {"steps": steps + ad_lines, "instructions": instructions, "warnings": out["warnings"]}
