"""Translate changes into AD instructions for the receiving site.

This backend never talks to a domain controller. The other site (an agent next to its
AD) applies these instructions. Every instruction is idempotent ("make it so"), so
applying one twice is harmless; the same change can arrive both from the producer
and, later, from change detection.

Instruction shape:
  {"instruction_id", "op", "object_class", "key": {<ad attr>: value}, "openiam_id",
   "attributes"?, "changes"?: [{"attribute", "old", "new"}], "target"?, "reason"?,
   "effective_date"?, "source"}
ops: create, update, delete, enable, disable, add_member, remove_member
"""

import uuid
from typing import Any, Literal

from pydantic import BaseModel

DEFAULT_ATTRIBUTES: dict[str, dict[str, str]] = {
    "user": {"firstName": "givenName", "lastName": "sn", "middleInit": "initials",
             "nickname": "displayName", "title": "title", "login": "sAMAccountName",
             "email": "mail", "employeeId": "employeeID", "phone": "telephoneNumber"},
    "group": {"name": "cn", "description": "description"},
    "role": {"name": "cn", "description": "description"},
    "organization": {"name": "ou", "description": "description"},
}


class AdMapping(BaseModel):
    # OpenIAM entity -> AD object class; null means "send no instructions for it".
    classes: dict[str, str | None] = {"user": "user", "group": "group", "role": "group",
                                      "organization": "organizationalUnit"}
    # Per entity: OpenIAM field -> AD attribute. Unmapped fields are not sent.
    attributes: dict[str, dict[str, str]] = DEFAULT_ATTRIBUTES
    # Per entity: AD attribute that identifies the object on the receiving side.
    keys: dict[str, str] = {"user": "employeeID", "group": "cn", "role": "cn",
                            "organization": "ou"}
    # What a user disappearing from OpenIAM means in AD. Other objects are deleted.
    on_user_delete: Literal["disable", "delete"] = "disable"
    # Optional user status field (as seen in OpenIAM search results) that means disabled.
    user_status_field: str | None = None
    user_disabled_values: list[str] = []

    def map(self, entity: str, record: dict[str, Any]) -> dict[str, Any]:
        fields = self.attributes.get(entity, {})
        return {attr: record[f] for f, attr in fields.items() if record.get(f) not in (None, "")}

    def key(self, entity: str, record: dict[str, Any], openiam_id: str | None) -> dict[str, Any]:
        attr = self.keys.get(entity)
        value = self.map(entity, record).get(attr) if attr else None
        # Without the key attribute, the receiver can still match on the OpenIAM id.
        return {attr: value} if value not in (None, "") else {"openiamId": openiam_id}


def instruction(op: str, object_class: str, key: dict[str, Any], openiam_id: str | None, *,
                source: str, **fields: Any) -> dict[str, Any]:
    return {"instruction_id": str(uuid.uuid4()), "op": op, "object_class": object_class,
            "key": key, "openiam_id": openiam_id, "source": source,
            **{k: v for k, v in fields.items() if v not in (None, [], {})}}


def _fmt(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= 60 else text[:57] + "..."


def from_change_event(event: dict[str, Any], m: AdMapping,
                      attribution: dict[str, Any] | None = None,
                      audit: list[dict[str, Any]] | None = None
                      ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Instructions + `why` for one change detected in OpenIAM (created / updated / deleted).

    `attribution` says what the source of truth (producer) did to this record since the
    previous run: {"fields": [...], "created": bool, "state_changed": bool, "event_ids": [...]}.
    Those parts were already sent as producer instructions, so they are not repeated;
    whatever is left was changed directly in OpenIAM by an admin.
    `audit`: OpenIAM audit entries for this object since the previous run (who, action, when).
    """
    entity, action, oid = event["entity"], event["action"], event["entity_id"]
    att = attribution or {}
    from_sot = {"source": "source-of-truth", "summary": "made by producer event(s), "
                "already sent as producer instructions", "event_ids": att.get("event_ids")}

    def admin(summary: str) -> dict[str, Any]:
        why: dict[str, Any] = {"source": "openiam-admin", "summary": summary,
                               "run_id": event.get("run_id")}
        if audit:
            actors = sorted({str(a["by"]) for a in audit if a.get("by")})
            if actors:
                why["summary"] = f"{summary} (by {', '.join(actors)})"
            why["audit"] = audit
        return why

    cls = m.classes.get(entity)
    if action == "created":
        if att.get("created"):
            return [], from_sot
        why = admin(f"{entity} created directly in OpenIAM")
        if not cls:
            return [], why
        data = event["data"]
        return [instruction("create", cls, m.key(entity, data, oid), oid, source="openiam-change",
                            attributes=m.map(entity, data), why=why)], why
    if action == "deleted":
        why = admin(f"{entity} removed from OpenIAM")
        if not cls:
            return [], why
        prev = event["previous"]
        op = m.on_user_delete if entity == "user" else "delete"
        return [instruction(op, cls, m.key(entity, prev, oid), oid, source="openiam-change",
                            reason="removed from OpenIAM", why=why)], why

    changes = event.get("changes") or {}
    by_sot = set(att.get("fields") or [])
    sf = m.user_status_field
    if att.get("state_changed") and sf:
        by_sot.add(sf)
    admin_changes = {f: c for f, c in changes.items() if f not in by_sot}
    if not admin_changes:
        return [], from_sot
    described = ", ".join(f"{f} {_fmt(c['old'])} -> {_fmt(c['new'])}"
                          for f, c in sorted(admin_changes.items()))
    why = admin(f"changed directly in OpenIAM: {described}")
    if att:
        why["also_from_source_of_truth"] = sorted(set(changes) & by_sot)
    if not cls:
        return [], why

    new = event["data"]
    old = {**new, **{f: c["old"] for f, c in changes.items()}}
    key = m.key(entity, old, oid)  # the object as the receiver knows it now
    fields = m.attributes.get(entity, {})
    attr_changes = [{"attribute": fields[f], "old": c["old"], "new": c["new"]}
                    for f, c in sorted(admin_changes.items()) if f in fields]
    out = []
    if attr_changes:
        out.append(instruction("update", cls, key, oid, source="openiam-change",
                               changes=attr_changes, why=why))
    if entity == "user" and sf and sf in admin_changes:
        was = str(admin_changes[sf]["old"]) in m.user_disabled_values
        now = str(admin_changes[sf]["new"]) in m.user_disabled_values
        if was != now:
            out.append(instruction("disable" if now else "enable", cls, key, oid,
                                   source="openiam-change", why=why,
                                   reason=f"{sf}: {admin_changes[sf]['old']} -> {admin_changes[sf]['new']}"))
    return out, why
