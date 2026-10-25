"""Drift report: does the target still match the last zip applied for a domain?

OpenIAM target: every user in the zip is looked up in the remote OpenIAM (by match_field)
and its mapped fields compared; groups / organizations / roles are checked by name.
AD target: the zip's AD instructions are re-planned as a dry run; anything that is not a
"noop" is a difference between AD and what the instructions want.
Read-only: nothing is changed.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from sqlalchemy import insert, select

from ..openiam import OpenIAMError
from .engine import BadBundle, Consumer, ConsumerError, read_bundle

MAX_ITEMS = 2000


async def drift_report(consumer: Consumer, domain: str, requested_by: str) -> dict[str, Any]:
    store = consumer.store
    state = store.domain_state(domain)
    if state is None:
        raise ConsumerError(f"no zip has been applied for domain {domain!r}")
    f = store.file(state["last_file"])
    if not f or not f.get("stored_at") or not Path(f["stored_at"]).exists():
        raise ConsumerError(f"the last zip for {domain!r} is no longer in the archive")
    try:
        bundle = read_bundle(Path(f["stored_at"]), trusted=consumer._trusted,
                             require_signature=consumer.cfg.require_signature,
                             identities=consumer._identities)
    except BadBundle as e:
        raise ConsumerError(f"cannot read {f['name']}: {e}") from e

    if consumer.target == "ad":
        planned = await asyncio.to_thread(consumer.ad.plan, bundle.instructions)
        items = [{"kind": f"ad:{i['object_class']}", "key": i.get("key"), "issue": i["ldap"],
                  "detail": i.get("error") or json.dumps(i.get("changes") or i.get("attributes"),
                                                         default=str)[:500],
                  "why": i.get("why")}
                 for i in planned if i["ldap"] != "noop"]
        checked = len(planned)
    else:
        items, checked = await _openiam_drift(consumer, bundle.entities)

    summary = {"checked": checked, "differences": len(items), "zip": f["name"],
               "data_as_of": state["last_generated_at"], "target": consumer.target}
    for i in items:
        summary[i["issue"]] = summary.get(i["issue"], 0) + 1
    status = "clean" if not items else "drift"
    t = store.db.tables.drift_reports
    with store.db.begin() as conn:
        report_id = conn.execute(insert(t).values(
            at=time.time(), domain=domain, status=status, summary=summary,
            items=items[:MAX_ITEMS], requested_by=requested_by)).inserted_primary_key[0]
    return {"report_id": report_id, "domain": domain, "status": status, **summary}


async def _openiam_drift(consumer: Consumer, entities: dict[str, list[dict]]) -> tuple[list, int]:
    u = consumer.cfg.user
    items: list[dict[str, Any]] = []
    checked = 0
    for rec in entities.get("user", []):
        key = rec.get(u.match_field)
        if key in (None, ""):
            continue
        checked += 1
        try:
            page = await consumer.client.search(u.search_path, {u.match_field: str(key)}, 0, 5)
        except OpenIAMError as e:
            items.append({"kind": "user", "key": str(key), "issue": "error", "detail": str(e)})
            continue
        remote = [b for b in page["beans"] if str(b.get(u.match_field)) == str(key)]
        if not remote:
            items.append({"kind": "user", "key": str(key), "issue": "missing",
                          "detail": "in the zip, not in the remote OpenIAM"})
            continue
        r = remote[0]
        diffs = {dst: {"zip": rec.get(src), "remote": r.get(dst)}
                 for src, dst in u.fields.items()
                 if rec.get(src) not in (None, "") and str(rec.get(src)) != str(r.get(dst))}
        if diffs:
            items.append({"kind": "user", "key": str(key), "issue": "different",
                          "detail": json.dumps(diffs, default=str)[:500]})
    for kind in ("organization", "group", "role"):
        d = consumer.cfg.directories[kind]
        for rec in entities.get(kind, []):
            name = rec.get(d.name_field)
            if not name:
                continue
            checked += 1
            try:
                found = await consumer._search_named(kind, str(name))
            except (OpenIAMError, ConsumerError) as e:
                items.append({"kind": kind, "key": name, "issue": "error", "detail": str(e)})
                continue
            if found is None:
                items.append({"kind": kind, "key": name, "issue": "missing",
                              "detail": "in the zip, not in the remote OpenIAM"})
    return items, checked


def drift_page(consumer: Consumer, domain: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    t = consumer.store.db.tables.drift_reports
    q = select(t).order_by(t.c.id.desc()).limit(limit)
    if domain:
        q = q.where(t.c.domain == domain)
    with consumer.store.db.begin() as conn:
        return [dict(r._mapping) for r in conn.execute(q)]
