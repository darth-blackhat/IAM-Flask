"""Detect changes in OpenIAM by diffing full snapshots against the last-seen state.

OpenIAM offers no change feed or "modified since" filter, so each run pulls every
configured entity type in full. A run is all-or-nothing: if any fetch fails, nothing
is recorded, because a partial fetch would look like mass deletion.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from ..ad import from_change_event
from ..logs import logger
from ..openiam import OpenIAMClient
from .audit import fetch_audit
from .config import EntityConfig, SyncConfig
from .store import Store


class SyncError(Exception):
    pass


class MassDeleteError(SyncError):
    pass


def normalize(bean: dict[str, Any], cfg: EntityConfig) -> dict[str, Any]:
    data = {k: v for k, v in bean.items() if k not in cfg.ignore_fields}
    if cfg.include_fields:
        data = {k: v for k, v in data.items() if k in cfg.include_fields or k == cfg.id_field}
    # Round-trip through JSON so stored and freshly fetched data compare identically.
    return json.loads(json.dumps(data, default=str))


def digest(data: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {k: {"old": old.get(k), "new": new.get(k)}
            for k in sorted(old.keys() | new.keys()) if old.get(k) != new.get(k)}


async def fetch_entity(client: OpenIAMClient, name: str,
                       cfg: EntityConfig) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for query in cfg.queries:
        seen: set[str] = set()
        offset = 0
        while True:
            beans = (await client.search(cfg.path, query, offset, cfg.page_size))["beans"]
            new = 0
            for bean in beans:
                raw_id = bean.get(cfg.id_field) if isinstance(bean, dict) else None
                if raw_id in (None, ""):
                    raise SyncError(f"{name}: record without `{cfg.id_field}` from {cfg.path}")
                entity_id = str(raw_id)
                if entity_id not in seen:
                    seen.add(entity_id)
                    new += 1
                records[entity_id] = normalize(bean, cfg)
            if len(beans) < cfg.page_size:
                break
            if new == 0:
                # A full page with nothing new means the endpoint ignores `from`; stop
                # rather than loop forever or silently miss records.
                raise SyncError(f"{name}: paging on {cfg.path} returned no new records "
                                f"at offset {offset}")
            offset += cfg.page_size
    return records


def _event(run_id: int, entity: str, entity_id: str, action: str, *,
           data: dict | None = None, previous: dict | None = None,
           changes: dict | None = None) -> dict[str, Any]:
    return {
        "event_id": str(uuid.uuid4()),
        "type": f"{entity}.{action}",
        "entity": entity,
        "entity_id": entity_id,
        "action": action,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "data": data,
        "previous": previous,
        "changes": changes,
    }


async def run_sync(client: OpenIAMClient, store: Store, cfg: SyncConfig, *,
                   baseline: bool = False, allow_mass_delete: bool = False,
                   attributor: Any = None) -> dict[str, Any]:
    """Pull every entity, record differences as events. Returns a per-entity summary.

    `baseline` stores the current state without emitting events (first run, when the
    other site was already loaded some other way).
    `attributor(user_id, since)` reports what the source of truth (producer) changed on a
    user since the previous run, so those changes are not reported as admin changes.
    """
    since = store.last_run_start()
    run_id = store.start_run()
    try:
        fetched = {name: await fetch_entity(client, name, ecfg)
                   for name, ecfg in cfg.entities.items()}
        # Who changed what since the previous run (best effort; {} when unavailable).
        audit = (await fetch_audit(client, cfg.audit, since)
                 if cfg.audit and since is not None and not baseline else {})
        summary: dict[str, Any] = {}
        with store.connect() as db:
            for name, current in fetched.items():
                previous = store.load_state(db, name)
                deleted = previous.keys() - current.keys()
                if (not allow_mass_delete and len(deleted) >= cfg.mass_delete_min
                        and len(deleted) > cfg.max_delete_ratio * len(previous)):
                    raise MassDeleteError(
                        f"{name}: {len(deleted)} of {len(previous)} records disappeared; "
                        "refusing to emit deletes (check queries/permissions, or rerun "
                        "with allow_mass_delete)")
                events = []
                counts = {"created": 0, "updated": 0, "deleted": 0, "unchanged": 0}
                for entity_id, data in current.items():
                    h = digest(data)
                    old = previous.get(entity_id)
                    if old is None:
                        counts["created"] += 1
                        events.append(_event(run_id, name, entity_id, "created", data=data))
                    elif old[0] != h:
                        counts["updated"] += 1
                        events.append(_event(run_id, name, entity_id, "updated", data=data,
                                             changes=diff(old[1], data)))
                    else:
                        counts["unchanged"] += 1
                        continue
                    store.upsert_state(db, name, entity_id, h, data)
                for entity_id in sorted(deleted):
                    counts["deleted"] += 1
                    events.append(_event(run_id, name, entity_id, "deleted",
                                         previous=previous[entity_id][1]))
                    store.delete_state(db, name, entity_id)
                if not baseline:
                    for e in events:
                        att = (attributor(e["entity_id"], since)
                               if attributor and e["entity"] == "user" and since is not None else None)
                        e["instructions"], e["why"] = from_change_event(
                            e, cfg.ad, att, audit.get(str(e["entity_id"])))
                    store.add_events(db, events)
                summary[name] = counts
    except Exception as e:
        store.finish_run(run_id, "failed", error=f"{type(e).__name__}: {e}")
        logger.bind(run_id=run_id).warning("sync run {} failed: {}", run_id, e)
        raise
    store.finish_run(run_id, "baseline" if baseline else "ok", summary)
    return {"run_id": run_id, "baseline": baseline, "entities": summary}
