"""Read OpenIAM's audit log to tell *who* changed a record directly in OpenIAM.

Only the root /rest/api/auditlog is confirmed by OpenIAM's docs; the search path, the
time criterion and the field names differ per deployment, so all of them are config
(see AuditConfig). Audit enrichment is best effort: a failing audit query never stops
change detection, it only leaves `why.audit` out.
"""

from datetime import datetime, timezone
from typing import Any

from ..logs import logger
from ..openiam import OpenIAMClient, OpenIAMError
from .config import AuditConfig
from .paths import extract


def _since_value(since: float, fmt: str) -> Any:
    if fmt == "epoch_ms":
        return int(since * 1000)
    if fmt == "epoch_s":
        return int(since)
    return datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _entry(rec: dict[str, Any], cfg: AuditConfig) -> dict[str, Any]:
    f = cfg.fields
    out = {"audit_id": rec.get(f.id), "at": rec.get(f.time), "by": rec.get(f.actor),
           "by_id": rec.get(f.actor_id), "action": rec.get(f.action), "result": rec.get(f.result)}
    return {k: v for k, v in out.items() if v not in (None, "")}


async def fetch_audit(client: OpenIAMClient, cfg: AuditConfig,
                      since: float) -> dict[str, list[dict[str, Any]]]:
    """target object id -> audit entries (oldest first) since `since`. {} if unavailable."""
    criteria = {**cfg.criteria, cfg.since_criterion: _since_value(since, cfg.since_format)}
    index: dict[str, list[dict[str, Any]]] = {}
    seen = 0
    try:
        async for rec in client.iter_search(cfg.search_path, criteria, cfg.page_size,
                                            cfg.max_records):
            seen += 1
            entry = _entry(rec, cfg)
            for target_id in extract(rec, cfg.fields.target_id):
                index.setdefault(target_id, []).append(entry)
    except (OpenIAMError, ValueError) as e:
        logger.warning("audit log unavailable, changes are reported without who/when: {}", e)
        return {}
    if seen >= cfg.max_records:
        logger.warning("audit log: stopped at max_records={}; older entries not matched", seen)
    for entries in index.values():
        entries.sort(key=lambda x: str(x.get("at", "")))
    return index
