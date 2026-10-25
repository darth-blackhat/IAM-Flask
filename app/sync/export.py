"""Export OpenIAM data as one zip per domain into a folder.

Each zip holds <entity>.<format> files plus manifest.json (counts, sha256 per file).
Zips are written as hidden .partial files and renamed when complete, so whatever
watches the folder never picks up a half-written zip.
"""

import hashlib
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .. import bundlesec
from ..csvutil import to_csv
from ..logs import logger
from ..openiam import OpenIAMClient
from .config import DomainSplit, ExportConfig, SyncConfig
from .engine import fetch_entity
from .paths import extract
from .store import Store

FORMAT_VERSION = 1
INSTRUCTIONS_FILE = "ad_instructions.jsonl"
Source = Literal["live", "snapshot"]
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                     *(f"LPT{i}" for i in range(1, 10))}


async def collect(client: OpenIAMClient, store: Store, cfg: SyncConfig,
                  source: Source) -> dict[str, list[dict[str, Any]]]:
    """Every record of every configured entity: pulled now ("live"), or the last sync's copy."""
    if source == "live":
        out = {}
        for name, ecfg in cfg.entities.items():
            records = await fetch_entity(client, name, ecfg)
            out[name] = [records[k] for k in sorted(records)]
        return out
    out = {}
    for name in cfg.entities:
        rows: list[dict[str, Any]] = []
        while page := store.snapshot(name, len(rows), 1000):
            rows.extend(page)
        out[name] = rows
    return out


def split_domains(data: dict[str, list[dict]], split: DomainSplit) -> dict[str, dict[str, list]]:
    if not split.by_field:
        domains = {"all": dict(data)}
    else:
        domains: dict[str, dict[str, list]] = {}
        for entity, field in split.by_field.items():
            for rec in data[entity]:
                names = extract(rec, field) or ([split.unassigned] if split.unassigned else [])
                for name in names:
                    bucket = domains.setdefault(name, {e: [] for e in split.by_field})
                    bucket[entity].append(rec)
        for bucket in domains.values():
            for entity in split.shared:
                bucket[entity] = data[entity]
    if split.only:
        domains = {d: v for d, v in domains.items() if d in split.only}
    return domains


def content_hash(entities: dict[str, list]) -> str:
    return hashlib.sha256(json.dumps(entities, sort_keys=True, default=str).encode()).hexdigest()


def safe_name(domain: str) -> str:
    """Domain -> file/folder name. Altered names get a hash suffix so they stay unique."""
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", domain).strip("._")[:80] or "domain"
    if name != domain or name.upper() in _WINDOWS_RESERVED:
        name = f"{name}-{hashlib.sha1(domain.encode()).hexdigest()[:8]}"
    return name


def _render(rows: list[dict], fmt: str) -> bytes:
    if fmt == "jsonl":
        return "".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in rows).encode()
    if fmt == "json":
        return json.dumps(rows, indent=2, sort_keys=True, default=str).encode()
    return to_csv(rows).encode() if rows else b""


def write_zip(dest: Path, domain: str, entities: dict[str, list], formats: list[str],
              meta: dict[str, Any],
              instructions: list[dict[str, Any]] | None = None, *,
              signing_key: Any = None, recipients: list | None = None) -> tuple[Path, dict[str, Any]]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    final = dest / f"openiam-{safe_name(domain)}-{stamp}.zip{'.age' if recipients else ''}"
    partial = dest / f".{final.name}.partial"
    files = []
    try:
        with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED) as zf:
            for entity, rows in entities.items():
                for fmt in formats:
                    content = _render(rows, fmt)
                    arc = f"{entity}.{fmt}"
                    zf.writestr(arc, content)
                    files.append({"name": arc, "entity": entity, "format": fmt,
                                  "records": len(rows), "bytes": len(content),
                                  "sha256": hashlib.sha256(content).hexdigest()})
            if instructions is not None:
                content = _render(instructions, "jsonl")
                zf.writestr(INSTRUCTIONS_FILE, content)
                files.append({"name": INSTRUCTIONS_FILE, "entity": "ad_instructions",
                              "format": "jsonl", "records": len(instructions),
                              "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
            manifest = {"format_version": FORMAT_VERSION, "domain": domain,
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "counts": {e: len(rows) for e, rows in entities.items()},
                        "ad_instructions": len(instructions or []),
                        "files": files, **meta}
            if signing_key is not None:
                manifest["signing_key_id"] = bundlesec.key_id(signing_key.public_key())
            manifest_bytes = json.dumps(manifest, indent=2, default=str).encode()
            zf.writestr("manifest.json", manifest_bytes)
            if signing_key is not None:
                zf.writestr(bundlesec.SIGNATURE_FILE, bundlesec.sign(manifest_bytes, signing_key))
        if recipients:
            partial.write_bytes(bundlesec.encrypt(partial.read_bytes(), recipients))
        os.replace(partial, final)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return final, manifest


def prune(dest: Path, domain: str, keep: int | None) -> list[str]:
    """Delete this domain's oldest zips beyond `keep`. Only files this exporter named."""
    if keep is None:
        return []
    pattern = re.compile(rf"^openiam-{re.escape(safe_name(domain))}-\d{{8}}T\d{{12}}Z\.zip(\.age)?$")
    mine = sorted(p for p in dest.iterdir() if p.is_file() and pattern.match(p.name))
    removed = mine[:-keep] if len(mine) > keep else []
    for p in removed:
        p.unlink()
    return [p.name for p in removed]


def event_domains(event: dict[str, Any], split: DomainSplit, known: list[str],
                  store: Store) -> list[str]:
    """Domain(s) an outbox event belongs to: from its data, its previous data, or the
    last-seen record of the same object."""
    entity = event.get("entity")
    if not split.by_field:
        return ["all"]
    if entity in split.shared:
        return known
    path = split.by_field.get(entity)
    if path:
        records = [event.get("data"), event.get("previous")]
        if event.get("entity_id"):
            records.append(store.state_record(entity, str(event["entity_id"])))
        for rec in records:
            if rec and (values := extract(rec, path)):
                return values
    return [split.unassigned] if split.unassigned else []


def minimizer(ex: ExportConfig, cfg: SyncConfig):
    """record, entity -> record with only the allowed fields (plus id and domain field)."""
    def keep(record: dict | None, entity: str | None) -> dict | None:
        allowed = ex.fields.get(entity or "")
        if record is None or not allowed:
            return record
        always = {cfg.entities[entity].id_field if entity in cfg.entities else "id"}
        path = ex.domains.by_field.get(entity or "")
        if path:
            always.add(path.split(".")[0])
        return {k: v for k, v in record.items() if k in allowed or k in always}
    return keep


def instruction_lines(event: dict[str, Any], domain: str, keep=None) -> list[dict[str, Any]]:
    """One ad_instructions.jsonl line per instruction: what to do, why, and the data."""
    return [{"seq": event["seq"], "event_id": event["event_id"], "event_type": event.get("type"),
             "detected_at": event.get("detected_at"), "domain": domain,
             "entity": event.get("entity"), "entity_id": event.get("entity_id"),
             "employee_id": event.get("employee_id"),
             "instruction": {k: v for k, v in ins.items() if k != "why"},
             "why": ins.get("why") or event.get("why"),
             "data": keep(event.get("data"), event.get("entity")) if keep else event.get("data"),
             "previous": (keep(event.get("previous"), event.get("entity")) if keep
                          else event.get("previous"))}
            for ins in event.get("instructions") or []]


async def export_domains(client: OpenIAMClient, store: Store, cfg: SyncConfig, *,
                         source: Source = "snapshot", force: bool = False,
                         run_id: int | None = None) -> dict[str, Any]:
    """One zip per domain whose data changed since its last export (all with force).

    A domain that existed before but now has no records gets a final zip with empty
    files and "removed": true, so the receiving side learns it is gone.
    """
    ex: ExportConfig = cfg.export
    signing_key = bundlesec.load_signing_key(ex.signing_key_file) if ex.signing_key_file else None
    recipients = bundlesec.load_recipients(ex.encrypt_to) if ex.encrypt_to else None
    data = await collect(client, store, cfg, source)
    domains = split_domains(data, ex.domains)
    keep = minimizer(ex, cfg)
    if ex.fields:
        domains = {d: {e: [keep(r, e) for r in rows] for e, rows in ents.items()}
                   for d, ents in domains.items()}
    last = store.last_exports()
    removed = {d for d in last if d not in domains and (not ex.domains.only or d in ex.domains.only)}
    for d in removed:
        domains[d] = {e: [] for e in data}

    # Zip target: pending instructions travel inside the zip of their domain.
    zip_mode = cfg.target.type == "zip"
    pending = store.pending_all() if zip_mode else []
    lines: dict[str, list[dict[str, Any]]] = {}
    seqs_by_domain: dict[str, set[int]] = {}
    known = sorted(domains)
    for event in pending:
        if not event.get("instructions"):
            continue
        for d in event_domains(event, ex.domains, known, store):
            if ex.domains.only and d not in ex.domains.only:
                continue
            lines.setdefault(d, []).extend(instruction_lines(event, d, keep))
            seqs_by_domain.setdefault(d, set()).add(event["seq"])
    for d in lines:
        domains.setdefault(d, {e: [] for e in data})

    results = []
    failed_seqs: set[int] = set()
    for domain in sorted(domains):
        entities = domains[domain]
        h = content_hash(entities)
        if not force and not lines.get(domain) and last.get(domain, {}).get("content_hash") == h:
            results.append({"domain": domain, "status": "unchanged"})
            continue
        dest = Path(ex.folder) / safe_name(domain) if ex.subfolder_per_domain else Path(ex.folder)
        meta = {"source": source, "openiam_base_url": client.base_url, "sync_run_id": run_id,
                "removed": domain in removed}
        try:
            dest.mkdir(parents=True, exist_ok=True)
            path, manifest = write_zip(dest, domain, entities, ex.formats, meta,
                                       lines.get(domain, []) if zip_mode else None,
                                       signing_key=signing_key, recipients=recipients)
            pruned = prune(dest, domain, ex.keep)
        except OSError as e:
            logger.bind(domain=domain).error("export of domain {} to {} failed: {}", domain, dest, e)
            results.append({"domain": domain, "status": "failed", "error": str(e)})
            failed_seqs |= seqs_by_domain.get(domain, set())
            continue
        store.record_export(domain, h, str(path), sum(manifest["counts"].values()))
        logger.bind(domain=domain, file=str(path)).info("exported domain {} -> {} ({})", domain,
                                                         path, manifest["counts"])
        results.append({"domain": domain, "status": "removed" if domain in removed else "exported",
                        "file": str(path), "counts": manifest["counts"],
                        "ad_instructions": manifest["ad_instructions"], "pruned": pruned})
    if zip_mode:
        # Written (or nothing to write): delivered. A failed domain keeps its events
        # pending for the next export.
        done = sorted({e["seq"] for e in pending} - failed_seqs)
        if done:
            store.mark_delivered(done)
    return {"source": source, "folder": ex.folder, "domains": results}
