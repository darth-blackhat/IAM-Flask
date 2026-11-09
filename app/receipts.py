"""AD receipts: the consumer site tells the producer what happened to each instruction.

Consumer site
  After a zip is handled (and again when an AD plan is approved or rejected later) a
  receipt is queued in the consumer's database (the oversight web can queue one too: it
  holds no keys). The consumer service signs each queued receipt with its own Ed25519
  key (`iam keys signing`), optionally encrypts it to the producer (age), and writes it
  atomically into `receipts.folder` on the share:
      receipt-<site>-<UTC>-<n>.json        {"receipt": {...}, "signature", "key_id"}
      receipt-<site>-<UTC>-<n>.json.age    the same, encrypted

Producer site
  The service imports the folder: every receipt must be signed by the key trusted for
  the site it names (site A cannot speak for site B), duplicates are ignored, and each
  instruction's latest status is stored. Failures raise an `ad.failed` notification.
  Imported files are moved to <folder>/imported/ (rejected ones to <folder>/rejected/).

Instruction statuses: applied, unchanged (already so), failed, skipped, planned,
awaiting_approval, rejected (plan rejected on the consumer), not_applied (zip stale /
skipped / unreadable), covered_by_records (OpenIAM target: applied through the records).
"""

import json
import re
import shutil
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import insert, select, update

from . import bundlesec
from .db import Database
from .logs import logger

SITE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
MAX_RECEIPT_BYTES = 5 * 1024 * 1024
FINAL = {"applied", "unchanged", "failed", "skipped", "rejected", "not_applied", "covered_by_records"}


def _site(v: str) -> str:
    if not SITE.match(v or ""):
        raise ValueError("site: lowercase letters, digits, - and _ (max 63)")
    return v


class ReceiptWriterConfig(BaseModel):
    """Consumer side (consumer.yaml `receipts:`)."""
    folder: str
    site: str
    signing_key_file: str                  # from `iam keys signing`: this site's private key
    encrypt_to: list[str] = []             # the producer's age recipient(s)

    @field_validator("site")
    @classmethod
    def _site_ok(cls, v: str) -> str:
        return _site(v)


class ReceiptImportConfig(BaseModel):
    """Producer side (sync.yaml `receipts:`)."""
    folder: str
    # site -> its .pub signing key, or several during a key rotation (old + new).
    trusted: dict[str, str | list[str]] = Field(default_factory=dict)
    require_signature: bool = True
    age_identity_file: str | list[str] | None = None   # several during a rotation
    require_encryption: bool = False

    @field_validator("trusted")
    @classmethod
    def _sites(cls, v: dict[str, str | list[str]]) -> dict[str, str | list[str]]:
        for site in v:
            _site(site)
        return v


def load_all_identities(paths: str | list[str] | None):
    """age identities from one file or several (old + new during a key rotation)."""
    if not paths:
        return None
    out = []
    for p in [paths] if isinstance(paths, str) else paths:
        out.extend(bundlesec.load_identities(p))
    return out


def _canonical(receipt: dict[str, Any]) -> bytes:
    return json.dumps(receipt, sort_keys=True, separators=(",", ":"), default=str).encode()


# ---- building ---------------------------------------------------------------------------

def item_status(item: dict[str, Any], plan_status: str) -> str:
    """One AD plan item -> receipt status."""
    if plan_status in ("planned", "awaiting_approval", "rejected"):
        return plan_status
    ldap = item.get("ldap")
    if ldap == "noop":
        return "unchanged"
    if ldap == "skipped":
        return "skipped"
    return "applied" if item.get("ok") else "failed"


def from_plan(plan: dict[str, Any], zip_name: str | None) -> dict[str, Any]:
    status = plan["status"]
    items = []
    for i in plan.get("items") or []:
        detail = " | ".join(str(x) for x in (i.get("dn"), i.get("error"), i.get("note")) if x) or None
        items.append({"instruction_id": i.get("instruction_id"), "op": i.get("op"),
                      "object_class": i.get("object_class"), "key": i.get("key"),
                      "status": item_status(i, status), "detail": detail})
    return {"zip": zip_name, "zip_sha256": plan.get("file_sha256"), "domain": plan.get("domain"),
            "status": status, "target": "ad", "plan_id": plan.get("id"), "instructions": items}


def not_applied(zip_name: str, sha: str, domain: str | None, status: str, reason: str,
                lines: list[dict[str, Any]] | None = None, target: str = "ad") -> dict[str, Any]:
    return {"zip": zip_name, "zip_sha256": sha, "domain": domain, "status": status, "target": target,
            "reason": reason,
            "instructions": [{"instruction_id": (ln.get("instruction") or {}).get("instruction_id"),
                              "op": (ln.get("instruction") or {}).get("op"), "status": "not_applied",
                              "detail": reason} for ln in lines or []]}


# ---- consumer: outbox + writer --------------------------------------------------------

class ReceiptOutbox:
    def __init__(self, db: Database):
        self.db, self.t = db, db.tables.consumer_receipts

    def add(self, receipt: dict[str, Any]) -> int:
        with self.db.begin() as conn:
            return conn.execute(insert(self.t).values(at=time.time(), payload=receipt, status="pending")
                                ).inserted_primary_key[0]

    def pending(self, limit: int = 200) -> list[dict[str, Any]]:
        c = self.t.c
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(self.t).where(c.status == "pending").order_by(c.id).limit(limit))]

    def mark(self, rid: int, file: str) -> None:
        with self.db.begin() as conn:
            conn.execute(update(self.t).where(self.t.c.id == rid).values(
                status="written", file=file, written_at=time.time()))

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(self.t).order_by(self.t.c.id.desc()).limit(limit))]


class ReceiptWriter:
    def __init__(self, cfg: ReceiptWriterConfig, db: Database):
        self.cfg, self.outbox = cfg, ReceiptOutbox(db)
        self.key = bundlesec.load_signing_key(cfg.signing_key_file)
        self.key_id = bundlesec.key_id(self.key.public_key())
        self.recipients = bundlesec.load_recipients(cfg.encrypt_to) if cfg.encrypt_to else []

    def flush(self) -> list[str]:
        """Sign and write every queued receipt. A share that is down leaves them queued."""
        written = []
        folder = Path(self.cfg.folder)
        for row in self.outbox.pending():
            receipt = {**row["payload"], "site": self.cfg.site, "receipt_id": row["id"],
                       "created_at": row["at"]}
            body = _canonical(receipt)
            envelope = json.dumps({"receipt": receipt, "key_id": self.key_id,
                                   "signature": bundlesec.sign(body, self.key).decode()}).encode()
            name = f"receipt-{self.cfg.site}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(row['at']))}-{row['id']}.json"
            if self.recipients:
                envelope, name = bundlesec.encrypt(envelope, self.recipients), name + ".age"
            try:
                folder.mkdir(parents=True, exist_ok=True)
                tmp = folder / f".{name}.partial"
                tmp.write_bytes(envelope)
                tmp.replace(folder / name)                 # atomic: the producer never sees half a file
            except OSError as e:
                logger.warning("receipt {} not written (share unavailable?): {}", row["id"], e)
                break
            self.outbox.mark(row["id"], str(folder / name))
            written.append(name)
        return written


# ---- producer: import + store ---------------------------------------------------------

class ReceiptError(Exception):
    pass


class ReceiptStore:
    def __init__(self, db: Database):
        self.db, self.r, self.i = db, db.tables.ad_receipts, db.tables.ad_receipt_items

    def seen(self, site: str, receipt_id: int) -> bool:
        c = self.r.c
        with self.db.begin() as conn:
            return conn.execute(select(c.id).where(c.site == site, c.receipt_id == receipt_id)).first() is not None

    def save(self, receipt: dict[str, Any], signed_by: str | None) -> int:
        site, now = receipt["site"], time.time()
        with self.db.begin() as conn:
            rid = conn.execute(insert(self.r).values(
                site=site, receipt_id=int(receipt["receipt_id"]), zip_name=receipt.get("zip"),
                zip_sha256=receipt.get("zip_sha256"), domain=receipt.get("domain"),
                status=str(receipt.get("status"))[:30], created_at=float(receipt.get("created_at") or now),
                received_at=now, signed_by=signed_by, payload=receipt)).inserted_primary_key[0]
            for item in receipt.get("instructions") or []:
                iid = item.get("instruction_id")
                if not iid:
                    continue
                row = {"instruction_id": str(iid)[:64], "site": site, "status": str(item.get("status"))[:30],
                       "detail": (str(item.get("detail")) if item.get("detail") else None),
                       "at": float(receipt.get("created_at") or now), "receipt": rid}
                # Keep the newest status per instruction and site (receipts can arrive out of order).
                old = conn.execute(select(self.i.c.at).where(self.i.c.instruction_id == row["instruction_id"],
                                                             self.i.c.site == site)).scalar()
                if old is None:
                    conn.execute(insert(self.i).values(**row))
                elif row["at"] >= old:
                    conn.execute(update(self.i).where(self.i.c.instruction_id == row["instruction_id"],
                                                      self.i.c.site == site).values(**row))
        return rid

    def for_instructions(self, ids: list[str]) -> dict[str, list[dict[str, Any]]]:
        """instruction id -> [{site, status, detail, at}]"""
        if not ids:
            return {}
        out: dict[str, list[dict[str, Any]]] = {}
        with self.db.begin() as conn:
            for chunk in range(0, len(ids), 500):
                for r in conn.execute(select(self.i).where(self.i.c.instruction_id.in_(ids[chunk:chunk + 500]))):
                    out.setdefault(r.instruction_id, []).append(dict(r._mapping))
        return out

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.db.begin() as conn:
            return [dict(r._mapping) for r in conn.execute(
                select(self.r).order_by(self.r.c.id.desc()).limit(limit))]

    def last_per_site(self) -> dict[str, float]:
        from sqlalchemy import func
        c = self.r.c
        with self.db.begin() as conn:
            return {s: t for s, t in conn.execute(select(c.site, func.max(c.received_at)).group_by(c.site))}


def summarize_ad(ids: list[str], found: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """For a request: how its instructions fared at the consumer sites."""
    by_status: dict[str, int] = {}
    sites = set()
    for iid in ids:
        for r in found.get(iid, []):
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
            sites.add(r["site"])
    reported = sum(1 for iid in ids if iid in found)
    return {"total": len(ids), "reported": reported, "by_status": by_status, "sites": sorted(sites),
            "failed": by_status.get("failed", 0)}


def import_receipts(db: Database, cfg: ReceiptImportConfig) -> dict[str, Any]:
    from .notify import Notifications
    folder = Path(cfg.folder)
    if not folder.is_dir():
        raise ReceiptError(f"receipts folder {folder} does not exist or is not reachable")
    trusted = {site: [bundlesec.load_public_key(x) for x in ([p] if isinstance(p, str) else p)]
               for site, p in cfg.trusted.items()}
    identities = load_all_identities(cfg.age_identity_file)
    store, notes = ReceiptStore(db), Notifications(db)
    counts = {"imported": 0, "duplicate": 0, "rejected": 0}
    for path in sorted(folder.glob("receipt-*.json*")):
        if path.name.startswith(".") or not path.is_file():
            continue
        try:
            receipt, signed_by = _read(path, trusted, identities, cfg)
            if store.seen(receipt["site"], int(receipt["receipt_id"])):
                counts["duplicate"] += 1
            else:
                store.save(receipt, signed_by)
                counts["imported"] += 1
                failed = [i for i in receipt.get("instructions") or [] if i.get("status") == "failed"]
                if failed:
                    notes.add("ad.failed", f"AD change failed at {receipt['site']} ({len(failed)})",
                              "\n".join(f"{i.get('op')} {i.get('object_class') or ''} {i.get('key')}: {i.get('detail')}"
                                        for i in failed[:20]),
                              {"site": receipt["site"], "zip": receipt.get("zip"), "failed": len(failed)})
            _move(path, folder / "imported")
        except (ReceiptError, bundlesec.BundleSecurityError, ValueError, KeyError) as e:
            counts["rejected"] += 1
            logger.warning("receipt {} rejected: {}", path.name, e)
            _move(path, folder / "rejected")
    return counts


def _read(path: Path, trusted: dict, identities, cfg: ReceiptImportConfig) -> tuple[dict[str, Any], str | None]:
    raw = path.read_bytes()
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt too large")
    if path.name.endswith(".age"):
        if not identities:
            raise ReceiptError("encrypted receipt but no age_identity_file")
        raw = bundlesec.decrypt(raw, identities)
    elif cfg.require_encryption:
        raise ReceiptError("receipt is not encrypted")
    env = json.loads(raw)
    receipt = env.get("receipt")
    if not isinstance(receipt, dict):
        raise ReceiptError("not a receipt")
    site = _site(str(receipt.get("site") or ""))
    int(receipt.get("receipt_id"))
    signed_by = None
    if site in trusted:
        # Only the key trusted for THIS site counts: one site cannot speak for another.
        bundlesec.verify(_canonical(receipt), (env.get("signature") or "").encode() or None,
                         {f"{site}#{i}": k for i, k in enumerate(trusted[site])})
        signed_by = site
    elif cfg.require_signature:
        raise ReceiptError(f"no trusted key for site {site!r}")
    return receipt, signed_by


def _move(path: Path, dest: Path) -> None:
    try:
        dest.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(dest / path.name))
    except OSError as e:
        logger.error("could not move receipt {}: {}", path.name, e)
