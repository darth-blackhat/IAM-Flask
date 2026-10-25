"""Pick up the producer side's per-domain zips and apply them to the remote OpenIAM.

Per zip:
  1. verify   manifest.json and the sha256 of every file; a bad zip goes to `failed/`
  2. order    an older zip for a domain never overwrites a newer one already applied
  3. apply    organizations, groups, roles, then users; unchanged records are skipped,
              so a full-domain zip only causes the real changes
  4. archive  move the zip to archive/<domain>/
Records that fail are not marked as applied, so the next zip for that domain retries them.
"""

import asyncio
import hashlib
import io
import json
import re
import shutil
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple

from .. import bundlesec
from ..config import Settings
from ..db import LockTimeout
from ..logs import logger
from ..openiam import OpenIAMClient, OpenIAMError
from ..schemas import EmailIn, UserIn
from ..sync.engine import digest
from ..sync.export import extract, safe_name
from .ad_target import AdApplier, AdError, change_count, summarize
from .ad_watch import AdWatcher
from .inbox_watch import InboxWatcher
from .config import ENTITY_ORDER, ConsumerConfig
from .store import ConsumerStore

ZIP_NAME = re.compile(r"^openiam-.+-(\d{8}T\d{12}Z)\.zip(\.age)?$")
ENTITLE_ARG = {"group": "group_ids", "role": "role_ids", "organization": "organization_ids"}


def summarize_by(rows: list[dict], key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return out


class ConsumerError(Exception):
    pass


class ConsumerBusy(ConsumerError):
    pass


class BadBundle(ConsumerError):
    pass


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class Bundle(NamedTuple):
    manifest: dict[str, Any]
    entities: dict[str, list[dict]]
    instructions: list[dict]
    signed_by: str | None
    encrypted: bool


def read_bundle(path: Path, *, trusted: dict | None = None, require_signature: bool = False,
                identities: list | None = None, require_encryption: bool = False) -> Bundle:
    """Decrypt (if .age), verify the signature (if trusted keys are given) and every
    file's sha256, then parse."""
    encrypted = path.name.endswith(".age")
    if require_encryption and not encrypted:
        raise BadBundle("zip is not encrypted, and encryption is required")
    try:
        raw = path.read_bytes()
        if encrypted:
            if not identities:
                raise BadBundle("encrypted zip, but no age_identity_file is configured")
            raw = bundlesec.decrypt(raw, identities)
    except bundlesec.BundleSecurityError as e:
        raise BadBundle(str(e)) from e
    except OSError as e:
        raise BadBundle(f"unreadable bundle: {e}") from e
    signed_by = None
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            manifest_bytes = zf.read("manifest.json")
            if trusted or require_signature:
                names = set(zf.namelist())
                sig = zf.read(bundlesec.SIGNATURE_FILE) if bundlesec.SIGNATURE_FILE in names else None
                if sig is not None or require_signature:
                    try:
                        signed_by = bundlesec.verify(manifest_bytes, sig, trusted or {})
                    except bundlesec.BundleSecurityError as e:
                        raise BadBundle(str(e)) from e
            manifest = json.loads(manifest_bytes)
            by_name = {}
            for f in manifest.get("files", []):
                content = zf.read(f["name"])
                if hashlib.sha256(content).hexdigest() != f["sha256"]:
                    raise BadBundle(f"checksum mismatch for {f['name']}")
                by_name[f["name"]] = content
    except (zipfile.BadZipFile, KeyError, json.JSONDecodeError, OSError) as e:
        raise BadBundle(f"unreadable bundle: {type(e).__name__}: {e}") from e
    if signed_by and manifest.get("signing_key_id") not in (None, signed_by):
        raise BadBundle("manifest names a different signing key than the one that signed it")
    if not manifest.get("domain") or not manifest.get("generated_at"):
        raise BadBundle("manifest has no domain / generated_at")
    entities = {}
    for entity in manifest.get("counts", {}):
        if (raw := by_name.get(f"{entity}.jsonl")) is not None:
            entities[entity] = [json.loads(line) for line in raw.decode().splitlines() if line]
        elif (raw := by_name.get(f"{entity}.json")) is not None:
            entities[entity] = json.loads(raw)
        else:
            raise BadBundle(f"no {entity}.jsonl or {entity}.json (export with format jsonl or json)")
        if len(entities[entity]) != manifest["counts"][entity]:
            raise BadBundle(f"{entity}: {len(entities[entity])} records, manifest says "
                            f"{manifest['counts'][entity]}")
    instructions = []
    if (raw_ins := by_name.get("ad_instructions.jsonl")) is not None:
        instructions = [json.loads(line) for line in raw_ins.decode().splitlines() if line]
    return Bundle(manifest, entities, instructions, signed_by, encrypted)


class Consumer:
    def __init__(self, client: OpenIAMClient | None, store: ConsumerStore, cfg: ConsumerConfig,
                 settings: Settings, *, target: str = "openiam", ad: AdApplier | None = None):
        self.client, self.store, self.cfg, self.settings = client, store, cfg, settings
        if target == "ad" and ad is None:
            raise ConsumerError("CONSUMER_TARGET=ad needs the `ad:` section in consumer.yaml")
        self.target, self.ad = target, ad
        self.watcher = (AdWatcher(ad, store, ad.cfg.watch)
                        if target == "ad" and ad is not None and ad.cfg.watch.enabled else None)
        self._names: dict[tuple[str, str], str] = {}
        self._trusted = {bundlesec.key_id(k): k for k in
                         (bundlesec.load_public_key(p) for p in cfg.trusted_signing_keys)}
        self._identities = (bundlesec.load_identities(cfg.age_identity_file)
                            if cfg.age_identity_file else None)
        # Called once per loop iteration (daily retention purge).
        self.housekeeping = None
        # Set by the builder: operator requests from the oversight web.
        self.operator_requests = None

    # ---- scanning -----------------------------------------------------------

    def find_bundles(self) -> list[Path]:
        inbox = Path(self.cfg.inbox)
        if not inbox.is_dir():
            raise ConsumerError(f"inbox {inbox} does not exist or is not reachable")
        skip = [Path(p).resolve() for p in (self.cfg.archive, self.cfg.failed) if p]
        found = []
        for p in inbox.rglob("openiam-*.zip*"):
            # Skip in-progress uploads and our own archive if it lives inside the inbox.
            if p.name.startswith(".") or not ZIP_NAME.match(p.name):
                continue
            rp = p.resolve()
            if any(rp.is_relative_to(s) for s in skip):
                continue
            try:
                if time.time() - p.stat().st_mtime < self.cfg.settle_seconds:
                    continue   # still being copied in: next round
            except OSError:
                continue
            found.append(p)
        return sorted(found, key=lambda p: (ZIP_NAME.match(p.name).group(1), p.name))

    async def scan(self) -> dict[str, Any]:
        try:
            async with self.store.db.lock("consumer", timeout=0):
                self._names.clear()
                results = [await self.process_file(p) for p in self.find_bundles()]
        except LockTimeout:
            raise ConsumerBusy("another consumer scan is running") from None
        return {"files": results}

    async def loop(self) -> None:
        arrived = asyncio.Event()
        inbox_watch = None
        if self.cfg.watch_inbox:
            inbox_watch = InboxWatcher(self.cfg.inbox, arrived, self.cfg.watch_polling)
            try:
                inbox_watch.start()
            except Exception as e:   # e.g. inotify limits: keep the timed scan
                logger.warning("inbox watchdog unavailable, timed scan only: {}", e)
                inbox_watch = None
        try:
            await self._loop(arrived)
        finally:
            if inbox_watch is not None:
                inbox_watch.stop()

    async def _loop(self, arrived: asyncio.Event) -> None:
        while True:
            arrived.clear()
            try:
                result = await self.scan()
                if result["files"]:
                    logger.info("consumer scan: {}", [(f["name"], f["status"]) for f in result["files"]])
            except asyncio.CancelledError:
                raise
            except ConsumerBusy:
                logger.info("consumer scan skipped: another instance is scanning")
            except Exception:
                logger.exception("consumer scan failed")
            if self.watcher is not None and self.watcher.due():
                try:
                    await self.watch_ad()
                except Exception:
                    logger.exception("AD change watch failed")
            if self.housekeeping:
                self.housekeeping()
            # Wait for a zip to arrive or the next timed scan, answering operator
            # requests every few seconds meanwhile.
            deadline = time.monotonic() + self.cfg.interval_seconds
            while (left := deadline - time.monotonic()) > 0:
                if self.operator_requests is not None:
                    try:
                        await self.operator_requests.run_pending("consumer", self.operator_handlers())
                    except Exception:
                        logger.exception("operator request loop")
                try:
                    await asyncio.wait_for(arrived.wait(),
                                           min(self.settings.operator_poll_seconds or left, left))
                except TimeoutError:
                    continue
                await asyncio.sleep(self.cfg.settle_seconds + 0.5)   # let the copy finish
                break

    # ---- one file -----------------------------------------------------------

    async def process_file(self, path: Path, *, force: bool = False) -> dict[str, Any]:
        """`force` (operator "reprocess"): apply again even if seen before or older."""
        sha = file_sha256(path)
        name = path.name
        prior = self.store.file(sha)
        if prior and prior["status"] != "processing" and not force:
            # Same bytes seen before (e.g. archive disabled, or copied in twice).
            self._move(path, prior.get("domain"), self.cfg.archive)
            return {"name": name, "sha256": sha, "domain": prior.get("domain"), "status": "duplicate"}

        now = time.time()
        try:
            bundle = read_bundle(path, trusted=self._trusted,
                                 require_signature=self.cfg.require_signature,
                                 identities=self._identities,
                                 require_encryption=self.cfg.require_encryption)
            manifest, entities = bundle.manifest, bundle.entities
        except BadBundle as e:
            self.store.save_file(sha256=sha, name=name, status="failed", received_at=now,
                                 processed_at=now, error=str(e))
            self.store.log_action(sha, None, None, None, "reject", False, str(e))
            stored = self._move(path, None, self.cfg.failed)
            self.store.update_file(sha, stored_at=stored)
            logger.warning("consumer rejected {}: {}", name, e)
            return {"name": name, "sha256": sha, "status": "failed", "error": str(e)}

        domain, generated = manifest["domain"], manifest["generated_at"]
        base = dict(sha256=sha, name=name, domain=domain, generated_at=generated, received_at=now,
                    counts=manifest.get("counts"))
        last = self.store.domain_state(domain)
        if self.cfg.domains and domain not in self.cfg.domains:
            status, summary = "skipped", {"reason": "domain not accepted"}
        elif last and generated <= last["last_generated_at"] and not force:
            status, summary = "stale", {"reason": f"older than applied {last['last_generated_at']}"}
        else:
            self.store.save_file(**base, status="processing")
            if self.target == "ad":
                try:
                    summary, status = await self._apply_ad(sha, domain, bundle.instructions)
                except AdError as e:
                    # AD unreachable is not the zip's fault: leave it in the inbox, retry next scan.
                    logger.warning("AD unavailable, {} stays in the inbox: {}", name, e)
                    return {"name": name, "sha256": sha, "domain": domain, "status": "retry",
                            "error": str(e)}
            else:
                summary = await self._apply(sha, domain, entities)
                if self.cfg.apply_instructions and bundle.instructions:
                    extra = await self._apply_instructions_openiam(sha, domain, bundle.instructions)
                    for k, v in extra.items():
                        summary[k] = summary.get(k, 0) + v
                status = "applied" if summary.get("failed", 0) == 0 else "partial"
            if not last or generated > last["last_generated_at"]:
                self.store.save_domain(domain, generated, sha, sum(len(v) for v in entities.values()))
        self.store.save_file(**base, status=status, processed_at=time.time(), summary=summary)
        stored = self._move(path, domain, self.cfg.archive)
        self.store.update_file(sha, stored_at=stored)
        logger.bind(domain=domain, file=name).info("consumer {} {} ({}): {}", status, name, domain, summary)
        return {"name": name, "sha256": sha, "domain": domain, "status": status, "summary": summary}

    def _move(self, path: Path, domain: str | None, dest_root: str | None) -> str:
        if not dest_root or not path.exists():
            return str(path)
        if path.resolve().is_relative_to(Path(dest_root).resolve()):
            return str(path)   # reprocessed from the archive: leave it where it is
        dest = Path(dest_root) / (safe_name(domain) if domain else "_unknown")
        try:
            dest.mkdir(parents=True, exist_ok=True)
            target = dest / path.name
            n = 1
            while target.exists():
                target = dest / f"{path.stem}.{n}{path.suffix}"
                n += 1
            shutil.move(str(path), str(target))
        except OSError as e:
            # The result is already recorded; the next scan sees a duplicate and retries
            # the move. Never let a full or read-only archive stop the scan.
            logger.error("could not move {} to {}: {}", path.name, dest, e)
            return str(path)
        return str(target)

    # ---- AD target ----------------------------------------------------------

    async def _apply_ad(self, sha: str, domain: str, lines: list[dict]) -> tuple[dict, str]:
        if not lines:
            return {"ad_instructions": 0}, "applied"
        cfg = self.ad.cfg
        items = await asyncio.to_thread(self.ad.plan, lines)
        changes = change_count(items)
        if cfg.mode == "dry_run":
            plan_status = "planned"
        elif cfg.mode == "approve" or changes > cfg.max_changes_auto:
            plan_status = "awaiting_approval"
        else:
            items = await asyncio.to_thread(self.ad.apply, lines)
            plan_status = "applied" if all(i["ok"] for i in items) else "partial"
            await self._own_writes(items)
        summary = {"ad_instructions": len(lines), "changes": changes, **summarize(items)}
        plan_id = self.store.save_plan(file_sha256=sha, domain=domain, mode=cfg.mode,
                                       status=plan_status, lines=lines, items=items, summary=summary,
                                       applied_at=time.time() if plan_status in ("applied", "partial") else None)
        self._log_ad(sha, domain, items, applied=plan_status in ("applied", "partial"))
        summary["plan_id"] = plan_id
        file_status = {"planned": "planned", "awaiting_approval": "awaiting_approval"}.get(
            plan_status, plan_status)
        return summary, file_status

    async def _own_writes(self, items: list[dict]) -> None:
        """Tell the watcher what the consumer itself just changed, so it does not alert."""
        if self.watcher is not None:
            dns = [i.get("dn") for i in items if i.get("ok") and i["ldap"] in ("add", "modify")]
            await asyncio.to_thread(self.watcher.record_own, dns)

    async def watch_ad(self) -> dict[str, Any]:
        if self.watcher is None:
            raise ConsumerError("the AD change watch is not enabled on this consumer")
        async with self.store.db.lock("consumer", timeout=60):
            alerts = await asyncio.to_thread(self.watcher.poll)
        return {"alerts": len(alerts), "by_severity": summarize_by(alerts, "severity")}

    def _log_ad(self, sha: str, domain: str, items: list[dict], applied: bool) -> None:
        for i in items:
            ok = i.get("ok", i["ldap"] != "error")
            detail = " | ".join(x for x in (i.get("dn"), i.get("error"), i.get("note"), i.get("why")) if x)
            self.store.log_action(sha, domain, f"ad:{i['object_class']}", json.dumps(i.get("key")),
                                  f"{i['op']}:{i['ldap']}{'' if applied else ' (planned)'}", ok, detail)

    async def approve_plan(self, plan_id: int, by: str) -> dict[str, Any]:
        plan = self.store.plan(plan_id)
        if plan is None or plan["status"] != "awaiting_approval":
            raise ConsumerError(f"plan {plan_id} is not awaiting approval")
        if self.ad is None:
            raise ConsumerError("this consumer has no AD target")
        items = await asyncio.to_thread(self.ad.apply, plan["lines"])
        await self._own_writes(items)
        status = "applied" if all(i["ok"] for i in items) else "partial"
        summary = {**plan["summary"], **summarize(items), "applied_by": by}
        self.store.update_plan(plan_id, status=status, items=items, summary=summary,
                               decided_by=by, decided_at=time.time(), applied_at=time.time())
        self._log_ad(plan["file_sha256"], plan["domain"], items, applied=True)
        self.store.update_file(plan["file_sha256"], status=status)
        return {"plan_id": plan_id, "status": status, **summarize(items)}

    def operator_handlers(self) -> dict:
        async def scan(_: dict) -> dict:
            return await self.scan()

        async def reprocess(params: dict) -> dict:
            f = self.store.file(params["sha256"])
            if not f or not f.get("stored_at") or not Path(f["stored_at"]).exists():
                raise ConsumerError("zip not found in the archive")
            return await self.process_file(Path(f["stored_at"]), force=True)

        async def ad_approve(params: dict) -> dict:
            return await self.approve_plan(int(params["plan_id"]), params.get("by", "operator"))

        async def drift(params: dict) -> dict:
            from .drift import drift_report
            domains = ([params["domain"]] if params.get("domain")
                       else [d["domain"] for d in self.store.all_domains()])
            return {"reports": [await drift_report(self, d, params.get("by", "operator"))
                                for d in domains]}
        async def ad_watch(_: dict) -> dict:
            return await self.watch_ad()
        return {"scan": scan, "reprocess": reprocess, "ad_approve": ad_approve, "drift": drift,
                "ad_watch": ad_watch}

    # ---- OpenIAM target: instructions ------------------------------------------

    async def _apply_instructions_openiam(self, sha: str, domain: str,
                                          lines: list[dict]) -> dict[str, int]:
        """Carry out what the zip's records cannot express, in instruction order."""
        counts: Counter[str] = Counter()
        for line in sorted(lines, key=lambda x: x.get("seq") or 0):
            ins = line["instruction"]
            op, cls = ins["op"], ins["object_class"]
            key = json.dumps(ins.get("key"))
            why = (line.get("why") or {}).get("summary")
            if op in ("create", "update") or (op == "delete" and cls != "user"):
                counts["covered_by_records"] += 1
                continue
            try:
                done = await self._do_instruction(ins)
            except (ConsumerError, OpenIAMError) as e:
                counts["failed"] += 1
                self.store.log_action(sha, domain, f"instruction:{cls}", key, op, False,
                                      f"{e}" + (f" | why: {why}" if why else ""))
                continue
            counts[f"instruction_{op}"] += 1
            self.store.log_action(sha, domain, f"instruction:{cls}", key, op, True,
                                  " | ".join(x for x in (done, why) if x))
        return dict(counts)

    async def _remote_user_id(self, key: dict) -> str:
        (attr, value), = key.items()
        field = self.cfg.instruction_user_keys.get(attr)
        if field is None:
            raise ConsumerError(f"no OpenIAM field for instruction key {attr} (instruction_user_keys)")
        page = await self.client.search(self.cfg.user.search_path, {field: str(value)}, 0, 5)
        hits = [b for b in page["beans"] if str(b.get(field)) == str(value)]
        if len(hits) != 1:
            raise ConsumerError(f"{len(hits)} remote users have {field}={value}")
        return str(hits[0]["id"])

    async def _do_instruction(self, ins: dict) -> str:
        op, cls = ins["op"], ins["object_class"]
        if op in ("enable", "disable", "delete"):
            if cls != "user":
                return "skipped: not a user"
            uid = await self._remote_user_id(ins["key"])
            action = op if op != "delete" else ("disable" if self.cfg.user.on_missing == "disable" else None)
            if action is None:
                return "skipped: on_missing is ignore"
            await self.client.user_action(action, uid, reason=ins.get("reason") or f"instruction {op}")
            return f"{action} remote user {uid}"
        if op in ("add_member", "remove_member"):
            uid = await self._remote_user_id((ins.get("member") or {}).get("key") or {})
            name = str(next(iter((ins.get("key") or {}).values()), ""))
            kinds = ["organization"] if cls == "organizationalUnit" else ["group", "role"]
            for kind in kinds:   # an AD group may be an OpenIAM group or role
                object_id = await self._search_named(kind, name)
                if object_id:
                    arg = {"group": "group_ids", "role": "role_ids", "organization": "organization_ids"}[kind]
                    await self.client.entitle(uid, operation="ADD" if op == "add_member" else "DELETE",
                                              **{arg: [object_id]})
                    return f"{op} {kind} {name}"
            raise ConsumerError(f"{'/'.join(kinds)} {name!r} not in the remote OpenIAM")
        return f"skipped: unknown op {op}"

    # ---- applying -----------------------------------------------------------

    async def _apply(self, sha: str, domain: str, entities: dict[str, list[dict]]) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for entity in ENTITY_ORDER:
            if entity not in entities:
                continue
            previous = self.store.records_for(domain, entity)
            seen: set[str] = set()
            for rec in entities[entity]:
                sid = str(rec.get("id") or "")
                if not sid:
                    counts["failed"] += 1
                    self.store.log_action(sha, domain, entity, None, "failed", False, "record has no id")
                    continue
                seen.add(sid)
                h = digest(rec)
                prev = previous.get(sid)
                if prev and prev["hash"] == h:
                    counts["unchanged"] += 1
                    continue
                try:
                    if entity == "user":
                        remote_id, granted, action, detail = await self._apply_user(rec, prev)
                    else:
                        remote_id, action = await self._apply_named(entity, rec)
                        granted, detail = None, None
                except (ConsumerError, OpenIAMError) as e:
                    counts["failed"] += 1
                    self.store.log_action(sha, domain, entity, sid, "failed", False, str(e))
                    continue
                self.store.save_record(domain, entity, sid, h, remote_id, granted)
                self.store.log_action(sha, domain, entity, sid, action, True, detail)
                counts[action] += 1
            for sid in sorted(previous.keys() - seen):
                await self._missing(sha, domain, entity, sid, previous[sid], counts)
        return dict(counts)

    async def _missing(self, sha: str, domain: str, entity: str, sid: str, prev: dict,
                       counts: Counter) -> None:
        still_elsewhere = any(sid in self.store.records_for(d["domain"], entity)
                              for d in self.store.all_domains() if d["domain"] != domain)
        if (entity == "user" and self.cfg.user.on_missing == "disable" and prev["remote_id"]
                and not still_elsewhere):
            try:
                await self.client.user_action("disable", prev["remote_id"],
                                              reason=f"no longer in domain {domain}")
            except OpenIAMError as e:
                counts["failed"] += 1
                self.store.log_action(sha, domain, entity, sid, "failed", False, f"disable: {e}")
                return
            counts["disabled"] += 1
            self.store.log_action(sha, domain, entity, sid, "disabled", True,
                                  f"no longer in domain {domain}")
        else:
            counts["missing"] += 1
            self.store.log_action(sha, domain, entity, sid, "missing", True,
                                  "still in another domain" if still_elsewhere else "left as is")
        self.store.drop_record(domain, entity, sid)

    async def _apply_user(self, rec: dict, prev: dict | None):
        u = self.cfg.user
        key = rec.get(u.match_field)
        if key in (None, ""):
            raise ConsumerError(f"user has no {u.match_field}; cannot match it in the remote OpenIAM")
        key = str(key)
        remote_id = (prev or {}).get("remote_id") or await self._find_user(key)
        mapped = {dst: rec[src] for src, dst in u.fields.items() if rec.get(src) not in (None, "")}
        mapped[u.match_field] = key
        first, last = mapped.pop("firstName", None), mapped.pop("lastName", None)
        if not first or not last:
            raise ConsumerError("user has no first/last name after field mapping")
        email = rec.get(u.email_field) if u.email_field else None
        user = UserIn(id=remote_id, first_name=first, last_name=last, extra=mapped,
                      emails=[EmailIn(email=str(email))] if email else [])
        resp = await self.client.save_user(user.to_openiam(self.settings))
        action = "updated" if remote_id else "created"
        remote_id = remote_id or (resp.get("contextValues") or {}).get("userId")
        if not remote_id:
            raise ConsumerError("remote OpenIAM saved the user but returned no userId")

        granted: dict[str, list[str]] = {}
        notes = []
        previous = (prev or {}).get("granted") or {}
        for kind, path in u.memberships.items():
            desired = set()
            for name in extract(rec, path):
                try:
                    desired.add((await self._resolve(kind, name))[0])
                except ConsumerError as e:
                    notes.append(str(e))
            had = set(previous.get(kind, []))
            if add := desired - had:
                await self.client.entitle(remote_id, operation="ADD", **{ENTITLE_ARG[kind]: sorted(add)})
            if remove := had - desired:
                await self.client.entitle(remote_id, operation="DELETE",
                                          **{ENTITLE_ARG[kind]: sorted(remove)})
            granted[kind] = sorted(desired)
            if add or remove:
                notes.append(f"{kind}: +{len(add)} -{len(remove)}")
        return remote_id, granted or None, action, "; ".join(notes) or None

    async def _find_user(self, key: str) -> str | None:
        u = self.cfg.user
        page = await self.client.search(u.search_path, {u.match_field: key}, 0, 5)
        matches = [b for b in page["beans"] if str(b.get(u.match_field)) == key]
        if len(matches) > 1:
            raise ConsumerError(f"{len(matches)} remote users have {u.match_field}={key}")
        return str(matches[0]["id"]) if matches else None

    async def _apply_named(self, entity: str, rec: dict) -> tuple[str, str]:
        d = self.cfg.directories[entity]
        name = rec.get(d.name_field)
        if not name:
            raise ConsumerError(f"{entity} record has no {d.name_field}")
        object_id, created = await self._resolve(entity, str(name))
        return object_id, "created" if created else "exists"

    async def _resolve(self, entity: str, name: str) -> tuple[str, bool]:
        """Remote id for a name, creating the object if configured. (id, created)."""
        if (entity, name) in self._names:
            return self._names[(entity, name)], False
        object_id = await self._search_named(entity, name)
        created = object_id is None
        if created:
            d = self.cfg.directories[entity]
            if not d.create_path:
                raise ConsumerError(f"{entity} {name!r} is not in the remote OpenIAM "
                                    f"(set directories.{entity}.create_path to create it)")
            body = json.loads(json.dumps(d.create_body).replace("{name}", json.dumps(name)[1:-1]))
            await self.client.call_ajax(d.create_path, body)
            object_id = await self._search_named(entity, name)
            if object_id is None:
                raise ConsumerError(f"created {entity} {name!r} but cannot find it afterwards")
        self._names[(entity, name)] = object_id
        return object_id, created

    async def _search_named(self, entity: str, name: str) -> str | None:
        d = self.cfg.directories[entity]
        page = await self.client.search(d.search_path, {d.name_field: name}, 0, 50)
        matches = [b for b in page["beans"] if b.get(d.name_field) == name]
        if len(matches) > 1:
            raise ConsumerError(f"{len(matches)} remote {entity}s are named {name!r}")
        return str(matches[0][d.id_field]) if matches else None
