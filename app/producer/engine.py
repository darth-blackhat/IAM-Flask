"""Apply producer events (hire, terminate, leave, compliance/training status, ...) to OpenIAM.

Each event updates the producer's desired state for the person, then reconciles OpenIAM with it:
  1. the user record          (saveUser, matched by employee id)
  2. employment / account     (terminate, leave, enable/disable from status holds)
  3. groups, roles, orgs      (only the ones this backend granted are ever removed)
Every step is safe to repeat, so a failed event can simply be sent again.
"""

import uuid
from datetime import date, datetime, time, timezone
from typing import Any

from ..ad import AdMapping, instruction
from ..config import Settings
from ..db import LockTimeout
from ..logs import logger
from ..openiam import OpenIAMClient, OpenIAMError
from ..schemas import UserIn
from .config import KINDS, ProducerConfig, Kind
from .schemas import ProducerEvent, ProducerResult
from .store import Person, ProducerStore

ENTITLE_ARG = {"group": "group_ids", "role": "role_ids", "organization": "organization_ids"}
LOCK_TIMEOUT = 60.0
EVENT_FIELD = {"group": "groups", "role": "roles", "organization": "organizations"}


class ProducerError(Exception):
    pass


class ProducerProcessor:
    def __init__(self, client: OpenIAMClient, store: ProducerStore, cfg: ProducerConfig,
                 settings: Settings, *, ad: AdMapping | None = None, outbox: Any = None):
        """`outbox` is the sync Store: AD instructions go out with the other change events."""
        self.client, self.store, self.cfg, self.settings = client, store, cfg, settings
        self.ad = ad or AdMapping()
        self.outbox = outbox

    async def process_many(self, events: list[ProducerEvent]) -> list[ProducerResult]:
        """In order. After a failure, later events for the same person are skipped."""
        failed: set[str] = set()
        results = []
        for ev in events:
            if ev.employee_id in failed:
                skipped = ProducerResult(employee_id=ev.employee_id, type=ev.type,
                                         event_id=ev.event_id, ok=False,
                                         error="skipped: an earlier event for this employee failed")
                self._finish(ev, skipped)
                results.append(skipped)
                continue
            result = await self.process(ev)
            if not result.ok:
                failed.add(ev.employee_id)
            results.append(result)
        return results

    async def process(self, ev: ProducerEvent) -> ProducerResult:
        result = ProducerResult(employee_id=ev.employee_id, type=ev.type, event_id=ev.event_id)
        try:
            # One event at a time across every backend instance, so a person's events
            # never interleave and a resent event_id is never applied twice.
            async with self.store.db.lock("producer", timeout=LOCK_TIMEOUT):
                if ev.event_id and (prev := self.store.processed(ev.event_id)):
                    # Answer from the record; its instructions were already sent.
                    result = ProducerResult.model_validate({**prev, "duplicate": True,
                                                            "instructions": []})
                else:
                    try:
                        await self._apply(ev, result)
                    except (ProducerError, OpenIAMError) as e:
                        result.ok = False
                        result.error = str(e)
                    # Even a failed event may have applied some steps: send those.
                    self._emit(ev, result)
                    if result.ok and ev.event_id:
                        self.store.mark_processed(ev.event_id, result.model_dump())
        except LockTimeout as e:
            result.ok = False
            result.error = f"busy, retry later: {e}"
        self._finish(ev, result)
        return result

    def _emit(self, ev: ProducerEvent, r: ProducerResult) -> None:
        """Queue the AD instructions for what was applied, in the sync outbox."""
        if not r.instructions or self.outbox is None:
            return
        event = {"event_id": str(uuid.uuid4()), "type": f"producer.{ev.type}", "entity": "user",
                 "entity_id": r.user_id, "action": ev.type, "employee_id": ev.employee_id,
                 "producer_event_id": ev.event_id,
                 "detected_at": datetime.now(timezone.utc).isoformat(),
                 # What the source of truth sent for this person (when the event had data).
                 "data": self._flat, "previous": None, "changes": None,
                 "why": self._why(f"HR {ev.type} for {ev.employee_id}"
                                  + (f": {ev.reason}" if ev.reason else "")),
                 "instructions": r.instructions}
        try:
            with self.outbox.connect() as conn:
                self.outbox.add_events(conn, [event])
        except Exception as e:  # OpenIAM is already changed; make the gap loud.
            logger.bind(employee_id=ev.employee_id).error(
                "OpenIAM updated but AD instructions could not be queued: {}", e)
            r.warnings.append(f"AD instructions not queued: {e}")

    def _finish(self, ev: ProducerEvent, result: ProducerResult) -> None:
        try:
            self.store.record_activity(result.model_dump(mode="json"))
        except Exception as e:
            logger.error("could not record producer activity: {}", e)
        log = logger.bind(employee_id=ev.employee_id, event_type=ev.type, event_id=ev.event_id,
                          user_id=result.user_id)
        if result.ok:
            log.info("producer {} for {}: {}", ev.type, ev.employee_id,
                     "; ".join(result.actions) or "no change")
            for w in result.warnings:
                log.warning("producer {} for {}: {}", ev.type, ev.employee_id, w)
        else:
            log.warning("producer {} for {} failed: {}", ev.type, ev.employee_id, result.error)

    def _user_key(self, employee_id: str) -> dict[str, Any]:
        return {self.ad.keys.get("user", "employeeID"): employee_id}

    def _why(self, summary: str) -> dict[str, Any]:
        """Why an instruction exists: the source-of-truth event behind it."""
        why = {**self._ctx, "summary": summary}
        return {k: v for k, v in why.items() if v not in (None, {}, [])}

    def _instruct(self, r: ProducerResult, op: str, *, summary: str, **fields: Any) -> None:
        if self.ad.classes.get("user"):
            r.instructions.append(instruction(op, self.ad.classes["user"],
                                              self._user_key(r.employee_id), r.user_id,
                                              source="producer", why=self._why(summary), **fields))

    # ---- steps --------------------------------------------------------------

    async def _apply(self, ev: ProducerEvent, r: ProducerResult) -> None:
        # Events are applied one at a time (lock), so per-event context can live here.
        self._flat: dict[str, Any] | None = None
        self._ctx = {"source": "source-of-truth", "event": ev.type, "event_id": ev.event_id,
                     "employee_id": ev.employee_id, "reason": ev.reason,
                     "effective_date": ev.effective_date.isoformat() if ev.effective_date else None,
                     "statuses": dict(ev.statuses) or None}
        person = self.store.get_person(ev.employee_id)
        if person and person.employment == "terminated" and ev.type in ("hire", "update", "return"):
            raise ProducerError("employee is terminated in OpenIAM; a rehire must be handled manually")

        if ev.type in ("hire", "update"):
            person = await self._upsert_user(ev, person, r)
        elif person is None:
            user_id = await self._find_user(ev.employee_id)
            if user_id is None:
                raise ProducerError(f"employee {ev.employee_id} is not in OpenIAM; send a hire first")
            person = Person(ev.employee_id, user_id)
        r.user_id = person.user_id

        # Record the producer's desired state before touching OpenIAM, so a retry knows the goal.
        for kind in KINDS:
            names = getattr(ev, EVENT_FIELD[kind])
            if names is not None:
                person.assignments[kind] = sorted(set(names))
        for status, value in ev.statuses.items():
            if self.cfg.rule(status, value) is None:
                r.warnings.append(f"no rule for {status}={value}; recorded only")
            person.statuses[status] = value
        target = {"terminate": "terminated", "leave": "leave", "return": "active"}.get(ev.type)
        if target:
            person.employment_target = target
        self.store.save_person(person)

        try:
            await self._reconcile_access(person, ev, r)
            await self._reconcile_memberships(person, r)
        finally:
            self.store.save_person(person)

    async def _upsert_user(self, ev: ProducerEvent, person: Person | None, r: ProducerResult) -> Person:
        user_id = person.user_id if person else await self._find_user(ev.employee_id)
        if ev.person is None:
            if user_id is None:
                raise ProducerError(f"employee {ev.employee_id} is not in OpenIAM and the event has no person data")
        else:
            p = ev.person
            user = UserIn(id=user_id, first_name=p.first_name, last_name=p.last_name,
                          emails=p.emails, phones=p.phones, metadata_type_id=p.metadata_type_id,
                          extra={**p.extra, self.cfg.employee_id_field: ev.employee_id})
            payload = user.to_openiam(self.settings)
            resp = await self.client.save_user(payload)
            r.actions.append("user updated" if user_id else "user created")
            created = user_id is None
            user_id = user_id or (resp.get("contextValues") or {}).get("userId")
            if not user_id:
                raise ProducerError("OpenIAM saved the user but returned no userId")
            r.user_id = user_id
            flat = {**payload, "employeeId": ev.employee_id,
                    "email": p.emails[0].email if p.emails else None,
                    "phone": p.phones[0].number if p.phones else None}
            self._flat = {k: v for k, v in flat.items() if v is not None}
            # Search results show emails/phones flat; count those fields as written too.
            r.fields_set = sorted(set(self._flat) | ({"email"} if p.emails else set())
                                  | ({"phone"} if p.phones else set()))
            self._instruct(r, "create" if created else "update",
                           summary=(f"HR {ev.type}: new person in the source of truth" if created
                                    else f"HR {ev.type}: person data from the source of truth"),
                           attributes=self.ad.map("user", flat))
        if person is None:
            person = Person(ev.employee_id, user_id)
            # Saved now so a later failure can never lead to a second create.
            self.store.save_person(person)
        return person

    async def _find_user(self, employee_id: str) -> str | None:
        field = self.cfg.employee_id_field
        page = await self.client.search(self.cfg.user_search_path, {field: employee_id}, 0, 5)
        # Only trust records that really carry this employee id, in case the search
        # ignores the criterion and returns arbitrary users.
        matches = [b for b in page["beans"] if str(b.get(field)) == employee_id]
        if len(matches) > 1:
            raise ProducerError(f"{len(matches)} OpenIAM users have {field}={employee_id}; fix the duplicates")
        return str(matches[0]["id"]) if matches else None

    async def _reconcile_access(self, p: Person, ev: ProducerEvent, r: ProducerResult) -> None:
        acts = self.cfg.lifecycle_actions
        reason = ev.reason or f"producer {ev.type}"
        if p.employment_target == "terminated":
            if p.employment != "terminated":
                when = _perform_date(ev.effective_date)
                await self.client.user_action(acts.terminate, p.user_id, reason=reason, perform_date=when)
                p.employment, p.enabled = "terminated", False
                r.state_changed = True
                r.actions.append(f"terminated{' on ' + when if when else ''}")
                self._instruct(r, "disable", reason=reason, lifecycle="terminated",
                               effective_date=when,
                               summary="HR terminate" + (f": {ev.reason}" if ev.reason else ""))
            return
        if p.employment_target == "leave":
            if p.employment != "leave":
                await self.client.user_action(acts.leave, p.user_id, reason=reason,
                                              perform_date=_perform_date(ev.effective_date))
                p.employment, p.enabled = "leave", False
                r.state_changed = True
                r.actions.append("leave of absence")
                self._instruct(r, "disable", reason=reason, lifecycle="leave",
                               effective_date=_perform_date(ev.effective_date),
                               summary="HR leave of absence" + (f": {ev.reason}" if ev.reason else ""))
            return

        holds = sorted(s for s, v in p.statuses.items() if (rule := self.cfg.rule(s, v)) and rule.hold)
        want_enabled = not holds
        hold_reason = f"holds: {', '.join(holds)}" if holds else reason
        hold_text = ", ".join(f"{s}={p.statuses[s]}" for s in holds)
        if p.employment == "leave":
            action = acts.return_ if want_enabled else "disable"
            await self.client.user_action(action, p.user_id, reason=hold_reason)
            p.employment, p.enabled = "active", want_enabled
            r.state_changed = True
            r.actions.append("returned from leave" + ("" if want_enabled else f" ({hold_reason})"))
            self._instruct(r, "enable" if want_enabled else "disable", reason=hold_reason,
                           lifecycle="returned",
                           summary="HR return from leave" + (f"; still on hold: {hold_text}" if holds else ""))
        elif want_enabled != p.enabled:
            await self.client.user_action("enable" if want_enabled else "disable", p.user_id,
                                          reason=hold_reason)
            p.enabled = want_enabled
            r.state_changed = True
            r.actions.append("enabled" if want_enabled else f"disabled ({hold_reason})")
            self._instruct(r, "enable" if want_enabled else "disable", reason=hold_reason,
                           holds=holds,
                           summary=(f"hold active: {hold_text}" if holds
                                    else "all holds cleared: " + ", ".join(
                                        f"{s}={v}" for s, v in sorted(p.statuses.items()))))

    def _desired_names(self, p: Person) -> dict[Kind, dict[str, str]]:
        """kind -> {name: why the person should have it}."""
        desired: dict[Kind, dict[str, str]] = {k: {} for k in KINDS}
        if p.employment_target == "terminated" and self.cfg.terminate_removes_access:
            return desired
        for kind in KINDS:
            for name in p.assignments.get(kind, []):
                desired[kind].setdefault(name, f"in the HR {kind} list")
        for status, value in sorted(p.statuses.items()):
            if rule := self.cfg.rule(status, value):
                for kind, names in rule.by_kind().items():
                    for name in names:
                        desired[kind].setdefault(name, f"status rule {status}={value}")
        return desired

    async def _reconcile_memberships(self, p: Person, r: ProducerResult) -> None:
        terminated = p.employment_target == "terminated"
        for kind, origins in self._desired_names(p).items():
            # Resolve every name before changing anything, so an unknown name never
            # leaves this kind half-applied.
            desired = {await self._resolve(kind, n, r): n for n in sorted(origins)}
            current = self.store.memberships(p.employee_id, kind)
            add, remove = set(desired) - current, current - set(desired)
            if add:
                await self.client.entitle(p.user_id, operation="ADD", **{ENTITLE_ARG[kind]: sorted(add)})
                self.store.add_memberships(p.employee_id, kind, add)
                r.actions.append(f"added to {kind} " + ", ".join(sorted(desired[i] for i in add)))
                # AD knows the group by its OpenIAM/AD name, not the producer's alias.
                aliases = self.cfg.directories[kind].aliases
                self._instruct_members(r, "add_member", kind,
                                       {i: aliases.get(desired[i], desired[i]) for i in sorted(add)},
                                       {i: f"source of truth: {origins[desired[i]]}" for i in add})
            if remove:
                # Names before the membership rows go: the receiver knows groups by name.
                names = {i: self.store.name_for(kind, i) for i in sorted(remove)}
                await self.client.entitle(p.user_id, operation="DELETE",
                                          **{ENTITLE_ARG[kind]: sorted(remove)})
                why = ("HR terminate: access granted by the source of truth removed" if terminated
                       else "no longer in the HR list or any active status rule")
                self._instruct_members(r, "remove_member", kind, names, {i: why for i in remove})
                self.store.remove_memberships(p.employee_id, kind, remove)
                r.actions.append(f"removed from {len(remove)} {kind}(s)")

    def _instruct_members(self, r: ProducerResult, op: str, kind: Kind,
                          names: dict[str, str | None], summaries: dict[str, str]) -> None:
        cls = self.ad.classes.get(kind)
        if not cls:
            return
        key_attr = self.ad.keys.get(kind, "cn")
        member = {"object_class": self.ad.classes.get("user") or "user",
                  "key": self._user_key(r.employee_id), "openiam_id": r.user_id}
        for object_id, name in names.items():
            key = {key_attr: name} if name else {"openiamId": object_id}
            r.instructions.append(instruction(op, cls, key, object_id, source="producer",
                                              member=member, why=self._why(summaries[object_id])))

    async def _resolve(self, kind: Kind, source_name: str, r: ProducerResult) -> str:
        """Producer name -> OpenIAM id, via aliases, then search (filtered by `require`)."""
        d = self.cfg.directories[kind]
        name = d.aliases.get(source_name, source_name)
        if object_id := self.store.lookup(kind, name):
            return object_id
        object_id = await self._search(kind, name)
        if object_id is None:
            if not d.create_path:
                raise ProducerError(f"{kind} {name!r} not found in OpenIAM"
                              + (f" with {d.require}" if d.require else "")
                              + f" (producer name {source_name!r}; add an alias, or set "
                              f"directories.{kind}.create_path to create it)")
            await self.client.call_ajax(d.create_path, _render(d.create_body, name))
            r.actions.append(f"created {kind} {name}")
            object_id = await self._search(kind, name)
            if object_id is None:
                raise ProducerError(f"created {kind} {name!r} but cannot find it afterwards")
        self.store.remember(kind, name, object_id)
        return object_id

    async def _search(self, kind: Kind, name: str) -> str | None:
        d = self.cfg.directories[kind]
        page = await self.client.search(d.search_path, {**d.search_extra, d.name_field: name}, 0, 50)
        matches = [b for b in page["beans"]
                   if b.get(d.name_field) == name
                   and all(b.get(k) == v for k, v in d.require.items())]
        if len(matches) > 1:
            raise ProducerError(f"{len(matches)} OpenIAM {kind}s match {name!r}; "
                          f"narrow it with directories.{kind}.require")
        return str(matches[0][d.id_field]) if matches else None


def _perform_date(value: date | datetime | None) -> str | None:
    """OpenIAM's UTC performDataString for a future date; None means do it now."""
    if value is None:
        return None
    if not isinstance(value, datetime):
        value = datetime.combine(value, time.min, tzinfo=timezone.utc)
    elif value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    if value <= datetime.now(timezone.utc):
        return None
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def _render(template: Any, name: str) -> Any:
    if isinstance(template, str):
        return template.replace("{name}", name)
    if isinstance(template, dict):
        return {k: _render(v, name) for k, v in template.items()}
    if isinstance(template, list):
        return [_render(v, name) for v in template]
    return template
