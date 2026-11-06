"""Read-only analysis of what this site knows: role mining, peer outliers, orphan and
dormant accounts, the organization tree, and dashboard statistics. Nothing here changes
anything; suggestions become changes only through normal (approved) requests."""

import time
from collections import Counter, defaultdict
from itertools import combinations
from typing import Any

from sqlalchemy import func, select

from .db import Database
from .governance import Governance

LAST_LOGIN_FIELDS = ("lastLogin", "lastLoginDate", "lastDate", "lastLoginTime")
PARENT_FIELDS = ("parentId", "parentOrganizationId", "parentOrgId", "parent")


def _ts(value: Any) -> float | None:
    """Epoch seconds from OpenIAM's epoch-ms numbers or ISO strings."""
    if isinstance(value, (int, float)) and value > 0:
        return value / 1000 if value > 1e11 else float(value)
    if isinstance(value, str) and value:
        from datetime import datetime
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


class Insights:
    def __init__(self, db: Database):
        self.db, self.t, self.gov = db, db.tables, Governance(db)

    def _snapshot(self, kind: str) -> list[dict[str, Any]]:
        s = self.t.sync_entity_state.c
        with self.db.begin() as conn:
            return [r.data or {} for r in conn.execute(select(s.data).where(s.entity_type == kind))]

    # ---- role mining ---------------------------------------------------------

    def role_candidates(self, min_users: int = 3, max_size: int = 4, limit: int = 25) -> list[dict[str, Any]]:
        """Group / role combinations held together by at least `min_users` people: candidate
        business roles (bundle them, then grant the role instead of each group)."""
        holdings: dict[str, set[str]] = defaultdict(set)
        for (eid, kind, name) in self.gov.entitlements():
            if kind in ("group", "role"):
                holdings[eid].add(f"{kind}:{name}")
        counts: Counter = Counter()
        for items in holdings.values():
            ordered = sorted(items)[:30]                 # bound the combinatorics per person
            for size in range(2, min(max_size, len(ordered)) + 1):
                counts.update(combinations(ordered, size))
        frequent = [(combo, n) for combo, n in counts.items() if n >= min_users]
        # Keep the largest combinations: drop one that a bigger combo with the same count covers.
        frequent.sort(key=lambda x: (-len(x[0]), -x[1]))
        kept: list[tuple[tuple[str, ...], int]] = []
        for combo, n in frequent:
            if not any(set(combo) < set(k) and n == kn for k, kn in kept):
                kept.append((combo, n))
        kept.sort(key=lambda x: (-x[1] * len(x[0]), x[0]))
        return [{"entitlements": list(c), "users": n, "size": len(c)} for c, n in kept[:limit]]

    def peer_outliers(self, peer_field: str = "title", min_peers: int = 4,
                      max_share: float = 0.2) -> list[dict[str, Any]]:
        """Access few of a person's peers (same title, or domain) have: worth reviewing."""
        peers: dict[str, list[str]] = defaultdict(list)
        for u in self._snapshot("user"):
            eid, key = u.get("employeeId"), u.get(peer_field)
            if eid and isinstance(key, str) and key:
                peers[key].append(str(eid))
        held: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for (eid, kind, name) in self.gov.entitlements():
            held[eid].add((kind, name))
        out = []
        for key, members in peers.items():
            if len(members) < min_peers:
                continue
            counts = Counter(e for m in members for e in held.get(m, ()))
            for m in members:
                for ent in held.get(m, ()):
                    share = counts[ent] / len(members)
                    if share <= max_share:
                        out.append({"employee_id": m, "peer_group": key, "kind": ent[0], "name": ent[1],
                                    "peers_with_it": counts[ent], "peers": len(members)})
        return sorted(out, key=lambda r: (r["peers_with_it"], r["employee_id"]))

    # ---- account hygiene -----------------------------------------------------

    def orphans(self) -> list[dict[str, Any]]:
        """OpenIAM users with no source-of-truth (HR) record here: no employee id, or one the
        producer has never sent. Only meaningful once HR events flow through the producer."""
        p = self.t.producer_people.c
        with self.db.begin() as conn:
            known = {r.employee_id for r in conn.execute(select(p.employee_id))}
        out = []
        for u in self._snapshot("user"):
            eid = str(u.get("employeeId") or "")
            if not eid or eid not in known:
                out.append({"employee_id": eid or None, "openiam_id": u.get("id"), "login": u.get("login"),
                            "name": f"{u.get('firstName') or ''} {u.get('lastName') or ''}".strip(),
                            "status": u.get("userStatus") or u.get("status"),
                            "reason": "no employee id" if not eid else "no HR record"})
        return out

    def dormant(self, days: int = 90, now: float | None = None) -> list[dict[str, Any]]:
        """Users whose last sign-in (as OpenIAM reports it) is older than `days`, or unknown."""
        cutoff = (now or time.time()) - days * 86400
        out = []
        for u in self._snapshot("user"):
            last = next((t for f in LAST_LOGIN_FIELDS if (t := _ts(u.get(f)))), None)
            if last is None or last < cutoff:
                out.append({"employee_id": u.get("employeeId"), "login": u.get("login"),
                            "name": f"{u.get('firstName') or ''} {u.get('lastName') or ''}".strip(),
                            "last_login": time.strftime("%Y-%m-%d", time.gmtime(last)) if last else None,
                            "days": int(((now or time.time()) - last) // 86400) if last else None,
                            "status": u.get("userStatus") or u.get("status")})
        return sorted(out, key=lambda r: (r["days"] is not None, -(r["days"] or 0)))

    # ---- organization tree ----------------------------------------------------

    def org_tree(self) -> list[dict[str, Any]]:
        """Organizations nested by their parent (when OpenIAM reports one)."""
        orgs = self._snapshot("organization")
        by_id = {str(o.get("id")): {**o, "children": []} for o in orgs if o.get("id") is not None}
        roots = []
        for o in by_id.values():
            parent = next((o.get(f) for f in PARENT_FIELDS if o.get(f)), None)
            if isinstance(parent, dict):
                parent = parent.get("id")
            if parent is not None and str(parent) in by_id and str(parent) != str(o.get("id")):
                by_id[str(parent)]["children"].append(o)
            else:
                roots.append(o)

        def sort(nodes):
            nodes.sort(key=lambda n: str(n.get("name") or ""))
            for n in nodes:
                sort(n["children"])
            return nodes
        return sort(roots)

    # ---- dashboard -----------------------------------------------------------

    def weekly_jml(self, weeks: int = 12, now: float | None = None) -> dict[str, Any]:
        """Joiners (hire), movers (update), leavers (terminate) per week from producer activity."""
        now = now or time.time()
        week = 7 * 86400
        start = now - weeks * week
        a = self.t.producer_activity.c
        series = {"joiners": [0] * weeks, "movers": [0] * weeks, "leavers": [0] * weeks}
        kind = {"hire": "joiners", "update": "movers", "terminate": "leavers"}
        with self.db.begin() as conn:
            rows = conn.execute(select(a.at, a.event_type).where(a.at >= start, a.ok.is_(True),
                                                                 a.duplicate.is_(False)))
            for at, event in rows:
                if event in kind:
                    i = min(weeks - 1, int((at - start) // week))
                    series[kind[event]][i] += 1
        labels = [time.strftime("%d %b", time.gmtime(start + i * week)) for i in range(weeks)]
        return {"labels": labels, "series": series}

    def approval_stats(self) -> dict[str, Any]:
        r = self.t.operator_requests.c
        with self.db.begin() as conn:
            waiting = conn.execute(select(func.count()).where(r.status == "awaiting_approval")).scalar()
            rows = conn.execute(select(r.at, r.decided_at).where(r.action.like("directory%"),
                                                                 r.decided_at.is_not(None),
                                                                 r.requested_by.not_like("system:%"))
                                .order_by(r.id.desc()).limit(200)).all()
        hours = sorted((d - a) / 3600 for a, d in rows if d and a and d >= a)
        median = hours[len(hours) // 2] if hours else None
        return {"waiting": waiting, "median_hours": median, "decided": len(hours)}
