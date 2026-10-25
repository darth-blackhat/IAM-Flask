"""Prometheus metrics, read from the database at scrape time.

Every instance reports the same numbers (they come from the shared database), so scrape
one instance per site or deduplicate with `max by` in queries. No personal data: only
counts, states, ages and domain names.
"""

import time

from prometheus_client import CollectorRegistry, generate_latest, start_http_server
from prometheus_client.core import GaugeMetricFamily
from sqlalchemy import func, select

from .db import Database

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


class DbCollector:
    def __init__(self, db: Database, role: str):
        self.db, self.role = db, role

    def collect(self):
        t, now = self.db.tables, time.time()
        up = GaugeMetricFamily("backend_iam_up", "1 if the database answered", labels=["role"])
        try:
            with self.db.engine.connect() as conn:
                yield from self._collect(conn, t, now)
            up.add_metric([self.role], 1)
        except Exception:
            up.add_metric([self.role], 0)
        yield up

    def _collect(self, conn, t, now):
        o = t.sync_outbox.c
        outbox = GaugeMetricFamily("backend_iam_outbox_events", "Outbox events by state", labels=["state"])
        pending = (o.delivered_at.is_(None)) & (o.dead.is_(False))
        for state, cond in (("pending", pending), ("delivered", o.delivered_at.is_not(None)),
                            ("dead", o.dead.is_(True))):
            outbox.add_metric([state], conn.execute(select(func.count()).where(cond)).scalar() or 0)
        yield outbox
        oldest = conn.execute(select(func.min(o.created_at)).where(pending)).scalar()
        yield GaugeMetricFamily("backend_iam_outbox_oldest_pending_seconds",
                                "Age of the oldest undelivered event", value=now - oldest if oldest else 0)

        r = t.sync_runs.c
        last = conn.execute(select(t.sync_runs).order_by(r.id.desc()).limit(1)).first()
        last_ok = conn.execute(select(func.max(r.finished_at)).where(r.status.in_(["ok", "baseline"]))).scalar()
        yield GaugeMetricFamily("backend_iam_sync_last_success_timestamp_seconds",
                                "End of the last successful change-detection run", value=last_ok or 0)
        g = GaugeMetricFamily("backend_iam_sync_last_run_failed", "1 if the latest run failed")
        g.add_metric([], 1 if last is not None and last.status == "failed" else 0)
        yield g
        if last is not None and last.finished_at:
            yield GaugeMetricFamily("backend_iam_sync_last_run_duration_seconds",
                                    "Duration of the latest run", value=last.finished_at - last.started_at)
        blocked = GaugeMetricFamily("backend_iam_sync_mass_delete_blocked",
                                    "1 if the latest run was refused as a mass delete")
        blocked.add_metric([], 1 if last is not None and "MassDeleteError" in (last.error or "") else 0)
        yield blocked

        a = t.producer_activity.c
        prod = GaugeMetricFamily("backend_iam_producer_events_24h", "Producer events in the last 24 h",
                                 labels=["type", "result"])
        for etype, ok, n in conn.execute(select(a.event_type, a.ok, func.count())
                                         .where(a.at >= now - 86400).group_by(a.event_type, a.ok)):
            prod.add_metric([etype, "ok" if ok else "failed"], n)
        yield prod

        f = t.consumer_files.c
        files = GaugeMetricFamily("backend_iam_consumer_files_24h", "Zips received in the last 24 h",
                                  labels=["status"])
        for status, n in conn.execute(select(f.status, func.count()).where(f.received_at >= now - 86400)
                                      .group_by(f.status)):
            files.add_metric([status], n)
        yield files

        d = t.consumer_domains.c
        age = GaugeMetricFamily("backend_iam_consumer_domain_applied_age_seconds",
                                "Seconds since each domain's data was last applied", labels=["domain"])
        for domain, updated in conn.execute(select(d.domain, d.updated_at)):
            age.add_metric([domain], now - updated)
        yield age

        p = t.ad_plans.c
        plans = GaugeMetricFamily("backend_iam_ad_plans", "AD plans by status", labels=["status"])
        for status, n in conn.execute(select(p.status, func.count()).group_by(p.status)):
            plans.add_metric([status], n)
        yield plans

        q = t.operator_requests.c
        reqs = GaugeMetricFamily("backend_iam_operator_requests", "Operator requests by status",
                                 labels=["status"])
        for status, n in conn.execute(select(q.status, func.count()).group_by(q.status)):
            reqs.add_metric([status], n)
        yield reqs

        dr = t.drift_reports.c
        latest = (select(dr.domain, func.max(dr.id).label("id")).group_by(dr.domain)).subquery()
        drift = GaugeMetricFamily("backend_iam_drift_differences",
                                  "Differences in each domain's latest drift report", labels=["domain"])
        for domain, summary in conn.execute(select(dr.domain, dr.summary).join(latest, dr.id == latest.c.id)):
            drift.add_metric([domain], (summary or {}).get("differences", 0))
        yield drift

        al = t.ad_change_alerts.c
        ad_alerts = GaugeMetricFamily("backend_iam_ad_unacknowledged_alerts",
                                      "AD changes made outside the consumer, not yet acknowledged",
                                      labels=["severity"])
        for sev in ("info", "warning", "critical"):
            ad_alerts.add_metric([sev], conn.execute(select(func.count()).where(
                al.severity == sev, al.acknowledged_at.is_(None))).scalar() or 0)
        yield ad_alerts

        u = t.web_users.c
        yield GaugeMetricFamily("backend_iam_web_users_locked", "Web users currently locked out",
                                value=conn.execute(select(func.count()).where(u.locked_until > now)).scalar() or 0)
        au = t.audit_trail.c
        yield GaugeMetricFamily("backend_iam_auth_failures_1h", "Refused logins / API calls in the last hour",
                                value=conn.execute(select(func.count()).where(au.at >= now - 3600,
                                                                              au.ok.is_(False))).scalar() or 0)


def registry_for(db: Database, role: str) -> CollectorRegistry:
    reg = CollectorRegistry(auto_describe=True)
    reg.register(DbCollector(db, role))
    return reg


def render(registry: CollectorRegistry) -> bytes:
    return generate_latest(registry)


def serve(db: Database, role: str, host: str, port: int) -> None:
    """Background metrics listener for services without an HTTP API (consumer)."""
    start_http_server(port, addr=host, registry=registry_for(db, role))
