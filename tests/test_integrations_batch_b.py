"""Jira check + comments, notifications (email / webhooks) and their guards."""

import asyncio
import hashlib
import hmac
import json
import time

import httpx
import pytest

from app.config import Settings
from app.directory import DirectoryError
from app.governance import Governance
from app.jira import Jira, JiraError
from app.notify import (EmailChannel, Notifications, Notifier, NotifyConfig, UnsafeTarget, Webhook,
                        check_target, render_template, wants)
from app.operator import OperatorRequests

from .test_directory import J, queued
from .test_web import add_user, csrf, login


def run(coro):
    return asyncio.run(coro)


# ---- Jira ----------------------------------------------------------------------------

def jira_transport(statuses: dict[str, str], comments: list):
    def handle(request: httpx.Request) -> httpx.Response:
        key = request.url.path.split("/")[5]
        assert request.headers["Authorization"].startswith("Basic ")
        if request.method == "POST":
            comments.append((key, json.loads(request.content)["body"]))
            return httpx.Response(201, json={})
        if key not in statuses:
            return httpx.Response(404)
        return httpx.Response(200, json={"fields": {"status": {"name": statuses[key]}, "summary": "s"}})
    return httpx.MockTransport(handle)


def jira(mode: str, comments: list, **kw) -> Jira:
    s = Settings(_env_file=None, jira_base_url="https://acme.atlassian.net", jira_check=mode,
                 jira_allowed_statuses="Approved, In Progress", jira_user="svc@acme.example",
                 jira_api_token="tok", jira_comment=True, **kw)
    return Jira(s, transport=jira_transport({"IAM-1": "Approved", "IAM-2": "Open"}, comments))


def test_jira_enforce_warn_and_comment():
    comments: list = []
    j = jira("enforce", comments)
    assert run(j.check("IAM-1"))["status"] == "Approved"
    with pytest.raises(JiraError, match="'Open'"):
        run(j.check("IAM-2"))
    with pytest.raises(JiraError, match="does not exist"):
        run(j.check("IAM-3"))
    w = jira("warn", comments)
    assert run(w.check("IAM-2"))["ok"] is False
    run(w.comment("IAM-1", "done"))
    assert comments == [("IAM-1", "done")]
    with pytest.raises(ValueError):
        Jira(Settings(_env_file=None, jira_check="enforce", jira_base_url="http://plain.example", jira_api_token="t"))


def test_directory_change_refused_when_ticket_not_approved(service, sync):
    comments: list = []
    service.jira = jira("enforce", comments)
    with pytest.raises(DirectoryError, match="Jira"):
        run(service.handle({**J, "jira_ticket": "IAM-2", "via": "ad", "kind": "group", "op": "create", "name": "G"}))
    assert queued(sync) == []                                       # nothing changed
    run(service.handle({**J, "jira_ticket": "IAM-1", "via": "ad", "kind": "group", "op": "create", "name": "G"}))
    assert len(queued(sync)) == 1
    assert [k for k, _ in comments] == ["IAM-2", "IAM-1"]           # both outcomes commented
    assert "FAILED" in comments[0][1] and "Done" in comments[1][1]
    events = [n["event"] for n in Notifications(service.notes.db).recent()]
    assert events == ["request.done", "request.failed"]


# ---- notifications ---------------------------------------------------------------------

def test_templates_and_event_filters():
    out = render_template({"msg": "${title}: ${text}", "n": "${data}"},
                          {"title": 'He said "hi"', "text": "x", "data": {"a": 1}})
    assert out == {"msg": 'He said "hi": x', "n": '{"a": 1}'}
    assert render_template("teams", {"title": "T", "text": "x"}) == {"text": "**T**\n\nx"}
    assert render_template({"x": "${__import__('os')}"}, {}) == {"x": "${__import__('os')}"}   # no code runs
    assert wants(["request.*"], "request.done") and not wants(["sod.blocked"], "request.done")


def test_webhook_targets_are_guarded():
    for bad in ("http://8.8.8.8/x", "https://127.0.0.1/x", "https://10.1.2.3/x", "https://[::1]/x",
                "https://169.254.169.254/latest/meta-data", "https://user:pw@8.8.8.8/", "ftp://8.8.8.8/"):
        with pytest.raises(UnsafeTarget):
            check_target(bad)
    check_target("https://8.8.8.8/hook")
    check_target("https://10.1.2.3/x", allow_private=True)


def test_notifier_signs_webhooks_and_sends_email(database):
    got = []

    def handle(request: httpx.Request) -> httpx.Response:
        got.append(request)
        return httpx.Response(200)
    sent_mail = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            self.host = host
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def starttls(self, context):
            sent_mail.append("starttls")
        def login(self, user, pw):
            sent_mail.append(("login", user, pw))
        def send_message(self, msg):
            sent_mail.append(msg["Subject"])

    cfg = NotifyConfig(
        webhooks=[Webhook(name="itsm", url="https://10.0.0.5/hook", allow_private=True, secret_env="S",
                          events=["request.*"], template={"t": "${title}", "ticket": "${jira_ticket}"}),
                  Webhook(name="other", url="https://10.0.0.6/x", allow_private=True, events=["sod.blocked"])],
        email=EmailChannel(host="smtp.test", username="u", password_env="P", **{"from": "a@x"}, to=["b@x"]))
    notes = Notifications(database)
    notes.add("request.done", "Applied: create group G", "text", {"jira_ticket": "IAM-1"})
    n = Notifier(database, cfg, env={"S": "hook-secret", "P": "smtp-pw"},
                 transport=httpx.MockTransport(handle), smtp_factory=FakeSMTP)
    assert run(n.run_pending()) == 1
    [req] = got                                                     # only the matching webhook
    assert json.loads(req.content) == {"t": "Applied: create group G", "ticket": "IAM-1"}
    expected = "sha256=" + hmac.new(b"hook-secret", req.content, hashlib.sha256).hexdigest()
    assert req.headers["X-Signature"] == expected
    assert sent_mail == ["starttls", ("login", "u", "smtp-pw"), "[backend-iam] Applied: create group G"]
    assert notes.recent()[0]["status"] == "sent"


def test_failed_delivery_is_retried_then_dead(database):
    cfg = NotifyConfig(webhooks=[Webhook(name="down", url="https://10.0.0.5/", allow_private=True)])
    notes = Notifications(database)
    notes.add("audit.tampered", "x", "y")
    n = Notifier(database, cfg, env={}, transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    for _ in range(10):
        run(n.run_pending())
    row = notes.recent()[0]
    assert row["status"] == "dead" and row["attempts"] == 10 and "503" in row["last_error"]


def test_web_queues_approval_notifications(make_web, database):
    add_user(database, "otto", "operator")
    add_user(database, "mia", "admin")
    c = make_web()
    login(c, "otto", "a-long-password-1")
    c.post("/directory/request", data={"csrf_token": csrf(c, "/directory"), "via": "ad", "kind": "group",
                                       "op": "create", "name": "G", "jira_ticket": "IAM-3",
                                       "reason": "a team needs this group"})
    [req] = OperatorRequests(database).page("producer")
    m = make_web()
    login(m, "mia", "a-long-password-1")
    m.post(f"/approvals/{req['id']}/approve", data={"csrf_token": csrf(m, "/approvals")})
    events = [n["event"] for n in Notifications(database).recent()]
    assert events == ["request.approved", "request.awaiting_approval"]
    assert m.get("/admin/notifications").status_code == 200


def test_overdue_campaign_reported_once(database):
    from .test_governance import seed
    seed(database)
    gov = Governance(database)
    cid = gov.start_campaign("Q4", "web:boss", due_days=1)
    t = database.tables.cert_campaigns
    with database.begin() as conn:
        conn.execute(t.update().where(t.c.id == cid).values(due_at=time.time() - 10))
    assert [c["id"] for c in gov.overdue_campaigns()] == [cid]
    assert gov.overdue_campaigns() == []


def test_webhook_connects_to_the_checked_address_only(database, monkeypatch):
    """DNS rebinding: the first lookup says public, a second would say 127.0.0.1. Only one
    lookup happens and the request goes to the checked address, Host / SNI unchanged."""
    import socket
    answers = iter(["93.184.216.34", "127.0.0.1"])

    def fake_getaddrinfo(host, port, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (next(answers), port))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    seen = []

    def handle(request):
        seen.append((request.url.host, request.headers["Host"], request.extensions.get("sni_hostname")))
        return httpx.Response(200)
    cfg = NotifyConfig(webhooks=[Webhook(name="h", url="https://hooks.example.com:8443/x")])
    Notifications(database).add("sod.blocked", "t", "x")
    assert run(Notifier(database, cfg, env={}, transport=httpx.MockTransport(handle)).run_pending()) == 1
    assert seen == [("93.184.216.34", "hooks.example.com:8443", "hooks.example.com")]
