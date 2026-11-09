"""Retention of the newer tables; Jira status shown to (and enforced for) approvers."""

import asyncio
import time

from app.config import Settings
from app.jira import annotate_waiting
from app.maintenance import purge
from app.notify import Notifications
from app.operator import OperatorRequests
from app.receipts import ReceiptOutbox

from .test_integrations_batch_b import jira
from .test_web import add_user, csrf, login

DAY = 86400


def run(coro):
    return asyncio.run(coro)


def test_retention_covers_new_tables_but_never_open_work(database):
    old = time.time() - 400 * DAY
    notes, reqs = Notifications(database), OperatorRequests(database)
    sent = notes.add("sod.blocked", "a", "b")
    waiting = notes.add("sod.blocked", "c", "d")
    notes.finish(sent, True, None, 1)
    out = ReceiptOutbox(database)
    written, queued = out.add({"x": 1}), out.add({"x": 2})
    out.mark(written, "f")
    rejected = reqs.create("producer", "directory", {"op": "create"}, "web:otto")
    reqs.decide(rejected, False, "web:boss")
    still_waiting = reqs.create("producer", "directory", {"op": "create"}, "web:otto")
    t = database.tables
    with database.begin() as conn:
        for table, col in ((t.notifications, "at"), (t.consumer_receipts, "written_at"), (t.operator_requests, "at")):
            conn.execute(table.update().values({col: old}))
        conn.execute(t.consumer_receipts.update().where(t.consumer_receipts.c.id == queued).values(at=old))
    counts = purge(database, Settings(_env_file=None))
    assert counts["notifications"] == 1 and counts["receipts written (consumer)"] == 1
    assert counts["operator requests"] == 1
    assert [n["id"] for n in notes.recent()] == [waiting]               # undelivered: kept
    assert [r["id"] for r in out.pending()] == [queued]                   # not yet written: kept
    assert [r["id"] for r in reqs.page("producer")] == [still_waiting]    # still waiting: kept


def test_approvers_see_the_jira_status_and_enforce_blocks(make_web, database):
    reqs = OperatorRequests(database)
    good = reqs.create("producer", "directory", {"op": "create", "kind": "group", "name": "G",
                                                 "jira_ticket": "IAM-1", "reason": "x" * 12}, "web:otto")
    bad = reqs.create("producer", "directory", {"op": "create", "kind": "group", "name": "H",
                                                "jira_ticket": "IAM-2", "reason": "x" * 12}, "web:otto")
    assert run(annotate_waiting(database, jira("enforce", []))) == 2
    assert run(annotate_waiting(database, jira("enforce", []))) == 0       # fresh: not looked up again
    assert reqs.get(good)["checks"]["jira"]["status"] == "Approved"
    assert "'Open'" in reqs.get(bad)["checks"]["jira"]["problem"]
    add_user(database, "mia", "admin")
    c = make_web(jira_check="enforce")
    login(c, "mia", "a-long-password-1")
    page = c.get("/approvals").get_data(as_text=True)
    assert "Jira:" in page and "Approved" in page
    t = csrf(c, "/approvals")
    c.post(f"/approvals/{bad}/approve", data={"csrf_token": t})
    c.post(f"/approvals/{good}/approve", data={"csrf_token": t})
    assert reqs.get(bad)["status"] == "awaiting_approval"                  # refused: ticket not allowed
    assert reqs.get(good)["status"] == "pending"
