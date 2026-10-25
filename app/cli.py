"""Command line entry point: `iam serve | ping | import | search | export | raw | api-docs`."""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .config import get_settings
from .importer import ImportError_, parse_users
from .logs import setup_logging
from .csvutil import to_csv
from .main import build_client
from .openiam import OpenIAMError
from .service import inject_users


def _criteria(text: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as e:
        raise SystemExit(f"--criteria must be JSON, e.g. '{{\"lastName\": \"Smith\"}}': {e}")
    if not isinstance(value, dict) or not value:
        raise SystemExit("--criteria must be a non-empty JSON object")
    return value


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


async def _run(args: argparse.Namespace) -> int:
    settings = get_settings()
    async with build_client(settings) as client:
        if args.cmd == "ping":
            await client.check_auth()
            print("OK: token obtained from", settings.openiam_base_url)
        elif args.cmd == "import":
            path = Path(args.file)
            try:
                users = parse_users(path.read_bytes(), path.name)
            except ImportError_ as e:
                _print({"error": str(e), "row_errors": e.row_errors})
                return 2
            result = await inject_users(client, settings, users, dry_run=args.dry_run,
                                        concurrency=args.concurrency)
            _print(result.model_dump(exclude_none=True))
            return 0 if result.failed == 0 else 1
        elif args.cmd == "search":
            _print(await client.search_users(_criteria(args.criteria), args.offset, args.size))
        elif args.cmd == "export":
            users = [u async for u in client.iter_users(_criteria(args.criteria), args.page_size,
                                                         args.limit)]
            text = to_csv(users) if args.format == "csv" else json.dumps(users, indent=2, default=str)
            if args.output:
                Path(args.output).write_text(text, encoding="utf-8", newline="")
                print(f"wrote {len(users)} users to {args.output}", file=sys.stderr)
            else:
                print(text)
        elif args.cmd == "raw":
            body = json.loads(args.body) if args.body else None
            _print(await client.raw(args.method, args.path, json=body))
        elif args.cmd == "api-docs":
            _print(await client.api_docs(args.front_end))
        elif args.cmd == "sync":
            return await _sync(args, settings, client)
        elif args.cmd == "producer":
            return await _producer(args, settings, client)
        elif args.cmd == "consumer":
            return await _consumer(args, settings, client)
    return 0


async def _consumer(args: argparse.Namespace, settings, client) -> int:
    from .consumer import ConsumerError
    from .main import build_consumer, build_database

    consumer = build_consumer(settings, client, build_database(settings))
    if consumer is None:
        raise SystemExit(f"no consumer config at {settings.consumer_config_path} "
                         "(copy consumer.example.yaml, or set CONSUMER_CONFIG_PATH)")
    if args.consumer_cmd == "watch":
        if settings.consumer_metrics_port:
            from .metrics import serve as serve_metrics
            serve_metrics(consumer.store.db, "consumer", settings.consumer_metrics_host,
                          settings.consumer_metrics_port)
        await consumer.loop()
        return 0
    try:
        result = await consumer.scan()
    except ConsumerError as e:
        _print({"error": str(e)})
        return 1
    _print(result)
    return 0 if all(f["status"] not in ("failed", "partial") for f in result["files"]) else 1


def _webuser(args: argparse.Namespace, settings) -> int:
    import getpass
    import os

    from .main import build_database
    from .security import AuditTrail
    from .web.auth import WebUserStore
    db = build_database(settings)
    users, audit = WebUserStore(db), AuditTrail(db)
    actor = f"cli:{getpass.getuser()}"
    cmd = args.webuser_cmd
    if cmd == "list":
        _print(users.list())
        return 0

    def ask() -> str:
        # Non-interactive (Ansible): WEBUSER_PASSWORD; otherwise prompt twice.
        if pw := os.environ.get("WEBUSER_PASSWORD"):
            return pw
        first = getpass.getpass("password: ")
        if first != getpass.getpass("again: "):
            raise SystemExit("passwords differ")
        return first
    try:
        if cmd == "add":
            users.create(args.username, ask(), args.role)
        elif cmd == "passwd":
            users.set_password(args.username, ask())
        elif cmd == "role":
            users.set_role(args.username, args.role) or _missing(args.username)
        elif cmd == "unlock":
            users.unlock(args.username) or _missing(args.username)
        else:
            users.set_disabled(args.username, cmd == "disable") or _missing(args.username)
    except ValueError as e:
        audit.record("cli", actor, f"user.{cmd}", ok=False, target=args.username, detail=str(e))
        raise SystemExit(str(e))
    audit.record("cli", actor, f"user.{cmd}", ok=True, target=args.username)
    print(f"{cmd}: {args.username} done")
    return 0


def _missing(name: str):
    raise SystemExit(f"no web user {name}")


async def _producer(args: argparse.Namespace, settings, client) -> int:
    from .main import build_database, build_producer, build_sync
    from .producer import ProducerEvent
    from .producer.config import KINDS

    db = build_database(settings)
    sync = build_sync(settings, client, db)
    producer = build_producer(settings, client, db, sync)
    if producer is None:
        raise SystemExit(f"no producer config at {settings.producer_config_path} "
                         "(copy producer.example.yaml, or set PRODUCER_CONFIG_PATH)")
    if args.producer_cmd == "apply":
        doc = json.loads(Path(args.file).read_text(encoding="utf-8"))
        rows = doc.get("events", doc) if isinstance(doc, dict) else doc
        events = [ProducerEvent.model_validate(e) for e in (rows if isinstance(rows, list) else [rows])]
        results = await producer.process_many(events)
        if sync is not None:
            if any(r.instructions for r in results):
                await sync.deliver()
            await sync.aclose()
        _print([r.model_dump(exclude_defaults=True) for r in results])
        return 0 if all(r.ok for r in results) else 1
    person = producer.store.get_person(args.employee_id)
    if person is None:
        print("unknown employee", file=sys.stderr)
        return 1
    _print({**vars(person),
            "applied": {k: sorted(producer.store.memberships(args.employee_id, k)) for k in KINDS}})
    return 0


async def _sync(args: argparse.Namespace, settings, client) -> int:
    from .main import build_database, build_sync
    from .sync import SyncError

    db = build_database(settings)
    sync = build_sync(settings, client, db)
    if sync is not None:
        from .main import build_producer
        producer = build_producer(settings, client, db, sync)
        if producer is not None:
            sync.attributor = producer.store.attribution
    if sync is None:
        raise SystemExit(f"no sync config at {settings.sync_config_path} "
                         "(copy sync.example.yaml, or set SYNC_CONFIG_PATH)")
    try:
        if args.sync_cmd == "run":
            try:
                _print(await sync.run(baseline=args.baseline,
                                      allow_mass_delete=args.allow_mass_delete,
                                      deliver=not args.no_deliver))
            except SyncError as e:
                _print({"error": str(e)})
                return 1
        elif args.sync_cmd == "watch":
            await sync.loop()
        elif args.sync_cmd == "export":
            try:
                result = await sync.export(source=args.source, force=args.force)
            except SyncError as e:
                _print({"error": str(e)})
                return 1
            _print(result)
            return 0 if all(d["status"] != "failed" for d in result["domains"]) else 1
        elif args.sync_cmd == "deliver":
            _print(await sync.deliver())
        elif args.sync_cmd == "retry-dead":
            _print({"requeued": sync.store.retry_dead()})
        elif args.sync_cmd == "status":
            _print({"tracked": sync.store.counts(), "outbox": sync.store.outbox_stats(),
                    "runs": sync.store.recent_runs(5)})
    finally:
        await sync.aclose()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="iam", description="Push users into / pull data from OpenIAM")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the HTTP API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")

    sub.add_parser("ping", help="check OpenIAM credentials")

    s = sub.add_parser("import", help="create/update users from a .csv or .json file")
    s.add_argument("file")
    s.add_argument("--dry-run", action="store_true", help="validate and map only; send nothing")
    s.add_argument("--concurrency", type=int, default=4)

    s = sub.add_parser("search", help="one page of user search")
    s.add_argument("--criteria", required=True, help='JSON, e.g. \'{"lastName": "Smith"}\'')
    s.add_argument("--offset", type=int, default=0)
    s.add_argument("--size", type=int, default=50)

    s = sub.add_parser("export", help="all users matching criteria")
    s.add_argument("--criteria", required=True)
    s.add_argument("--format", choices=["json", "csv"], default="json")
    s.add_argument("--page-size", type=int, default=100)
    s.add_argument("--limit", type=int)
    s.add_argument("-o", "--output")

    s = sub.add_parser("raw", help="call any OpenIAM REST endpoint")
    s.add_argument("method", choices=["GET", "POST", "PUT", "DELETE", "PATCH"])
    s.add_argument("path", help="e.g. /webconsole/rest/api/users/search")
    s.add_argument("--body", help="JSON request body")

    s = sub.add_parser("api-docs", help="dump the deployment's OpenAPI spec")
    s.add_argument("--front-end", choices=["webconsole", "selfservice", "idp"], default="webconsole")

    s = sub.add_parser("sync", help="detect OpenIAM changes and send them to the other site")
    ss = s.add_subparsers(dest="sync_cmd", required=True)
    r = ss.add_parser("run", help="one detect + deliver cycle")
    r.add_argument("--baseline", action="store_true",
                   help="record current state without emitting events")
    r.add_argument("--allow-mass-delete", action="store_true")
    r.add_argument("--no-deliver", action="store_true")
    ss.add_parser("watch", help="run cycles every interval_seconds until stopped")
    ss.add_parser("deliver", help="send pending events now")
    e = ss.add_parser("export", help="write one zip per domain into export.folder")
    e.add_argument("--source", choices=["live", "snapshot"], default="live",
                   help="pull from OpenIAM now (live) or use the last sync's copy")
    e.add_argument("--force", action="store_true", help="export every domain, even unchanged")
    ss.add_parser("retry-dead", help="re-queue events that ran out of attempts")
    ss.add_parser("status", help="tracked counts, outbox and recent runs")

    s = sub.add_parser("consumer", help="apply the producer side's zips to this site's OpenIAM")
    cs = s.add_subparsers(dest="consumer_cmd", required=True)
    cs.add_parser("scan", help="process every zip waiting in the inbox, once")
    cs.add_parser("watch", help="scan every interval_seconds until stopped")

    s = sub.add_parser("apikey", help="API keys: create (shown once), list, revoke")
    aks = s.add_subparsers(dest="apikey_cmd", required=True)
    a = aks.add_parser("create")
    a.add_argument("name")
    a.add_argument("--scope", action="append", required=True, help="repeatable; see `iam apikey scopes`")
    a.add_argument("--cidr", action="append", default=[], help="allowed source network, repeatable")
    a.add_argument("--expires-days", type=int)
    a = aks.add_parser("revoke")
    a.add_argument("name")
    aks.add_parser("list")
    aks.add_parser("scopes")

    s = sub.add_parser("keys", help="create signing / encryption keys for the zips (offline)")
    ks = s.add_subparsers(dest="keys_cmd", required=True)
    k = ks.add_parser("signing", help="Ed25519 pair: PREFIX.key (producer) and PREFIX.pub (consumers)")
    k.add_argument("prefix", help="e.g. keys/export-signing")
    k = ks.add_parser("age", help="age identity for a consumer site; prints its recipient")
    k.add_argument("file", help="e.g. keys/consumer-b.age")

    s = sub.add_parser("maintenance", help="database migrations and retention")
    ms = s.add_subparsers(dest="maintenance_cmd", required=True)
    ms.add_parser("migrate", help="bring the database schema up to date (also done at start)")
    m = ms.add_parser("purge", help="delete rows older than the RETENTION_* windows")
    m.add_argument("--dry-run", action="store_true", help="only count what would be deleted")

    s = sub.add_parser("web", help="producer-site web UI (activity, AD instructions, runs, API keys)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8090)
    s = sub.add_parser("oversight", help="consumer-site web UI (zips, actions, AD plans and changes, drift)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8091)

    s = sub.add_parser("webuser", help="web UI users (both UIs share them per database)")
    ws = s.add_subparsers(dest="webuser_cmd", required=True)
    w = ws.add_parser("add")
    w.add_argument("username")
    w.add_argument("--role", choices=["viewer", "operator", "admin"], default="viewer")
    w = ws.add_parser("passwd")
    w.add_argument("username")
    for name in ("disable", "enable", "unlock"):
        w = ws.add_parser(name)
        w.add_argument("username")
    w = ws.add_parser("role")
    w.add_argument("username")
    w.add_argument("role", choices=["viewer", "operator", "admin"])
    ws.add_parser("list")

    s = sub.add_parser("producer", help="apply producer events (hire, terminate, statuses, ...)")
    ps = s.add_subparsers(dest="producer_cmd", required=True)
    a = ps.add_parser("apply", help="apply events from a JSON file (list, or {\"events\": [...]})")
    a.add_argument("file")
    a = ps.add_parser("person", help="show recorded state for one employee")
    a.add_argument("employee_id")

    args = p.parse_args(argv)
    settings = get_settings()
    setup_logging(settings.log_level, settings.log_json, settings.log_file, settings.log_redact)
    if args.cmd == "apikey":
        import getpass

        from .main import build_database
        from .security import SCOPES, ApiKeyStore, AuditTrail
        db = build_database(settings)
        store, audit = ApiKeyStore(db), AuditTrail(db)
        actor = f"cli:{getpass.getuser()}"
        if args.apikey_cmd == "create":
            key = store.create(args.name, args.scope, args.cidr, args.expires_days, created_by=actor)
            audit.record("cli", actor, "apikey.create", ok=True, target=args.name,
                         detail=f"scopes={args.scope} cidrs={args.cidr}")
            print(f"API key for {args.name} (shown once, store it now):\n{key}")
        elif args.apikey_cmd == "revoke":
            ok = store.revoke(args.name)
            audit.record("cli", actor, "apikey.revoke", ok=ok, target=args.name)
            print("revoked" if ok else "no such active key")
            return 0 if ok else 1
        elif args.apikey_cmd == "scopes":
            _print(SCOPES)
        else:
            _print(store.list())
        return 0
    if args.cmd == "keys":
        from . import bundlesec
        if args.keys_cmd == "signing":
            priv, pub = bundlesec.generate_signing_key(Path(args.prefix))
            print(f"private key (producer site, export.signing_key_file): {priv}")
            print(f"public key  (consumer sites, trusted_signing_keys):   {pub}")
            print(f"key id: {bundlesec.key_id(bundlesec.load_public_key(str(pub)))}")
        else:
            recipient = bundlesec.generate_age_identity(Path(args.file))
            print(f"identity  (consumer site, age_identity_file): {args.file}")
            print(f"recipient (producer site, export.encrypt_to): {recipient}")
        return 0
    if args.cmd == "maintenance":
        from .main import build_database
        from .maintenance import purge
        db = build_database(settings)
        if args.maintenance_cmd == "migrate":
            _print({"schema_version": db.schema_version()})
        else:
            _print(purge(db, settings, dry_run=args.dry_run))
        return 0
    if args.cmd in ("web", "oversight"):
        from .web import serve
        serve(settings, args.host, args.port, site="producer" if args.cmd == "web" else "consumer")
        return 0
    if args.cmd == "webuser":
        return _webuser(args, settings)
    if args.cmd == "serve":
        import uvicorn
        # log_config=None: uvicorn logs go through loguru instead of its own handlers.
        uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload,
                    log_config=None)
        return 0
    try:
        return asyncio.run(_run(args))
    except OpenIAMError as e:
        _print({"error": str(e), "openiam_status": e.status, "openiam_errors": e.errors})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
