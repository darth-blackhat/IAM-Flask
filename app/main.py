import asyncio
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Security, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader

from .config import Settings, get_settings
from .consumer import Consumer, ConsumerStore, load_consumer_config
from .consumer.ad_target import AdApplier
from .csvutil import to_csv
from .importer import ImportError_, parse_users
from .logs import logger, setup_logging
from .maintenance import DailyPurge
from .operator import OperatorRequests
from .metrics import CONTENT_TYPE as METRICS_CONTENT_TYPE
from .metrics import registry_for, render
from .openiam import OpenIAMAuthError, OpenIAMClient, OpenIAMError
from .openiam.client import USER_ACTIONS
from .security import (ApiKeyStore, AuditTrail, Authenticator, Principal, RateLimiter,
                       client_ip, parse_networks)
from .schemas import (ActionIn, BulkInjectResult, EntitleIn, ExportIn, InjectResult, RawIn,
                      SearchIn, UserIn)
from .producer import (ProducerEvent, ProducerProcessor, ProducerResult, ProducerStore,
                       load_producer_config)
from .producer.config import KINDS
from .service import inject_user, inject_users
from .db import Database
from .sync import (MassDeleteError, Store, SyncBusy, SyncError, SyncService, build_target,
                   load_config)

MAX_UPLOAD_BYTES = 20 * 1024 * 1024


def build_client(settings: Settings) -> OpenIAMClient:
    return OpenIAMClient(settings.openiam_base_url, settings.openiam_client_id,
                         settings.openiam_client_secret.get_secret_value(),
                         verify_tls=settings.openiam_verify_tls,
                         timeout=settings.openiam_timeout_seconds)


def build_database(settings: Settings) -> Database:
    db = Database(settings.database_url, settings.database_schema)
    db.migrate()
    return db


def build_sync(settings: Settings, client: OpenIAMClient, db: Database) -> SyncService | None:
    """None when there is no sync config file: the sync routes then answer 503."""
    if not Path(settings.sync_config_path).is_file():
        return None
    cfg = load_config(settings.sync_config_path)
    sync = SyncService(client, Store(db), cfg, build_target(cfg))
    sync.housekeeping = DailyPurge(db, settings).maybe_run
    return sync


def build_producer(settings: Settings, client: OpenIAMClient, db: Database,
                   sync: SyncService | None = None) -> ProducerProcessor | None:
    """None when there is no producer config file: the producer routes then answer 503.

    With sync configured, the producer's AD instructions go out through its outbox/target.
    """
    if not Path(settings.producer_config_path).is_file():
        return None
    return ProducerProcessor(client, ProducerStore(db),
                             load_producer_config(settings.producer_config_path), settings,
                             ad=sync.cfg.ad if sync else None,
                             outbox=sync.store if sync else None)


def build_consumer(settings: Settings, client: OpenIAMClient, db: Database) -> Consumer | None:
    if not Path(settings.consumer_config_path).is_file():
        return None
    cfg = load_consumer_config(settings.consumer_config_path)
    ad = AdApplier(cfg.ad) if settings.consumer_target == "ad" and cfg.ad else None
    consumer = Consumer(client if settings.consumer_target == "openiam" else None,
                        ConsumerStore(db), cfg, settings, target=settings.consumer_target, ad=ad)
    consumer.housekeeping = DailyPurge(db, settings).maybe_run
    consumer.operator_requests = OperatorRequests(db)
    return consumer


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Honour a dependency override (tests) here too, not only in route dependencies.
    settings = app.dependency_overrides.get(get_settings, get_settings)()
    app.state.settings = settings
    setup_logging(settings.log_level, settings.log_json, settings.log_file, settings.log_redact)
    if not hasattr(app.state, "openiam"):  # tests inject their own client
        app.state.openiam = build_client(settings)
    own_db = not hasattr(app.state, "db")  # tests inject their own database
    if own_db:
        app.state.db = build_database(settings)
    db = app.state.db
    if not hasattr(app.state, "sync"):
        app.state.sync = build_sync(settings, app.state.openiam, db)
    if not hasattr(app.state, "producer"):
        app.state.producer = build_producer(settings, app.state.openiam, db, app.state.sync)
    app.state.audit = AuditTrail(db)
    app.state.auth = Authenticator(ApiKeyStore(db), settings.backend_api_key.get_secret_value(),
                                   settings.api_allowed_cidrs)
    app.state.limiter = RateLimiter(settings.api_rate_per_minute)
    app.state.trusted_proxies = parse_networks(settings.trusted_proxies)
    if not settings.backend_api_key.get_secret_value() and not ApiKeyStore(db).list():
        logger.warning("no API keys exist: every request will be refused. "
                       "Create one with `iam apikey create NAME --scope ...`")
    if app.state.sync is not None and app.state.producer is not None:
        app.state.sync.attributor = app.state.producer.store.attribution
    tasks = []
    if settings.sync_schedule and app.state.sync is not None:
        tasks.append(asyncio.create_task(app.state.sync.loop()))
    if app.state.sync is not None and settings.operator_poll_seconds > 0:
        tasks.append(asyncio.create_task(_operator_loop(
            OperatorRequests(db), "producer", app.state.sync.operator_handlers(),
            settings.operator_poll_seconds)))
    logger.info("backend-iam started: openiam={} sync={} producer={} scheduler={}",
                settings.openiam_base_url, app.state.sync is not None,
                app.state.producer is not None, settings.sync_schedule)
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        if app.state.sync is not None:
            await app.state.sync.aclose()
        await app.state.openiam.aclose()
        if own_db:
            db.engine.dispose()
            del app.state.db


async def _operator_loop(requests: OperatorRequests, service: str, handlers: dict,
                         every: float) -> None:
    """Run what operators asked for in the web UI."""
    while True:
        try:
            await requests.run_pending(service, handlers)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("operator request loop")
        await asyncio.sleep(every)


app = FastAPI(title="backend-iam", version="0.1.0",
              description="Push user data into OpenIAM and pull data out of it.",
              lifespan=lifespan)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
SECURITY_HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}


@app.middleware("http")
async def guard(request: Request, call_next):
    """Body size limit, security headers, and an audit record for every write."""
    settings = request.app.state.settings
    if request.method in ("POST", "PUT", "PATCH"):
        length = request.headers.get("content-length")
        if length is None and request.headers.get("transfer-encoding"):
            return JSONResponse({"detail": "Content-Length required"}, status_code=411)
        if length is not None and (not length.isdigit() or int(length) > settings.max_request_bytes):
            return JSONResponse({"detail": "request body too large"}, status_code=413)
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    principal = getattr(request.state, "principal", None)
    if principal is not None and request.method != "GET":
        route = request.scope.get("route")
        request.app.state.audit.record(
            "api", f"api:{principal.name}", f"{request.method} {getattr(route, 'path', request.url.path)}",
            ok=response.status_code < 400, ip=getattr(request.state, "client_ip", None),
            target=request.url.path, detail=f"HTTP {response.status_code}")
    return response


def require(scope: str):
    """Dependency: a valid API key (X-API-Key or Authorization: Bearer) with `scope`."""
    async def check(request: Request,
                    key: Annotated[str | None, Security(_api_key_header)]) -> Principal:
        if not key:
            authz = request.headers.get("authorization", "")
            key = authz[7:].strip() if authz.lower().startswith("bearer ") else None
        state = request.app.state
        ip = client_ip(request.client.host if request.client else None,
                       request.headers.get("x-forwarded-for"), state.trusted_proxies)
        principal, reason = state.auth.authenticate(key, ip)
        if principal is None:
            state.audit.record("api", "unknown", f"{request.method} {request.url.path}", ok=False,
                               ip=ip, detail=reason)
            raise HTTPException(401, reason)
        if not principal.allows(scope):
            state.audit.record("api", f"api:{principal.name}", f"{request.method} {request.url.path}",
                               ok=False, ip=ip, detail=f"missing scope {scope}")
            raise HTTPException(403, f"API key {principal.name} lacks scope {scope}")
        allowed, wait = state.limiter.allow(principal.name)
        if not allowed:
            raise HTTPException(429, "rate limit exceeded",
                                headers={"Retry-After": str(int(wait) + 1)})
        request.state.principal, request.state.client_ip = principal, ip
        return principal
    return Depends(check)


def get_client(request: Request) -> OpenIAMClient:
    return request.app.state.openiam


Client = Annotated[OpenIAMClient, Depends(get_client)]
Cfg = Annotated[Settings, Depends(get_settings)]


@app.exception_handler(OpenIAMError)
async def openiam_error_handler(request: Request, exc: OpenIAMError) -> JSONResponse:
    if isinstance(exc, OpenIAMAuthError):
        code = 502
    else:
        code = {400: 400, 401: 403, 403: 403, 404: 404}.get(exc.status or 0, 502)
    logger.bind(openiam_status=exc.status, openiam_errors=exc.errors).warning(
        "{} {} -> {}: {}", request.method, request.url.path, code, exc)
    return JSONResponse(status_code=code, content={
        "detail": str(exc), "openiam_status": exc.status, "openiam_errors": exc.errors})


@app.get("/metrics", dependencies=[require("metrics:read")])
async def metrics(request: Request) -> Response:
    """Prometheus metrics (API key with scope metrics:read)."""
    reg = getattr(request.app.state, "metrics", None)
    if reg is None:
        reg = request.app.state.metrics = registry_for(request.app.state.db, "producer")
    return Response(render(reg), media_type=METRICS_CONTENT_TYPE)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/openiam/ping", dependencies=[require("openiam:raw")])
async def ping(client: Client) -> dict[str, Any]:
    """Check that this backend can obtain an OpenIAM token."""
    await client.check_auth()
    return {"openiam": "reachable", "token": "obtained"}


# ---- inject ----------------------------------------------------------------

@app.post("/users", dependencies=[require("users:write")], response_model=InjectResult)
async def create_or_update_user(user: UserIn, client: Client, settings: Cfg,
                                dry_run: bool = False) -> InjectResult:
    result = await inject_user(client, settings, user, dry_run=dry_run)
    if not result.ok and result.user_id is None:
        raise HTTPException(400, result.model_dump())
    return result


@app.post("/users/bulk", dependencies=[require("users:write")], response_model=BulkInjectResult)
async def bulk_users(users: list[UserIn], client: Client, settings: Cfg,
                     dry_run: bool = False,
                     concurrency: Annotated[int, Query(ge=1, le=16)] = 4) -> BulkInjectResult:
    return await inject_users(client, settings, users, dry_run=dry_run, concurrency=concurrency)


@app.post("/users/import", dependencies=[require("users:write")], response_model=BulkInjectResult)
async def import_users(file: Annotated[UploadFile, File(description=".csv or .json")],
                       client: Client, settings: Cfg, dry_run: bool = False,
                       concurrency: Annotated[int, Query(ge=1, le=16)] = 4) -> BulkInjectResult:
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "file too large")
    try:
        users = parse_users(data, file.filename or "")
    except ImportError_ as e:
        raise HTTPException(422, {"detail": str(e), "row_errors": e.row_errors})
    return await inject_users(client, settings, users, dry_run=dry_run, concurrency=concurrency)


@app.post("/users/{user_id}/entitlements", dependencies=[require("users:write")])
async def entitle_user(user_id: str, body: EntitleIn, client: Client) -> dict[str, Any]:
    return await client.entitle(user_id, operation=body.operation, role_ids=body.role_ids,
                                group_ids=body.group_ids, organization_ids=body.organization_ids,
                                resource_ids=body.resource_ids)


@app.post("/users/{user_id}/actions/{action}", dependencies=[require("users:write")])
async def user_action(user_id: str, action: str, client: Client,
                      body: ActionIn | None = None) -> dict[str, Any]:
    if action not in USER_ACTIONS:
        raise HTTPException(404, f"unknown action; expected one of {sorted(USER_ACTIONS)}")
    body = body or ActionIn()
    return await client.user_action(action, user_id, reason=body.reason,
                                    description=body.description, perform_date=body.perform_date)


# ---- pull ------------------------------------------------------------------

@app.post("/users/search", dependencies=[require("users:read")])
async def search_users(body: SearchIn, client: Client) -> dict[str, Any]:
    """One page of OpenIAM's user search, returned as OpenIAM's BeanResponse."""
    return await client.search_users(body.criteria, body.from_, body.size)


@app.post("/users/export", dependencies=[require("users:read")])
async def export_users(body: ExportIn, client: Client,
                       format: Literal["json", "csv"] = "json") -> Response:
    """Every user matching `criteria`, paging through OpenIAM's search."""
    users = [u async for u in client.iter_users(body.criteria, body.page_size, body.limit)]
    if format == "json":
        return JSONResponse({"count": len(users), "users": users})
    return Response(to_csv(users), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="openiam-users.csv"'})


@app.get("/openiam/api-docs", dependencies=[require("openiam:raw")])
async def api_docs(client: Client,
                   front_end: Literal["webconsole", "selfservice", "idp"] = "webconsole") -> Any:
    """The connected deployment's OpenAPI spec: every endpoint `/openiam/raw` can call."""
    return await client.api_docs(front_end)


@app.post("/openiam/raw", dependencies=[require("openiam:raw")])
async def raw(body: RawIn, client: Client) -> Any:
    """Call any OpenIAM REST endpoint (roles, groups, orgs, resources, audit, ...)."""
    try:
        return await client.raw(body.method, body.path, json=body.body, params=body.params)
    except ValueError as e:
        raise HTTPException(400, str(e))


# ---- producer intake ---------------------------------------------------------

def get_producer(request: Request) -> ProducerProcessor:
    producer = getattr(request.app.state, "producer", None)
    if producer is None:
        raise HTTPException(503, "producer intake is not configured (no producer config file)")
    return producer


Producer = Annotated[ProducerProcessor, Depends(get_producer)]


@app.post("/producer/events", dependencies=[require("producer:write")])
async def producer_events(events: ProducerEvent | list[ProducerEvent], producer: Producer,
                          request: Request) -> list[ProducerResult]:
    """Hire / update / terminate / leave / return / status events, applied in order.

    Always HTTP 200 with one result per event; check each `ok`.
    """
    results = await producer.process_many(events if isinstance(events, list) else [events])
    # Send the new AD instructions now instead of waiting for the next sync cycle.
    sync = getattr(request.app.state, "sync", None)
    if sync is not None and any(r.instructions for r in results):
        with suppress(SyncBusy):  # a running cycle delivers them anyway
            await sync.deliver()
    return results


@app.get("/producer/people/{employee_id}", dependencies=[require("producer:read")])
async def producer_person(employee_id: str, producer: Producer) -> dict[str, Any]:
    """What the producer asked for and what has been applied in OpenIAM for one person."""
    person = producer.store.get_person(employee_id)
    if person is None:
        raise HTTPException(404, "unknown employee")
    return {**vars(person),
            "applied": {k: sorted(producer.store.memberships(employee_id, k)) for k in KINDS}}


# ---- change detection --------------------------------------------------------

def get_sync(request: Request) -> SyncService:
    sync = getattr(request.app.state, "sync", None)
    if sync is None:
        raise HTTPException(503, "sync is not configured (no sync config file)")
    return sync


Sync = Annotated[SyncService, Depends(get_sync)]


@app.post("/sync/run", dependencies=[require("sync:run")])
async def sync_run(sync: Sync, baseline: bool = False, allow_mass_delete: bool = False,
                   deliver: bool = True) -> dict[str, Any]:
    """Pull users/groups/orgs/roles, record what changed, send events to the target."""
    try:
        return await sync.run(baseline=baseline, allow_mass_delete=allow_mass_delete,
                              deliver=deliver)
    except (MassDeleteError, SyncBusy) as e:
        raise HTTPException(409, str(e))
    except SyncError as e:
        raise HTTPException(502, str(e))


@app.post("/sync/deliver", dependencies=[require("sync:run")])
async def sync_deliver(sync: Sync) -> dict[str, Any]:
    try:
        return await sync.deliver()
    except SyncBusy as e:
        raise HTTPException(409, str(e))


@app.post("/sync/export", dependencies=[require("sync:run")])
async def sync_export(sync: Sync, source: Literal["live", "snapshot"] = "live",
                      force: bool = False) -> dict[str, Any]:
    """Pull everything and write one zip per domain (only changed/new ones unless force)."""
    try:
        return await sync.export(source=source, force=force)
    except SyncBusy as e:
        raise HTTPException(409, str(e))
    except SyncError as e:
        raise HTTPException(400 if "no `export`" in str(e) else 502, str(e))


@app.post("/sync/retry-dead", dependencies=[require("sync:run")])
async def sync_retry_dead(sync: Sync) -> dict[str, int]:
    """Re-queue events that ran out of delivery attempts."""
    return {"requeued": sync.store.retry_dead()}


@app.get("/sync/status", dependencies=[require("sync:read")])
async def sync_status(sync: Sync) -> dict[str, Any]:
    return {"tracked": sync.store.counts(), "outbox": sync.store.outbox_stats(),
            "target": sync.cfg.target.type, "runs": sync.store.recent_runs(5)}


@app.get("/sync/events", dependencies=[require("sync:read")])
async def sync_events(sync: Sync, after: Annotated[int, Query(ge=0)] = 0,
                      limit: Annotated[int, Query(ge=1, le=5000)] = 500) -> dict[str, Any]:
    """Pull feed for the other site: pass the last `seq` you processed as `after`."""
    events = sync.store.events_after(after, limit)
    return {"events": events, "next_after": events[-1]["seq"] if events else after}


@app.get("/sync/snapshot/{entity}", dependencies=[require("sync:read")])
async def sync_snapshot(entity: str, sync: Sync, offset: Annotated[int, Query(ge=0)] = 0,
                        limit: Annotated[int, Query(ge=1, le=5000)] = 500) -> dict[str, Any]:
    """Last-seen copy of an entity type, for loading the other site from scratch."""
    if entity not in sync.cfg.entities:
        raise HTTPException(404, f"unknown entity; configured: {sorted(sync.cfg.entities)}")
    return {"entity": entity, "items": sync.store.snapshot(entity, offset, limit)}
