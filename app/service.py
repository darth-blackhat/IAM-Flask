import asyncio

from .config import Settings
from .logs import logger
from .openiam import OpenIAMClient, OpenIAMError
from .schemas import BulkInjectResult, InjectResult, UserIn


async def inject_user(client: OpenIAMClient, settings: Settings, user: UserIn, *,
                      dry_run: bool = False, index: int | None = None) -> InjectResult:
    """Create or update one user in OpenIAM, then apply any role/group/org entitlements."""
    payload = user.to_openiam(settings)
    if dry_run:
        return InjectResult(index=index, ok=True, dry_run=True, user_id=user.id,
                            created=user.id is None)
    try:
        resp = await client.save_user(payload)
    except OpenIAMError as e:
        return InjectResult(index=index, ok=False, error=str(e), error_codes=e.errors)

    user_id = (resp.get("contextValues") or {}).get("userId") or user.id
    result = InjectResult(index=index, ok=True, user_id=user_id, created=user.id is None,
                          account_states=_as_text(resp.get("successMessage")))

    if user.has_entitlements():
        if not user_id:
            result.ok = False
            result.entitled = False
            result.error = "user saved but OpenIAM returned no userId, so entitlements were skipped"
            return result
        try:
            await client.entitle(user_id, role_ids=user.role_ids, group_ids=user.group_ids,
                                 organization_ids=user.organization_ids,
                                 resource_ids=user.resource_ids)
            result.entitled = True
        except OpenIAMError as e:
            # The user exists now; report the partial failure instead of hiding it.
            result.ok = False
            result.entitled = False
            result.error = f"user saved, entitlement failed: {e}"
            result.error_codes = e.errors
    return result


async def inject_users(client: OpenIAMClient, settings: Settings, users: list[UserIn], *,
                       dry_run: bool = False, concurrency: int = 4) -> BulkInjectResult:
    sem = asyncio.Semaphore(max(concurrency, 1))

    async def one(i: int, u: UserIn) -> InjectResult:
        async with sem:
            return await inject_user(client, settings, u, dry_run=dry_run, index=i)

    results = await asyncio.gather(*(one(i, u) for i, u in enumerate(users)))
    succeeded = sum(r.ok for r in results)
    if not dry_run:
        logger.info("bulk inject: {} of {} users succeeded", succeeded, len(results))
    return BulkInjectResult(total=len(results), succeeded=succeeded,
                            failed=len(results) - succeeded, results=list(results))


def _as_text(value) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return str(value)
