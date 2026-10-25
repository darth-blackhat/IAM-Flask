import asyncio

import pytest

from app.openiam import OpenIAMAuthError, OpenIAMError


def run(coro):
    return asyncio.run(coro)


def test_token_failure_with_http_200_is_an_error(make_client):
    async def go():
        async with make_client(secret="wrong") as c:
            await c.check_auth()
    with pytest.raises(OpenIAMAuthError, match="Bad client credentials"):
        run(go())


def test_token_is_cached_and_refreshed_after_401(fake, make_client):
    async def go():
        async with make_client() as c:
            await c.save_user({"firstName": "A", "lastName": "One"})
            await c.search_users({"lastName": "One"})
            assert fake.tokens_issued == 1
            fake.expire_tokens()
            page = await c.search_users({"lastName": "One"})
            assert fake.tokens_issued == 2
            return page
    assert len(run(go())["beans"]) == 1


def test_refusal_with_http_200_raises(make_client):
    async def go():
        async with make_client() as c:
            await c.user_action("disable", "nope", reason="test")
    with pytest.raises(OpenIAMError) as e:
        run(go())
    assert e.value.status == 404
    assert e.value.errors[0]["error"] == "USER_NOT_FOUND"


def test_empty_search_bean_raises(make_client):
    async def go():
        async with make_client() as c:
            await c.search_users({})
    with pytest.raises(OpenIAMError, match="no search criteria"):
        run(go())


def test_iter_users_pages_and_limits(fake, make_client):
    async def go():
        async with make_client() as c:
            for i in range(7):
                await c.save_user({"firstName": f"U{i}", "lastName": "Page"})
            everyone = [u async for u in c.iter_users({"lastName": "Page"}, page_size=3)]
            limited = [u async for u in c.iter_users({"lastName": "Page"}, page_size=3, limit=4)]
            return everyone, limited
    everyone, limited = run(go())
    assert len(everyone) == 7 and len({u["id"] for u in everyone}) == 7
    assert len(limited) == 4


@pytest.mark.parametrize("path", ["/etc/passwd", "/webconsole/rest/api/../../admin", "/webconsole/other"])
def test_raw_rejects_paths_outside_rest_api(make_client, path):
    async def go():
        async with make_client() as c:
            await c.raw("GET", path)
    with pytest.raises(ValueError):
        run(go())
