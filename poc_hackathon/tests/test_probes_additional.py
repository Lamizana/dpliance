import datetime
import httpx

from redteam.safety.domain import Intensity, Severity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.registry import get_probe


def _client(handler):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]),
                  excluded=[], window=Window(start=datetime.date(2026, 10, 1),
                  end=datetime.date(2026, 12, 31)), allowed_intensity=Intensity.ACTIVE,
                  signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    return GuardedHttpClient(guard, Intensity.ACTIVE, max_requests=50,
                             transport=httpx.MockTransport(handler))


async def test_cors_reflected_with_credentials_is_high():
    c = _client(lambda r: httpx.Response(200, headers={
        "access-control-allow-origin": r.headers.get("origin", ""),
        "access-control-allow-credentials": "true"}))
    res = await get_probe("web.cors").run(c, "http://localhost/")
    assert res.found and res.finding.severity is Severity.HIGH
    await c.aclose()


async def test_cors_absent_is_clean():
    c = _client(lambda r: httpx.Response(200, text="x"))
    res = await get_probe("web.cors").run(c, "http://localhost/")
    assert not res.found
    await c.aclose()


async def test_cookies_missing_flags_flags_session_httponly():
    c = _client(lambda r: httpx.Response(200, headers={
        "set-cookie": "sessionid=abc; Path=/"}))
    res = await get_probe("web.cookies").run(c, "http://localhost/")
    assert res.found and res.finding.severity is Severity.HIGH
    await c.aclose()


async def test_cookies_complete_flags_is_clean():
    c = _client(lambda r: httpx.Response(200, headers={
        "set-cookie": "sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"}))
    res = await get_probe("web.cookies").run(c, "http://localhost/")
    assert not res.found
    await c.aclose()


async def test_wellknown_flags_sensitive_disallow():
    def handler(r):
        if r.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /backup\nDisallow: /css\n")
        return httpx.Response(404, text="")
    c = _client(handler)
    res = await get_probe("web.wellknown").run(c, "http://localhost/")
    assert res.found and "/backup" in res.evidence and "/css" not in res.evidence
    await c.aclose()
