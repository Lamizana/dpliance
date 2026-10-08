import datetime
import httpx

from redteam.safety.domain import Intensity
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


async def test_security_headers_probe_flags_missing():
    c = _client(lambda req: httpx.Response(200, text="x", headers={"server": "nginx"}))
    res = await get_probe("web.security_headers").run(c, "http://localhost/")
    assert res.found and res.finding is not None
    await c.aclose()


async def test_reflected_input_probe_detects_marker():
    c = _client(lambda req: httpx.Response(200, text="echo " + req.url.params.get("q", "")))
    res = await get_probe("web.reflected_input").run(c, "http://localhost/search")
    assert res.found
    await c.aclose()


async def test_reflected_input_probe_no_reflection():
    c = _client(lambda req: httpx.Response(200, text="static page"))
    res = await get_probe("web.reflected_input").run(c, "http://localhost/search")
    assert not res.found
    await c.aclose()
