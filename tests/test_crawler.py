import datetime
import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.crawler import crawl


def _guard():
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]),
                  excluded=[], window=Window(start=datetime.date(2026, 10, 1),
                  end=datetime.date(2026, 12, 31)), allowed_intensity=Intensity.ACTIVE,
                  signature="x")
    return ScopeGuard(scope, today=datetime.date(2026, 11, 1))


PAGES = {
    "/": '<a href="/a">a</a><a href="http://evil.example/x">evil</a>',
    "/a": '<a href="/">home</a>',
}


def _transport():
    def handler(req):
        return httpx.Response(200, text=PAGES.get(req.url.path, ""),
                              headers={"server": "nginx"})
    return httpx.MockTransport(handler)


async def test_crawl_stays_in_host_and_dedups():
    c = GuardedHttpClient(_guard(), Intensity.PASSIVE, max_requests=50, transport=_transport())
    surface = await crawl(c, "http://localhost/", max_pages=10, max_depth=2)
    paths = sorted({p.url for p in surface.pages})
    assert "http://localhost/" in paths and "http://localhost/a" in paths
    assert all("evil.example" not in p.url for p in surface.pages)
    await c.aclose()
