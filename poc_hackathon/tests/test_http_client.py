import datetime
import httpx
import pytest

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard, ScopeViolation
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient, RequestBudgetExceeded


def _guard():
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=["127.0.0.1/32"]),
                  excluded=[], window=Window(start=datetime.date(2026, 10, 1),
                  end=datetime.date(2026, 12, 31)), allowed_intensity=Intensity.ACTIVE,
                  signature="x")
    return ScopeGuard(scope, today=datetime.date(2026, 11, 1))


def _transport():
    return httpx.MockTransport(lambda req: httpx.Response(200, text="ok"))


async def test_in_scope_request_ok():
    c = GuardedHttpClient(_guard(), Intensity.PASSIVE, max_requests=10, transport=_transport())
    r = await c.get("http://localhost/x")
    assert r.status_code == 200
    await c.aclose()


async def test_out_of_scope_refused():
    c = GuardedHttpClient(_guard(), Intensity.PASSIVE, max_requests=10, transport=_transport())
    with pytest.raises(ScopeViolation):
        await c.get("http://evil.example/x")
    await c.aclose()


async def test_budget_enforced():
    c = GuardedHttpClient(_guard(), Intensity.PASSIVE, max_requests=1, transport=_transport())
    await c.get("http://localhost/a")
    with pytest.raises(RequestBudgetExceeded):
        await c.get("http://localhost/b")
    await c.aclose()
