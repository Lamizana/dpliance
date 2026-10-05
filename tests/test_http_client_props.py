import datetime
from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient


def _guard():
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.INTRUSIVE, signature="x")
    return ScopeGuard(s, today=datetime.date(2026, 11, 1))


def test_exposes_guard_and_intensity():
    g = _guard()
    c = GuardedHttpClient(g, Intensity.ACTIVE, max_requests=5)
    assert c.guard is g
    assert c.intensity is Intensity.ACTIVE
