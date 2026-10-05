"""AvailabilityProbe : prouve un RISQUE de DoS sans jamais mettre le service en charge.

Pas de mise en charge, pas de flood, pas de répétition : les tests vérifient aussi
que la sonde n'émet qu'une poignée de GET budgétés (détection, pas d'attaque).
"""
import datetime

import httpx

from redteam.safety.domain import Intensity, Severity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Authorized, Scope, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.availability import AvailabilityProbe


def _client(handler):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]),
                  excluded=[], window=Window(start=datetime.date(2026, 10, 1),
                  end=datetime.date(2026, 12, 31)), allowed_intensity=Intensity.ACTIVE,
                  signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    return GuardedHttpClient(guard, Intensity.ACTIVE, max_requests=50,
                             transport=httpx.MockTransport(handler))


def _vulnerable(req):
    # xmlrpc.php exposé (405 typique), racine sans rate-limit ni empreinte WAF.
    if req.url.path == "/xmlrpc.php":
        return httpx.Response(405, text="XML-RPC server accepts POST requests only.")
    return httpx.Response(200, text="home", headers={"server": "nginx"})


def _clean(req):
    # xmlrpc.php absent (404), racine protégée (rate-limit + empreinte WAF).
    if req.url.path == "/xmlrpc.php":
        return httpx.Response(404, text="not found")
    return httpx.Response(200, text="home",
                          headers={"x-ratelimit-limit": "100", "cf-ray": "7d-CDG"})


async def test_probe_is_active_and_detection_only():
    probe = AvailabilityProbe()
    assert probe.id == "web.availability"
    assert probe.intensity is Intensity.ACTIVE


async def test_flags_weaknesses_without_load():
    c = _client(_vulnerable)
    res = await AvailabilityProbe().run(c, "http://localhost/")
    assert res.found
    findings = res.all_findings()
    titles = [f.title for f in findings]
    severities = {f.severity for f in findings}
    # xmlrpc exposé -> MEDIUM ; pas de rate-limit -> MEDIUM ; pas de WAF -> LOW.
    assert any("xmlrpc" in t.lower() for t in titles)
    assert Severity.MEDIUM in severities and Severity.LOW in severities
    # DÉTECTION SEULEMENT : une poignée de GET, aucune mise en charge/flood.
    assert c.count == 2
    await c.aclose()


async def test_clean_target_has_no_findings():
    c = _client(_clean)
    res = await AvailabilityProbe().run(c, "http://localhost/")
    assert not res.found
    assert res.all_findings() == []
    assert c.count == 2
    await c.aclose()
