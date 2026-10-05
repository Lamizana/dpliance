import datetime
import httpx

from redteam.safety.domain import Intensity, Finding, Severity, Remediation
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.agents.nodes import verify_findings, confidence_score


def _state(handler):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
                  window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
                  allowed_intensity=Intensity.ACTIVE, signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(handler)
    return {"guard": guard, "target": "http://localhost/",
            "client_factory": lambda intensity: _mk(guard, intensity, transport)}


def _mk(guard, intensity, transport):
    from redteam.tools.http_client import GuardedHttpClient
    return GuardedHttpClient(guard, intensity, max_requests=50, transport=transport)


def _fake_finding(probe_id):
    return Finding(module_id=probe_id, target="http://localhost/", severity=Severity.MEDIUM,
                   title="En-têtes de sécurité manquants", evidence="e",
                   remediation=Remediation(summary="s", reference="r"))


async def test_confirmed_when_evidence_reproduced():
    # headers manquants -> la sonde retrouve la preuve au rejeu
    state = _state(lambda req: httpx.Response(200, text="x", headers={"server": "nginx"}))
    out = await verify_findings(state, [_fake_finding("web.security_headers")])
    assert len(out) == 1 and out[0]["status"] == "confirmed"


async def test_discarded_when_no_evidence():
    # tous les en-têtes présents -> aucune preuve au rejeu -> faux positif écarté
    hdrs = {"strict-transport-security": "x", "content-security-policy": "x",
            "x-frame-options": "x", "x-content-type-options": "x"}
    state = _state(lambda req: httpx.Response(200, text="x", headers=hdrs))
    out = await verify_findings(state, [_fake_finding("web.security_headers")])
    assert all(o["status"] == "discarded" for o in out)


def test_confidence_weights_evidence():
    assert confidence_score(1.0, False) < confidence_score(0.0, True)
