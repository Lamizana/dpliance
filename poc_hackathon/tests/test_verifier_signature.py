import datetime
import httpx

from redteam.safety.domain import Intensity, Finding, Severity, Remediation
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult
from redteam.tools.registry import PROBES
from redteam.agents.nodes import verify_findings, finding_signature


def _guard():
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.INTRUSIVE, signature="x")
    return ScopeGuard(s, today=datetime.date(2026, 11, 1))


def _fake_probe(probe_id, probe_intensity, titles_on_rerun):
    class _P:
        id = probe_id
        intensity = probe_intensity
        description = "fake"
        async def run(self, client, target):
            fs = [Finding(module_id=probe_id, target=target, severity=Severity.MEDIUM,
                          title=t, evidence="e",
                          remediation=Remediation(summary="s", reference="r"))
                  for t in titles_on_rerun]
            return ProbeResult(found=bool(fs), evidence="rerun", findings=fs)
    return _P()


def _state(transport=None):
    g = _guard()
    return {"guard": g, "target": "http://localhost/",
            "client_factory": lambda it: GuardedHttpClient(g, it, max_requests=50,
                                                            transport=transport or httpx.MockTransport(
                                                                lambda r: httpx.Response(200)))}


def _cand(probe_id, title):
    return Finding(module_id=probe_id, target="http://localhost/", severity=Severity.MEDIUM,
                   title=title, evidence="e", remediation=Remediation(summary="s", reference="r"))


async def test_signature_confirmed_and_discarded(monkeypatch):
    # rerun re-signals only "A" (not "B") for probe p1
    p1 = _fake_probe("p1", Intensity.ACTIVE, ["A"])
    monkeypatch.setitem(PROBES, "p1", p1)
    out = await verify_findings(_state(), [_cand("p1", "A"), _cand("p1", "B")])
    by_title = {v["finding"].title: v["status"] for v in out}
    assert by_title == {"A": "confirmed", "B": "discarded"}


def test_finding_signature_shape():
    f = _cand("p1", "A")
    assert finding_signature(f) == ("p1", "http://localhost/", "A")
