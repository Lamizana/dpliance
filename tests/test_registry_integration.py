import datetime
import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.registry import PROBES, get_probe
from redteam.agents.nodes import attacker_node, verify_findings


def test_registry_has_all_probes():
    for pid in ["web.security_headers", "web.availability",
                "tool.nuclei", "tool.nmap", "tool.sqlmap"]:
        assert pid in PROBES and get_probe(pid).id == pid


def _state(monkeypatch):
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.INTRUSIVE, signature="x")
    g = ScopeGuard(s, today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="x",
                                    headers={"server": "nginx"}))
    return {"run_id": "t", "mode": "crew", "guard": g,
            "client_factory": lambda it: GuardedHttpClient(g, it, max_requests=50, transport=transport),
            "trace": None}


async def test_tool_adapter_multi_findings_through_attacker_and_verifier(monkeypatch):
    # nuclei adapter with mocked exec + pretend-installed → 2 findings, both verified
    from redteam.tools.adapters.nuclei import NucleiAdapter
    from pathlib import Path
    sample = (Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl").read_text()
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    async def _exec(argv):
        return (0, sample, "")
    monkeypatch.setattr(NucleiAdapter, "_exec", lambda self, argv: _exec(argv))

    from redteam.safety.domain import Step
    st = _state(monkeypatch)
    st["plan"] = [Step(module_id="tool.nuclei", target="http://localhost/",
                       intensity=Intensity.ACTIVE, description="nuclei")]
    st = await attacker_node(st)
    assert len(st["raw_findings"]) == 2            # multi-findings collected
    verified = await verify_findings(st, st["raw_findings"])
    assert all(v["status"] == "confirmed" for v in verified)  # signatures reproduced
