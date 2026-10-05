import datetime
import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.crawler import SurfaceMap, Page
from redteam.llm.backend import MockBackend
from redteam.agents import crew_graph, single_agent


def _base_state(mode):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
                  window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
                  allowed_intensity=Intensity.ACTIVE, signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="x",
                                    headers={"server": "nginx/1.2"}))
    surface = SurfaceMap(pages=[Page(url="http://localhost/", status=200,
                         headers={"server": "nginx/1.2"}, body_snippet="x")], links=[])
    recon_json = ('[{"probe_id":"web.security_headers","target":"http://localhost/",'
                  '"rationale":"no headers"}]')
    return {
        "run_id": "t", "mode": mode, "target": "http://localhost/", "surface": surface,
        "hypotheses": [], "plan": [], "raw_findings": [], "confirmed": [], "replans": 0,
        "max_replans": 1, "report_md": "",
        "backend": MockBackend(responses={"Surface map": recon_json}, default="résumé"),
        "guard": guard, "trace": None,
        "client_factory": lambda intensity: GuardedHttpClient(guard, intensity,
                          max_requests=50, transport=transport),
    }


async def test_crew_graph_runs_end_to_end():
    out = await crew_graph.run_audit(_base_state("crew"))
    assert out["report_md"]
    assert len(out["confirmed"]) >= 1  # headers manquants confirmés


async def test_single_graph_runs_end_to_end():
    out = await single_agent.run_audit(_base_state("single"))
    assert out["report_md"]
