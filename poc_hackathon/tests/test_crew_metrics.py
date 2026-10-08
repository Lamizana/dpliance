"""Régression : en mode crew, la boucle de replanification ne doit PAS
double-compter les événements de trace. Les métriques agrégées depuis une vraie
TraceLog doivent refléter la réalité d'une seule passe attaque+vérification.
"""
import datetime

import httpx

from redteam.agents import crew_graph
from redteam.benchmark.metrics import metrics_from_trace
from redteam.llm.backend import MockBackend
from redteam.monitoring.trace import TraceLog
from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Authorized, Scope, Window
from redteam.tools.crawler import Page, SurfaceMap
from redteam.tools.http_client import GuardedHttpClient


def _state(mode, trace):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
                  window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
                  allowed_intensity=Intensity.ACTIVE, signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(lambda req: httpx.Response(
        200, text="x", headers={"server": "nginx/1.2"}))
    surface = SurfaceMap(pages=[Page(url="http://localhost/", status=200,
                         headers={"server": "nginx/1.2"}, body_snippet="x")], links=[])
    # Deux hypothèses distinctes : on doit observer exactement 2 tool_call (une passe).
    recon_json = ('[{"probe_id":"web.security_headers","target":"http://localhost/",'
                  '"rationale":"no headers"},'
                  '{"probe_id":"web.version_disclosure","target":"http://localhost/",'
                  '"rationale":"server banner"}]')
    return {
        "run_id": "t", "mode": mode, "target": "http://localhost/", "surface": surface,
        "hypotheses": [], "plan": [], "raw_findings": [], "confirmed": [],
        "replans": 0, "max_replans": 1, "report_md": "",
        "backend": MockBackend(responses={"Surface map": recon_json}, default="résumé"),
        "guard": guard, "trace": trace,
        "client_factory": lambda intensity: GuardedHttpClient(guard, intensity,
                          max_requests=50, transport=transport),
    }


async def test_crew_trace_metrics_not_doubled(tmp_path):
    trace = TraceLog(str(tmp_path / "trace.jsonl"), run_id="t", mode="crew")
    out = await crew_graph.run_audit(_state("crew", trace))

    events = trace.events()
    tool_calls = [e for e in events if e.type == "tool_call"]
    verifications = [e for e in events if e.type == "verification"]

    # Chaque sonde n'est exécutée qu'une fois (pas de rejeu lors de la replanif).
    tools = [e.tool for e in tool_calls]
    assert len(tools) == len(set(tools)) == 2

    # Chaque candidat n'est vérifié qu'une fois (identifiants uniques).
    ids = [e.finding_id for e in verifications]
    assert len(ids) == len(set(ids))

    # Les métriques agrégées depuis la trace == la réalité de l'état final.
    m = metrics_from_trace(events, 0.0)
    assert m.tool_calls == len(set(tools))
    assert m.confirmed_count == len(out["confirmed"])
    assert m.confirmed_count >= 1  # en-têtes manquants confirmés
