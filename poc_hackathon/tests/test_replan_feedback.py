"""Régression P1 : la replanification en mode crew DOIT relancer le LLM.

Sans cela, le replan est un tour de manège vide (constat 2 d'audit/06) : il
incrémente un compteur puis repasse par un planner qui rejoue tout, sans jamais
proposer de nouvelle hypothèse. Les traces réelles montraient « 0 étapes » à
chaque replan.
"""
import datetime

import httpx

from redteam.agents import crew_graph
from redteam.agents.prompts import RECON_SYSTEM
from redteam.llm.backend import LLMResult, MockBackend
from redteam.monitoring.trace import TraceLog
from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Authorized, Scope, Window
from redteam.tools.crawler import Page, SurfaceMap
from redteam.tools.http_client import GuardedHttpClient


class CountingBackend(MockBackend):
    """MockBackend qui journalise (system, user) et peut séquencer ses réponses."""

    def __init__(self, responses=None, default="résumé", sequence=None):
        super().__init__(responses=responses, default=default)
        self.calls: list[dict] = []
        self._sequence = list(sequence or [])

    def complete(self, system: str, user: str) -> LLMResult:
        if system == RECON_SYSTEM and self._sequence:
            text = self._sequence.pop(0)
        else:
            text = super().complete(system, user).text
        self.calls.append({"system": system, "user": user, "text": text})
        return LLMResult(text=text, model="mock", tokens_in=1, tokens_out=1, latency_ms=1)


def _state(backend, trace, max_replans=1):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
                  window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
                  allowed_intensity=Intensity.ACTIVE, signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(lambda req: httpx.Response(
        200, text="x", headers={"server": "nginx/1.2"}))
    surface = SurfaceMap(pages=[Page(url="http://localhost/", status=200,
                         headers={"server": "nginx/1.2"}, body_snippet="x")], links=[])
    return {
        "run_id": "t", "mode": "crew", "target": "http://localhost/", "surface": surface,
        "hypotheses": [], "plan": [], "raw_findings": [], "confirmed": [],
        "replans": 0, "max_replans": max_replans, "report_md": "",
        "backend": backend, "guard": guard, "trace": trace,
        "client_factory": lambda intensity: GuardedHttpClient(guard, intensity,
                          max_requests=50, transport=transport),
    }


_FIRST = ('[{"probe_id":"web.security_headers","target":"http://localhost/",'
          '"rationale":"no headers"},'
          '{"probe_id":"web.version_disclosure","target":"http://localhost/",'
          '"rationale":"banner"}]')

_FRESH = ('[{"probe_id":"web.availability","target":"http://localhost/",'
          '"rationale":"new angle after feedback"}]')


def _recon_calls(backend):
    return [c for c in backend.calls if c["system"] == RECON_SYSTEM]


async def test_replan_rellms_with_feedback(tmp_path):
    trace = TraceLog(str(tmp_path / "trace.jsonl"), run_id="t", mode="crew")
    backend = CountingBackend(sequence=[_FIRST, _FRESH])
    out = await crew_graph.run_audit(_state(backend, trace))

    recon_calls = _recon_calls(backend)
    assert len(recon_calls) >= 2, (
        "le replan n'a jamais relancé le LLM recon "
        f"(appels : {[(c['system'][:20], c['user'][:30]) for c in backend.calls]})")

    # Le user message du replan porte le feedback « déjà testé ».
    feedback_user = recon_calls[-1]["user"].lower()
    assert ("already" in feedback_user or "executed" in feedback_user
            or "déjà" in feedback_user), "feedback « déjà testé » absent du replan"

    # La trace reflète le 2e appel LLM recon (visible côté monitoring).
    llm_events = [e for e in trace.events() if e.type == "llm_call"]
    assert len(llm_events) >= 2, "2e appel LLM recon non tracé"

    # L'hypothèse NEUVE proposée au replan a bien été exécutée.
    tools = {e.tool for e in trace.events() if e.type == "tool_call"}
    assert "web.availability" in tools, "la nouvelle hypothèse du replan n'a pas été planifiée"

    assert out["report_md"]
    assert out["replans"] == 1


async def test_replan_no_new_hypothesis_ends_in_report(tmp_path):
    """Le 2e recon ne propose rien de neuf → reporter, sans double exécution."""
    trace = TraceLog(str(tmp_path / "trace.jsonl"), run_id="t", mode="crew")
    # Tous les retours recon donnent les MÊMES hypothèses (déjà exécutées).
    backend = CountingBackend(sequence=[_FIRST, _FIRST])
    out = await crew_graph.run_audit(_state(backend, trace, max_replans=2))

    tool_calls = [e for e in trace.events() if e.type == "tool_call"]
    tools = sorted(e.tool for e in tool_calls)
    assert tools == sorted(set(tools)) == ["web.security_headers", "web.version_disclosure"], \
        "rejeu détecté lors d'un replan sans nouvelle hypothèse"
    assert out["report_md"]
    assert out["replans"] == 1  # plus rien à vérifier → route report, pas 2e replan


async def test_replan_feedback_mentions_discarded_when_present(tmp_path):
    """Le feedback signale aussi les candidats écartés par le verifier."""
    trace = TraceLog(str(tmp_path / "trace.jsonl"), run_id="t", mode="crew")
    # La 1re hypothèse ne se reproduit pas au rejeu → discarded.
    backend = CountingBackend(sequence=[_FIRST, _FRESH])
    await crew_graph.run_audit(_state(backend, trace))

    recon_users = [c["user"] for c in _recon_calls(backend)]
    assert len(recon_users) >= 2
    last = recon_users[-1].lower()
    assert "already" in last or "executed" in last or "déjà" in last
