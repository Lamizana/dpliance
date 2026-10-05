"""Nœuds du graphe d'audit : recon, planner, attacker, verifier, reporter.

Principe : les nœuds LLM (recon/planner/reporter) raisonnent ; attacker/verifier
exécutent des sondes déterministes. Aucune vuln n'est retenue sans preuve
reproductible (verifier).
"""
from __future__ import annotations

import datetime

from redteam.agents.parsing import extract_json_list
from redteam.agents.prompts import RECON_SYSTEM, REPORTER_SYSTEM
from redteam.agents.state import AuditState, Hypothesis
from redteam.monitoring.trace import TraceEvent
from redteam.safety.domain import Finding, Step
from redteam.tools.registry import PROBES, get_probe


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def confidence_score(llm_claim: float, has_evidence: bool) -> float:
    return 0.3 * llm_claim + 0.7 * (1.0 if has_evidence else 0.0)


def _emit(state: AuditState, **kw) -> None:
    trace = state.get("trace")
    if trace is not None:
        trace.emit(TraceEvent(ts=now_iso(), run_id=state["run_id"], mode=state["mode"], **kw))


async def recon_node(state: AuditState) -> AuditState:
    surface = state.get("surface")
    summary = "" if surface is None else "\n".join(
        f"{p.url} [{p.status}] server={p.headers.get('server', '')}" for p in surface.pages[:30])
    res = state["backend"].complete(RECON_SYSTEM, f"Surface map:\n{summary}")
    _emit(state, agent="recon", phase="recon", type="llm_call", model=res.model,
          tokens_in=res.tokens_in, tokens_out=res.tokens_out, latency_ms=res.latency_ms)
    hyps: list[Hypothesis] = []
    for item in extract_json_list(res.text):
        pid = item.get("probe_id")
        if pid in PROBES:
            hyps.append(Hypothesis(probe_id=pid, target=item.get("target", state["target"]),
                                   rationale=item.get("rationale", "")))
    if not hyps:  # repli sûr : si le LLM n'a rien proposé d'exploitable, on teste tout
        hyps = [Hypothesis(probe_id=pid, target=state["target"], rationale="repli")
                for pid in PROBES]
    state["hypotheses"] = hyps
    _emit(state, agent="recon", phase="recon", type="decision",
          rationale=f"{len(hyps)} hypothèses retenues")
    return state


async def planner_node(state: AuditState) -> AuditState:
    hyps = state.get("hypotheses", [])
    state["plan"] = [Step(module_id=h.probe_id, target=h.target,
                          intensity=PROBES[h.probe_id].intensity, description=h.rationale)
                     for h in hyps if state["guard"].check(h.target, PROBES[h.probe_id].intensity).allowed]
    _emit(state, agent="planner", phase="plan", type="decision",
          rationale=f"{len(state['plan'])} étapes dans le périmètre")
    return state


async def attacker_node(state: AuditState) -> AuditState:
    raw: list[Finding] = []
    for step in state.get("plan", []):
        probe = get_probe(step.module_id)
        client = state["client_factory"](probe.intensity)
        try:
            result = await probe.run(client, step.target)
        finally:
            await client.aclose()
        _emit(state, agent="attacker", phase="act", type="tool_call", tool=probe.id,
              http_count=client.count, rationale=step.description)
        if result.found and result.finding is not None:
            raw.append(result.finding)
    state["raw_findings"] = raw
    return state


async def verify_findings(state: AuditState, raw: list[Finding]) -> list[dict]:
    verified: list[dict] = []
    for i, finding in enumerate(raw):
        probe = get_probe(finding.module_id)
        client = state["client_factory"](probe.intensity)
        try:
            recheck = await probe.run(client, finding.target)
        finally:
            await client.aclose()
        has_evidence = recheck.found
        status = "confirmed" if has_evidence else "discarded"
        conf = confidence_score(1.0, has_evidence)
        verified.append({"finding": finding, "status": status, "confidence": conf,
                         "evidence": recheck.evidence, "finding_id": f"F{i + 1}"})
    return verified


async def verifier_node(state: AuditState) -> AuditState:
    verified = await verify_findings(state, state.get("raw_findings", []))
    for v in verified:
        _emit(state, agent="verifier", phase="verify", type="verification",
              finding_id=v["finding_id"], severity=v["finding"].severity.value,
              status=v["status"], confidence=v["confidence"],
              rationale=v["evidence"][:120])
    state["confirmed"] = [v for v in verified if v["status"] == "confirmed"]
    return state


async def reporter_node(state: AuditState) -> AuditState:
    confirmed = state.get("confirmed", [])
    listing = "\n".join(f"- [{v['finding'].severity.value}] {v['finding'].title}" for v in confirmed)
    res = state["backend"].complete(REPORTER_SYSTEM, f"Findings confirmés:\n{listing or 'aucun'}")
    _emit(state, agent="reporter", phase="report", type="llm_call", model=res.model,
          tokens_in=res.tokens_in, tokens_out=res.tokens_out, latency_ms=res.latency_ms)
    state["report_md"] = res.text
    return state
