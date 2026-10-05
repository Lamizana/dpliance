"""Orchestration de bout en bout : scope → crawl → graphe → rapport + métriques."""
from __future__ import annotations

import datetime
import json
import os
import time

import httpx

from redteam.agents import crew_graph, single_agent
from redteam.agents.state import AuditState
from redteam.benchmark.metrics import metrics_from_trace
from redteam.report.html import render_html
from redteam.report.markdown import render_markdown
from redteam.safety.audit import export_bundle
from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.signing import SigningKeyError, default_signer
from redteam.tools.crawler import crawl
from redteam.tools.http_client import GuardedHttpClient


def build_state(mode: str, target: str, scope, guard: ScopeGuard, backend, trace,
                transport: httpx.BaseTransport | None = None, surface=None,
                crawl_pages: int = 20, max_replans: int = 1) -> AuditState:
    def client_factory(intensity: Intensity) -> GuardedHttpClient:
        return GuardedHttpClient(guard, intensity,
                                 max_requests=scope.limits.max_requests_per_module,
                                 transport=transport)
    return {
        "run_id": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), "mode": mode,
        "target": target, "surface": surface, "hypotheses": [], "plan": [],
        "raw_findings": [], "confirmed": [], "executed_steps": set(),
        "replans": 0, "max_replans": max_replans, "_verified_count": 0,
        "report_md": "", "backend": backend, "guard": guard, "trace": trace,
        "client_factory": client_factory, "_scope": scope, "_transport": transport,
        "_crawl_pages": crawl_pages,
    }


def _audit_bundle(state: AuditState) -> dict | None:
    """Résumé d'intégrité du journal d'audit, si une trace chaînée existe.

    Au moment du rapport, le checkpoint signé n'est pas encore écrit : le bundle
    rapporte donc honnêtement une chaîne cohérente mais non ancrée (on ne simule
    aucun ancrage). Sans trace ou sans audit (benchmark/tests), retourne None."""
    trace = state.get("trace")
    audit = getattr(trace, "audit", None) if trace is not None else None
    if audit is None:
        return None
    try:
        signer = default_signer()
    except SigningKeyError:
        signer = None
    return export_bundle(audit.path, signer)


async def run_graph(state: AuditState, run_dir: str) -> dict:
    os.makedirs(run_dir, exist_ok=True)
    start = time.monotonic()
    # Recon crawl si la surface n'est pas fournie.
    if state.get("surface") is None:
        client = state["client_factory"](Intensity.PASSIVE)
        try:
            state["surface"] = await crawl(client, state["target"],
                                           max_pages=state.get("_crawl_pages", 20))
        finally:
            await client.aclose()
    module = crew_graph if state["mode"] == "crew" else single_agent
    out = await module.run_audit(state)
    duration = time.monotonic() - start

    scope = state.get("_scope")
    summary = out.get("report_md", "")
    events = state["trace"].events() if state.get("trace") is not None else []
    m = metrics_from_trace(events, duration_s=round(duration, 3))
    md = render_markdown(scope=scope, confirmed=out.get("confirmed", []), summary=summary,
                         audit_bundle=_audit_bundle(state), metrics=m.model_dump())
    with open(os.path.join(run_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(run_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(md))
    with open(os.path.join(run_dir, "state.json"), "w", encoding="utf-8") as fh:
        json.dump({"confirmed": [{"id": v["finding_id"], "title": v["finding"].title,
                                  "status": v["status"], "confidence": v["confidence"]}
                                 for v in out.get("confirmed", [])]}, fh, ensure_ascii=False, indent=2)
    return {"confirmed": out.get("confirmed", []), "metrics": m.model_dump(), "report_md": md}
