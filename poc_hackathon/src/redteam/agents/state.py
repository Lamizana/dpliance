"""État partagé du graphe d'audit (LangGraph) et objets associés."""
from __future__ import annotations

from typing import Any, Callable, TypedDict

from pydantic import BaseModel

from redteam.safety.domain import Finding, Step
from redteam.tools.crawler import SurfaceMap


class Hypothesis(BaseModel):
    probe_id: str
    target: str
    rationale: str


class AuditState(TypedDict, total=False):
    run_id: str
    mode: str
    target: str
    surface: SurfaceMap | None
    hypotheses: list[Hypothesis]
    plan: list[Step]
    raw_findings: list[Finding]
    confirmed: list[dict[str, Any]]
    executed_steps: set[tuple[str, str]]
    replans: int
    report_md: str
    # handles d'exécution (non sérialisés dans le rapport)
    backend: Any
    guard: Any
    trace: Any
    client_factory: Callable[..., Any]
    max_replans: int
    # champs internes au runner (déclarés pour que LangGraph ne les filtre pas)
    _scope: Any
    _transport: Any
    _crawl_pages: int
    _verified_count: int
    # feedback injecté avant un replan (steps exécutés + candidats écartés)
    _recon_extra: str
    # titres des candidats écartés par le verifier (feedback de replan)
    _discarded: list[str]
