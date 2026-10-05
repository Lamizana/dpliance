"""Graphe multi-agents (crew) : recon → planner → attacker → verifier → reporter,
avec une boucle de replanification bornée (adaptativité)."""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from redteam.agents.nodes import (attacker_node, now_iso, planner_node, recon_node,
                                   reporter_node, verifier_node)
from redteam.agents.state import AuditState
from redteam.monitoring.trace import TraceEvent


async def _maybe_replan(state: AuditState) -> AuditState:
    # Boucle d'adaptativité : au plus max_replans tours.
    state["replans"] = state.get("replans", 0)
    return state


def _route_after_verify(state: AuditState) -> str:
    if state.get("replans", 0) < state.get("max_replans", 1) and state.get("raw_findings"):
        return "replan"
    return "report"


async def _replan_node(state: AuditState) -> AuditState:
    state["replans"] = state.get("replans", 0) + 1
    trace = state.get("trace")
    if trace is not None:
        trace.emit(TraceEvent(ts=now_iso(), run_id=state["run_id"], mode=state["mode"],
                              agent="planner", phase="plan", type="strategy_change",
                              rationale=f"replanification #{state['replans']}"))
    return state


def build_crew_graph():
    g = StateGraph(AuditState)
    g.add_node("recon", recon_node)
    g.add_node("planner", planner_node)
    g.add_node("attacker", attacker_node)
    g.add_node("verifier", verifier_node)
    g.add_node("replan", _replan_node)
    g.add_node("reporter", reporter_node)
    g.add_edge(START, "recon")
    g.add_edge("recon", "planner")
    g.add_edge("planner", "attacker")
    g.add_edge("attacker", "verifier")
    g.add_conditional_edges("verifier", _route_after_verify,
                            {"replan": "replan", "report": "reporter"})
    g.add_edge("replan", "attacker")
    g.add_edge("reporter", END)
    return g.compile()


async def run_audit(state: AuditState) -> AuditState:
    # recursion_limit évite toute boucle infinie même si la condition change.
    return await build_crew_graph().ainvoke(state, config={"recursion_limit": 25})
