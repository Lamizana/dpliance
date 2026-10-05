"""Graphe mono-agent (généraliste) : une seule passe recon→act→verify→report.

Partage exactement les mêmes outils et le même Verifier que le mode crew, pour
une comparaison « toutes choses égales par ailleurs »."""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from redteam.agents.nodes import (attacker_node, planner_node, recon_node,
                                   reporter_node, verifier_node)
from redteam.agents.state import AuditState


async def _single_node(state: AuditState) -> AuditState:
    state = await recon_node(state)
    state = await planner_node(state)
    state = await attacker_node(state)
    state = await verifier_node(state)
    state = await reporter_node(state)
    return state


def build_single_graph():
    g = StateGraph(AuditState)
    g.add_node("single", _single_node)
    g.add_edge(START, "single")
    g.add_edge("single", END)
    return g.compile()


async def run_audit(state: AuditState) -> AuditState:
    return await build_single_graph().ainvoke(state, config={"recursion_limit": 10})
