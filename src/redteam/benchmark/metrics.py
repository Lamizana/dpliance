"""Agrégation des métriques d'un run à partir de sa trace, et qualité vs ground truth."""
from __future__ import annotations

from pydantic import BaseModel

from redteam.monitoring.trace import TraceEvent


class RunMetrics(BaseModel):
    run_id: str
    mode: str
    duration_s: float
    llm_calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    tool_calls: int = 0
    raw_count: int = 0
    confirmed_count: int = 0
    discarded_count: int = 0
    replans: int = 0
    errors: int = 0


def metrics_from_trace(events: list[TraceEvent], duration_s: float) -> RunMetrics:
    run_id = events[0].run_id if events else "?"
    mode = events[0].mode if events else "?"
    m = RunMetrics(run_id=run_id, mode=mode, duration_s=duration_s)
    for e in events:
        if e.type == "llm_call":
            m.llm_calls += 1
            m.tokens_in += e.tokens_in or 0
            m.tokens_out += e.tokens_out or 0
        elif e.type == "tool_call":
            m.tool_calls += 1
        elif e.type == "verification":
            if e.status == "confirmed":
                m.confirmed_count += 1
            elif e.status == "discarded":
                m.discarded_count += 1
        elif e.type == "strategy_change":
            m.replans += 1
        elif e.type == "error":
            m.errors += 1
    m.raw_count = m.confirmed_count + m.discarded_count
    return m


def quality(confirmed_ids: set[str], truth_ids: set[str]) -> dict:
    tp = len(confirmed_ids & truth_ids)
    precision = tp / len(confirmed_ids) if confirmed_ids else 0.0
    recall = tp / len(truth_ids) if truth_ids else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}
