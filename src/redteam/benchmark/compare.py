"""Tableau comparatif Markdown entre plusieurs runs (mono vs crew, modèle A/B)."""
from __future__ import annotations

from redteam.benchmark.metrics import RunMetrics


def compare_runs(metrics: list[RunMetrics]) -> str:
    cols = ["mode", "duration_s", "llm_calls", "tokens_in", "tokens_out",
            "tool_calls", "confirmed_count", "discarded_count", "replans", "errors"]
    lines = ["| " + " | ".join(["run_id"] + cols) + " |",
             "| " + " | ".join(["---"] * (len(cols) + 1)) + " |"]
    for m in metrics:
        row = [m.run_id] + [str(getattr(m, c)) for c in cols]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"
