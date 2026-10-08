"""Tableau comparatif Markdown entre plusieurs runs (mono vs crew, modèle A/B)."""
from __future__ import annotations

import yaml

from redteam.benchmark.metrics import RunMetrics


def load_ground_truth(path: str) -> set[str]:
    """Charge l'ensemble des `probe_id` connus (vérité terrain) depuis un YAML."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return {item["probe_id"] for item in data.get("known_findings", [])
            if item.get("probe_id")}


def quality_report(rows: list[tuple[str, dict]]) -> str:
    """Bloc Markdown précision/rappel/F1 par mode (qualité objective vs vérité terrain)."""
    lines = ["", "## Qualité vs vérité terrain", "",
             "| mode | précision | rappel | F1 |",
             "| --- | --- | --- | --- |"]
    for mode, q in rows:
        lines.append(f"| {mode} | {q['precision']:.2f} | {q['recall']:.2f} | {q['f1']:.2f} |")
    return "\n".join(lines) + "\n"


def compare_runs(metrics: list[RunMetrics]) -> str:
    cols = ["mode", "duration_s", "llm_calls", "tokens_in", "tokens_out",
            "tool_calls", "confirmed_count", "discarded_count", "replans", "errors"]
    lines = ["| " + " | ".join(["run_id"] + cols) + " |",
             "| " + " | ".join(["---"] * (len(cols) + 1)) + " |"]
    for m in metrics:
        row = [m.run_id] + [str(getattr(m, c)) for c in cols]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"
