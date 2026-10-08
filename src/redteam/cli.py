"""Interface en ligne de commande du PoC Red Team IA."""
from __future__ import annotations

import asyncio
import datetime
import os

import typer
import yaml

from redteam.benchmark.compare import compare_runs, load_ground_truth, quality_report
from redteam.benchmark.metrics import RunMetrics, quality
from redteam.config import load_settings
from redteam.llm.backend import FeatherlessBackend, MockBackend
from redteam.monitoring.langsmith import activate_langsmith
from redteam.monitoring.live import LiveConsole
from redteam.monitoring.trace import TraceLog
from redteam.runner import build_state, run_graph
from redteam.safety.audit import AuditLog
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import compute_signature, load_scope
from redteam.safety.signing import SigningKeyError, default_signer

app = typer.Typer(help="Red Team IA — audit cybersécurité adaptatif sous mandat.")

TEMPLATE = "config/scope.template.yaml"
GROUND_TRUTH = "eval/mirage_ground_truth.yaml"


def prepare_scope(target: str):
    """Charge le gabarit, injecte la cible, signe et recharge le scope."""
    # Robustesse PoC : clé de signature éphémère si aucune n'est configurée, afin
    # que signature et vérification du même run utilisent la même clé (cohérence
    # et garantie anti-altération préservées intra-run, sans setup manuel).
    if not (os.getenv("REDTEAM_SIGNING_KEY") or os.getenv("REDSCOPE_SIGNING_KEY")):
        os.environ["REDTEAM_SIGNING_KEY"] = "dev-ephemeral-key"
    with open(TEMPLATE, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    from urllib.parse import urlparse
    host = urlparse(target).hostname or "localhost"
    if host not in data["authorized"]["domains"]:
        data["authorized"]["domains"].append(host)
    data["signature"] = compute_signature(data)
    with open("scope.yaml", "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh)
    scope = load_scope("scope.yaml")
    guard = ScopeGuard(scope, today=datetime.date.today())
    return scope, guard


def _backend(settings, mock: bool):
    if mock or not settings.featherless_api_key:
        return MockBackend(default="(mode mock — pas de clé API)")
    return FeatherlessBackend(settings.featherless_api_key, settings.base_url, settings.model)


@app.command("scope-show")
def scope_show():
    settings = load_settings()
    scope, _ = prepare_scope(settings.target)
    typer.echo(f"Mission : {scope.mission}\nPérimètre : {scope.authorized.domains}")


@app.command()
def run(mode: str = "crew", target: str = "", mock: bool = False):
    settings = load_settings()
    activate_langsmith(settings)  # tracing LangSmith avant le premier appel LLM
    target = target or settings.target
    scope, guard = prepare_scope(target)
    run_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join("runs", f"{mode}-{run_id}")
    os.makedirs(run_dir, exist_ok=True)
    audit = AuditLog(os.path.join(run_dir, "audit.jsonl"))
    trace = TraceLog(os.path.join(run_dir, "trace.jsonl"), run_id=run_id, mode=mode,
                     audit=audit, live=LiveConsole(enabled=True))
    state = build_state(mode=mode, target=target, scope=scope, guard=guard,
                        backend=_backend(settings, mock), trace=trace)
    out = asyncio.run(run_graph(state, run_dir=run_dir))
    try:
        audit.write_checkpoint(default_signer())
    except SigningKeyError:
        typer.echo("Avertissement : checkpoint anti-troncature ignoré (clé de signature "
                   "indisponible) — le journal chaîné reste valide.")
    typer.echo(f"Rapport : {run_dir}/report.md")
    typer.echo(f"Findings confirmés : {out['metrics']['confirmed_count']} | "
               f"faux-positifs écartés : {out['metrics']['discarded_count']}")


@app.command()
def benchmark(modes: str = "single,crew", target: str = "", mock: bool = False):
    settings = load_settings()
    activate_langsmith(settings)  # tracing LangSmith avant le premier appel LLM
    target = target or settings.target
    truth_ids = load_ground_truth(GROUND_TRUTH)
    results: list[RunMetrics] = []
    quality_rows: list[tuple[str, dict]] = []
    for mode in modes.split(","):
        mode = mode.strip()
        scope, guard = prepare_scope(target)
        run_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + mode
        run_dir = os.path.join("runs", f"bench-{run_id}")
        os.makedirs(run_dir, exist_ok=True)
        trace = TraceLog(os.path.join(run_dir, "trace.jsonl"), run_id=run_id, mode=mode,
                         live=LiveConsole(enabled=False))
        state = build_state(mode=mode, target=target, scope=scope, guard=guard,
                            backend=_backend(settings, mock), trace=trace)
        out = asyncio.run(run_graph(state, run_dir=run_dir))
        results.append(RunMetrics(**out["metrics"]))
        confirmed_ids = {v["finding"].module_id for v in out["confirmed"]}
        quality_rows.append((mode, quality(confirmed_ids, truth_ids)))
    table = compare_runs(results) + quality_report(quality_rows)
    with open("runs/benchmark.md", "w", encoding="utf-8") as fh:
        fh.write(table)
    typer.echo(table)
    for mode, q in quality_rows:
        typer.echo(f"[{mode}] précision={q['precision']:.2f} rappel={q['recall']:.2f} "
                   f"F1={q['f1']:.2f}")


if __name__ == "__main__":
    app()
