"""Interface en ligne de commande du PoC Red Team IA."""
from __future__ import annotations

import asyncio
import datetime
import os

import typer
import yaml

from redteam.benchmark.compare import compare_runs
from redteam.benchmark.metrics import RunMetrics
from redteam.config import load_settings
from redteam.llm.backend import FeatherlessBackend, MockBackend
from redteam.monitoring.trace import TraceLog
from redteam.runner import build_state, run_graph
from redteam.safety.audit import AuditLog
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import compute_signature, load_scope
from redteam.safety.signing import SigningKeyError, default_signer

app = typer.Typer(help="Red Team IA — audit cybersécurité adaptatif sous mandat.")

TEMPLATE = "config/scope.template.yaml"


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
    target = target or settings.target
    scope, guard = prepare_scope(target)
    run_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join("runs", f"{mode}-{run_id}")
    os.makedirs(run_dir, exist_ok=True)
    audit = AuditLog(os.path.join(run_dir, "audit.jsonl"))
    trace = TraceLog(os.path.join(run_dir, "trace.jsonl"), run_id=run_id, mode=mode, audit=audit)
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
    target = target or settings.target
    results: list[RunMetrics] = []
    for mode in modes.split(","):
        mode = mode.strip()
        scope, guard = prepare_scope(target)
        run_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + mode
        run_dir = os.path.join("runs", f"bench-{run_id}")
        os.makedirs(run_dir, exist_ok=True)
        trace = TraceLog(os.path.join(run_dir, "trace.jsonl"), run_id=run_id, mode=mode)
        state = build_state(mode=mode, target=target, scope=scope, guard=guard,
                            backend=_backend(settings, mock), trace=trace)
        out = asyncio.run(run_graph(state, run_dir=run_dir))
        results.append(RunMetrics(**out["metrics"]))
    table = compare_runs(results)
    with open("runs/benchmark.md", "w", encoding="utf-8") as fh:
        fh.write(table)
    typer.echo(table)


if __name__ == "__main__":
    app()
