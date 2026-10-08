"""Affichage temps réel du raisonnement des agents (console rich)."""
from __future__ import annotations

from redteam.monitoring.trace import TraceEvent


def format_event(e: TraceEvent) -> str:
    bits = [f"[{e.phase}]", e.agent]
    if e.type == "verification":
        bits.append(f"{e.finding_id} {e.severity} → {e.status} ({e.confidence:.2f})")
    elif e.type == "tool_call":
        bits.append(f"outil {e.tool} (req={e.http_count})")
    elif e.type == "llm_call":
        bits.append(f"llm {e.model} (in={e.tokens_in} out={e.tokens_out})")
    elif e.type == "strategy_change":
        bits.append(f"↻ {e.rationale}")
    else:
        bits.append(e.type + (f" — {e.rationale}" if e.rationale else ""))
    return " ".join(str(b) for b in bits)


class LiveConsole:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._console = None
        if enabled:
            try:
                from rich.console import Console
                self._console = Console()
            except Exception:
                self.enabled = False

    def show(self, event: TraceEvent) -> None:
        if self.enabled and self._console is not None:
            self._console.print(format_event(event))
