"""Traçage unifié des décisions, appels d'outils et findings.

Chaque événement est journalisé en JSONL. Les événements critiques sont, en
plus, appendus au journal d'audit chaîné (infalsifiable) pour servir de preuve
de ce que l'IA a réellement fait.
"""
from __future__ import annotations

from pydantic import BaseModel

from redteam.safety.audit import AuditLog

CRITICAL_TYPES = {"decision", "finding", "verification", "strategy_change", "error"}


class TraceEvent(BaseModel):
    ts: str
    run_id: str
    mode: str
    agent: str
    phase: str
    type: str
    model: str | None = None
    prompt_hash: str | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    latency_ms: int | None = None
    tool: str | None = None
    http_count: int | None = None
    finding_id: str | None = None
    severity: str | None = None
    status: str | None = None
    confidence: float | None = None
    rationale: str | None = None


class TraceLog:
    def __init__(self, path: str, run_id: str, mode: str, audit: AuditLog | None = None):
        self.path = path
        self.run_id = run_id
        self.mode = mode
        self.audit = audit

    def emit(self, event: TraceEvent) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(event.model_dump_json() + "\n")
        if self.audit is not None and event.type in CRITICAL_TYPES:
            self.audit.append(event.type, event.agent,
                              {"finding_id": event.finding_id, "status": event.status,
                               "rationale": event.rationale})

    def events(self) -> list[TraceEvent]:
        out: list[TraceEvent] = []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        out.append(TraceEvent.model_validate_json(line))
        except FileNotFoundError:
            pass
        return out
