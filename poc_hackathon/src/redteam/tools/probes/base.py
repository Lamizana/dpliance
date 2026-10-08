"""Contrat commun des sondes de détection."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from redteam.safety.domain import Finding, Intensity
from redteam.tools.http_client import GuardedHttpClient


class ProbeResult(BaseModel):
    found: bool
    evidence: str
    finding: Finding | None = None
    findings: list[Finding] = []

    def all_findings(self) -> list[Finding]:
        """Findings du run : la liste si fournie, sinon le finding unique, sinon []."""
        if self.findings:
            return self.findings
        return [self.finding] if self.finding is not None else []


@runtime_checkable
class Probe(Protocol):
    id: str
    intensity: Intensity
    description: str

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult: ...
