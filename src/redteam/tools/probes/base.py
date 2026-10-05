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


@runtime_checkable
class Probe(Protocol):
    id: str
    intensity: Intensity
    description: str

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult: ...
