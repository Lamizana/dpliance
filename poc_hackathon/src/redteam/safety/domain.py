from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel


class Intensity(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"

    @property
    def rank(self) -> int:
        return {"passive": 0, "active": 1, "intrusive": 2}[self.value]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Remediation(BaseModel):
    summary: str
    reference: str


class Finding(BaseModel):
    module_id: str
    target: str
    severity: Severity
    title: str
    evidence: str
    remediation: Remediation


class Step(BaseModel):
    module_id: str
    target: str
    intensity: Intensity
    description: str


@runtime_checkable
class Module(Protocol):
    id: str
    intensity: Intensity
    category: str
    requires: list[str]

    def plan(self, target: str, ctx: dict) -> list[Step]: ...
    def run(self, target: str, ctx: dict) -> list[Finding]: ...
