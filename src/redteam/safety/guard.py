from __future__ import annotations

import datetime
import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel

from redteam.safety.domain import Intensity
from redteam.safety.scope import Scope


class ScopeViolation(Exception):
    pass


class GuardDecision(BaseModel):
    allowed: bool
    reason: str


def _host(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()


def _domain_matches(host: str, pattern: str) -> bool:
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


def _ip_in_cidr(host: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


class ScopeGuard:
    def __init__(self, scope: Scope, today: datetime.date):
        self.scope = scope
        self.today = today

    def check(self, target: str, intensity: Intensity) -> GuardDecision:
        host = _host(target)
        for ex in self.scope.excluded:
            ex_lower = ex.lower()
            if host == ex_lower or host.endswith("." + ex_lower) or _domain_matches(host, ex):
                return GuardDecision(allowed=False, reason=f"Cible explicitement exclue : {host}")
        in_domains = any(_domain_matches(host, d) for d in self.scope.authorized.domains)
        in_ips = any(_ip_in_cidr(host, c) for c in self.scope.authorized.ips)
        if not (in_domains or in_ips):
            return GuardDecision(allowed=False, reason=f"Cible hors périmètre autorisé : {host}")
        if not (self.scope.window.start <= self.today <= self.scope.window.end):
            return GuardDecision(allowed=False, reason="Action hors fenêtre temporelle autorisée.")
        if intensity.rank > self.scope.allowed_intensity.rank:
            return GuardDecision(
                allowed=False,
                reason=f"intensité {intensity.value} > plafond ({self.scope.allowed_intensity.value}).",
            )
        return GuardDecision(allowed=True, reason="Autorisé.")

    def authorize(self, target: str, intensity: Intensity) -> None:
        decision = self.check(target, intensity)
        if not decision.allowed:
            raise ScopeViolation(decision.reason)

    def authorize_sandbox(self, target: str) -> None:
        host = _host(target).lower()
        for value in self.scope.sandbox.values():
            v = value.lower()
            if host == v or host.endswith("." + v) or _domain_matches(host, v):
                return
        raise ScopeViolation(f"Cible hors sandbox consentie : {host}")
