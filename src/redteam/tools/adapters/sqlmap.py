"""Adaptateur sqlmap (INTRUSIF) : prouve l'exploitabilité SQLi sans exfiltrer de données.

JAMAIS de --dump : on confirme l'injection + on lit un identifiant anodin (--banner)
comme preuve d'accès. Palier intrusive → confirmation explicite requise en amont.
"""
from __future__ import annotations

import re

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.adapters.base import ToolAdapter

_INJECTABLE = re.compile(r"parameter '([^']+)' is .*injectable", re.IGNORECASE)
_PARAM_LINE = re.compile(r"Parameter:\s*([^\s(]+)", re.IGNORECASE)


class SqlmapAdapter(ToolAdapter):
    id = "tool.sqlmap"
    intensity = Intensity.INTRUSIVE
    description = "Preuve d'exploitation SQLi (sans dump de données)."
    binary = "sqlmap"
    timeout = 300.0

    def build_argv(self, target: str) -> list[str]:
        return [self.binary, "-u", target, "--batch", "--crawl=0", "--level=2",
                "--risk=1", "--technique=BEUST", "--flush-session", "--banner"]

    def parse(self, stdout: str, target: str) -> list[Finding]:
        params: list[str] = _INJECTABLE.findall(stdout) or _PARAM_LINE.findall(stdout)
        if not params:
            return []
        banner = ""
        m = re.search(r"banner:\s*'([^']+)'", stdout)
        if m:
            banner = f" ; bannière SGBD : {m.group(1)}"
        seen: list[str] = []
        findings: list[Finding] = []
        for p in params:
            if p in seen:
                continue
            seen.append(p)
            findings.append(Finding(
                module_id=self.id, target=target, severity=Severity.HIGH,
                title=f"Injection SQL confirmée (paramètre {p})",
                evidence=f"paramètre '{p}' injectable (sqlmap){banner}",
                remediation=Remediation(
                    summary="Requêtes paramétrées / ORM ; valider et échapper les entrées.",
                    reference="OWASP — SQL Injection")))
        return findings
