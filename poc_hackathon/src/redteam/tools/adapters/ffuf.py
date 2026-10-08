"""Adaptateur ffuf : découverte de contenu à la racine, débit borné (non-DoS)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.adapters.base import ToolAdapter
from redteam.tools.probes.base import ProbeResult


class FfufAdapter(ToolAdapter):
    id = "tool.ffuf"
    intensity = Intensity.ACTIVE
    description = "Découverte de contenu (ffuf), rate-limité — jamais de récursion."
    binary = "ffuf"
    timeout = 180.0
    wordlist = "/opt/wordlists/ffuf-raft-small.txt"

    def build_argv(self, target: str) -> list[str]:
        p = urlparse(target)
        base = f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
        return [
            self.binary, "-u", f"{base}/FUZZ", "-w", self.wordlist,
            "-rate", "20", "-t", "5", "-timeout", "10", "-maxtime", "120",
            "-mc", "200,204,301,302,307,401,403,405,500",
            "-non-recursive", "-s",
            "-of", "json", "-o", "/dev/stdout",
        ]

    async def run(self, client, target: str) -> ProbeResult:
        # Autorisation d'abord (invariant du confinement), puis wordlist :
        # jamais de lancement ffuf avec un -w inexistant.
        client.guard.authorize(target, client.intensity)
        if not Path(self.wordlist).is_file():
            return ProbeResult(found=False, evidence="wordlist absente (sonde sautée)")
        return await super().run(client, target)

    def parse(self, stdout: str, target: str) -> list[Finding]:
        results = _extract_results(stdout)
        findings: list[Finding] = []
        for r in results:
            status = int(r.get("status") or 0)
            if status in (401, 403):
                sev, title = Severity.MEDIUM, "Endpoint protégé découvert"
            elif status in (200, 204):
                sev, title = Severity.MEDIUM, "Chemin exposé"
            elif status in (301, 302, 307):
                sev, title = Severity.LOW, "Redirection racine"
            elif status == 405:
                sev, title = Severity.LOW, "Méthode HTTP inattendue"
            else:
                continue
            findings.append(Finding(
                module_id=self.id, target=target, severity=sev, title=title,
                evidence=f"{r.get('url', '')} → {status} ({r.get('length', 0)} octets)",
                remediation=Remediation(
                    summary="Restreindre l'accès à ce chemin (401/403/404).",
                    reference="OWASP WSTG — Content Discovery")))
        return findings


def _extract_results(text: str) -> list[dict]:
    """Extrait la liste `results` du JSON ffuf, tolérant aux lignes d'UI."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    return data.get("results", []) if isinstance(data, dict) else []
