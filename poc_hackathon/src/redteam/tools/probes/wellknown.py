"""Analyse robots.txt et la présence de .well-known/security.txt (divulgation)."""
from __future__ import annotations

import re

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_DISALLOW = re.compile(r"(?im)^disallow:\s*(/\S*)")
_SENSITIVE = re.compile(r"(admin|backup|private|internal|staging|debug|\.git|\.env|config)",
                        re.IGNORECASE)


class WellKnownProbe:
    id = "web.wellknown"
    intensity = Intensity.PASSIVE
    description = "Examine robots.txt (chemins sensibles) et security.txt."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        base = target.rstrip("/")
        try:
            resp = await client.get(base + "/robots.txt")
        except Exception:
            return ProbeResult(found=False, evidence="requête échouée")
        hits: list[str] = []
        if resp.status_code == 200 and resp.text.strip():
            hits = [p for p in _DISALLOW.findall(resp.text) if _SENSITIVE.search(p)]
        try:
            sec = await client.get(base + "/.well-known/security.txt")
            sec_ok = sec.status_code == 200 and "contact:" in sec.text.lower()
        except Exception:
            sec_ok = False
        if not hits:
            ev = ("robots.txt sans chemin sensible ; security.txt "
                  + ("présent" if sec_ok else "absent"))
            return ProbeResult(found=False, evidence=ev)
        ev = f"robots.txt expose : {', '.join(hits)} (security.txt {'présent' if sec_ok else 'absent'})"
        return ProbeResult(
            found=True, evidence=ev,
            finding=Finding(module_id=self.id, target=target, severity=Severity.LOW,
                            title="Chemin sensible exposé par robots.txt",
                            evidence=ev,
                            remediation=Remediation(
                                summary="Retirer ces chemins de robots.txt et les protéger côté serveur.",
                                reference="OWASP — Information Leakage")))
