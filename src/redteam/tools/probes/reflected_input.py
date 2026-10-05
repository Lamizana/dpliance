"""Détecte un reflet non échappé d'un paramètre (candidat XSS réfléchi).

Envoie un marqueur inoffensif et vérifie s'il réapparaît tel quel dans la
réponse. C'est un indicateur de reflet, pas un exploit.
"""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_MARKER = "rtMARKER12345"


class ReflectedInputProbe:
    id = "web.reflected_input"
    intensity = Intensity.ACTIVE
    description = "Détecte le reflet non échappé d'un paramètre (candidat XSS réfléchi)."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        sep = "&" if "?" in target else "?"
        probe_url = f"{target}{sep}q={_MARKER}"
        try:
            resp = await client.get(probe_url)
        except Exception:
            return ProbeResult(found=False, evidence="requête échouée")
        if _MARKER not in resp.text:
            return ProbeResult(found=False, evidence="marqueur non reflété")
        return ProbeResult(
            found=True, evidence=f"marqueur reflété dans la réponse de {probe_url}",
            finding=Finding(module_id=self.id, target=target, severity=Severity.MEDIUM,
                            title="Reflet non échappé d'un paramètre (candidat XSS)",
                            evidence=f"Le marqueur {_MARKER} est renvoyé tel quel.",
                            remediation=Remediation(
                                summary="Échapper/encoder les entrées réfléchies ; CSP.",
                                reference="OWASP — Cross Site Scripting")))
