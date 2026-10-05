"""Détecte l'absence d'en-têtes de sécurité (preuve = en-têtes reçus)."""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_REQUIRED = ["strict-transport-security", "content-security-policy",
             "x-frame-options", "x-content-type-options"]


class SecurityHeadersProbe:
    id = "web.security_headers"
    intensity = Intensity.PASSIVE
    description = "Vérifie la présence des en-têtes de sécurité HTTP standard."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        try:
            resp = await client.get(target)
        except Exception:
            return ProbeResult(found=False, evidence="requête échouée")
        present = {k.lower() for k in resp.headers.keys()}
        missing = [h for h in _REQUIRED if h not in present]
        if not missing:
            return ProbeResult(found=False, evidence="tous les en-têtes présents")
        return ProbeResult(
            found=True, evidence=f"en-têtes manquants : {', '.join(missing)}",
            finding=Finding(module_id=self.id, target=target, severity=Severity.MEDIUM,
                            title="En-têtes de sécurité manquants",
                            evidence=f"Manquants : {', '.join(missing)}",
                            remediation=Remediation(
                                summary="Ajouter HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
                                reference="OWASP Secure Headers Project")))
