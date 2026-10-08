"""Détecte une politique CORS permissive (Origin reflété ou wildcard)."""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_ORIGIN = "https://evil.example"


class CorsProbe:
    id = "web.cors"
    intensity = Intensity.ACTIVE
    description = "Vérifie si la cible réfléchit un Origin arbitraire (CORS permissif)."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        try:
            resp = await client.get(target, headers={"Origin": _ORIGIN})
        except Exception:
            return ProbeResult(found=False, evidence="requête échouée")
        acao = (resp.headers.get("access-control-allow-origin") or "").strip()
        if not acao:
            return ProbeResult(found=False, evidence="pas d'Access-Control-Allow-Origin")
        creds = (resp.headers.get("access-control-allow-credentials") or "").lower() == "true"
        reflected = acao in (_ORIGIN, "null")
        if not (reflected or acao == "*"):
            return ProbeResult(found=False, evidence=f"ACAO restreint : {acao}")
        if reflected and creds:
            sev, why = Severity.HIGH, f"Origin reflété avec credentials : {acao}"
        elif reflected:
            sev, why = Severity.MEDIUM, f"Origin reflété : {acao}"
        else:
            sev, why = Severity.MEDIUM, "wildcard (*) sans credentials"
        return ProbeResult(
            found=True, evidence=why,
            finding=Finding(module_id=self.id, target=target, severity=sev,
                            title="Politique CORS permissive",
                            evidence=f"ACAO={acao}, credentials={creds} (Origin envoyé : {_ORIGIN})",
                            remediation=Remediation(
                                summary="Limiter Access-Control-Allow-Origin aux origines de confiance.",
                                reference="OWASP — CORS")))
