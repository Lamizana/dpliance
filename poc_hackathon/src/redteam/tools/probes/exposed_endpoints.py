"""Teste un petit jeu de chemins sensibles courants (preuve = statut 200)."""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_PATHS = ["/.git/config", "/.env", "/server-status", "/phpinfo.php"]


class ExposedEndpointsProbe:
    id = "web.exposed_endpoints"
    intensity = Intensity.ACTIVE
    description = "Vérifie l'exposition de fichiers/endpoints sensibles courants."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        base = target.rstrip("/")
        hits: list[str] = []
        for path in _PATHS:
            try:
                resp = await client.get(base + path)
            except Exception:
                continue
            if resp.status_code == 200 and resp.text.strip():
                hits.append(path)
        if not hits:
            return ProbeResult(found=False, evidence="aucun endpoint sensible accessible")
        ev = f"accessibles (200) : {', '.join(hits)}"
        return ProbeResult(
            found=True, evidence=ev,
            finding=Finding(module_id=self.id, target=target, severity=Severity.HIGH,
                            title="Fichiers/endpoints sensibles exposés",
                            evidence=ev,
                            remediation=Remediation(
                                summary="Bloquer l'accès public à ces chemins (403/404).",
                                reference="OWASP — Sensitive Data Exposure")))
