"""Détecte la divulgation de versions via l'en-tête Server / X-Powered-By."""
from __future__ import annotations

import re

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_VERSION = re.compile(r"\d+\.\d+")


class VersionDisclosureProbe:
    id = "web.version_disclosure"
    intensity = Intensity.PASSIVE
    description = "Détecte une version logicielle exposée dans les en-têtes."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        try:
            resp = await client.get(target)
        except Exception:
            return ProbeResult(found=False, evidence="requête échouée")
        banners = {h: resp.headers.get(h, "") for h in ("server", "x-powered-by")}
        disclosed = {h: v for h, v in banners.items() if v and _VERSION.search(v)}
        if not disclosed:
            return ProbeResult(found=False, evidence=f"bannières : {banners}")
        ev = "; ".join(f"{h}: {v}" for h, v in disclosed.items())
        return ProbeResult(
            found=True, evidence=ev,
            finding=Finding(module_id=self.id, target=target, severity=Severity.LOW,
                            title="Divulgation de version logicielle",
                            evidence=ev,
                            remediation=Remediation(
                                summary="Masquer les numéros de version dans les en-têtes.",
                                reference="OWASP Testing Guide — Fingerprinting")))
