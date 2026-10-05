"""Sonde de disponibilité (ACTIVE) : prouve un RISQUE de déni de service SANS l'exploiter.

Remplaçant responsable d'un module DoS : aucune mise en charge, aucun flood, aucune
répétition. Seulement quelques GET budgétés qui constatent des faiblesses connues
(xmlrpc.php exposé, absence d'indice de limitation de débit, absence d'empreinte de WAF).
On DÉTECTE le risque qui mènerait à un déni de service, on ne le déclenche jamais :
le service n'est ni stressé ni mis à terre.
"""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

# Indices d'une limitation de débit observable (un seul suffit à écarter le finding).
_RATE_LIMIT_HINTS = (
    "ratelimit-limit", "ratelimit-remaining", "x-ratelimit-limit",
    "x-rate-limit-limit", "retry-after",
)
# Empreintes d'un pare-feu applicatif / CDN protecteur (un seul suffit).
_WAF_HEADER_HINTS = (
    "cf-ray", "x-sucuri-id", "x-sucuri-cache", "x-akamai-transformed",
    "x-cdn", "x-waf", "x-amz-cf-id", "x-datadome",
)
_WAF_SERVER_TOKENS = ("cloudflare", "sucuri", "akamai", "incapsula", "awselb", "big-ip")

_DOS_REF = "OWASP — Denial of Service Cheat Sheet"


class AvailabilityProbe:
    id = "web.availability"
    intensity = Intensity.ACTIVE
    description = ("Détecte des faiblesses menant à un déni de service (xmlrpc.php "
                   "exposé, pas de limitation de débit observable, pas de WAF) "
                   "sans jamais mettre le service en charge.")

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        base = target.rstrip("/")
        findings: list[Finding] = []

        # 1) xmlrpc.php exposé — amplificateur DoS bien connu (un seul GET, pas de POST).
        try:
            resp = await client.get(base + "/xmlrpc.php")
        except Exception:
            resp = None
        if resp is not None and resp.status_code != 404:
            findings.append(Finding(
                module_id=self.id, target=target, severity=Severity.MEDIUM,
                title="Point xmlrpc.php exposé (amplification DoS possible)",
                evidence=f"/xmlrpc.php répond (statut {resp.status_code}) au lieu de 404",
                remediation=Remediation(
                    summary="Bloquer ou désactiver xmlrpc.php s'il n'est pas requis.",
                    reference=_DOS_REF)))

        # 2) racine : indice de limitation de débit + empreinte WAF (un seul GET).
        try:
            root = await client.get(base + "/")
        except Exception:
            root = None
        if root is not None:
            headers = {k.lower(): v for k, v in root.headers.items()}
            if not any(h in headers for h in _RATE_LIMIT_HINTS):
                findings.append(Finding(
                    module_id=self.id, target=target, severity=Severity.MEDIUM,
                    title="Aucune limitation de débit observable",
                    evidence=("aucun en-tête de limitation de débit "
                              "(RateLimit-*, Retry-After) dans la réponse"),
                    remediation=Remediation(
                        summary=("Appliquer une limitation de débit par IP/clé "
                                 "au niveau du proxy ou de l'application."),
                        reference=_DOS_REF)))
            server = headers.get("server", "").lower()
            has_waf = (any(h in headers for h in _WAF_HEADER_HINTS)
                       or any(t in server for t in _WAF_SERVER_TOKENS))
            if not has_waf:
                findings.append(Finding(
                    module_id=self.id, target=target, severity=Severity.LOW,
                    title="Aucune empreinte de WAF détectée",
                    evidence="aucun en-tête révélant un pare-feu applicatif / CDN protecteur",
                    remediation=Remediation(
                        summary=("Placer un WAF/CDN devant le service pour absorber "
                                 "les pics de trafic malveillant."),
                        reference=_DOS_REF)))

        evidence = ("; ".join(f.title for f in findings) if findings
                    else "aucune faiblesse de disponibilité détectée")
        return ProbeResult(found=bool(findings), evidence=evidence, findings=findings)
