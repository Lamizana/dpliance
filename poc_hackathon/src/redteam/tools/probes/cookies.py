"""Inspecte les flags de sécurité des cookies (HttpOnly / Secure / SameSite)."""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_SESSION = ("session", "sess", "sid", "auth", "token", "jwt")


class CookiesProbe:
    id = "web.cookies"
    intensity = Intensity.PASSIVE
    description = "Vérifie les flags HttpOnly/Secure/SameSite des cookies renvoyés."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        try:
            resp = await client.get(target)
        except Exception:
            return ProbeResult(found=False, evidence="requête échouée")
        cookies = resp.headers.get_list("set-cookie")
        if not cookies:
            return ProbeResult(found=False, evidence="aucun Set-Cookie")
        issues: list[str] = []
        session_missing_httponly = False
        for c in cookies:
            name = c.split("=", 1)[0].strip().lower()
            low = c.lower()
            missing = [f for f, k in (("HttpOnly", "httponly"), ("Secure", "secure"),
                                      ("SameSite", "samesite")) if k not in low]
            if missing:
                issues.append(f"{name} : sans {', '.join(missing)}")
            if any(t in name for t in _SESSION) and "httponly" not in low:
                session_missing_httponly = True
        if not issues:
            return ProbeResult(found=False, evidence=f"{len(cookies)} cookie(s), flags complets")
        sev = Severity.HIGH if session_missing_httponly else Severity.MEDIUM
        return ProbeResult(
            found=True, evidence=f"cookies à risque : {'; '.join(issues)}",
            finding=Finding(module_id=self.id, target=target, severity=sev,
                            title="Cookies sans flags de sécurité",
                            evidence="; ".join(issues),
                            remediation=Remediation(
                                summary="Poser HttpOnly, Secure et SameSite sur tous les cookies.",
                                reference="OWASP — Session Management")))
