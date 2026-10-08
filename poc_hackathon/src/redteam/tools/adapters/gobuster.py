"""Adaptateur gobuster : découverte de contenu (mode dir), sortie texte, preuve = statut HTTP.

Wordlist maison bornée (`tools/wordlists/top-paths.txt`, ~90 entrées) : le volume de
requêtes reste sous le budget du scope et le Verifier peut rejouer le scan sans
montée en charge. Threads bas + délai entre requêtes, mono-cible, pas de follow-redirect.
"""
from __future__ import annotations

import re
from pathlib import Path

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.adapters.base import ToolAdapter

WORDLIST = Path(__file__).resolve().parents[1] / "wordlists" / "top-paths.txt"

# Sortie gobuster : "/admin                  (Status: 200) [Size: 123] [--> /login]"
_LINE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d{3})\)(?:\s+\[Size:\s*(?P<size>\d+)\])?")

_HIGH = re.compile(r"(\.git|\.env|\.htpasswd|\.svn|dump|backup|config|adminer|phpmyadmin)",
                   re.IGNORECASE)


class GobusterAdapter(ToolAdapter):
    id = "tool.gobuster"
    intensity = Intensity.ACTIVE
    description = "Découverte de contenu par wordlist bornée (gobuster)."
    binary = "gobuster"
    timeout = 300.0

    def build_argv(self, target: str) -> list[str]:
        # -q : sorties propres (résultats seuls) ; --no-color : parse prévisible ;
        # -t 5 + --delay 100ms : borné ; pas de -r (follow-redirect hors hôte) ni -x.
        return [self.binary, "dir", "-u", target, "-w", str(WORDLIST),
                "-q", "--no-color", "-t", "5", "--delay", "100ms"]

    def parse(self, stdout: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        for line in stdout.splitlines():
            m = _LINE.match(line.strip())
            if not m:
                continue
            # gobuster imprime le chemin relatif parfois sans "/" initial : on le
            # normalise pour que le titre (donc la signature de rejeu) soit stable.
            path = "/" + m.group("path").lstrip("/")
            status = int(m.group("status"))
            size = m.group("size") or "?"
            title = f"Chemin exposé : {path}"
            signature = (self.id, target, title)
            if signature in seen:
                continue
            seen.add(signature)
            if status in (200, 201) and _HIGH.search(path):
                sev = Severity.HIGH
            elif status in (200, 201):
                sev = Severity.MEDIUM
            else:  # 3xx/401/403 : existence du chemin, contenu non confirmé
                sev = Severity.LOW
            findings.append(Finding(
                module_id=self.id, target=target, severity=sev, title=title,
                evidence=f"statut {status}, taille {size} — {target.rstrip('/')}{path}",
                remediation=Remediation(
                    summary="Restreindre l'accès à ce chemin (404/403) s'il est interne.",
                    reference="OWASP — Content Discovery")))
        return findings
