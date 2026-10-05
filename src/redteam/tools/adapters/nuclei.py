"""Adaptateur nuclei : détection par templates, sortie JSONL, preuve reproductible."""
from __future__ import annotations

import json

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.adapters.base import ToolAdapter

_SEV = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
        "high": Severity.HIGH, "critical": Severity.CRITICAL}


class NucleiAdapter(ToolAdapter):
    id = "tool.nuclei"
    intensity = Intensity.ACTIVE
    description = "Détection de vulnérabilités par templates (nuclei)."
    binary = "nuclei"

    def build_argv(self, target: str) -> list[str]:
        return [self.binary, "-target", target, "-jsonl", "-silent", "-no-color",
                "-rate-limit", "50", "-severity", "info,low,medium,high,critical"]

    def parse(self, stdout: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()  # signatures déjà émises dans ce run
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue  # ligne bruitée : on ignore, on ne casse pas
            info = obj.get("info", {})
            tid = obj.get("template-id", "unknown")
            sev = _SEV.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            matched = obj.get("matched-at", target)
            ref = (info.get("reference") or ["nuclei"])
            title = f"{info.get('name', tid)} [{tid}]"
            # Dédoublonnage par signature (module_id, target, title) : un même template
            # matché à plusieurs endroits ne doit pas gonfler confirmed_count. On garde
            # la première occurrence et on préserve l'ordre d'apparition.
            signature = (self.id, target, title)
            if signature in seen:
                continue
            seen.add(signature)
            findings.append(Finding(
                module_id=self.id, target=target, severity=sev,
                title=title,
                evidence=f"matched-at: {matched} ({obj.get('matcher-name', '')})".strip(),
                remediation=Remediation(summary="Corriger selon le template nuclei.",
                                        reference=ref[0] if isinstance(ref, list) else str(ref))))
        return findings
