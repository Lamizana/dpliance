"""Adaptateur nmap : services/versions + scripts NSE 'vuln' (jamais 'dos')."""
from __future__ import annotations

from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.adapters.base import ToolAdapter


class NmapAdapter(ToolAdapter):
    id = "tool.nmap"
    intensity = Intensity.ACTIVE
    description = "Scan services/versions + NSE vuln non destructifs (nmap)."
    binary = "nmap"

    def build_argv(self, target: str) -> list[str]:
        host = urlparse(target).hostname or target
        # 'not dos' : on exclut explicitement toute catégorie de déni de service.
        return [self.binary, "-sV", "-Pn", "-T3", "--script", "vuln and not dos",
                "-oX", "-", host]

    def parse(self, stdout: str, target: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return []
        for port in root.iter("port"):
            svc = port.find("service")
            if svc is not None and svc.get("version"):
                name = svc.get("product", svc.get("name", "service"))
                findings.append(Finding(
                    module_id=self.id, target=target, severity=Severity.LOW,
                    title=f"Version exposée : {name} {svc.get('version')}",
                    evidence=f"port {port.get('portid')} — {name} {svc.get('version')}",
                    remediation=Remediation(summary="Masquer les bannières de version.",
                                            reference="OWASP Testing Guide — Fingerprinting")))
            for script in port.findall("script"):
                out = (script.get("output") or "")
                if "VULNERABLE" in out.upper():
                    findings.append(Finding(
                        module_id=self.id, target=target, severity=Severity.HIGH,
                        title=f"NSE {script.get('id')}",
                        evidence=out.strip()[:300],
                        remediation=Remediation(summary="Traiter la vulnérabilité remontée par NSE.",
                                                reference=str(script.get('id')))))
        return findings
