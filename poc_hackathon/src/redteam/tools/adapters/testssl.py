"""Adaptateur testssl.sh : audit TLS (protocoles + défauts), mono-cible.

testssl.sh écrit son JSON flat sur stderr (--jsonfile /dev/stderr) pour ne pas
mélanger avec l'affichage écran : ToolAdapter.result_stream = "stderr".
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.adapters.base import ToolAdapter

# ids de testssl.sh qui portent une information exploitable (le reste est bruit).
_KEEP_IDS = {"protocol", "server_defaults", "rc4", "beast", "poodle", "heartbleed",
             "robot", "renegotiation", "hsts", "vulns", "rc4_2016", "triple_des"}

_SEVERITY = {"FATAL": Severity.HIGH, "CRITICAL": Severity.HIGH, "MUTUAL": Severity.HIGH,
             "WARN": Severity.MEDIUM, "INFO": Severity.LOW, "OK": None}


class TestsslAdapter(ToolAdapter):
    id = "tool.testssl"
    intensity = Intensity.ACTIVE
    description = "Audit TLS (testssl.sh) : protocoles et défauts serveur, mono-cible."
    binary = "testssl.sh"
    timeout = 300.0
    result_stream = "stderr"

    def build_argv(self, target: str) -> list[str]:
        p = urlparse(target)
        hostport = p.hostname or target
        if p.port:
            hostport = f"{hostport}:{p.port}"
        return [self.binary, "--quiet", "--color", "0", "--warnings", "off",
                "--connect-timeout", "10", "--openssl-timeout", "10",
                "-p", "--jsonfile", "/dev/stderr", hostport]

    def parse(self, stderr: str, target: str) -> list[Finding]:
        text = stderr.strip()
        start, end = text.find("["), text.rfind("]")
        if start < 0 or end <= start:
            return []
        try:
            entries = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for e in entries if isinstance(entries, list) else []:
            if not isinstance(e, dict) or e.get("id") not in _KEEP_IDS:
                continue
            sev = _SEVERITY.get(str(e.get("severity", "")).upper())
            if sev is None:
                continue
            findings.append(Finding(
                module_id=self.id, target=target, severity=sev,
                title=f"TLS : {e['id']}",
                evidence=str(e.get("finding", ""))[:300],
                remediation=Remediation(
                    summary="Durcir la configuration TLS (protocoles, en-têtes, cipher).",
                    reference="OWASP — Transport Layer Security Cheat Sheet")))
        return findings
