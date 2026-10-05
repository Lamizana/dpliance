"""Base des adaptateurs d'outils externes.

Un outil (nuclei, nmap, sqlmap) est un binaire qui fait ses propres appels réseau
et échappe donc au GuardedHttpClient. Le confinement est assuré AVANT lancement :
autorisation de la cible par le ScopeGuard, cible unique, timeout, et skip propre
si le binaire n'est pas installé.
"""
from __future__ import annotations

import asyncio
import shutil

from redteam.safety.domain import Finding, Intensity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult


class ToolAdapter:
    id: str = "tool.base"
    intensity: Intensity = Intensity.ACTIVE
    description: str = ""
    binary: str = ""
    timeout: float = 120.0
    max_output: int = 1_000_000

    def build_argv(self, target: str) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str, target: str) -> list[Finding]:
        raise NotImplementedError

    async def _exec(self, argv: list[str]) -> tuple[int, str, str]:
        """Lance le binaire, borné par timeout ; renvoie (code, stdout, stderr)."""
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except (asyncio.TimeoutError, TimeoutError):
            proc.kill()
            raise TimeoutError(f"{self.binary} a dépassé le délai de {self.timeout}s")
        return (proc.returncode or 0,
                out.decode("utf-8", "replace")[: self.max_output],
                err.decode("utf-8", "replace")[: self.max_output])

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        # Confinement : autoriser la cible AVANT tout lancement (le binaire sortirait
        # sinon du périmètre sans arbitrage possible).
        client.guard.authorize(target, client.intensity)
        if shutil.which(self.binary) is None:
            return ProbeResult(found=False, evidence=f"{self.binary} non installé (sonde sautée)")
        try:
            _rc, out, _err = await self._exec(self.build_argv(target))
        except TimeoutError as exc:
            return ProbeResult(found=False, evidence=f"timeout : {exc}")
        except Exception as exc:  # noqa: BLE001 - un outil qui échoue ne casse pas l'audit
            return ProbeResult(found=False, evidence=f"échec d'exécution : {exc}")
        findings = self.parse(out, target)
        evidence = f"{self.binary}: {len(findings)} résultat(s)" if findings else f"{self.binary}: aucun résultat"
        return ProbeResult(found=bool(findings), evidence=evidence, findings=findings)
