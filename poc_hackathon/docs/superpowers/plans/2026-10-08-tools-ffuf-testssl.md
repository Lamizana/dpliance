# Outils ffuf + testssl.sh — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter deux adaptateurs d'outils réels (`tool.ffuf` découverte de contenu, `tool.testssl` audit TLS) au registre des sondes, avec bornes non-DoS, intégration LLM et image Docker.

**Architecture:** Chaque outil est une sous-classe de `ToolAdapter` (contrat `Probe` existant) : confinement pré-lancement hérité, mono-cible, `parse()` → `list[Finding]`, rejeu par le `Verifier`. Un ajout rétrocompatible dans `base.py` (`result_stream`) permet à testssl d'écrire son JSON sur `stderr`.

**Tech Stack:** Python 3.11, pytest/pytest-asyncio (`asyncio_mode=auto`), uv, Docker (Debian bookworm), ruff.

**Spec:** `docs/superpowers/specs/2026-10-08-tools-ffuf-testssl-design.md`

## Global Constraints

- Intensité maximale des deux nouveaux outils : `active` (plafond signé du scope, jamais `intrusive`).
- ffuf : `-rate 20`, `-t 5`, `-maxtime 120`, `-timeout 10`, `-non-recursive`, **jamais** `-r`, jamais de récursion, mono-hôte (`scheme://host[:port]/FUZZ`).
- testssl : **uniquement** `-p` (protocoles), `--connect-timeout 10`, `--openssl-timeout 10`, mono-hôte `host[:port]`, JSON via `--jsonfile /dev/stderr`.
- Aucun flag destructif/brute-force (`-X POST`, `--dump`, catégorie `dos` interdits).
- Suite de tests **100 % offline** : aucun test ne lance un binaire réel (pattern `shutil.which` mocké).
- Code en anglais, documentation en français.
- Pas de secret dans l'image (`.env` déjà exclu par `.dockerignore`).
- **Aucun `git commit` sans demande explicite de l'utilisateur** — les étapes « Commit » sont des points d'arrêt facultatifs (décocher tant que non demandé).
- Commandes exécutées depuis `/home/alex/Code/Neoloji/poc_hackathon`.

## Review Focus

1. **Sortie ffuf sale** — ffuf écrit son JSON mélangé à des lignes d'UI : `parse` doit extraire le sous-bloc JSON. *Test : `test_parse_tolerates_ui_noise`.*
2. **`result_stream` casse les adaptateurs existants** — le hook doit lire `stdout` par défaut. *Tests : `test_result_stream_defaults_to_stdout` + toute la suite existante (nuclei/nmap/sqlmap).*
3. **URL cible avec chemin/port** — `build_argv` doit produire `scheme://host[:port]/FUZZ` (jamais le chemin `/fr/`, jamais d'hôte secondaire). *Test : `test_build_argv_keeps_port_and_drops_path`.*
4. **Wordlist absente à l'exécution** — ffuf doit sauter proprement **après** autorisation, sans lancer le binaire. *Test : `test_missing_wordlist_skips_before_exec` + `test_wordlist_missing_still_authorizes`.*
5. **Outils jamais planifiés** — si `tool.ffuf`/`tool.testssl` ne sont pas littéralement dans les prompts, le LLM ne les proposera jamais. *Test : `test_prompts_list_new_tool_ids`.*

---

### Task 1: Hook `result_stream` dans `ToolAdapter`

**Files:**
- Modify: `src/redteam/tools/adapters/base.py` (attribut de classe + sélection du flux dans `run`)
- Test: `tests/test_adapter_base.py`

**Interfaces:**
- Consumes: `ToolAdapter.run()` existant, `_exec()` → `tuple[int, str, str]` (rc, stdout, stderr).
- Produces: attribut de classe `ToolAdapter.result_stream: str` (défaut `"stdout"`) ; `run()` choisit le flux avant `self.parse(text, target)`. La tâche 3 (`TestsslAdapter`) s'appuie sur `result_stream = "stderr"`.

- [x] **Step 1: Écrire le test qui échoue**

Ajouter en fin de `tests/test_adapter_base.py` :

```python
async def test_result_stream_defaults_to_stdout():
    assert getattr(_FakeAdapter, "result_stream", None) == "stdout"


async def test_result_stream_stderr_reads_stderr(monkeypatch):
    class _ErrAdapter(_FakeAdapter):
        result_stream = "stderr"

    seen = {}

    def _parse(self, text, target):
        seen["text"] = text
        return []

    a = _ErrAdapter()
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    monkeypatch.setattr(_ErrAdapter, "parse", _parse)
    monkeypatch.setattr(_ErrAdapter, "_exec", lambda self, argv: _ok_screen_and_json())
    res = await a.run(_client(), "http://localhost/")
    assert res.found is False          # parse a renvoyé []
    assert seen["text"] == "JSON-BLOB"  # lu sur stderr, pas sur stdout


async def _ok_screen_and_json():
    return (0, "SCREEN-OUTPUT", "JSON-BLOB")
```

- [x] **Step 2: Vérifier l'échec**

Run: `.venv/bin/python -m pytest tests/test_adapter_base.py -v`
Expected: FAIL — `AttributeError: type object '_FakeAdapter' has no attribute 'result_stream'` (ou test vert car `getattr` retourne `None` → assertion échoue) ; le 2ᵉ test échoue sur `seen["text"] == "SCREEN-OUTPUT"`.

- [x] **Step 3: Implémenter**

Dans `src/redteam/tools/adapters/base.py`, dans `class ToolAdapter:` après `max_output` :

```python
    # Flux dont `run()` alimente `parse()` : "stdout" par défaut ; "stderr" pour
    # les outils qui écrivent leur sortie machine sur stderr (testssl.sh).
    result_stream: str = "stdout"
```

Et dans `run()`, remplacer :

```python
        findings = self.parse(out, target)
```

par :

```python
        text = _err if self.result_stream == "stderr" else out
        findings = self.parse(text, target)
```

- [x] **Step 4: Vérifier le passage**

Run: `.venv/bin/python -m pytest tests/test_adapter_base.py -v`
Expected: PASS (tous les tests du fichier, y compris les 4 préexistants).

- [x] **Step 5: Vérifier la non-régression globale**

Run: `.venv/bin/python -m pytest -q`
Expected: `67 passed` (65 + 2).

- [ ] **Step 6: Commit** *(facultatif — seulement si l'utilisateur le demande)*

```bash
git add src/redteam/tools/adapters/base.py tests/test_adapter_base.py
git commit -m "feat(adapters): add result_stream hook to ToolAdapter"
```

---

### Task 2: Adaptateur ffuf

**Files:**
- Create: `tests/fixtures/ffuf_sample.json`
- Create: `tests/test_adapter_ffuf.py`
- Create: `src/redteam/tools/adapters/ffuf.py`

**Interfaces:**
- Consumes: `ToolAdapter` (Task 1 : `result_stream="stdout"` par défaut), `Finding/Severity/Remediation` (`src/redteam/safety/domain.py`), `ProbeResult` (`src/redteam/tools/probes/base.py`).
- Produces: `FfufAdapter` avec `id = "tool.ffuf"`, `intensity = Intensity.ACTIVE`, `binary = "ffuf"`, `wordlist = "/opt/wordlists/ffuf-raft-small.txt"`, `run()` surcharge (skip wordlist). Enregistré en Tâche 4.

- [x] **Step 1: Créer la fixture** `tests/fixtures/ffuf_sample.json`

```json
{
  "commandLine": "ffuf -u https://hackathon.mirage-analytics.com/FUZZ -w /opt/wordlists/ffuf-raft-small.txt -of json -o /dev/stdout",
  "time": "2026-10-08T10:00:00+02:00",
  "results": [
    {"input": {"FUZZ": "admin"}, "position": 1, "status": 403, "length": 280,
     "words": 9, "lines": 9, "content-type": "text/html", "redirectlocation": "",
     "url": "https://hackathon.mirage-analytics.com/admin",
     "host": "https://hackathon.mirage-analytics.com"},
    {"input": {"FUZZ": "backup"}, "position": 2, "status": 200, "length": 4210,
     "words": 120, "lines": 300, "content-type": "text/html", "redirectlocation": "",
     "url": "https://hackathon.mirage-analytics.com/backup",
     "host": "https://hackathon.mirage-analytics.com"},
    {"input": {"FUZZ": "old"}, "position": 3, "status": 301, "length": 0,
     "words": 1, "lines": 1, "content-type": "text/html",
     "redirectlocation": "https://hackathon.mirage-analytics.com/old/",
     "url": "https://hackathon.mirage-analytics.com/old",
     "host": "https://hackathon.mirage-analytics.com"},
    {"input": {"FUZZ": "api"}, "position": 4, "status": 405, "length": 12,
     "words": 2, "lines": 1, "content-type": "application/json", "redirectlocation": "",
     "url": "https://hackathon.mirage-analytics.com/api",
     "host": "https://hackathon.mirage-analytics.com"},
    {"input": {"FUZZ": "missing"}, "position": 5, "status": 404, "length": 15,
     "words": 3, "lines": 1, "content-type": "text/html", "redirectlocation": "",
     "url": "https://hackathon.mirage-analytics.com/missing",
     "host": "https://hackathon.mirage-analytics.com"}
  ]
}
```

- [x] **Step 2: Écrire les tests qui échouent** `tests/test_adapter_ffuf.py`

```python
"""Tests hors ligne de l'adaptateur ffuf (aucun binaire requis)."""
import json
from pathlib import Path

import httpx
import pytest

from redteam.safety.domain import Intensity, Severity
from redteam.safety.guard import ScopeGuard, ScopeViolation
from redteam.safety.scope import Authorized, Scope, Window
from redteam.tools.adapters.ffuf import FfufAdapter
from redteam.tools.http_client import GuardedHttpClient

SAMPLE = (Path(__file__).parent / "fixtures" / "ffuf_sample.json").read_text()


def _client(intensity=Intensity.ACTIVE):
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=__import__("datetime").date(2026, 10, 1),
                            end=__import__("datetime").date(2026, 12, 31)),
              allowed_intensity=Intensity.ACTIVE, signature="x")
    g = ScopeGuard(s, today=__import__("datetime").date(2026, 11, 1))
    return GuardedHttpClient(g, intensity, max_requests=5,
                             transport=httpx.MockTransport(lambda r: httpx.Response(200)))


def test_build_argv_single_host_rate_limited():
    argv = FfufAdapter().build_argv("https://hackathon.mirage-analytics.com/fr/")
    assert "https://hackathon.mirage-analytics.com/FUZZ" in argv   # racine, pas /fr/
    assert "-rate" in argv and "20" in argv
    assert "-t" in argv and "5" in argv
    assert "-maxtime" in argv and "120" in argv
    assert "-non-recursive" in argv
    assert "-r" not in argv            # jamais de follow-redirects (comparaison exacte)
    assert "-recursion" not in argv
    assert "-X" not in argv            # aucun verb destructif
    assert argv.count("FUZZ") == 1


def test_build_argv_keeps_port_and_drops_path():
    argv = FfufAdapter().build_argv("http://localhost:8080/deep/path")
    assert "http://localhost:8080/FUZZ" in argv
    assert not any("deep" in a for a in argv)


def test_parse_maps_statuses_to_severities():
    fs = FfufAdapter().parse(SAMPLE, "https://hackathon.mirage-analytics.com/")
    assert len(fs) == 4                      # le 404 est ignoré
    by_status = {f.evidence.split("→")[1].split("(")[0].strip(): f for f in fs}
    assert by_status["403"].severity is Severity.MEDIUM
    assert by_status["403"].title == "Endpoint protégé découvert"
    assert by_status["200"].severity is Severity.MEDIUM
    assert by_status["200"].title == "Chemin exposé"
    assert by_status["301"].severity is Severity.LOW
    assert by_status["405"].severity is Severity.LOW
    assert all(f.module_id == "tool.ffuf" for f in fs)


def test_parse_tolerates_ui_noise():
    dirty = "INFO: fetching...\n" + SAMPLE + "\n-- statistics --"
    fs = FfufAdapter().parse(dirty, "https://hackathon.mirage-analytics.com/")
    assert len(fs) == 4


def test_parse_empty_and_invalid():
    assert FfufAdapter().parse("", "http://localhost/") == []
    assert FfufAdapter().parse("no json here", "http://localhost/") == []


def test_intensity_is_active_not_intrusive():
    assert FfufAdapter().intensity is Intensity.ACTIVE


async def test_missing_wordlist_skips_before_exec(monkeypatch):
    a = FfufAdapter()
    a.wordlist = "/nonexistent/wordlist.txt"
    calls = {"n": 0}

    async def _exec(argv):
        calls["n"] += 1
        return (0, "", "")

    monkeypatch.setattr(a, "_exec", _exec)
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    res = await a.run(_client(), "http://localhost/")
    assert res.found is False and "wordlist" in res.evidence
    assert calls["n"] == 0


async def test_wordlist_missing_still_authorizes():
    a = FfufAdapter()
    a.wordlist = "/nonexistent/wordlist.txt"
    with pytest.raises(ScopeViolation):          # hors scope → refus AVANT tout
        await a.run(_client(), "http://evil.example/")
```

- [x] **Step 3: Vérifier l'échec**

Run: `.venv/bin/python -m pytest tests/test_adapter_ffuf.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'redteam.tools.adapters.ffuf'`.

- [x] **Step 4: Implémenter** `src/redteam/tools/adapters/ffuf.py`

```python
"""Adaptateur ffuf : découverte de contenu à la racine, débit borné (non-DoS)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.adapters.base import ToolAdapter
from redteam.tools.probes.base import ProbeResult


class FfufAdapter(ToolAdapter):
    id = "tool.ffuf"
    intensity = Intensity.ACTIVE
    description = "Découverte de contenu (ffuf), rate-limité — jamais de récursion."
    binary = "ffuf"
    timeout = 180.0
    wordlist = "/opt/wordlists/ffuf-raft-small.txt"

    def build_argv(self, target: str) -> list[str]:
        p = urlparse(target)
        base = f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "")
        return [
            self.binary, "-u", f"{base}/FUZZ", "-w", self.wordlist,
            "-rate", "20", "-t", "5", "-timeout", "10", "-maxtime", "120",
            "-mc", "200,204,301,302,307,401,403,405,500",
            "-non-recursive", "-s",
            "-of", "json", "-o", "/dev/stdout",
        ]

    async def run(self, client, target: str) -> ProbeResult:
        # Autorisation d'abord (invariant du confinement), puis wordlist :
        # jamais de lancement ffuf avec un -w inexistant.
        client.guard.authorize(target, client.intensity)
        if not Path(self.wordlist).is_file():
            return ProbeResult(found=False, evidence="wordlist absente (sonde sautée)")
        return await super().run(client, target)

    def parse(self, stdout: str, target: str) -> list[Finding]:
        results = _extract_results(stdout)
        findings: list[Finding] = []
        for r in results:
            status = int(r.get("status") or 0)
            if status in (401, 403):
                sev, title = Severity.MEDIUM, "Endpoint protégé découvert"
            elif status in (200, 204):
                sev, title = Severity.MEDIUM, "Chemin exposé"
            elif status in (301, 302, 307):
                sev, title = Severity.LOW, "Redirection racine"
            elif status == 405:
                sev, title = Severity.LOW, "Méthode HTTP inattendue"
            else:
                continue
            findings.append(Finding(
                module_id=self.id, target=target, severity=sev, title=title,
                evidence=f"{r.get('url', '')} → {status} ({r.get('length', 0)} octets)",
                remediation=Remediation(
                    summary="Restreindre l'accès à ce chemin (401/403/404).",
                    reference="OWASP WSTG — Content Discovery")))
        return findings


def _extract_results(text: str) -> list[dict]:
    """Extrait la liste `results` du JSON ffuf, tolérant aux lignes d'UI."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    return data.get("results", []) if isinstance(data, dict) else []
```

- [x] **Step 5: Vérifier le passage**

Run: `.venv/bin/python -m pytest tests/test_adapter_ffuf.py -v`
Expected: PASS (8 tests).

- [ ] **Step 6: Commit** *(facultatif — seulement si l'utilisateur le demande)*

```bash
git add src/redteam/tools/adapters/ffuf.py tests/test_adapter_ffuf.py tests/fixtures/ffuf_sample.json
git commit -m "feat(adapters): add ffuf content-discovery adapter"
```

---

### Task 3: Adaptateur testssl.sh

**Files:**
- Create: `tests/fixtures/testssl_sample.json`
- Create: `tests/test_adapter_testssl.py`
- Create: `src/redteam/tools/adapters/testssl.py`

**Interfaces:**
- Consumes: `ToolAdapter` avec `result_stream = "stderr"` (Task 1), `Finding/Severity/Remediation`.
- Produces: `TestsslAdapter` avec `id = "tool.testssl"`, `intensity = Intensity.ACTIVE`, `binary = "testssl.sh"`, `result_stream = "stderr"`. Enregistré en Tâche 4.

- [x] **Step 1: Créer la fixture** `tests/fixtures/testssl_sample.json`

```json
[
 {"id": "service", "ip": "78.232.7.202:443", "port": "443", "severity": "INFO", "finding": "HTTP service detected (via ALPN)"},
 {"id": "protocol", "ip": "78.232.7.202:443", "port": "443", "severity": "WARN", "finding": "TLS 1.0 offered"},
 {"id": "protocol", "ip": "78.232.7.202:443", "port": "443", "severity": "WARN", "finding": "TLS 1.1 offered"},
 {"id": "server_defaults", "ip": "78.232.7.202:443", "port": "443", "severity": "INFO", "finding": "TLS 1.2 sig algs: rsa_pss_rsae_sha256"},
 {"id": "hsts", "ip": "78.232.7.202:443", "port": "443", "severity": "WARN", "finding": "HSTS NOT offered"},
 {"id": "heartbleed", "ip": "78.232.7.202:443", "port": "443", "severity": "OK", "finding": "not vulnerable"},
 {"id": "scanTime", "ip": "78.232.7.202:443", "port": "443", "severity": "INFO", "finding": "Scan done in 12 seconds"}
]
```

- [x] **Step 2: Écrire les tests qui échouent** `tests/test_adapter_testssl.py`

```python
"""Tests hors ligne de l'adaptateur testssl.sh (aucun binaire requis)."""
import json
from pathlib import Path

from redteam.safety.domain import Intensity, Severity
from redteam.tools.adapters.testssl import TestsslAdapter

SAMPLE = (Path(__file__).parent / "fixtures" / "testssl_sample.json").read_text()


def test_build_argv_bounded_protocols_only():
    argv = TestsslAdapter().build_argv("https://hackathon.mirage-analytics.com/fr/")
    assert "testssl.sh" in argv
    assert "-p" in argv                       # protocoles seulement, pas de sweep
    assert "--jsonfile" in argv and "/dev/stderr" in argv
    assert "--connect-timeout" in argv and "10" in argv
    assert "--openssl-timeout" in argv and "10" in argv
    assert "--quiet" in argv and "--color" in argv
    # mono-cible : l'hôte seul, jamais le chemin /fr/
    assert argv[-1] == "hackathon.mirage-analytics.com"
    assert not any(a.startswith("http") for a in argv)


def test_build_argv_appends_port():
    argv = TestsslAdapter().build_argv("https://localhost:8443/x")
    assert argv[-1] == "localhost:8443"


def test_result_stream_is_stderr():
    assert TestsslAdapter().result_stream == "stderr"
    assert TestsslAdapter().intensity is Intensity.ACTIVE


def test_parse_maps_severities_and_filters_noise():
    fs = TestsslAdapter().parse(SAMPLE, "https://hackathon.mirage-analytics.com/")
    titles = [f.title for f in fs]
    assert len(fs) == 4                                  # protocol x2, server_defaults, hsts
    assert titles.count("TLS : protocol") == 2           # TLS 1.0 + 1.1, même titre
    assert "TLS : hsts" in titles
    assert not any("scanTime" in t for t in titles)       # id hors allowlist -> ignoré
    assert not any("heartbleed" in t for t in titles)     # severity OK -> ignorée
    by_title = {f.title: f for f in fs}
    assert by_title["TLS : protocol"].severity is Severity.MEDIUM   # WARN -> MEDIUM
    assert by_title["TLS : hsts"].severity is Severity.MEDIUM
    assert all(f.module_id == "tool.testssl" for f in fs)


def test_parse_empty_and_invalid():
    assert TestsslAdapter().parse("", "https://localhost/") == []
    assert TestsslAdapter().parse("garbage", "https://localhost/") == []
    assert TestsslAdapter().parse("[]", "https://localhost/") == []
```

- [x] **Step 3: Vérifier l'échec**

Run: `.venv/bin/python -m pytest tests/test_adapter_testssl.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'redteam.tools.adapters.testssl'`.

- [x] **Step 4: Implémenter** `src/redteam/tools/adapters/testssl.py`

```python
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
```

- [x] **Step 5: Vérifier le passage**

Run: `.venv/bin/python -m pytest tests/test_adapter_testssl.py -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit** *(facultatif — seulement si l'utilisateur le demande)*

```bash
git add src/redteam/tools/adapters/testssl.py tests/test_adapter_testssl.py tests/fixtures/testssl_sample.json
git commit -m "feat(adapters): add testssl.sh TLS adapter"
```

---

### Task 4: Enregistrement au LLM et au registre

**Files:**
- Modify: `src/redteam/tools/registry.py`
- Modify: `src/redteam/agents/prompts.py`
- Modify: `tests/test_registry_integration.py`

**Interfaces:**
- Consumes: `FfufAdapter` (Tâche 2), `TestsslAdapter` (Tâche 3), `PROBES` existant.
- Produces: `PROBES["tool.ffuf"]`, `PROBES["tool.testssl"]` ; chaînes `RECON_SYSTEM`/`SINGLE_SYSTEM` contenant les deux ids littéralement (utilisées par `recon_node`/`single_node`).

- [ ] **Step 1: Écrire le test qui échoue**

Dans `tests/test_registry_integration.py`, remplacer `test_registry_has_all_probes` par :

```python
def test_registry_has_all_probes():
    for pid in ["web.security_headers", "web.availability",
                "tool.nuclei", "tool.nmap", "tool.sqlmap",
                "tool.ffuf", "tool.testssl"]:
        assert pid in PROBES and get_probe(pid).id == pid


def test_new_tools_are_active_not_intrusive():
    from redteam.safety.domain import Intensity
    assert PROBES["tool.ffuf"].intensity is Intensity.ACTIVE
    assert PROBES["tool.testssl"].intensity is Intensity.ACTIVE


def test_prompts_list_new_tool_ids():
    from redteam.agents.prompts import RECON_SYSTEM, SINGLE_SYSTEM
    for prompt in (RECON_SYSTEM, SINGLE_SYSTEM):
        assert "tool.ffuf" in prompt and "tool.testssl" in prompt
```

- [ ] **Step 2: Vérifier l'échec**

Run: `.venv/bin/python -m pytest tests/test_registry_integration.py -v`
Expected: FAIL — `AssertionError` : `tool.ffuf` absent de `PROBES` puis des prompts.

- [ ] **Step 3: Implémenter le registre**

Dans `src/redteam/tools/registry.py`, après les imports existants :

```python
from redteam.tools.adapters.ffuf import FfufAdapter
from redteam.tools.adapters.testssl import TestsslAdapter
```

et dans le tuple de `PROBES`, après `SqlmapAdapter()` :

```python
        FfufAdapter(), TestsslAdapter(),
```

- [ ] **Step 4: Implémenter les prompts**

Dans `src/redteam/agents/prompts.py`, dans `RECON_SYSTEM`, étendre la liste :

```python
    "{'probe_id': one of [web.security_headers, web.version_disclosure, "
    "web.exposed_endpoints, web.reflected_input, web.availability, "
    "tool.nuclei, tool.nmap, tool.sqlmap, tool.ffuf, tool.testssl], "
```

et dans `SINGLE_SYSTEM`, étendre la ligne équivalente :

```python
    "[web.security_headers, web.version_disclosure, web.exposed_endpoints, "
    "web.reflected_input, web.availability, "
    "tool.nuclei, tool.nmap, tool.sqlmap, tool.ffuf, tool.testssl]. "
```

(Le reste de chaque chaîne reste inchangé ; respecter les guillemets/concaténation existants.)

- [ ] **Step 5: Vérifier le passage**

Run: `.venv/bin/python -m pytest tests/test_registry_integration.py tests/test_graph_smoke.py -v`
Expected: PASS — y compris `test_graph_smoke` (les prompts sont parsés par `extract_json_list`, la liste reste du JSON valide).

- [ ] **Step 6: Commit** *(facultatif — seulement si l'utilisateur le demande)*

```bash
git add src/redteam/tools/registry.py src/redteam/agents/prompts.py tests/test_registry_integration.py
git commit -m "feat: register ffuf/testssl probes in registry and LLM prompts"
```

---

### Task 5: Image Docker (outils + wordlist)

**Files:**
- Create: `config/wordlists/ffuf-fallback.txt`
- Modify: `Dockerfile` (après la couche nuclei, avant `WORKDIR /app`)

**Interfaces:**
- Consumes: chemin `FfufAdapter.wordlist = "/opt/wordlists/ffuf-raft-small.txt"` (Tâche 2), binary `testssl.sh` (Tâche 3), `ffuf` en `/usr/local/bin`.
- Produces: image `redteam-ia:latest` contenant `ffuf -V`, `testssl.sh --help`, `/opt/wordlists/ffuf-raft-small.txt`.

- [ ] **Step 1: Créer le wordlist de repli** `config/wordlists/ffuf-fallback.txt`

```
admin
administrator
api
backup
backups
cgi-bin
config
dashboard
db
debug
.env
.git
.gitconfig
hidden
import
internal
phpinfo.php
private
prod
server-status
staging
tmp
upload
uploads
wp-admin
wp-config.php
old
test
dev
console
actuator
health
metrics
robots.txt
sitemap.xml
swagger
graphql
console/login
```

(~40 entrées suffisent : c'est un **fallback**, la wordlist réelle est fetchée au build.)

- [ ] **Step 2: Modifier le `Dockerfile`**

Insérer **après** la couche `RUN nuclei -update-templates …` et **avant** `WORKDIR /app` :

```dockerfile
# ffuf : binaire GitHub release épinglé (amd64/arm64), comme nuclei.
ARG FFUF_VERSION=v2.1.0
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    case "$ARCH" in amd64) FARCH=amd64;; arm64) FARCH=arm64;; *) FARCH=amd64;; esac; \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_${FARCH}.tar.gz" \
      -o /tmp/ffuf.tgz; \
    tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf; \
    chmod +x /usr/local/bin ffuf; rm /tmp/ffuf.tgz; \
    ffuf -V

# testssl.sh : paquet Debian bookworm (pas de clone git).
RUN apt-get update && apt-get install -y --no-install-recommends testssl.sh && \
    rm -rf /var/lib/apt/lists/* && testssl.sh --help 2>&1 | head -1

# Wordlist ffuf : fallback versionné dans le repo, remplacé par raft-small au build.
COPY config/wordlists/ /opt/wordlists/
RUN curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt" \
      -o /opt/wordlists/ffuf-raft-small.txt || \
    cp /opt/wordlists/ffuf-fallback.txt /opt/wordlists/ffuf-raft-small.txt; \
    test -s /opt/wordlists/ffuf-raft-small.txt
```

- [ ] **Step 3: Vérifier l'image**

Run: `docker build -t redteam-ia .`
Expected: BUILD SUCCESSFUL ; les couches ffuf/testssl/wordlist visibles dans le log.

Run: `docker run --rm --entrypoint /bin/sh redteam-ia -c 'ffuf -V; testssl.sh --help 2>&1 | head -1; wc -l /opt/wordlists/ffuf-raft-small.txt'`
Expected: version ffuf, banner testssl, > 30 lignes (wordlist réelle ou fallback).

- [ ] **Step 4: Vérifier le skip hors conteneur (dégradation propre)**

Run: `.venv/bin/redteam run --mode single --target https://hackathon.mirage-analytics.com/fr/ --mock 2>&1 | tail -5`
Expected: run se termine, rapport écrit ; dans `trace.jsonl` les `tool_call` `tool.ffuf`/`tool.testssl` présents avec `found=False` (« binaire non installé »). Contrôler :
`grep -o '"tool": "tool\.[a-z]*"' runs/single-*/trace.jsonl | sort -u`

- [ ] **Step 5: Commit** *(facultatif — seulement si l'utilisateur le demande)*

```bash
git add Dockerfile config/wordlists/ffuf-fallback.txt
git commit -m "feat(docker): bundle ffuf, testssl.sh and ffuf wordlist"
```

---

### Task 6: Documentation et vérification finale

**Files:**
- Modify: `README.md` (tableau « Exécution en conteneur »)
- Modify: `docs/ARCHITECTURE.md` (§2.1 tableau des adaptateurs)
- Modify: `docs/METHODOLOGIE.md` (§4 Limites)

**Interfaces:**
- Consumes: les ids `tool.ffuf`/`tool.testssl` et leurs bornes (Tâches 2–5).
- Produces: doc cohérente avec le code ; rapport vert final.

- [ ] **Step 1: README**

Dans le tableau des adaptateurs, ajouter deux lignes :

```markdown
| `tool.ffuf` | **ffuf** | active | Découverte de contenu (rate-limité 20 req/s, mono-hôte, wordlist embarquée). |
| `tool.testssl` | **testssl.sh** | active | Audit TLS (protocoles + défauts serveur, mono-cible). |
```

Et ajouter `ffuf`/`testssl.sh` à la phrase « l'image Docker fournie (base Debian) les embarque ».

- [ ] **Step 2: ARCHITECTURE**

Dans `docs/ARCHITECTURE.md` §2.1 (tableau des adaptateurs), ajouter les mêmes deux lignes ; compléter la phrase sur les options de confinement : « nmap réduit au seul host ; nuclei `-target` ; ffuf mono-`FUZZ` à la racine avec `-rate 20 -maxtime 120` sans récursion ; sqlmap `--crawl=0`, jamais `--dump` ; testssl `-p` mono-hôte ».

- [ ] **Step 3: METHODOLOGIE (limites)**

Dans la section « Limites, échecs et pistes d'amélioration », ajouter :

```markdown
- **Requêtes émises par les binaires** : ffuf et testssl.sh (comme nuclei/nmap) font leurs
  propres connexions et échappent à l'arbitrage requête-par-requête du `ScopeGuard`. Bornes
  réelles : confinement pré-lancement (`guard.authorize`), mono-cible, options de débit
  (`-rate 20 -t 5 -maxtime 120` pour ffuf, `--connect-timeout 10` + `-p` pour testssl) et
  timeout d'exécution. Limite résiduelle assumée, identique au premier lot d'outils.
```

- [ ] **Step 4: Vérification complète**

Run: `.venv/bin/ruff check src tests`
Expected: `All checks passed!`

Run: `.venv/bin/python -m pytest -q`
Expected: `82 passed` (65 existants + 2 base + 8 ffuf + 5 testssl + 2 registry/prompts), 0 échec.

- [ ] **Step 5: Synthèse à présenter à l'utilisateur**

Résumer : fichiers ajoutés/modifiés, résultats des tests, état de l'image Docker, prochaine étape suggérée (run réel dans le conteneur pour mesurer l'apport ffuf/testssl dans `runs/benchmark.md`).

- [ ] **Step 6: Commit** *(facultatif — seulement si l'utilisateur le demande)*

```bash
git add README.md docs/ARCHITECTURE.md docs/METHODOLOGIE.md
git commit -m "docs: document ffuf and testssl adapters"
```
