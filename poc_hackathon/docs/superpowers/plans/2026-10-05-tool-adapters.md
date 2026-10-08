# Adaptateurs d'outils externes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Intégrer de vrais outils de sécurité (nuclei, nmap, sqlmap) comme adaptateurs respectant le contrat `Probe`, plus une sonde « faiblesse‑disponibilité » maison, pour que le PoC éprouve réellement la cible sous mandat — sans module DoS.

**Architecture:** Un `ToolAdapter` (base) implémente `Probe` en shellant vers un binaire, mais **autorise la cible via le ScopeGuard AVANT** tout lancement (les binaires échappent sinon au guard), reste mono‑cible, borné par timeout, et se saute proprement si l'outil est absent. Les outils produisent N findings par run → `ProbeResult` gagne `findings`. Le Verifier passe d'un simple « re‑trouve une preuve » à un **appariement de signature** `(module_id, target, title)` pour des sorties non déterministes, avec un seul re‑scan par sonde.

**Tech Stack:** Python 3.11+, asyncio subprocess, pydantic, httpx (sonde dispo + tests), pytest, ruff. Conteneur Debian/Kali pour l'exécution réelle.

**Spec:** `docs/superpowers/specs/2026-10-05-tool-adapters-design.md`

## Global Constraints

- Python **3.11+**. Code **anglais**, documentation/commentaires **français**.
- Aucune mention « Generated with Claude Code ». Attribution commit : `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- `ruff check src tests` **clean** et `python3 -m pytest -q` **vert** après chaque tâche.
- **Tous les tests hors ligne** : jamais de subprocess réel ni de réseau. Le `_exec` des adaptateurs est mocké ; les sorties d'outils sont des **fixtures** capturées ; la sonde dispo utilise `httpx.MockTransport`.
- **Sûreté outils externes** : `guard.authorize(target, intensity)` AVANT tout lancement ; **mono‑cible** ; timeout ; binaire absent → `ProbeResult(found=False)` (skip propre). Pas de DoS/DDoS. sqlmap **sans `--dump`**. nmap **sans scripts `dos`**. sqlmap est `INTRUSIVE` (gate de confirmation existant).
- Ne pas casser l'existant : les 4 sondes maison et toute la suite restent vertes.

## Review Focus

- **Binaire absent** (nuclei/nmap/sqlmap non installés) → l'adaptateur renvoie `found=False` avec une evidence claire, ne lève pas. Couvert Task 4 (base).
- **Cible hors périmètre passée à un adaptateur** → `guard.authorize` lève `ScopeViolation` **avant** tout subprocess (le binaire n'est jamais lancé). Couvert Task 4.
- **Sortie d'outil malformée/partielle** (JSON tronqué, XML vide) → le parseur renvoie `[]` / tolère, pas de crash. Couvert Tasks 5/6/7 (chaque `parse`).
- **Run multi‑findings vérifié** → seuls les findings dont la **signature** réapparaît au re‑scan sont `confirmed` ; les autres `discarded`. Couvert Task 3 (verifier).
- **Subprocess qui ne rend pas la main** → `timeout` le tue, l'adaptateur renvoie `found=False` (evidence « timeout »), l'audit continue. Couvert Task 4.

---

### Task 1: `ProbeResult.findings` (N findings par run) + attacker multi-findings

**Files:**
- Modify: `src/redteam/tools/probes/base.py`
- Modify: `src/redteam/agents/nodes.py` (`attacker_node`)
- Test: `tests/test_probe_result.py`

**Interfaces:**
- Produces: `ProbeResult.findings: list[Finding]` (défaut `[]`) + `ProbeResult.all_findings() -> list[Finding]` = `findings or ([finding] if finding else [])`.
- Consumes: `attacker_node` passe de `result.finding` à `result.all_findings()`.

- [ ] **Step 1: Write failing test** `tests/test_probe_result.py`

```python
from redteam.safety.domain import Finding, Severity, Remediation
from redteam.tools.probes.base import ProbeResult


def _f(title):
    return Finding(module_id="m", target="t", severity=Severity.LOW, title=title,
                   evidence="e", remediation=Remediation(summary="s", reference="r"))


def test_all_findings_prefers_list():
    r = ProbeResult(found=True, evidence="x", findings=[_f("a"), _f("b")])
    assert [f.title for f in r.all_findings()] == ["a", "b"]


def test_all_findings_falls_back_to_single():
    r = ProbeResult(found=True, evidence="x", finding=_f("solo"))
    assert [f.title for f in r.all_findings()] == ["solo"]


def test_all_findings_empty_when_nothing():
    assert ProbeResult(found=False, evidence="x").all_findings() == []
```

- [ ] **Step 2: Run** — `python3 -m pytest tests/test_probe_result.py -v` — Expected: FAIL (no `findings`/`all_findings`)

- [ ] **Step 3: Edit `src/redteam/tools/probes/base.py`** — add the field + method to `ProbeResult`:

```python
class ProbeResult(BaseModel):
    found: bool
    evidence: str
    finding: Finding | None = None
    findings: list[Finding] = []

    def all_findings(self) -> list[Finding]:
        """Findings du run : la liste si fournie, sinon le finding unique, sinon []."""
        if self.findings:
            return self.findings
        return [self.finding] if self.finding is not None else []
```

- [ ] **Step 4: Edit `attacker_node` in `src/redteam/agents/nodes.py`** — replace the single-finding append:

Replace:
```python
        if result.found and result.finding is not None:
            raw.append(result.finding)
```
with:
```python
        raw.extend(result.all_findings())
```

- [ ] **Step 5: Run full suite + lint** — `python3 -m pytest -q && ruff check src tests` — Expected: all green (existing probes set `finding`, still collected via `all_findings()`).

- [ ] **Step 6: Commit**

```bash
git add src/redteam/tools/probes/base.py src/redteam/agents/nodes.py tests/test_probe_result.py
git commit -m "feat(tools): ProbeResult.findings + attacker multi-findings

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `GuardedHttpClient` expose `guard` et `intensity`

**Files:**
- Modify: `src/redteam/tools/http_client.py`
- Test: `tests/test_http_client_props.py`

**Interfaces:**
- Produces: `GuardedHttpClient.guard -> ScopeGuard` et `GuardedHttpClient.intensity -> Intensity` (lecture seule). Les adaptateurs s'en servent pour `client.guard.authorize(target, client.intensity)` avant de shell‑out.

- [ ] **Step 1: Write failing test** `tests/test_http_client_props.py`

```python
import datetime
from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient


def _guard():
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.INTRUSIVE, signature="x")
    return ScopeGuard(s, today=datetime.date(2026, 11, 1))


def test_exposes_guard_and_intensity():
    g = _guard()
    c = GuardedHttpClient(g, Intensity.ACTIVE, max_requests=5)
    assert c.guard is g
    assert c.intensity is Intensity.ACTIVE
```

- [ ] **Step 2: Run** — `python3 -m pytest tests/test_http_client_props.py -v` — Expected: FAIL

- [ ] **Step 3: Edit `src/redteam/tools/http_client.py`** — add two properties after the existing `count` property:

```python
    @property
    def guard(self) -> ScopeGuard:
        return self._guard

    @property
    def intensity(self) -> Intensity:
        return self._intensity
```

- [ ] **Step 4: Run** — `python3 -m pytest tests/test_http_client_props.py -q && ruff check src tests` — Expected: PASS + clean
- [ ] **Step 5: Commit**

```bash
git add src/redteam/tools/http_client.py tests/test_http_client_props.py
git commit -m "feat(tools): expose guard/intensity sur GuardedHttpClient

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Verifier par appariement de signature (sorties non déterministes)

**Files:**
- Modify: `src/redteam/agents/nodes.py` (`verify_findings` + helper `finding_signature`)
- Test: `tests/test_verifier_signature.py`

**Interfaces:**
- Produces: `finding_signature(f: Finding) -> tuple[str, str, str]` = `(f.module_id, f.target, f.title)`.
- Modifies: `verify_findings(state, raw, offset=0)` — groupe les candidats par `(module_id, target)`, **re‑exécute chaque probe une seule fois**, et marque `confirmed` un candidat dont la **signature** réapparaît dans `recheck.all_findings()`, sinon `discarded`.
- Consumes: `ProbeResult.all_findings()` (Task 1).

- [ ] **Step 1: Write failing test** `tests/test_verifier_signature.py`

```python
import datetime
import httpx

from redteam.safety.domain import Intensity, Finding, Severity, Remediation
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult
from redteam.tools.registry import PROBES
from redteam.agents.nodes import verify_findings, finding_signature


def _guard():
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.INTRUSIVE, signature="x")
    return ScopeGuard(s, today=datetime.date(2026, 11, 1))


def _fake_probe(probe_id, intensity, titles_on_rerun):
    class _P:
        id = probe_id
        intensity = intensity
        description = "fake"
        async def run(self, client, target):
            fs = [Finding(module_id=probe_id, target=target, severity=Severity.MEDIUM,
                          title=t, evidence="e",
                          remediation=Remediation(summary="s", reference="r"))
                  for t in titles_on_rerun]
            return ProbeResult(found=bool(fs), evidence="rerun", findings=fs)
    return _P()


def _state(transport=None):
    g = _guard()
    return {"guard": g, "target": "http://localhost/",
            "client_factory": lambda it: GuardedHttpClient(g, it, max_requests=50,
                                                            transport=transport or httpx.MockTransport(
                                                                lambda r: httpx.Response(200)))}


def _cand(probe_id, title):
    return Finding(module_id=probe_id, target="http://localhost/", severity=Severity.MEDIUM,
                   title=title, evidence="e", remediation=Remediation(summary="s", reference="r"))


async def test_signature_confirmed_and_discarded(monkeypatch):
    # rerun re-signals only "A" (not "B") for probe p1
    p1 = _fake_probe("p1", Intensity.ACTIVE, ["A"])
    monkeypatch.setitem(PROBES, "p1", p1)
    out = await verify_findings(_state(), [_cand("p1", "A"), _cand("p1", "B")])
    by_title = {v["finding"].title: v["status"] for v in out}
    assert by_title == {"A": "confirmed", "B": "discarded"}


def test_finding_signature_shape():
    f = _cand("p1", "A")
    assert finding_signature(f) == ("p1", "http://localhost/", "A")
```

- [ ] **Step 2: Run** — `python3 -m pytest tests/test_verifier_signature.py -v` — Expected: FAIL (`finding_signature` absent; current verify re-run logic uses `recheck.found`)

- [ ] **Step 3: Edit `src/redteam/agents/nodes.py`** — add the helper near `confidence_score`:

```python
def finding_signature(f: Finding) -> tuple[str, str, str]:
    """Signature stable d'un finding pour l'appariement au rejeu (outils non déterministes)."""
    return (f.module_id, f.target, f.title)
```

Replace the body of `verify_findings` with a grouped, single-rescan, signature-matching version:

```python
async def verify_findings(state: AuditState, raw: list[Finding], offset: int = 0) -> list[dict]:
    # Grouper par (module_id, target) pour ne rejouer chaque sonde qu'UNE fois.
    groups: dict[tuple[str, str], list[Finding]] = {}
    order: list[tuple[str, str]] = []
    for f in raw:
        key = (f.module_id, f.target)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    verified: list[dict] = []
    i = 0
    for module_id, target in order:
        probe = get_probe(module_id)
        client = state["client_factory"](probe.intensity)
        try:
            recheck = await probe.run(client, target)
        finally:
            await client.aclose()
        reproduced = {finding_signature(g) for g in recheck.all_findings()}
        for f in groups[(module_id, target)]:
            has_evidence = finding_signature(f) in reproduced
            status = "confirmed" if has_evidence else "discarded"
            verified.append({
                "finding": f, "status": status,
                "confidence": confidence_score(1.0, has_evidence),
                "evidence": recheck.evidence, "finding_id": f"F{offset + i + 1}",
            })
            i += 1
    return verified
```

- [ ] **Step 4: Run full suite + lint** — `python3 -m pytest -q && ruff check src tests` — Expected: all green. (Existing `test_verifier.py` stays green: the security_headers finding title is stable, so its signature reappears → confirmed; when headers present the re-run yields no findings → discarded.)

- [ ] **Step 5: Commit**

```bash
git add src/redteam/agents/nodes.py tests/test_verifier_signature.py
git commit -m "feat(agents): verifier par appariement de signature + re-scan unique par sonde

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `ToolAdapter` base (subprocess borné, confinement scope, skip si absent)

**Files:**
- Create: `src/redteam/tools/adapters/__init__.py` (vide)
- Create: `src/redteam/tools/adapters/base.py`
- Test: `tests/test_adapter_base.py`

**Interfaces:**
- Consumes: `Probe`/`ProbeResult` (Task 1), `GuardedHttpClient.guard/intensity` (Task 2), `Finding`/`Intensity`, `ScopeViolation`.
- Produces: `ToolAdapter` with class attrs `id`, `intensity`, `description`, `binary`, `timeout: float = 120.0`, `max_output: int = 1_000_000` ; methods `build_argv(self, target) -> list[str]` and `parse(self, stdout: str, target) -> list[Finding]` (raise `NotImplementedError`), an overridable `async def _exec(self, argv) -> tuple[int, str, str]`, and `async def run(self, client, target) -> ProbeResult`.

- [ ] **Step 1: Write failing test** `tests/test_adapter_base.py`

```python
import datetime
import httpx
import pytest

from redteam.safety.domain import Intensity, Finding, Severity, Remediation
from redteam.safety.guard import ScopeGuard, ScopeViolation
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.adapters.base import ToolAdapter


def _client(intensity=Intensity.ACTIVE):
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.INTRUSIVE, signature="x")
    g = ScopeGuard(s, today=datetime.date(2026, 11, 1))
    return GuardedHttpClient(g, intensity, max_requests=5,
                             transport=httpx.MockTransport(lambda r: httpx.Response(200)))


class _FakeAdapter(ToolAdapter):
    id = "tool.fake"
    intensity = Intensity.ACTIVE
    description = "fake"
    binary = "definitely-not-installed-xyz"

    def build_argv(self, target):
        return [self.binary, target]

    def parse(self, stdout, target):
        return [Finding(module_id=self.id, target=target, severity=Severity.LOW,
                        title="hit", evidence=stdout[:20],
                        remediation=Remediation(summary="s", reference="r"))]


async def test_skips_cleanly_when_binary_absent():
    a = _FakeAdapter()
    res = await a.run(_client(), "http://localhost/")
    assert res.found is False and "non installé" in res.evidence


async def test_authorizes_before_exec(monkeypatch):
    a = _FakeAdapter()
    # out-of-scope target must raise before any exec attempt
    with pytest.raises(ScopeViolation):
        await a.run(_client(), "http://evil.example/")


async def test_parses_findings_from_mocked_exec(monkeypatch):
    a = _FakeAdapter()
    monkeypatch.setattr(a, "_exec", lambda argv: _ok("some-output"))
    # pretend the binary exists
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    res = await a.run(_client(), "http://localhost/")
    assert res.found is True and res.all_findings()[0].title == "hit"


async def test_timeout_returns_not_found(monkeypatch):
    a = _FakeAdapter()
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    async def _boom(argv):
        raise TimeoutError()
    monkeypatch.setattr(a, "_exec", _boom)
    res = await a.run(_client(), "http://localhost/")
    assert res.found is False and "timeout" in res.evidence.lower()


async def _ok(out):
    return (0, out, "")
```

- [ ] **Step 2: Run** — `python3 -m pytest tests/test_adapter_base.py -v` — Expected: FAIL (module absent)

- [ ] **Step 3: Create `src/redteam/tools/adapters/__init__.py`** (empty)

- [ ] **Step 4: Create `src/redteam/tools/adapters/base.py`**

```python
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
```

- [ ] **Step 5: Run** — `python3 -m pytest tests/test_adapter_base.py -q && ruff check src tests` — Expected: PASS + clean
- [ ] **Step 6: Commit**

```bash
git add src/redteam/tools/adapters/__init__.py src/redteam/tools/adapters/base.py tests/test_adapter_base.py
git commit -m "feat(adapters): base ToolAdapter (subprocess borné, confinement scope, skip si absent)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Adaptateur `tool.nuclei` (active)

**Files:**
- Create: `src/redteam/tools/adapters/nuclei.py`
- Create: `tests/fixtures/nuclei_sample.jsonl`
- Test: `tests/test_adapter_nuclei.py`

**Interfaces:**
- Consumes: `ToolAdapter` (Task 4).
- Produces: `NucleiAdapter` (id `tool.nuclei`, intensity ACTIVE, binary `nuclei`) with `build_argv` (mono‑cible, `-jsonl -silent`) and `parse` (une ligne JSON → un `Finding`).

- [ ] **Step 1: Create fixture `tests/fixtures/nuclei_sample.jsonl`** (deux lignes JSONL réalistes)

```json
{"template-id":"http-missing-security-headers","info":{"name":"Missing Security Headers","severity":"info"},"matched-at":"http://localhost/","matcher-name":"strict-transport-security"}
{"template-id":"CVE-2021-12345","info":{"name":"Example RCE","severity":"critical","reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-12345"]},"matched-at":"http://localhost/app"}
```

- [ ] **Step 2: Write failing test** `tests/test_adapter_nuclei.py`

```python
from pathlib import Path
from redteam.safety.domain import Severity
from redteam.tools.adapters.nuclei import NucleiAdapter

SAMPLE = (Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl").read_text()


def test_build_argv_is_single_target():
    argv = NucleiAdapter().build_argv("http://localhost/")
    assert "nuclei" in argv[0]
    assert "http://localhost/" in argv
    assert "-jsonl" in argv


def test_parse_maps_severity_and_title():
    fs = NucleiAdapter().parse(SAMPLE, "http://localhost/")
    assert len(fs) == 2
    crit = [f for f in fs if f.severity is Severity.CRITICAL]
    assert crit and "CVE-2021-12345" in crit[0].title
    assert "http" in crit[0].evidence


def test_parse_tolerates_garbage():
    assert NucleiAdapter().parse("not json\n\n{bad", "http://localhost/") == []
```

- [ ] **Step 3: Run** — `python3 -m pytest tests/test_adapter_nuclei.py -v` — Expected: FAIL

- [ ] **Step 4: Create `src/redteam/tools/adapters/nuclei.py`**

```python
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
            findings.append(Finding(
                module_id=self.id, target=target, severity=sev,
                title=f"{info.get('name', tid)} [{tid}]",
                evidence=f"matched-at: {matched} ({obj.get('matcher-name', '')})".strip(),
                remediation=Remediation(summary="Corriger selon le template nuclei.",
                                        reference=ref[0] if isinstance(ref, list) else str(ref))))
        return findings
```

- [ ] **Step 5: Run** — `python3 -m pytest tests/test_adapter_nuclei.py -q && ruff check src tests` — Expected: PASS + clean
- [ ] **Step 6: Commit**

```bash
git add src/redteam/tools/adapters/nuclei.py tests/fixtures/nuclei_sample.jsonl tests/test_adapter_nuclei.py
git commit -m "feat(adapters): nuclei (active) — parse JSONL -> findings

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Adaptateur `tool.nmap` (active, sans scripts `dos`)

**Files:**
- Create: `src/redteam/tools/adapters/nmap.py`
- Create: `tests/fixtures/nmap_sample.xml`
- Test: `tests/test_adapter_nmap.py`

**Interfaces:**
- Produces: `NmapAdapter` (id `tool.nmap`, ACTIVE, binary `nmap`), `build_argv` extrait l'hôte de l'URL et impose `--script "vuln and not dos"` + `-oX -`, `parse` lit le XML (services avec version → LOW ; scripts → selon sortie).

- [ ] **Step 1: Create fixture `tests/fixtures/nmap_sample.xml`** (XML nmap minimal : un hôte, un port avec service+version, un script vuln)

```xml
<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
        <script id="http-vuln-cve2021-1234" output="VULNERABLE: Example issue on /app"/>
      </port>
    </ports>
  </host>
</nmaprun>
```

- [ ] **Step 2: Write failing test** `tests/test_adapter_nmap.py`

```python
from pathlib import Path
from redteam.tools.adapters.nmap import NmapAdapter

SAMPLE = (Path(__file__).parent / "fixtures" / "nmap_sample.xml").read_text()


def test_build_argv_single_host_no_dos():
    argv = NmapAdapter().build_argv("https://localhost:443/x")
    assert "localhost" in argv          # host, not full URL
    assert any("not dos" in a for a in argv)  # dos scripts excluded
    assert "-sV" in argv


def test_parse_reports_service_and_script():
    fs = NmapAdapter().parse(SAMPLE, "https://localhost/")
    titles = " ".join(f.title.lower() for f in fs)
    assert "nginx" in titles or "1.18.0" in " ".join(f.evidence for f in fs)
    assert any("vuln" in f.title.lower() or "cve" in f.title.lower() for f in fs)


def test_parse_tolerates_empty():
    assert NmapAdapter().parse("", "https://localhost/") == []
```

- [ ] **Step 3: Run** — `python3 -m pytest tests/test_adapter_nmap.py -v` — Expected: FAIL

- [ ] **Step 4: Create `src/redteam/tools/adapters/nmap.py`**

```python
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
```

- [ ] **Step 5: Run** — `python3 -m pytest tests/test_adapter_nmap.py -q && ruff check src tests` — Expected: PASS + clean
- [ ] **Step 6: Commit**

```bash
git add src/redteam/tools/adapters/nmap.py tests/fixtures/nmap_sample.xml tests/test_adapter_nmap.py
git commit -m "feat(adapters): nmap (active) — services/versions + NSE vuln, jamais dos

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Adaptateur `tool.sqlmap` (intrusive, sans `--dump`)

**Files:**
- Create: `src/redteam/tools/adapters/sqlmap.py`
- Create: `tests/fixtures/sqlmap_sample.txt`
- Test: `tests/test_adapter_sqlmap.py`

**Interfaces:**
- Produces: `SqlmapAdapter` (id `tool.sqlmap`, **INTRUSIVE**, binary `sqlmap`), `build_argv` borné (`--batch --crawl=0 --level=2 --risk=1 --technique=BEUST --flush-session --banner`, **jamais `--dump`**), `parse` détecte un paramètre injectable → `Finding` HIGH.

- [ ] **Step 1: Create fixture `tests/fixtures/sqlmap_sample.txt`** (extrait de sortie sqlmap typique)

```
[INFO] testing connection to the target URL
[INFO] GET parameter 'id' is 'MySQL >= 5.0 boolean-based blind' injectable
sqlmap identified the following injection point(s):
Parameter: id (GET)
    Type: boolean-based blind
[INFO] the back-end DBMS is MySQL
banner: '5.7.38-log'
```

- [ ] **Step 2: Write failing test** `tests/test_adapter_sqlmap.py`

```python
from pathlib import Path
from redteam.safety.domain import Intensity, Severity
from redteam.tools.adapters.sqlmap import SqlmapAdapter

SAMPLE = (Path(__file__).parent / "fixtures" / "sqlmap_sample.txt").read_text()


def test_is_intrusive_and_never_dumps():
    a = SqlmapAdapter()
    assert a.intensity is Intensity.INTRUSIVE
    argv = a.build_argv("http://localhost/item?id=1")
    assert "--dump" not in argv and "--dump-all" not in argv
    assert "--batch" in argv and "http://localhost/item?id=1" in argv


def test_parse_detects_injectable_param():
    fs = SqlmapAdapter().parse(SAMPLE, "http://localhost/item?id=1")
    assert len(fs) >= 1
    f = fs[0]
    assert f.severity in (Severity.HIGH, Severity.CRITICAL)
    assert "id" in f.evidence and ("inject" in f.evidence.lower() or "blind" in f.evidence.lower())


def test_parse_no_injection_returns_empty():
    assert SqlmapAdapter().parse("[INFO] all tested parameters do not appear to be injectable",
                                 "http://localhost/x") == []
```

- [ ] **Step 3: Run** — `python3 -m pytest tests/test_adapter_sqlmap.py -v` — Expected: FAIL

- [ ] **Step 4: Create `src/redteam/tools/adapters/sqlmap.py`**

```python
"""Adaptateur sqlmap (INTRUSIF) : prouve l'exploitabilité SQLi sans exfiltrer de données.

JAMAIS de --dump : on confirme l'injection + on lit un identifiant anodin (--banner)
comme preuve d'accès. Palier intrusive → confirmation explicite requise en amont.
"""
from __future__ import annotations

import re

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.adapters.base import ToolAdapter

_INJECTABLE = re.compile(r"parameter '([^']+)' is .*injectable", re.IGNORECASE)
_PARAM_LINE = re.compile(r"Parameter:\s*([^\s(]+)", re.IGNORECASE)


class SqlmapAdapter(ToolAdapter):
    id = "tool.sqlmap"
    intensity = Intensity.INTRUSIVE
    description = "Preuve d'exploitation SQLi (sans dump de données)."
    binary = "sqlmap"
    timeout = 300.0

    def build_argv(self, target: str) -> list[str]:
        return [self.binary, "-u", target, "--batch", "--crawl=0", "--level=2",
                "--risk=1", "--technique=BEUST", "--flush-session", "--banner"]

    def parse(self, stdout: str, target: str) -> list[Finding]:
        params: list[str] = _INJECTABLE.findall(stdout) or _PARAM_LINE.findall(stdout)
        if not params:
            return []
        banner = ""
        m = re.search(r"banner:\s*'([^']+)'", stdout)
        if m:
            banner = f" ; bannière SGBD : {m.group(1)}"
        seen: list[str] = []
        findings: list[Finding] = []
        for p in params:
            if p in seen:
                continue
            seen.append(p)
            findings.append(Finding(
                module_id=self.id, target=target, severity=Severity.HIGH,
                title=f"Injection SQL confirmée (paramètre {p})",
                evidence=f"paramètre '{p}' injectable (sqlmap){banner}",
                remediation=Remediation(
                    summary="Requêtes paramétrées / ORM ; valider et échapper les entrées.",
                    reference="OWASP — SQL Injection")))
        return findings
```

- [ ] **Step 5: Run** — `python3 -m pytest tests/test_adapter_sqlmap.py -q && ruff check src tests` — Expected: PASS + clean
- [ ] **Step 6: Commit**

```bash
git add src/redteam/tools/adapters/sqlmap.py tests/fixtures/sqlmap_sample.txt tests/test_adapter_sqlmap.py
git commit -m "feat(adapters): sqlmap (intrusive) — preuve SQLi sans dump

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Sonde `web.availability` (active, remplaçant responsable du DoS)

**Files:**
- Create: `src/redteam/tools/probes/availability.py`
- Test: `tests/test_probe_availability.py`

**Interfaces:**
- Consumes: `GuardedHttpClient` (via `Probe.run`), `ProbeResult.findings`.
- Produces: `AvailabilityProbe` (id `web.availability`, ACTIVE) — détecte sans couper le service : `xmlrpc.php` accessible, absence de rate‑limiting observable, WAF non détecté. Renvoie `findings` (liste).

- [ ] **Step 1: Write failing test** `tests/test_probe_availability.py`

```python
import datetime
import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.availability import AvailabilityProbe


def _client(handler):
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.ACTIVE, signature="x")
    g = ScopeGuard(s, today=datetime.date(2026, 11, 1))
    return GuardedHttpClient(g, Intensity.ACTIVE, max_requests=50,
                             transport=httpx.MockTransport(handler))


async def test_flags_exposed_xmlrpc():
    def handler(req):
        if req.url.path == "/xmlrpc.php":
            return httpx.Response(200, text="XML-RPC server accepts POST requests only.")
        return httpx.Response(200, text="ok")
    c = _client(handler)
    res = await AvailabilityProbe().run(c, "http://localhost/")
    titles = " ".join(f.title.lower() for f in res.all_findings())
    assert res.found and "xmlrpc" in titles
    await c.aclose()


async def test_clean_target_no_findings():
    c = _client(lambda r: httpx.Response(404, text="not found",
                                         headers={"x-ratelimit-limit": "100"}))
    res = await AvailabilityProbe().run(c, "http://localhost/")
    assert res.found is False
    await c.aclose()
```

- [ ] **Step 2: Run** — `python3 -m pytest tests/test_probe_availability.py -v` — Expected: FAIL

- [ ] **Step 3: Create `src/redteam/tools/probes/availability.py`**

```python
"""Sonde de faiblesses de disponibilité (risque de déni de service) — SANS couper le service.

On prouve les faiblesses qui MÈNERAIENT à un DoS (xmlrpc exposé, absence de rate-limiting
observable, absence de WAF) par de simples requêtes sous budget. Aucune montée en charge,
aucune attaque de déni de service.
"""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_RL_HINTS = ("x-ratelimit-limit", "ratelimit-limit", "retry-after")
_WAF_HINTS = ("cloudflare", "sucuri", "mod_security", "awselb", "x-sucuri-id", "cf-ray")


class AvailabilityProbe:
    id = "web.availability"
    intensity = Intensity.ACTIVE
    description = "Faiblesses menant à un déni de service, prouvées sans couper le service."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        base = target.rstrip("/")
        findings: list[Finding] = []

        # 1) xmlrpc.php exposé (amplification / pingback)
        try:
            r = await client.get(base + "/xmlrpc.php")
            if r.status_code in (200, 405) and "xml-rpc" in r.text.lower():
                findings.append(Finding(
                    module_id=self.id, target=target, severity=Severity.MEDIUM,
                    title="xmlrpc.php exposé (risque d'amplification/DoS)",
                    evidence=f"/xmlrpc.php répond {r.status_code}",
                    remediation=Remediation(summary="Bloquer /xmlrpc.php ou désactiver XML-RPC.",
                                            reference="WordPress Hardening — xmlrpc")))
        except Exception:
            pass

        # 2) indices de rate-limiting / WAF sur la racine
        try:
            r = await client.get(base + "/")
            headers = {k.lower(): v for k, v in r.headers.items()}
            blob = " ".join(headers.keys()) + " " + " ".join(headers.values()).lower()
            if not any(h in headers for h in _RL_HINTS):
                findings.append(Finding(
                    module_id=self.id, target=target, severity=Severity.MEDIUM,
                    title="Absence d'indice de rate-limiting (risque de DoS applicatif)",
                    evidence="aucun en-tête de limitation de débit observé",
                    remediation=Remediation(summary="Mettre en place un rate-limiting (par IP / par compte).",
                                            reference="OWASP — Denial of Service")))
            if not any(w in blob for w in _WAF_HINTS):
                findings.append(Finding(
                    module_id=self.id, target=target, severity=Severity.LOW,
                    title="Aucun WAF détecté",
                    evidence="aucune empreinte de WAF dans les en-têtes",
                    remediation=Remediation(summary="Envisager un WAF/anti-DDoS en amont.",
                                            reference="OWASP — DoS Prevention")))
        except Exception:
            pass

        evidence = f"{len(findings)} faiblesse(s) de disponibilité" if findings else "aucune faiblesse observée"
        return ProbeResult(found=bool(findings), evidence=evidence, findings=findings)
```

- [ ] **Step 4: Run** — `python3 -m pytest tests/test_probe_availability.py -q && ruff check src tests` — Expected: PASS + clean
- [ ] **Step 5: Commit**

```bash
git add src/redteam/tools/probes/availability.py tests/test_probe_availability.py
git commit -m "feat(probes): web.availability — risque de DoS prouvé sans couper le service

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Enregistrement + intégration bout‑en‑bout

**Files:**
- Modify: `src/redteam/tools/registry.py`
- Modify: `src/redteam/agents/prompts.py` (ajouter les nouveaux ids aux prompts recon/single)
- Test: `tests/test_registry_integration.py`

**Interfaces:**
- Produces: `PROBES` contient désormais `web.security_headers`, `web.version_disclosure`, `web.exposed_endpoints`, `web.reflected_input`, `web.availability`, `tool.nuclei`, `tool.nmap`, `tool.sqlmap`.
- Modifies: les prompts recon/single listent les nouveaux ids autorisés.

- [ ] **Step 1: Write failing test** `tests/test_registry_integration.py`

```python
import datetime
import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.registry import PROBES, get_probe
from redteam.agents.nodes import attacker_node, verify_findings


def test_registry_has_all_probes():
    for pid in ["web.security_headers", "web.availability",
                "tool.nuclei", "tool.nmap", "tool.sqlmap"]:
        assert pid in PROBES and get_probe(pid).id == pid


def _state(monkeypatch):
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.INTRUSIVE, signature="x")
    g = ScopeGuard(s, today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text="x",
                                    headers={"server": "nginx"}))
    return {"run_id": "t", "mode": "crew", "guard": g,
            "client_factory": lambda it: GuardedHttpClient(g, it, max_requests=50, transport=transport),
            "trace": None}


async def test_tool_adapter_multi_findings_through_attacker_and_verifier(monkeypatch):
    # nuclei adapter with mocked exec + pretend-installed → 2 findings, both verified
    from redteam.tools.adapters.nuclei import NucleiAdapter
    from pathlib import Path
    sample = (Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl").read_text()
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    async def _exec(argv):
        return (0, sample, "")
    monkeypatch.setattr(NucleiAdapter, "_exec", lambda self, argv: _exec(argv))

    from redteam.safety.domain import Step
    st = _state(monkeypatch)
    st["plan"] = [Step(module_id="tool.nuclei", target="http://localhost/",
                       intensity=Intensity.ACTIVE, description="nuclei")]
    st = await attacker_node(st)
    assert len(st["raw_findings"]) == 2            # multi-findings collected
    verified = await verify_findings(st, st["raw_findings"])
    assert all(v["status"] == "confirmed" for v in verified)  # signatures reproduced
```

- [ ] **Step 2: Run** — `python3 -m pytest tests/test_registry_integration.py -v` — Expected: FAIL (tools not registered)

- [ ] **Step 3: Edit `src/redteam/tools/registry.py`** — import and register the new probes/adapters:

```python
"""Registre des sondes disponibles (id -> instance)."""
from __future__ import annotations

from redteam.tools.probes.base import Probe
from redteam.tools.probes.security_headers import SecurityHeadersProbe
from redteam.tools.probes.version_disclosure import VersionDisclosureProbe
from redteam.tools.probes.exposed_endpoints import ExposedEndpointsProbe
from redteam.tools.probes.reflected_input import ReflectedInputProbe
from redteam.tools.probes.availability import AvailabilityProbe
from redteam.tools.adapters.nuclei import NucleiAdapter
from redteam.tools.adapters.nmap import NmapAdapter
from redteam.tools.adapters.sqlmap import SqlmapAdapter

PROBES: dict[str, Probe] = {
    p.id: p for p in (
        SecurityHeadersProbe(), VersionDisclosureProbe(),
        ExposedEndpointsProbe(), ReflectedInputProbe(),
        AvailabilityProbe(),
        NucleiAdapter(), NmapAdapter(), SqlmapAdapter(),
    )
}


def get_probe(probe_id: str) -> Probe:
    return PROBES[probe_id]
```

- [ ] **Step 4: Edit `src/redteam/agents/prompts.py`** — update `RECON_SYSTEM` and `SINGLE_SYSTEM` so the allowed probe-id list includes the new ids: `web.security_headers, web.version_disclosure, web.exposed_endpoints, web.reflected_input, web.availability, tool.nuclei, tool.nmap, tool.sqlmap`. (Keep the "reply ONLY with a JSON array" instruction; just extend the id enumeration in both prompts.)

- [ ] **Step 5: Run full suite + lint** — `python3 -m pytest -q && ruff check src tests` — Expected: all green (incl. graph smoke still works — the 4 original probes untouched; new ones registered).

- [ ] **Step 6: Commit**

```bash
git add src/redteam/tools/registry.py src/redteam/agents/prompts.py tests/test_registry_integration.py
git commit -m "feat(tools): enregistrer availability + adaptateurs (nuclei/nmap/sqlmap) + prompts

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Conteneur Kali + documentation (FR) + gate final

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Modify: `README.md`, `docs/ARCHITECTURE.md`, `docs/METHODOLOGIE.md`

**Interfaces:** aucune (packaging + doc).

- [ ] **Step 1: Create `Dockerfile`** — base Debian/Kali installant les outils + le paquet :

```dockerfile
# Conteneur d'audit : Python + nuclei + nmap + sqlmap.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv nmap sqlmap golang-go ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# nuclei (binaire Go)
RUN GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true

WORKDIR /app
COPY . /app
RUN python3 -m pip install --break-system-packages -e ".[dev]"

# Exécution : monter .env et runs/. Exemple :
#   docker build -t redteam-ia .
#   docker run --rm --env-file .env -v "$PWD/runs:/app/runs" redteam-ia \
#     redteam run --mode crew --target "$MIRAGE_TARGET"
ENTRYPOINT ["redteam"]
CMD ["--help"]
```

- [ ] **Step 2: Create `.dockerignore`**

```
.git
runs/
scope.yaml
.env
__pycache__/
.venv/
.pytest_cache/
.ruff_cache/
.superpowers/
```

- [ ] **Step 3: Update `README.md`** — add a section « Exécution en conteneur (outils réels) » : `docker build` / `docker run` (comme dans le Dockerfile), liste des outils embarqués (nuclei/nmap/sqlmap), et rappel que **sans conteneur / sans l'outil installé, l'adaptateur se saute proprement** (le PoC reste utilisable, couverture réduite). Ajouter les nouveaux ids de sondes à la liste.

- [ ] **Step 4: Update `docs/ARCHITECTURE.md`** — décrire la couche `tools/adapters/` (contrat `Probe` via `ToolAdapter`), le **confinement pré‑lancement** (authorize → mono‑cible → timeout → skip), l'extension `ProbeResult.findings`, et le **Verifier par signature**.

- [ ] **Step 5: Update `docs/METHODOLOGIE.md`** — section « Éprouver la cible » : paliers active/intrusive, nuclei/nmap/sqlmap, et le **choix de ne pas faire de DoS** (risque prouvé via `web.availability` + test de charge en staging hors‑PoC). Ajouter à « Limites » la **limite résiduelle** : un outil externe n'est plus arbitré par le `ScopeGuard` une fois lancé (confinement pré‑lancement seulement).

- [ ] **Step 6: Final gate** — `ruff check src tests` (clean) + `python3 -m pytest -q` (vert). If red, STOP and report.

- [ ] **Step 7: Commit**

```bash
git add Dockerfile .dockerignore README.md docs/ARCHITECTURE.md docs/METHODOLOGIE.md
git commit -m "docs+docker: conteneur Kali (nuclei/nmap/sqlmap) + doc adaptateurs/limite résiduelle

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Notes d'exécution transverses

- **Ordre** : 1→10. Task 1 (ProbeResult) et Task 2 (props client) débloquent le reste ; Task 3 (verifier signature) dépend de Task 1 ; Task 4 (base) dépend de Tasks 1+2 ; Tasks 5/6/7 dépendent de Task 4 ; Task 9 dépend de 5/6/7/8.
- **Hors ligne** : jamais de subprocess/binaire réel en test — `_exec` mocké + `shutil.which` monkeypatché + fixtures. Jamais de réseau — `httpx.MockTransport`.
- **Compat** : les 4 sondes maison et la suite existante restent vertes à chaque étape (Task 1 et Task 3 sont conçues rétro‑compatibles).
- **Sûreté** : `authorize` avant exec (Task 4) ; sqlmap INTRUSIVE sans `--dump` ; nmap sans `dos` ; pas de module DoS.
