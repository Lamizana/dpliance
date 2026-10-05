# redteam-ia Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Construire un PoC de « Red Team IA » qui audite une cible autorisée (Mirage), adapte sa stratégie, vérifie ses findings par preuve déterministe, et trace/benchmarke tout pour comparer agent unique vs multi-agents.

**Architecture:** Python + LangGraph. Une colonne vertébrale de sûreté (scope signé, `ScopeGuard`, audit chaîné) reprise de `redscope` encadre chaque action. Le LLM (Featherless, compatible OpenAI) raisonne et priorise ; des outils déterministes (crawler, sondes) observent et prouvent. Deux graphes commutables (`single`/`crew`) partagent outils, Verifier et traçage pour permettre un benchmark « toutes choses égales par ailleurs ».

**Tech Stack:** Python 3.11+, LangGraph, langchain-openai, httpx (async), pydantic v2, typer, rich, PyYAML, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-10-05-redteam-ia-design.md`

## Global Constraints

- Python **3.11+**.
- **Code en anglais** ; **documentation (README, docs/, docstrings explicatives) en français**.
- Aucune mention « Generated with Claude Code » nulle part.
- Clé API **uniquement** via `.env` / variable d'environnement ; jamais en dur, jamais commitée.
- Les agents LLM ne font **jamais** d'I/O réseau directe : toute requête passe par `tools/http_client.py`, qui applique `ScopeGuard` + budget.
- Aucune vulnérabilité n'est retenue sans **preuve reproductible** capturée par une sonde déterministe.
- Les sondes sont des **détecteurs de preuve** (réponses HTTP, en-têtes, reflets), pas des exploits armés : pas de DoS, brute-force réel, altération de données.
- Modèle LLM par défaut : `huihui-ai/Huihui-Qwen3.8-27B-abliterated` ; base URL `https://api.featherless.ai/v1`.
- Tous les tests tournent **hors ligne** (LLM mocké via `MockBackend`, cible via serveur httpx local ou monkeypatch).
- Commits fréquents, un par tâche minimum. Lignes d'attribution de commit : `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

- **Cible hors périmètre passée au crawler/sonde** (ex. lien externe découvert en crawlant) → doit être refusée par `ScopeGuard`, jamais requêtée. Couvert en Task 9 (`http_client`) et Task 10 (`crawler`).
- **Finding proposé par le LLM sans preuve** (hallucination) → le Verifier doit le classer `discarded`, pas `confirmed`. Couvert en Task 14 (`verifier`).
- **Scope `scope.yaml` altéré après signature** → `load_scope` doit lever `ScopeSignatureError`. Couvert en Task 4.
- **Budget de requêtes dépassé** par une sonde emballée → `RequestBudgetExceeded`, l'exécution continue proprement. Couvert en Task 9.
- **Réponse LLM non-JSON / malformée** quand on attend une liste d'hypothèses → parse défensif, l'orchestrateur ne crashe pas et trace une `error`. Couvert en Task 12 (helper de parsing) et Task 13 (recon).

---

### Task 1: Project scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `.env.example`
- Create: `src/redteam/__init__.py`
- Create: `config/scope.template.yaml`
- Create: `tests/__init__.py`

**Interfaces:**
- Produces: package importable `redteam` (version `0.1.0`) ; dépendances installées.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "redteam-ia"
version = "0.1.0"
description = "PoC Red Team IA — audit cybersécurité adaptatif sous mandat"
requires-python = ">=3.11"
dependencies = [
    "langgraph>=0.2",
    "langchain-openai>=0.2",
    "langchain-core>=0.3",
    "httpx>=0.27",
    "pydantic>=2.7",
    "typer>=0.12",
    "rich>=13.7",
    "PyYAML>=6.0",
]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-asyncio>=0.23", "ruff>=0.5"]

[project.scripts]
redteam = "redteam.cli:app"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
pythonpath = ["src"]
```

- [ ] **Step 2: Write `.env.example`**

```bash
# Copier en .env et renseigner. Ne jamais committer .env.
FEATHERLESS_API_KEY=rc_xxx
FEATHERLESS_BASE_URL=https://api.featherless.ai/v1
REDTEAM_MODEL=huihui-ai/Huihui-Qwen3.8-27B-abliterated
# Cible autorisée (copie Mirage). Placeholder par défaut.
MIRAGE_TARGET=http://localhost:8080
# Clé de scellement du scope et de l'audit (HMAC). Générer une valeur aléatoire.
REDSCOPE_SIGNING_KEY=change-me-in-dev
```

- [ ] **Step 3: Write `src/redteam/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 4: Write `config/scope.template.yaml`** (sans `signature` : elle est calculée au lancement)

```yaml
mission: "Audit Red Team IA — cible Mirage (DPLIANCE)"
mandate_ref: "HACKATHON-NEOLOJI-2026"
client_contact: "hichem@dpliance.com"
authorized:
  domains: ["localhost"]
  ips: ["127.0.0.1/32"]
excluded: []
window:
  start: "2026-10-01"
  end: "2026-12-31"
allowed_intensity: "active"
sandbox: {}
limits:
  max_requests_per_module: 500
```

- [ ] **Step 5: Create empty `tests/__init__.py`**

```python
```

- [ ] **Step 6: Install and verify import**

Run: `pip install -e ".[dev]" && python -c "import redteam; print(redteam.__version__)"`
Expected: affiche `0.1.0`

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml .env.example src/redteam/__init__.py config/scope.template.yaml tests/__init__.py
git commit -m "chore: scaffold projet redteam-ia

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Safety — `domain.py` (port depuis redscope)

**Files:**
- Create: `src/redteam/safety/__init__.py` (vide)
- Create: `src/redteam/safety/domain.py`

**Interfaces:**
- Produces: `Intensity` (PASSIVE/ACTIVE/INTRUSIVE, `.rank`), `Severity`, `Remediation`, `Finding`, `Step`, `Module` (Protocol).

- [ ] **Step 1: Write `src/redteam/safety/domain.py`** (copie verbatim de `../hackingtool/redscope/domain.py` — contenu ci-dessous)

```python
from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel


class Intensity(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"

    @property
    def rank(self) -> int:
        return {"passive": 0, "active": 1, "intrusive": 2}[self.value]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Remediation(BaseModel):
    summary: str
    reference: str


class Finding(BaseModel):
    module_id: str
    target: str
    severity: Severity
    title: str
    evidence: str
    remediation: Remediation


class Step(BaseModel):
    module_id: str
    target: str
    intensity: Intensity
    description: str


@runtime_checkable
class Module(Protocol):
    id: str
    intensity: Intensity
    category: str
    requires: list[str]

    def plan(self, target: str, ctx: dict) -> list[Step]: ...
    def run(self, target: str, ctx: dict) -> list[Finding]: ...
```

- [ ] **Step 2: Write the failing test** `tests/test_domain.py`

```python
from redteam.safety.domain import Intensity, Severity, Finding, Remediation


def test_intensity_rank_orders_passive_below_intrusive():
    assert Intensity.PASSIVE.rank < Intensity.ACTIVE.rank < Intensity.INTRUSIVE.rank


def test_finding_roundtrips():
    f = Finding(module_id="m", target="t", severity=Severity.HIGH, title="x",
                evidence="e", remediation=Remediation(summary="s", reference="r"))
    assert f.severity is Severity.HIGH
```

- [ ] **Step 3: Run tests** — Run: `pytest tests/test_domain.py -v` — Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/redteam/safety/__init__.py src/redteam/safety/domain.py tests/test_domain.py
git commit -m "feat(safety): port domain models depuis redscope

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Safety — `signing.py` (port)

**Files:**
- Create: `src/redteam/safety/signing.py`
- Test: `tests/test_signing.py`

**Interfaces:**
- Produces: `Signer` (Protocol), `HmacSigner(key: bytes)`, `default_signer()`, `SigningKeyError`.

- [ ] **Step 1: Write `src/redteam/safety/signing.py`** (copie verbatim de `../hackingtool/redscope/signing.py`, mais renommer les variables d'env `REDSCOPE_*` → `REDTEAM_*`) :

```python
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Protocol, runtime_checkable


class SigningKeyError(Exception):
    pass


@runtime_checkable
class Signer(Protocol):
    def sign(self, content: bytes) -> str: ...
    def verify(self, content: bytes, signature: str) -> bool: ...


class HmacSigner:
    def __init__(self, key: bytes):
        self._key = key

    def sign(self, content: bytes) -> str:
        return hmac.new(self._key, content, hashlib.sha256).hexdigest()

    def verify(self, content: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(content), signature)


def default_signer() -> Signer:
    key = os.getenv("REDTEAM_SIGNING_KEY") or os.getenv("REDSCOPE_SIGNING_KEY")
    if key:
        return HmacSigner(key.encode("utf-8"))
    key_file = os.getenv("REDTEAM_SIGNING_KEY_FILE")
    if key_file:
        try:
            with open(key_file, "rb") as fh:
                return HmacSigner(fh.read())
        except OSError as exc:
            raise SigningKeyError(f"Clé de signature illisible : {key_file}") from exc
    raise SigningKeyError(
        "Aucune clé de signature : définir REDTEAM_SIGNING_KEY ou REDTEAM_SIGNING_KEY_FILE."
    )
```

- [ ] **Step 2: Write failing test** `tests/test_signing.py`

```python
from redteam.safety.signing import HmacSigner


def test_sign_verify_roundtrip():
    s = HmacSigner(b"k")
    sig = s.sign(b"hello")
    assert s.verify(b"hello", sig)
    assert not s.verify(b"tampered", sig)
```

- [ ] **Step 3: Run** — `pytest tests/test_signing.py -v` — Expected: PASS
- [ ] **Step 4: Commit**

```bash
git add src/redteam/safety/signing.py tests/test_signing.py
git commit -m "feat(safety): port signing (HMAC) depuis redscope

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Safety — `scope.py` (port)

**Files:**
- Create: `src/redteam/safety/scope.py`
- Test: `tests/test_scope.py`

**Interfaces:**
- Consumes: `Signer`, `default_signer` (Task 3) ; `Intensity` (Task 2).
- Produces: `Scope`, `Window`, `Authorized`, `Limits`, `load_scope(path, signer=None)`, `compute_signature(dict, signer=None)`, `ScopeSignatureError`.

- [ ] **Step 1: Write `src/redteam/safety/scope.py`** (copie verbatim de `../hackingtool/redscope/scope.py` en remplaçant les imports `from redscope.` par `from redteam.safety.`) :

```python
from __future__ import annotations

import datetime
import json

import yaml
from pydantic import BaseModel

from redteam.safety.domain import Intensity
from redteam.safety.signing import Signer, default_signer


class ScopeSignatureError(Exception):
    pass


class Window(BaseModel):
    start: datetime.date
    end: datetime.date


class Authorized(BaseModel):
    domains: list[str]
    ips: list[str]


class Limits(BaseModel):
    max_requests_per_module: int = 1000


class Scope(BaseModel):
    mission: str
    mandate_ref: str
    client_contact: str
    authorized: Authorized
    excluded: list[str]
    window: Window
    allowed_intensity: Intensity
    sandbox: dict[str, str] = {}
    limits: Limits = Limits()
    signature: str


def _canonical(scope_dict: dict) -> bytes:
    content = {k: v for k, v in scope_dict.items() if k != "signature"}
    return json.dumps(content, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")


def compute_signature(scope_dict: dict, signer: Signer | None = None) -> str:
    return (signer or default_signer()).sign(_canonical(scope_dict))


def load_scope(path: str, signer: Signer | None = None) -> Scope:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not (signer or default_signer()).verify(_canonical(data), data.get("signature", "")):
        raise ScopeSignatureError(
            "Signature invalide : le scope a été modifié après scellement, ou la clé diffère."
        )
    return Scope.model_validate(data)
```

- [ ] **Step 2: Write failing test** `tests/test_scope.py` (porté de redscope, imports adaptés)

```python
import datetime
import pytest
import yaml

from redteam.safety.domain import Intensity
from redteam.safety.signing import HmacSigner
from redteam.safety.scope import load_scope, compute_signature, ScopeSignatureError

KEY = HmacSigner(b"test-key")


def _scope_dict():
    return {
        "mission": "Audit Mirage", "mandate_ref": "REF-1", "client_contact": "x@d.fr",
        "authorized": {"domains": ["localhost", "*.mirage.local"], "ips": ["127.0.0.1/32"]},
        "excluded": ["admin.mirage.local"],
        "window": {"start": "2026-10-01", "end": "2026-12-31"},
        "allowed_intensity": "active", "sandbox": {},
    }


def _write_signed(tmp_path):
    data = _scope_dict()
    data["signature"] = compute_signature(data, signer=KEY)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_load_valid_scope(tmp_path):
    scope = load_scope(str(_write_signed(tmp_path)), signer=KEY)
    assert scope.allowed_intensity is Intensity.ACTIVE
    assert scope.window.end == datetime.date(2026, 12, 31)


def test_tampered_scope_rejected(tmp_path):
    p = _write_signed(tmp_path)
    data = yaml.safe_load(p.read_text())
    data["authorized"]["domains"].append("victim.example")
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(ScopeSignatureError):
        load_scope(str(p), signer=KEY)
```

- [ ] **Step 3: Run** — `pytest tests/test_scope.py -v` — Expected: PASS
- [ ] **Step 4: Commit**

```bash
git add src/redteam/safety/scope.py tests/test_scope.py
git commit -m "feat(safety): port scope signé depuis redscope

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Safety — `guard.py` (port)

**Files:**
- Create: `src/redteam/safety/guard.py`
- Test: `tests/test_guard.py`

**Interfaces:**
- Consumes: `Scope` (Task 4), `Intensity` (Task 2).
- Produces: `ScopeGuard(scope, today)`, `.check(target, intensity) -> GuardDecision`, `.authorize(target, intensity)`, `.authorize_sandbox(target)`, `ScopeViolation`, `GuardDecision(allowed: bool, reason: str)`.

- [ ] **Step 1: Write `src/redteam/safety/guard.py`** (copie verbatim de `../hackingtool/redscope/guard.py`, imports `redscope.` → `redteam.safety.`). Le fichier complet :

```python
from __future__ import annotations

import datetime
import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel

from redteam.safety.domain import Intensity
from redteam.safety.scope import Scope


class ScopeViolation(Exception):
    pass


class GuardDecision(BaseModel):
    allowed: bool
    reason: str


def _host(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()


def _domain_matches(host: str, pattern: str) -> bool:
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


def _ip_in_cidr(host: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


class ScopeGuard:
    def __init__(self, scope: Scope, today: datetime.date):
        self.scope = scope
        self.today = today

    def check(self, target: str, intensity: Intensity) -> GuardDecision:
        host = _host(target)
        for ex in self.scope.excluded:
            ex_lower = ex.lower()
            if host == ex_lower or host.endswith("." + ex_lower) or _domain_matches(host, ex):
                return GuardDecision(allowed=False, reason=f"Cible explicitement exclue : {host}")
        in_domains = any(_domain_matches(host, d) for d in self.scope.authorized.domains)
        in_ips = any(_ip_in_cidr(host, c) for c in self.scope.authorized.ips)
        if not (in_domains or in_ips):
            return GuardDecision(allowed=False, reason=f"Cible hors périmètre autorisé : {host}")
        if not (self.scope.window.start <= self.today <= self.scope.window.end):
            return GuardDecision(allowed=False, reason="Action hors fenêtre temporelle autorisée.")
        if intensity.rank > self.scope.allowed_intensity.rank:
            return GuardDecision(
                allowed=False,
                reason=f"intensité {intensity.value} > plafond ({self.scope.allowed_intensity.value}).",
            )
        return GuardDecision(allowed=True, reason="Autorisé.")

    def authorize(self, target: str, intensity: Intensity) -> None:
        decision = self.check(target, intensity)
        if not decision.allowed:
            raise ScopeViolation(decision.reason)

    def authorize_sandbox(self, target: str) -> None:
        host = _host(target).lower()
        for value in self.scope.sandbox.values():
            v = value.lower()
            if host == v or host.endswith("." + v) or _domain_matches(host, v):
                return
        raise ScopeViolation(f"Cible hors sandbox consentie : {host}")
```

- [ ] **Step 2: Write failing test** `tests/test_guard.py`

```python
import datetime
import pytest

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard, ScopeViolation
from redteam.safety.scope import Scope, Authorized, Window

TODAY = datetime.date(2026, 11, 1)


def _guard(**over):
    scope = Scope(
        mission="m", mandate_ref="r", client_contact="c",
        authorized=Authorized(domains=["localhost"], ips=["127.0.0.1/32"]),
        excluded=over.get("excluded", []),
        window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
        allowed_intensity=over.get("intensity", Intensity.ACTIVE), signature="x",
    )
    return ScopeGuard(scope, today=TODAY)


def test_in_scope_allowed():
    assert _guard().check("http://localhost/x", Intensity.PASSIVE).allowed


def test_out_of_scope_refused():
    assert not _guard().check("http://evil.example/x", Intensity.PASSIVE).allowed


def test_excluded_refused():
    g = _guard(excluded=["localhost"])
    assert not g.check("http://localhost/x", Intensity.PASSIVE).allowed


def test_intensity_ceiling():
    assert not _guard().check("http://localhost", Intensity.INTRUSIVE).allowed


def test_authorize_raises_out_of_scope():
    with pytest.raises(ScopeViolation):
        _guard().authorize("http://evil.example", Intensity.PASSIVE)
```

- [ ] **Step 3: Run** — `pytest tests/test_guard.py -v` — Expected: PASS
- [ ] **Step 4: Commit**

```bash
git add src/redteam/safety/guard.py tests/test_guard.py
git commit -m "feat(safety): port ScopeGuard depuis redscope

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Safety — `audit.py` (port, journal chaîné)

**Files:**
- Create: `src/redteam/safety/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: `Signer` (Task 3).
- Produces: `AuditLog(path, clock=...)` avec `.append(action, target, detail) -> str`, `.tip() -> (int, str)`, `.write_checkpoint(signer)` ; fonctions `verify_chain(path, expected_tip_hash=None) -> bool`, `read_checkpoint(path, signer)`, `export_bundle(path, signer=None) -> dict`, constante `GENESIS`.

- [ ] **Step 1: Write `src/redteam/safety/audit.py`** — copie verbatim de `../hackingtool/redscope/audit.py` (import `from redteam.safety.signing import Signer`). Le fichier combine : `_utc_now_iso`, `_entry_hash`, classe `AuditLog` (`_last_hash`, `append`, `tip`, `write_checkpoint`), `verify_chain`, `read_checkpoint`, `export_bundle`. (Contenu identique à la source déjà lue ; reproduire tel quel avec l'import ajusté.)

- [ ] **Step 2: Write failing test** `tests/test_audit.py`

```python
from redteam.safety.audit import AuditLog, verify_chain


def test_append_and_chain_valid(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append("run", "localhost", {"module": "a"})
    log.append("run", "localhost", {"module": "b"})
    assert verify_chain(p)


def test_tampering_breaks_chain(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    log = AuditLog(p)
    log.append("run", "localhost", {"module": "a"})
    lines = open(p).read().replace('"module": "a"', '"module": "HACKED"')
    open(p, "w").write(lines)
    assert not verify_chain(p)
```

- [ ] **Step 3: Run** — `pytest tests/test_audit.py -v` — Expected: PASS
- [ ] **Step 4: Commit**

```bash
git add src/redteam/safety/audit.py tests/test_audit.py
git commit -m "feat(safety): port journal d'audit chaîné depuis redscope

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Config loader

**Files:**
- Create: `src/redteam/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `Settings` (pydantic) avec `featherless_api_key: str | None`, `base_url: str`, `model: str`, `target: str`, `signing_key: str | None` ; `load_settings() -> Settings` (lit l'environnement).

- [ ] **Step 1: Write failing test** `tests/test_config.py`

```python
from redteam.config import load_settings


def test_load_settings_from_env(monkeypatch):
    monkeypatch.setenv("FEATHERLESS_API_KEY", "rc_x")
    monkeypatch.setenv("MIRAGE_TARGET", "http://localhost:8080")
    s = load_settings()
    assert s.featherless_api_key == "rc_x"
    assert s.target == "http://localhost:8080"
    assert s.model  # a une valeur par défaut
```

- [ ] **Step 2: Run** — `pytest tests/test_config.py -v` — Expected: FAIL (module absent)

- [ ] **Step 3: Write `src/redteam/config.py`**

```python
"""Chargement de la configuration depuis l'environnement (voir .env.example)."""
from __future__ import annotations

import os

from pydantic import BaseModel

DEFAULT_MODEL = "huihui-ai/Huihui-Qwen3.8-27B-abliterated"
DEFAULT_BASE_URL = "https://api.featherless.ai/v1"


class Settings(BaseModel):
    featherless_api_key: str | None = None
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    target: str = "http://localhost:8080"
    signing_key: str | None = None


def load_settings() -> Settings:
    return Settings(
        featherless_api_key=os.getenv("FEATHERLESS_API_KEY"),
        base_url=os.getenv("FEATHERLESS_BASE_URL", DEFAULT_BASE_URL),
        model=os.getenv("REDTEAM_MODEL", DEFAULT_MODEL),
        target=os.getenv("MIRAGE_TARGET", "http://localhost:8080"),
        signing_key=os.getenv("REDTEAM_SIGNING_KEY"),
    )
```

- [ ] **Step 4: Run** — `pytest tests/test_config.py -v` — Expected: PASS
- [ ] **Step 5: Commit**

```bash
git add src/redteam/config.py tests/test_config.py
git commit -m "feat: config loader depuis l'environnement

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: LLM backend (Featherless + Mock)

**Files:**
- Create: `src/redteam/llm/__init__.py` (vide)
- Create: `src/redteam/llm/backend.py`
- Create: `src/redteam/llm/models.py`
- Test: `tests/test_backend.py`

**Interfaces:**
- Consumes: `Settings` (Task 7).
- Produces:
  - `LLMResult(text: str, model: str, tokens_in: int, tokens_out: int, latency_ms: int)`.
  - `LLMBackend` (Protocol) : `.complete(system: str, user: str) -> LLMResult`.
  - `MockBackend(responses: dict[str, str] | None = None, default: str = "[mock]")` : déterministe, offline.
  - `FeatherlessBackend(api_key, base_url, model)` : via `langchain_openai.ChatOpenAI`.
  - `MODEL_CATALOG: dict[str, str]` (rôle → model id) dans `models.py`.

- [ ] **Step 1: Write failing test** `tests/test_backend.py`

```python
from redteam.llm.backend import MockBackend


def test_mock_backend_returns_configured_response():
    be = MockBackend(responses={"recon": "surface analysée"}, default="[mock]")
    out = be.complete("sys", "recon de la cible")
    assert out.text == "surface analysée"
    assert out.model == "mock"


def test_mock_backend_default():
    be = MockBackend()
    assert be.complete("s", "inconnu").text == "[mock]"
```

- [ ] **Step 2: Run** — `pytest tests/test_backend.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/llm/backend.py`**

```python
"""Abstraction LLM : backend Featherless (compatible OpenAI) et MockBackend offline.

Le MockBackend renvoie une réponse selon un mot-clé présent dans le prompt
utilisateur, ce qui permet des tests déterministes sans réseau.
"""
from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from pydantic import BaseModel


class LLMResult(BaseModel):
    text: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0


@runtime_checkable
class LLMBackend(Protocol):
    def complete(self, system: str, user: str) -> LLMResult: ...


class MockBackend:
    """Backend déterministe pour tests/démo hors ligne."""

    def __init__(self, responses: dict[str, str] | None = None, default: str = "[mock]"):
        self._responses = responses or {}
        self._default = default

    def complete(self, system: str, user: str) -> LLMResult:
        text = self._default
        for key, value in self._responses.items():
            if key in user:
                text = value
                break
        return LLMResult(text=text, model="mock", tokens_in=len(user), tokens_out=len(text))


class FeatherlessBackend:
    """Backend LLM via l'API Featherless (compatible OpenAI)."""

    def __init__(self, api_key: str, base_url: str, model: str):
        from langchain_openai import ChatOpenAI

        self.model = model
        self._llm = ChatOpenAI(model=model, api_key=api_key, base_url=base_url)

    def complete(self, system: str, user: str) -> LLMResult:
        from langchain_core.messages import HumanMessage, SystemMessage

        start = time.monotonic()
        resp = self._llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
        latency_ms = int((time.monotonic() - start) * 1000)
        usage = getattr(resp, "usage_metadata", None) or {}
        return LLMResult(
            text=str(resp.content), model=self.model,
            tokens_in=int(usage.get("input_tokens", 0)),
            tokens_out=int(usage.get("output_tokens", 0)),
            latency_ms=latency_ms,
        )
```

> Note d'implémentation : `ChatOpenAI` accepte `base_url` directement ; supprimer le paramètre `configuration=` inutile si la version installée le refuse (garder uniquement `base_url`).

- [ ] **Step 4: Write `src/redteam/llm/models.py`**

```python
"""Catalogue de modèles par rôle, pour permuter les modèles lors du benchmark."""
from __future__ import annotations

from redteam.config import DEFAULT_MODEL

# rôle logique -> identifiant de modèle Featherless
MODEL_CATALOG: dict[str, str] = {
    "default": DEFAULT_MODEL,
    "recon": DEFAULT_MODEL,
    "planner": DEFAULT_MODEL,
    "reporter": DEFAULT_MODEL,
}


def model_for(role: str) -> str:
    return MODEL_CATALOG.get(role, MODEL_CATALOG["default"])
```

- [ ] **Step 5: Create `src/redteam/llm/__init__.py`** (vide)

- [ ] **Step 6: Run** — `pytest tests/test_backend.py -v` — Expected: PASS
- [ ] **Step 7: Commit**

```bash
git add src/redteam/llm/ tests/test_backend.py
git commit -m "feat(llm): backend Featherless + MockBackend + catalogue modèles

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: Monitoring — `trace.py`

**Files:**
- Create: `src/redteam/monitoring/__init__.py` (vide)
- Create: `src/redteam/monitoring/trace.py`
- Test: `tests/test_trace.py`

**Interfaces:**
- Consumes: `AuditLog` (Task 6).
- Produces:
  - `TraceEvent(BaseModel)` avec les champs de la spec §5.
  - `TraceLog(path, run_id, mode, audit: AuditLog | None = None)` : `.emit(event: TraceEvent) -> None` (append JSONL ; si `type` ∈ `CRITICAL_TYPES`, appende aussi à l'audit chaîné), `.events() -> list[TraceEvent]` (relecture).
  - `CRITICAL_TYPES = {"decision", "finding", "verification", "strategy_change", "error"}`.

- [ ] **Step 1: Write failing test** `tests/test_trace.py`

```python
from redteam.monitoring.trace import TraceEvent, TraceLog
from redteam.safety.audit import AuditLog, verify_chain


def _ev(**kw):
    base = dict(run_id="r1", mode="crew", agent="recon", phase="recon", type="llm_call")
    base.update(kw)
    return TraceEvent(ts="2026-10-05T00:00:00Z", **base)


def test_emit_writes_jsonl(tmp_path):
    log = TraceLog(str(tmp_path / "trace.jsonl"), run_id="r1", mode="crew")
    log.emit(_ev())
    assert len(log.events()) == 1


def test_critical_event_also_audited(tmp_path):
    audit_path = str(tmp_path / "audit.jsonl")
    log = TraceLog(str(tmp_path / "trace.jsonl"), run_id="r1", mode="crew",
                   audit=AuditLog(audit_path))
    log.emit(_ev(type="finding", finding_id="F1", severity="high"))
    assert verify_chain(audit_path)
```

- [ ] **Step 2: Run** — `pytest tests/test_trace.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/monitoring/trace.py`**

```python
"""Traçage unifié des décisions, appels d'outils et findings.

Chaque événement est journalisé en JSONL. Les événements critiques sont, en
plus, appendus au journal d'audit chaîné (infalsifiable) pour servir de preuve
de ce que l'IA a réellement fait.
"""
from __future__ import annotations

import json

from pydantic import BaseModel

from redteam.safety.audit import AuditLog

CRITICAL_TYPES = {"decision", "finding", "verification", "strategy_change", "error"}


class TraceEvent(BaseModel):
    ts: str
    run_id: str
    mode: str
    agent: str
    phase: str
    type: str
    model: str | None = None
    prompt_hash: str | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    latency_ms: int | None = None
    tool: str | None = None
    http_count: int | None = None
    finding_id: str | None = None
    severity: str | None = None
    status: str | None = None
    confidence: float | None = None
    rationale: str | None = None


class TraceLog:
    def __init__(self, path: str, run_id: str, mode: str, audit: AuditLog | None = None):
        self.path = path
        self.run_id = run_id
        self.mode = mode
        self.audit = audit

    def emit(self, event: TraceEvent) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(event.model_dump_json() + "\n")
        if self.audit is not None and event.type in CRITICAL_TYPES:
            self.audit.append(event.type, event.agent,
                              {"finding_id": event.finding_id, "status": event.status,
                               "rationale": event.rationale})

    def events(self) -> list[TraceEvent]:
        out: list[TraceEvent] = []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        out.append(TraceEvent.model_validate_json(line))
        except FileNotFoundError:
            pass
        return out
```

- [ ] **Step 4: Run** — `pytest tests/test_trace.py -v` — Expected: PASS
- [ ] **Step 5: Commit**

```bash
git add src/redteam/monitoring/__init__.py src/redteam/monitoring/trace.py tests/test_trace.py
git commit -m "feat(monitoring): TraceEvent + TraceLog avec pont audit chaîné

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: Tools — `http_client.py` (async, budgété, guardé)

**Files:**
- Create: `src/redteam/tools/__init__.py` (vide)
- Create: `src/redteam/tools/http_client.py`
- Test: `tests/test_http_client.py`

**Interfaces:**
- Consumes: `ScopeGuard` (Task 5), `Intensity` (Task 2).
- Produces:
  - `RequestBudgetExceeded(Exception)`.
  - `GuardedHttpClient(guard, intensity, max_requests, transport=None)` avec `async def request(method, url, **kw) -> httpx.Response`, `async def get(url, **kw)`, `async def post(url, **kw)`, propriété `count`, `async def aclose()`. Chaque requête : `guard.authorize(url, intensity)` (lève `ScopeViolation` si hors scope) puis vérifie le budget.
  - Paramètre `transport` injectable (`httpx.MockTransport`) pour tester hors ligne.

- [ ] **Step 1: Write failing test** `tests/test_http_client.py`

```python
import datetime
import httpx
import pytest

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard, ScopeViolation
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient, RequestBudgetExceeded


def _guard():
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=["127.0.0.1/32"]),
                  excluded=[], window=Window(start=datetime.date(2026, 10, 1),
                  end=datetime.date(2026, 12, 31)), allowed_intensity=Intensity.ACTIVE,
                  signature="x")
    return ScopeGuard(scope, today=datetime.date(2026, 11, 1))


def _transport():
    return httpx.MockTransport(lambda req: httpx.Response(200, text="ok"))


async def test_in_scope_request_ok():
    c = GuardedHttpClient(_guard(), Intensity.PASSIVE, max_requests=10, transport=_transport())
    r = await c.get("http://localhost/x")
    assert r.status_code == 200
    await c.aclose()


async def test_out_of_scope_refused():
    c = GuardedHttpClient(_guard(), Intensity.PASSIVE, max_requests=10, transport=_transport())
    with pytest.raises(ScopeViolation):
        await c.get("http://evil.example/x")
    await c.aclose()


async def test_budget_enforced():
    c = GuardedHttpClient(_guard(), Intensity.PASSIVE, max_requests=1, transport=_transport())
    await c.get("http://localhost/a")
    with pytest.raises(RequestBudgetExceeded):
        await c.get("http://localhost/b")
    await c.aclose()
```

- [ ] **Step 2: Run** — `pytest tests/test_http_client.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/tools/http_client.py`**

```python
"""Client HTTP asynchrone : la SEULE porte de sortie réseau du PoC.

Toute requête est d'abord autorisée par le ScopeGuard (périmètre, fenêtre,
intensité) puis comptée contre un budget par exécution. Les agents LLM
n'accèdent jamais au réseau autrement que par ce client.
"""
from __future__ import annotations

import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard


class RequestBudgetExceeded(Exception):
    pass


class GuardedHttpClient:
    def __init__(self, guard: ScopeGuard, intensity: Intensity, max_requests: int,
                 transport: httpx.BaseTransport | None = None, timeout: float = 10.0):
        self._guard = guard
        self._intensity = intensity
        self._max = max_requests
        self._count = 0
        self._client = httpx.AsyncClient(transport=transport, timeout=timeout,
                                         follow_redirects=True)

    @property
    def count(self) -> int:
        return self._count

    async def request(self, method: str, url: str, **kw) -> httpx.Response:
        self._guard.authorize(url, self._intensity)  # lève ScopeViolation si hors scope
        if self._count >= self._max:
            raise RequestBudgetExceeded(f"Budget de requêtes dépassé (plafond {self._max}).")
        self._count += 1
        return await self._client.request(method, url, **kw)

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()
```

- [ ] **Step 4: Run** — `pytest tests/test_http_client.py -v` — Expected: PASS
- [ ] **Step 5: Commit**

```bash
git add src/redteam/tools/__init__.py src/redteam/tools/http_client.py tests/test_http_client.py
git commit -m "feat(tools): client HTTP async guardé + budgété

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 11: Tools — `crawler.py`

**Files:**
- Create: `src/redteam/tools/crawler.py`
- Test: `tests/test_crawler.py`

**Interfaces:**
- Consumes: `GuardedHttpClient` (Task 10).
- Produces:
  - `Page(url: str, status: int, headers: dict[str, str], body_snippet: str)`.
  - `SurfaceMap(pages: list[Page], links: list[str])`.
  - `async def crawl(client: GuardedHttpClient, seed: str, max_pages: int = 20, max_depth: int = 2) -> SurfaceMap`. BFS ; n'ajoute à la file que les liens **même hôte** que `seed` ; ignore silencieusement les liens hors scope (le guard refuserait de toute façon) ; dédoublonne.

- [ ] **Step 1: Write failing test** `tests/test_crawler.py`

```python
import datetime
import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.crawler import crawl


def _guard():
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]),
                  excluded=[], window=Window(start=datetime.date(2026, 10, 1),
                  end=datetime.date(2026, 12, 31)), allowed_intensity=Intensity.ACTIVE,
                  signature="x")
    return ScopeGuard(scope, today=datetime.date(2026, 11, 1))


PAGES = {
    "/": '<a href="/a">a</a><a href="http://evil.example/x">evil</a>',
    "/a": '<a href="/">home</a>',
}


def _transport():
    def handler(req):
        return httpx.Response(200, text=PAGES.get(req.url.path, ""),
                              headers={"server": "nginx"})
    return httpx.MockTransport(handler)


async def test_crawl_stays_in_host_and_dedups():
    c = GuardedHttpClient(_guard(), Intensity.PASSIVE, max_requests=50, transport=_transport())
    surface = await crawl(c, "http://localhost/", max_pages=10, max_depth=2)
    paths = sorted({p.url for p in surface.pages})
    assert "http://localhost/" in paths and "http://localhost/a" in paths
    assert all("evil.example" not in p.url for p in surface.pages)
    await c.aclose()
```

- [ ] **Step 2: Run** — `pytest tests/test_crawler.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/tools/crawler.py`**

```python
"""Crawler BFS asynchrone, borné par scope/budget/profondeur.

Cartographie la surface de la cible (pages, statuts, en-têtes, extraits de
corps). Ne suit que les liens du même hôte que la graine ; les liens hors
périmètre sont ignorés (et seraient de toute façon refusés par le guard).
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel

from redteam.tools.http_client import GuardedHttpClient

_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


class Page(BaseModel):
    url: str
    status: int
    headers: dict[str, str]
    body_snippet: str


class SurfaceMap(BaseModel):
    pages: list[Page]
    links: list[str]


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).hostname == urlparse(b).hostname


async def crawl(client: GuardedHttpClient, seed: str, max_pages: int = 20,
                max_depth: int = 2) -> SurfaceMap:
    seen: set[str] = set()
    pages: list[Page] = []
    all_links: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed, 0)])

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        resp = await client.get(url)
        body = resp.text[:2000]
        pages.append(Page(url=url, status=resp.status_code,
                          headers={k.lower(): v for k, v in resp.headers.items()},
                          body_snippet=body))
        for raw in _HREF.findall(resp.text):
            nxt = urljoin(url, raw)
            all_links.add(nxt)
            if _same_host(seed, nxt) and nxt not in seen:
                queue.append((nxt, depth + 1))

    return SurfaceMap(pages=pages, links=sorted(all_links))
```

- [ ] **Step 4: Run** — `pytest tests/test_crawler.py -v` — Expected: PASS
- [ ] **Step 5: Commit**

```bash
git add src/redteam/tools/crawler.py tests/test_crawler.py
git commit -m "feat(tools): crawler BFS async borné par scope/budget

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 12: Tools — sondes (`probes/`) + registre

**Files:**
- Create: `src/redteam/tools/probes/__init__.py`
- Create: `src/redteam/tools/probes/base.py`
- Create: `src/redteam/tools/probes/security_headers.py`
- Create: `src/redteam/tools/probes/version_disclosure.py`
- Create: `src/redteam/tools/probes/exposed_endpoints.py`
- Create: `src/redteam/tools/probes/reflected_input.py`
- Create: `src/redteam/tools/registry.py`
- Test: `tests/test_probes.py`

**Interfaces:**
- Consumes: `GuardedHttpClient` (Task 10), `Finding`, `Severity`, `Remediation`, `Intensity` (Task 2).
- Produces:
  - `ProbeResult(found: bool, evidence: str, finding: Finding | None)`.
  - Protocole `Probe` : attributs `id: str`, `intensity: Intensity`, `description: str` ; `async def run(self, client, target) -> ProbeResult`.
  - 4 sondes : `SecurityHeadersProbe` (id `web.security_headers`), `VersionDisclosureProbe` (`web.version_disclosure`), `ExposedEndpointsProbe` (`web.exposed_endpoints`), `ReflectedInputProbe` (`web.reflected_input`).
  - `PROBES: dict[str, Probe]` et `get_probe(id) -> Probe` dans `registry.py`.
- Chaque sonde produit une **preuve brute** (extrait de réponse) et ne lève pas sur erreur réseau : elle renvoie `found=False`.

- [ ] **Step 1: Write `src/redteam/tools/probes/base.py`**

```python
"""Contrat commun des sondes de détection."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from redteam.safety.domain import Finding, Intensity
from redteam.tools.http_client import GuardedHttpClient


class ProbeResult(BaseModel):
    found: bool
    evidence: str
    finding: Finding | None = None


@runtime_checkable
class Probe(Protocol):
    id: str
    intensity: Intensity
    description: str

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult: ...
```

- [ ] **Step 2: Write `src/redteam/tools/probes/security_headers.py`**

```python
"""Détecte l'absence d'en-têtes de sécurité (preuve = en-têtes reçus)."""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_REQUIRED = ["strict-transport-security", "content-security-policy",
             "x-frame-options", "x-content-type-options"]


class SecurityHeadersProbe:
    id = "web.security_headers"
    intensity = Intensity.PASSIVE
    description = "Vérifie la présence des en-têtes de sécurité HTTP standard."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        try:
            resp = await client.get(target)
        except Exception:
            return ProbeResult(found=False, evidence="requête échouée")
        present = {k.lower() for k in resp.headers.keys()}
        missing = [h for h in _REQUIRED if h not in present]
        if not missing:
            return ProbeResult(found=False, evidence="tous les en-têtes présents")
        return ProbeResult(
            found=True, evidence=f"en-têtes manquants : {', '.join(missing)}",
            finding=Finding(module_id=self.id, target=target, severity=Severity.MEDIUM,
                            title="En-têtes de sécurité manquants",
                            evidence=f"Manquants : {', '.join(missing)}",
                            remediation=Remediation(
                                summary="Ajouter HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
                                reference="OWASP Secure Headers Project")))
```

- [ ] **Step 3: Write `src/redteam/tools/probes/version_disclosure.py`**

```python
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
```

- [ ] **Step 4: Write `src/redteam/tools/probes/exposed_endpoints.py`**

```python
"""Teste un petit jeu de chemins sensibles courants (preuve = statut 200)."""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_PATHS = ["/.git/config", "/.env", "/server-status", "/phpinfo.php"]


class ExposedEndpointsProbe:
    id = "web.exposed_endpoints"
    intensity = Intensity.ACTIVE
    description = "Vérifie l'exposition de fichiers/endpoints sensibles courants."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        base = target.rstrip("/")
        hits: list[str] = []
        for path in _PATHS:
            try:
                resp = await client.get(base + path)
            except Exception:
                continue
            if resp.status_code == 200 and resp.text.strip():
                hits.append(path)
        if not hits:
            return ProbeResult(found=False, evidence="aucun endpoint sensible accessible")
        ev = f"accessibles (200) : {', '.join(hits)}"
        return ProbeResult(
            found=True, evidence=ev,
            finding=Finding(module_id=self.id, target=target, severity=Severity.HIGH,
                            title="Fichiers/endpoints sensibles exposés",
                            evidence=ev,
                            remediation=Remediation(
                                summary="Bloquer l'accès public à ces chemins (403/404).",
                                reference="OWASP — Sensitive Data Exposure")))
```

- [ ] **Step 5: Write `src/redteam/tools/probes/reflected_input.py`**

```python
"""Détecte un reflet non échappé d'un paramètre (candidat XSS réfléchi).

Envoie un marqueur inoffensif et vérifie s'il réapparaît tel quel dans la
réponse. C'est un indicateur de reflet, pas un exploit.
"""
from __future__ import annotations

from redteam.safety.domain import Finding, Intensity, Remediation, Severity
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.probes.base import ProbeResult

_MARKER = "rtMARKER12345"


class ReflectedInputProbe:
    id = "web.reflected_input"
    intensity = Intensity.ACTIVE
    description = "Détecte le reflet non échappé d'un paramètre (candidat XSS réfléchi)."

    async def run(self, client: GuardedHttpClient, target: str) -> ProbeResult:
        sep = "&" if "?" in target else "?"
        probe_url = f"{target}{sep}q={_MARKER}"
        try:
            resp = await client.get(probe_url)
        except Exception:
            return ProbeResult(found=False, evidence="requête échouée")
        if _MARKER not in resp.text:
            return ProbeResult(found=False, evidence="marqueur non reflété")
        return ProbeResult(
            found=True, evidence=f"marqueur reflété dans la réponse de {probe_url}",
            finding=Finding(module_id=self.id, target=target, severity=Severity.MEDIUM,
                            title="Reflet non échappé d'un paramètre (candidat XSS)",
                            evidence=f"Le marqueur {_MARKER} est renvoyé tel quel.",
                            remediation=Remediation(
                                summary="Échapper/encoder les entrées réfléchies ; CSP.",
                                reference="OWASP — Cross Site Scripting")))
```

- [ ] **Step 6: Write `src/redteam/tools/registry.py`**

```python
"""Registre des sondes disponibles (id -> instance)."""
from __future__ import annotations

from redteam.tools.probes.base import Probe
from redteam.tools.probes.security_headers import SecurityHeadersProbe
from redteam.tools.probes.version_disclosure import VersionDisclosureProbe
from redteam.tools.probes.exposed_endpoints import ExposedEndpointsProbe
from redteam.tools.probes.reflected_input import ReflectedInputProbe

PROBES: dict[str, Probe] = {
    p.id: p for p in (
        SecurityHeadersProbe(), VersionDisclosureProbe(),
        ExposedEndpointsProbe(), ReflectedInputProbe(),
    )
}


def get_probe(probe_id: str) -> Probe:
    return PROBES[probe_id]
```

- [ ] **Step 7: Write `src/redteam/tools/probes/__init__.py`** (vide)

- [ ] **Step 8: Write failing test** `tests/test_probes.py`

```python
import datetime
import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.registry import get_probe


def _client(handler):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]),
                  excluded=[], window=Window(start=datetime.date(2026, 10, 1),
                  end=datetime.date(2026, 12, 31)), allowed_intensity=Intensity.ACTIVE,
                  signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    return GuardedHttpClient(guard, Intensity.ACTIVE, max_requests=50,
                             transport=httpx.MockTransport(handler))


async def test_security_headers_probe_flags_missing():
    c = _client(lambda req: httpx.Response(200, text="x", headers={"server": "nginx"}))
    res = await get_probe("web.security_headers").run(c, "http://localhost/")
    assert res.found and res.finding is not None
    await c.aclose()


async def test_reflected_input_probe_detects_marker():
    c = _client(lambda req: httpx.Response(200, text="echo " + req.url.params.get("q", "")))
    res = await get_probe("web.reflected_input").run(c, "http://localhost/search")
    assert res.found
    await c.aclose()


async def test_reflected_input_probe_no_reflection():
    c = _client(lambda req: httpx.Response(200, text="static page"))
    res = await get_probe("web.reflected_input").run(c, "http://localhost/search")
    assert not res.found
    await c.aclose()
```

- [ ] **Step 9: Run** — `pytest tests/test_probes.py -v` — Expected: PASS
- [ ] **Step 10: Commit**

```bash
git add src/redteam/tools/probes/ src/redteam/tools/registry.py tests/test_probes.py
git commit -m "feat(tools): sondes de détection (headers, version, endpoints, reflet) + registre

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 13: Agents — état, prompts, parsing JSON défensif

**Files:**
- Create: `src/redteam/agents/__init__.py` (vide)
- Create: `src/redteam/agents/state.py`
- Create: `src/redteam/agents/prompts.py`
- Create: `src/redteam/agents/parsing.py`
- Test: `tests/test_parsing.py`

**Interfaces:**
- Consumes: `SurfaceMap` (Task 11), `Finding`, `Step` (Task 2), `TraceLog` (Task 9), `LLMBackend` (Task 8), `ScopeGuard` (Task 5).
- Produces:
  - `Hypothesis(probe_id: str, target: str, rationale: str)`.
  - `AuditState` (TypedDict) : `run_id, mode, target, surface (SurfaceMap|None), hypotheses (list[Hypothesis]), plan (list[Step]), raw_findings (list[Finding]), confirmed (list[dict]), replans (int), report_md (str)`. Plus les handles d'exécution non sérialisés : `backend`, `guard`, `trace`, `client_factory`.
  - `prompts.py` : `RECON_SYSTEM`, `PLANNER_SYSTEM`, `REPORTER_SYSTEM`, `SINGLE_SYSTEM` (chaînes, EN).
  - `parsing.py` : `extract_json_list(text: str) -> list[dict]` — tolère le texte autour d'un bloc JSON ; renvoie `[]` si rien d'exploitable (ne lève jamais).

- [ ] **Step 1: Write failing test** `tests/test_parsing.py`

```python
from redteam.agents.parsing import extract_json_list


def test_extract_clean_list():
    assert extract_json_list('[{"a": 1}]') == [{"a": 1}]


def test_extract_list_with_surrounding_text():
    text = 'Voici les hypothèses :\n[{"probe_id": "web.x"}]\nMerci.'
    assert extract_json_list(text) == [{"probe_id": "web.x"}]


def test_extract_garbage_returns_empty():
    assert extract_json_list("pas de json ici") == []
```

- [ ] **Step 2: Run** — `pytest tests/test_parsing.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/agents/parsing.py`**

```python
"""Parsing défensif des sorties LLM : on extrait le premier tableau JSON trouvé.

Un LLM peut entourer sa réponse de texte ; on ne doit jamais crasher sur une
sortie malformée. En cas d'échec, on renvoie une liste vide (l'orchestrateur
tracera alors une absence d'hypothèses plutôt qu'une erreur fatale).
"""
from __future__ import annotations

import json


def extract_json_list(text: str) -> list[dict]:
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        return []
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    return [x for x in parsed if isinstance(x, dict)] if isinstance(parsed, list) else []
```

- [ ] **Step 4: Write `src/redteam/agents/state.py`**

```python
"""État partagé du graphe d'audit (LangGraph) et objets associés."""
from __future__ import annotations

from typing import Any, Callable, TypedDict

from pydantic import BaseModel

from redteam.safety.domain import Finding, Step
from redteam.tools.crawler import SurfaceMap


class Hypothesis(BaseModel):
    probe_id: str
    target: str
    rationale: str


class AuditState(TypedDict, total=False):
    run_id: str
    mode: str
    target: str
    surface: SurfaceMap | None
    hypotheses: list[Hypothesis]
    plan: list[Step]
    raw_findings: list[Finding]
    confirmed: list[dict[str, Any]]
    replans: int
    report_md: str
    # handles d'exécution (non sérialisés dans le rapport)
    backend: Any
    guard: Any
    trace: Any
    client_factory: Callable[..., Any]
    max_replans: int
    # champs internes au runner (déclarés pour que LangGraph ne les filtre pas)
    _scope: Any
    _transport: Any
    _crawl_pages: int
```

- [ ] **Step 5: Write `src/redteam/agents/prompts.py`**

```python
"""Prompts système par rôle (en anglais, comme le code)."""
from __future__ import annotations

RECON_SYSTEM = (
    "You are a reconnaissance analyst for an AUTHORIZED security audit. "
    "Given a surface map (pages, headers, technologies), list candidate weaknesses "
    "to verify. Reply ONLY with a JSON array of objects "
    '{"probe_id": one of [web.security_headers, web.version_disclosure, '
    'web.exposed_endpoints, web.reflected_input], "target": url, "rationale": short}. '
    "Do not invent findings; you only propose checks."
)

PLANNER_SYSTEM = (
    "You order a list of audit checks from most to least promising. "
    "Reply ONLY with a JSON array of the same objects, reordered. Keep every item."
)

REPORTER_SYSTEM = (
    "You write a clear, factual security audit summary in French, one short paragraph, "
    "based ONLY on the confirmed findings provided. Do not add findings."
)

SINGLE_SYSTEM = (
    "You are a generalist security auditor for an AUTHORIZED target. "
    "From the surface map, propose checks to run. Reply ONLY with a JSON array of "
    '{"probe_id", "target", "rationale"} using the allowed probe ids. '
    "You propose; deterministic tools will verify."
)
```

- [ ] **Step 6: Write `src/redteam/agents/__init__.py`** (vide)

- [ ] **Step 7: Run** — `pytest tests/test_parsing.py -v` — Expected: PASS
- [ ] **Step 8: Commit**

```bash
git add src/redteam/agents/__init__.py src/redteam/agents/state.py src/redteam/agents/prompts.py src/redteam/agents/parsing.py tests/test_parsing.py
git commit -m "feat(agents): état, prompts, parsing JSON défensif

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 14: Agents — nœuds (recon, planner, attacker, verifier, reporter)

**Files:**
- Create: `src/redteam/agents/nodes.py`
- Test: `tests/test_verifier.py`

**Interfaces:**
- Consumes: `AuditState`, `Hypothesis` (Task 13), `get_probe`, `PROBES` (Task 12), `extract_json_list` (Task 13), `TraceEvent` (Task 9), prompts (Task 13), `now_iso` helper.
- Produces (fonctions async, chacune `(state: AuditState) -> AuditState`) :
  - `recon_node`, `planner_node`, `attacker_node`, `verifier_node`, `reporter_node`.
  - Helper `confidence_score(llm_claim: float, has_evidence: bool) -> float = 0.3*llm_claim + 0.7*(1.0 if has_evidence else 0.0)`.
  - `verify_findings(state, raw) -> list[dict]` : pour chaque finding candidat, **rejoue la sonde** via un client neuf ; `status="confirmed"` si la sonde retrouve une preuve, sinon `status="discarded"`. Chaque finding confirmé : `{finding, status, confidence, evidence}`.
- Un `raw_finding` dont la sonde ne retrouve **aucune** preuve au rejeu est `discarded` (faux-positif évité).

- [ ] **Step 1: Write failing test** `tests/test_verifier.py`

```python
import datetime
import httpx

from redteam.safety.domain import Intensity, Finding, Severity, Remediation
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.agents.nodes import verify_findings, confidence_score


def _state(handler):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
                  window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
                  allowed_intensity=Intensity.ACTIVE, signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(handler)
    return {"guard": guard, "target": "http://localhost/",
            "client_factory": lambda intensity: _mk(guard, intensity, transport)}


def _mk(guard, intensity, transport):
    from redteam.tools.http_client import GuardedHttpClient
    return GuardedHttpClient(guard, intensity, max_requests=50, transport=transport)


def _fake_finding(probe_id):
    return Finding(module_id=probe_id, target="http://localhost/", severity=Severity.MEDIUM,
                   title="t", evidence="e", remediation=Remediation(summary="s", reference="r"))


async def test_confirmed_when_evidence_reproduced():
    # headers manquants -> la sonde retrouve la preuve au rejeu
    state = _state(lambda req: httpx.Response(200, text="x", headers={"server": "nginx"}))
    out = await verify_findings(state, [_fake_finding("web.security_headers")])
    assert len(out) == 1 and out[0]["status"] == "confirmed"


async def test_discarded_when_no_evidence():
    # tous les en-têtes présents -> aucune preuve au rejeu -> faux positif écarté
    hdrs = {"strict-transport-security": "x", "content-security-policy": "x",
            "x-frame-options": "x", "x-content-type-options": "x"}
    state = _state(lambda req: httpx.Response(200, text="x", headers=hdrs))
    out = await verify_findings(state, [_fake_finding("web.security_headers")])
    assert all(o["status"] == "discarded" for o in out)


def test_confidence_weights_evidence():
    assert confidence_score(1.0, False) < confidence_score(0.0, True)
```

- [ ] **Step 2: Run** — `pytest tests/test_verifier.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/agents/nodes.py`**

```python
"""Nœuds du graphe d'audit : recon, planner, attacker, verifier, reporter.

Principe : les nœuds LLM (recon/planner/reporter) raisonnent ; attacker/verifier
exécutent des sondes déterministes. Aucune vuln n'est retenue sans preuve
reproductible (verifier).
"""
from __future__ import annotations

import datetime

from redteam.agents.parsing import extract_json_list
from redteam.agents.prompts import PLANNER_SYSTEM, RECON_SYSTEM, REPORTER_SYSTEM
from redteam.agents.state import AuditState, Hypothesis
from redteam.monitoring.trace import TraceEvent
from redteam.safety.domain import Finding, Intensity, Step
from redteam.tools.registry import PROBES, get_probe


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def confidence_score(llm_claim: float, has_evidence: bool) -> float:
    return 0.3 * llm_claim + 0.7 * (1.0 if has_evidence else 0.0)


def _emit(state: AuditState, **kw) -> None:
    trace = state.get("trace")
    if trace is not None:
        trace.emit(TraceEvent(ts=now_iso(), run_id=state["run_id"], mode=state["mode"], **kw))


async def recon_node(state: AuditState) -> AuditState:
    surface = state.get("surface")
    summary = "" if surface is None else "\n".join(
        f"{p.url} [{p.status}] server={p.headers.get('server', '')}" for p in surface.pages[:30])
    res = state["backend"].complete(RECON_SYSTEM, f"Surface map:\n{summary}")
    _emit(state, agent="recon", phase="recon", type="llm_call", model=res.model,
          tokens_in=res.tokens_in, tokens_out=res.tokens_out, latency_ms=res.latency_ms)
    hyps: list[Hypothesis] = []
    for item in extract_json_list(res.text):
        pid = item.get("probe_id")
        if pid in PROBES:
            hyps.append(Hypothesis(probe_id=pid, target=item.get("target", state["target"]),
                                   rationale=item.get("rationale", "")))
    if not hyps:  # repli sûr : si le LLM n'a rien proposé d'exploitable, on teste tout
        hyps = [Hypothesis(probe_id=pid, target=state["target"], rationale="repli")
                for pid in PROBES]
    state["hypotheses"] = hyps
    _emit(state, agent="recon", phase="recon", type="decision",
          rationale=f"{len(hyps)} hypothèses retenues")
    return state


async def planner_node(state: AuditState) -> AuditState:
    hyps = state.get("hypotheses", [])
    state["plan"] = [Step(module_id=h.probe_id, target=h.target,
                          intensity=PROBES[h.probe_id].intensity, description=h.rationale)
                     for h in hyps if state["guard"].check(h.target, PROBES[h.probe_id].intensity).allowed]
    _emit(state, agent="planner", phase="plan", type="decision",
          rationale=f"{len(state['plan'])} étapes dans le périmètre")
    return state


async def attacker_node(state: AuditState) -> AuditState:
    raw: list[Finding] = []
    for step in state.get("plan", []):
        probe = get_probe(step.module_id)
        client = state["client_factory"](probe.intensity)
        try:
            result = await probe.run(client, step.target)
        finally:
            await client.aclose()
        _emit(state, agent="attacker", phase="act", type="tool_call", tool=probe.id,
              http_count=client.count, rationale=step.description)
        if result.found and result.finding is not None:
            raw.append(result.finding)
    state["raw_findings"] = raw
    return state


async def verify_findings(state: AuditState, raw: list[Finding]) -> list[dict]:
    verified: list[dict] = []
    for i, finding in enumerate(raw):
        probe = get_probe(finding.module_id)
        client = state["client_factory"](probe.intensity)
        try:
            recheck = await probe.run(client, finding.target)
        finally:
            await client.aclose()
        has_evidence = recheck.found
        status = "confirmed" if has_evidence else "discarded"
        conf = confidence_score(1.0, has_evidence)
        verified.append({"finding": finding, "status": status, "confidence": conf,
                         "evidence": recheck.evidence, "finding_id": f"F{i + 1}"})
    return verified


async def verifier_node(state: AuditState) -> AuditState:
    verified = await verify_findings(state, state.get("raw_findings", []))
    for v in verified:
        _emit(state, agent="verifier", phase="verify", type="verification",
              finding_id=v["finding_id"], severity=v["finding"].severity.value,
              status=v["status"], confidence=v["confidence"],
              rationale=v["evidence"][:120])
    state["confirmed"] = [v for v in verified if v["status"] == "confirmed"]
    return state


async def reporter_node(state: AuditState) -> AuditState:
    confirmed = state.get("confirmed", [])
    listing = "\n".join(f"- [{v['finding'].severity.value}] {v['finding'].title}" for v in confirmed)
    res = state["backend"].complete(REPORTER_SYSTEM, f"Findings confirmés:\n{listing or 'aucun'}")
    _emit(state, agent="reporter", phase="report", type="llm_call", model=res.model,
          tokens_in=res.tokens_in, tokens_out=res.tokens_out, latency_ms=res.latency_ms)
    state["report_md"] = res.text
    return state
```

- [ ] **Step 4: Run** — `pytest tests/test_verifier.py -v` — Expected: PASS
- [ ] **Step 5: Commit**

```bash
git add src/redteam/agents/nodes.py tests/test_verifier.py
git commit -m "feat(agents): nœuds recon/planner/attacker/verifier/reporter + preuve déterministe

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 15: Agents — graphes `crew` et `single`

**Files:**
- Create: `src/redteam/agents/crew_graph.py`
- Create: `src/redteam/agents/single_agent.py`
- Test: `tests/test_graph_smoke.py`

**Interfaces:**
- Consumes: nœuds (Task 14), `AuditState` (Task 13).
- Produces:
  - `build_crew_graph()` → graphe LangGraph compilé : `recon → planner → attacker → verifier → (replan? planner : reporter) → END`. La condition de replan : si de nouveaux `raw_findings` non vus **et** `state["replans"] < state["max_replans"]`, retour au planner (incrément `replans` + event `strategy_change`) ; sinon reporter. Pour le PoC, la boucle s'arrête après au plus `max_replans` tours (valeur par défaut 1).
  - `build_single_graph()` → graphe à un nœud `single_node` qui enchaîne recon→attacker→verifier→reporter en une passe (généraliste).
  - Les deux exposent `async def run_audit(state: AuditState) -> AuditState`.

- [ ] **Step 1: Write `src/redteam/agents/crew_graph.py`**

```python
"""Graphe multi-agents (crew) : recon → planner → attacker → verifier → reporter,
avec une boucle de replanification bornée (adaptativité)."""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from redteam.agents.nodes import (attacker_node, now_iso, planner_node, recon_node,
                                   reporter_node, verifier_node)
from redteam.agents.state import AuditState
from redteam.monitoring.trace import TraceEvent


async def _maybe_replan(state: AuditState) -> AuditState:
    # Boucle d'adaptativité : au plus max_replans tours.
    state["replans"] = state.get("replans", 0)
    return state


def _route_after_verify(state: AuditState) -> str:
    if state.get("replans", 0) < state.get("max_replans", 1) and state.get("raw_findings"):
        return "replan"
    return "report"


async def _replan_node(state: AuditState) -> AuditState:
    state["replans"] = state.get("replans", 0) + 1
    trace = state.get("trace")
    if trace is not None:
        trace.emit(TraceEvent(ts=now_iso(), run_id=state["run_id"], mode=state["mode"],
                              agent="planner", phase="plan", type="strategy_change",
                              rationale=f"replanification #{state['replans']}"))
    return state


def build_crew_graph():
    g = StateGraph(AuditState)
    g.add_node("recon", recon_node)
    g.add_node("planner", planner_node)
    g.add_node("attacker", attacker_node)
    g.add_node("verifier", verifier_node)
    g.add_node("replan", _replan_node)
    g.add_node("reporter", reporter_node)
    g.add_edge(START, "recon")
    g.add_edge("recon", "planner")
    g.add_edge("planner", "attacker")
    g.add_edge("attacker", "verifier")
    g.add_conditional_edges("verifier", _route_after_verify,
                            {"replan": "replan", "report": "reporter"})
    g.add_edge("replan", "attacker")
    g.add_edge("reporter", END)
    return g.compile()


async def run_audit(state: AuditState) -> AuditState:
    # recursion_limit évite toute boucle infinie même si la condition change.
    return await build_crew_graph().ainvoke(state, config={"recursion_limit": 25})
```

> Note : pour éviter une boucle infinie, `_route_after_verify` doit renvoyer `report` dès que `replans >= max_replans`. La re-vérification après replan garde `raw_findings` ; comme `replans` est incrémenté, au tour suivant la route bascule sur `report`.

- [ ] **Step 2: Write `src/redteam/agents/single_agent.py`**

```python
"""Graphe mono-agent (généraliste) : une seule passe recon→act→verify→report.

Partage exactement les mêmes outils et le même Verifier que le mode crew, pour
une comparaison « toutes choses égales par ailleurs »."""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from redteam.agents.nodes import (attacker_node, planner_node, recon_node,
                                   reporter_node, verifier_node)
from redteam.agents.state import AuditState


async def _single_node(state: AuditState) -> AuditState:
    state = await recon_node(state)
    state = await planner_node(state)
    state = await attacker_node(state)
    state = await verifier_node(state)
    state = await reporter_node(state)
    return state


def build_single_graph():
    g = StateGraph(AuditState)
    g.add_node("single", _single_node)
    g.add_edge(START, "single")
    g.add_edge("single", END)
    return g.compile()


async def run_audit(state: AuditState) -> AuditState:
    return await build_single_graph().ainvoke(state, config={"recursion_limit": 10})
```

- [ ] **Step 3: Write failing test** `tests/test_graph_smoke.py`

```python
import datetime
import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.crawler import SurfaceMap, Page
from redteam.llm.backend import MockBackend
from redteam.agents import crew_graph, single_agent


def _base_state(mode):
    scope = Scope(mission="m", mandate_ref="r", client_contact="c",
                  authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
                  window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
                  allowed_intensity=Intensity.ACTIVE, signature="x")
    guard = ScopeGuard(scope, today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="x",
                                    headers={"server": "nginx/1.2"}))
    surface = SurfaceMap(pages=[Page(url="http://localhost/", status=200,
                         headers={"server": "nginx/1.2"}, body_snippet="x")], links=[])
    recon_json = ('[{"probe_id":"web.security_headers","target":"http://localhost/",'
                  '"rationale":"no headers"}]')
    return {
        "run_id": "t", "mode": mode, "target": "http://localhost/", "surface": surface,
        "hypotheses": [], "plan": [], "raw_findings": [], "confirmed": [], "replans": 0,
        "max_replans": 1, "report_md": "",
        "backend": MockBackend(responses={"Surface map": recon_json}, default="résumé"),
        "guard": guard, "trace": None,
        "client_factory": lambda intensity: GuardedHttpClient(guard, intensity,
                          max_requests=50, transport=transport),
    }


async def test_crew_graph_runs_end_to_end():
    out = await crew_graph.run_audit(_base_state("crew"))
    assert out["report_md"]
    assert len(out["confirmed"]) >= 1  # headers manquants confirmés


async def test_single_graph_runs_end_to_end():
    out = await single_agent.run_audit(_base_state("single"))
    assert out["report_md"]
```

- [ ] **Step 4: Run** — `pytest tests/test_graph_smoke.py -v` — Expected: PASS (si la route de replan boucle, vérifier `_route_after_verify`)
- [ ] **Step 5: Commit**

```bash
git add src/redteam/agents/crew_graph.py src/redteam/agents/single_agent.py tests/test_graph_smoke.py
git commit -m "feat(agents): graphes LangGraph crew (adaptatif) et single

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 16: Report — Markdown + HTML

**Files:**
- Create: `src/redteam/report/__init__.py` (vide)
- Create: `src/redteam/report/markdown.py`
- Create: `src/redteam/report/html.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `confirmed` (list[dict] de Task 14), `Scope` (Task 4), `export_bundle` (Task 6).
- Produces:
  - `render_markdown(scope, confirmed, summary, audit_bundle, metrics) -> str`.
  - `render_html(markdown_text, title) -> str` (enveloppe HTML minimale, lisible).

- [ ] **Step 1: Write failing test** `tests/test_report.py`

```python
from redteam.safety.domain import Finding, Severity, Remediation
from redteam.report.markdown import render_markdown


def _conf():
    f = Finding(module_id="web.security_headers", target="http://localhost/",
                severity=Severity.MEDIUM, title="En-têtes manquants", evidence="HSTS absent",
                remediation=Remediation(summary="ajouter HSTS", reference="OWASP"))
    return [{"finding": f, "status": "confirmed", "confidence": 0.85,
             "evidence": "HSTS absent", "finding_id": "F1"}]


def test_markdown_lists_confirmed_finding():
    md = render_markdown(scope=None, confirmed=_conf(), summary="résumé",
                         audit_bundle=None, metrics={"duration_s": 1.2})
    assert "En-têtes manquants" in md and "F1" in md and "0.85" in md
```

- [ ] **Step 2: Run** — `pytest tests/test_report.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/report/markdown.py`**

```python
"""Génération du rapport d'audit en Markdown (findings confirmés + preuves)."""
from __future__ import annotations

from typing import Any

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_markdown(scope: Any, confirmed: list[dict], summary: str,
                    audit_bundle: dict | None, metrics: dict) -> str:
    lines: list[str] = ["# Rapport d'audit — Red Team IA", ""]
    if scope is not None:
        lines += [f"- **Mission :** {scope.mission}", f"- **Mandat :** {scope.mandate_ref}", ""]
    lines += [f"**Synthèse :** {summary}", ""]
    lines += ["## Métriques", ""]
    for k, v in metrics.items():
        lines.append(f"- **{k} :** {v}")
    lines.append("")
    if not confirmed:
        lines += ["## Aucun finding confirmé", "", "Aucune preuve reproductible sur le périmètre.", ""]
    else:
        lines += ["## Findings confirmés", ""]
        for v in sorted(confirmed, key=lambda x: _ORDER.get(x["finding"].severity.value, 9)):
            f = v["finding"]
            lines += [
                f"### [{f.severity.value.upper()}] {v['finding_id']} — {f.title}",
                "",
                f"- **Cible :** {f.target}",
                f"- **Confiance :** {v['confidence']:.2f}",
                f"- **Preuve :** {v['evidence']}",
                f"- **Remédiation ({f.remediation.reference}) :** {f.remediation.summary}",
                "",
            ]
    if audit_bundle is not None:
        lines += ["## Intégrité de l'audit", "",
                  f"- **Entrées journalisées :** {audit_bundle.get('count', 0)}",
                  f"- **Empreinte de fin :** {audit_bundle.get('tip_hash', '')}",
                  f"- **Statut :** {audit_bundle.get('integrity_status', 'n/a')}", ""]
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Write `src/redteam/report/html.py`**

```python
"""Enveloppe HTML minimale et lisible autour du rapport Markdown."""
from __future__ import annotations

import html


def render_html(markdown_text: str, title: str = "Rapport Red Team IA") -> str:
    body = html.escape(markdown_text)
    return (
        "<!doctype html><html lang='fr'><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto;"
        "padding:0 1rem;line-height:1.5}pre{white-space:pre-wrap;background:#f6f8fa;"
        "padding:1rem;border-radius:8px}</style></head>"
        f"<body><pre>{body}</pre></body></html>"
    )
```

- [ ] **Step 5: Run** — `pytest tests/test_report.py -v` — Expected: PASS
- [ ] **Step 6: Commit**

```bash
git add src/redteam/report/ tests/test_report.py
git commit -m "feat(report): rapport Markdown + enveloppe HTML

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 17: Benchmark — métriques, ground truth, comparaison

**Files:**
- Create: `src/redteam/benchmark/__init__.py` (vide)
- Create: `src/redteam/benchmark/metrics.py`
- Create: `src/redteam/benchmark/compare.py`
- Create: `eval/mirage_ground_truth.yaml`
- Test: `tests/test_metrics.py`

**Interfaces:**
- Consumes: `TraceEvent` (Task 9), `confirmed` (Task 14).
- Produces:
  - `RunMetrics(BaseModel)` : `run_id, mode, duration_s, llm_calls, tokens_in, tokens_out, tool_calls, raw_count, confirmed_count, discarded_count, replans, errors`.
  - `metrics_from_trace(events: list[TraceEvent], duration_s: float) -> RunMetrics`.
  - `quality(confirmed_ids: set[str], truth_ids: set[str]) -> dict` → `precision, recall, f1`.
  - `compare_runs(metrics: list[RunMetrics]) -> str` (tableau Markdown).
  - `eval/mirage_ground_truth.yaml` : `known_findings: [ {probe_id: web.security_headers}, ... ]`.

- [ ] **Step 1: Write failing test** `tests/test_metrics.py`

```python
from redteam.monitoring.trace import TraceEvent
from redteam.benchmark.metrics import metrics_from_trace, quality


def _ev(type, **kw):
    return TraceEvent(ts="t", run_id="r", mode="crew", agent="a", phase="p", type=type, **kw)


def test_metrics_counts():
    events = [_ev("llm_call", tokens_in=10, tokens_out=5), _ev("tool_call"),
              _ev("verification", status="confirmed"), _ev("verification", status="discarded")]
    m = metrics_from_trace(events, duration_s=2.0)
    assert m.llm_calls == 1 and m.tool_calls == 1
    assert m.confirmed_count == 1 and m.discarded_count == 1
    assert m.tokens_in == 10


def test_quality_precision_recall():
    q = quality(confirmed_ids={"a", "b"}, truth_ids={"a", "c"})
    assert q["precision"] == 0.5 and q["recall"] == 0.5
```

- [ ] **Step 2: Run** — `pytest tests/test_metrics.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/benchmark/metrics.py`**

```python
"""Agrégation des métriques d'un run à partir de sa trace, et qualité vs ground truth."""
from __future__ import annotations

from pydantic import BaseModel

from redteam.monitoring.trace import TraceEvent


class RunMetrics(BaseModel):
    run_id: str
    mode: str
    duration_s: float
    llm_calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    tool_calls: int = 0
    raw_count: int = 0
    confirmed_count: int = 0
    discarded_count: int = 0
    replans: int = 0
    errors: int = 0


def metrics_from_trace(events: list[TraceEvent], duration_s: float) -> RunMetrics:
    run_id = events[0].run_id if events else "?"
    mode = events[0].mode if events else "?"
    m = RunMetrics(run_id=run_id, mode=mode, duration_s=duration_s)
    for e in events:
        if e.type == "llm_call":
            m.llm_calls += 1
            m.tokens_in += e.tokens_in or 0
            m.tokens_out += e.tokens_out or 0
        elif e.type == "tool_call":
            m.tool_calls += 1
        elif e.type == "verification":
            if e.status == "confirmed":
                m.confirmed_count += 1
            elif e.status == "discarded":
                m.discarded_count += 1
        elif e.type == "strategy_change":
            m.replans += 1
        elif e.type == "error":
            m.errors += 1
    m.raw_count = m.confirmed_count + m.discarded_count
    return m


def quality(confirmed_ids: set[str], truth_ids: set[str]) -> dict:
    tp = len(confirmed_ids & truth_ids)
    precision = tp / len(confirmed_ids) if confirmed_ids else 0.0
    recall = tp / len(truth_ids) if truth_ids else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}
```

- [ ] **Step 4: Write `src/redteam/benchmark/compare.py`**

```python
"""Tableau comparatif Markdown entre plusieurs runs (mono vs crew, modèle A/B)."""
from __future__ import annotations

from redteam.benchmark.metrics import RunMetrics


def compare_runs(metrics: list[RunMetrics]) -> str:
    cols = ["mode", "duration_s", "llm_calls", "tokens_in", "tokens_out",
            "tool_calls", "confirmed_count", "discarded_count", "replans", "errors"]
    lines = ["| " + " | ".join(["run_id"] + cols) + " |",
             "| " + " | ".join(["---"] * (len(cols) + 1)) + " |"]
    for m in metrics:
        row = [m.run_id] + [str(getattr(m, c)) for c in cols]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"
```

- [ ] **Step 5: Write `eval/mirage_ground_truth.yaml`**

```yaml
# Vulnérabilités connues de la cible Mirage (à ajuster selon le déploiement réel).
# Sert à calculer précision/rappel de l'audit IA.
known_findings:
  - probe_id: web.security_headers
  - probe_id: web.version_disclosure
  - probe_id: web.reflected_input
```

- [ ] **Step 6: Write `src/redteam/benchmark/__init__.py`** (vide)

- [ ] **Step 7: Run** — `pytest tests/test_metrics.py -v` — Expected: PASS
- [ ] **Step 8: Commit**

```bash
git add src/redteam/benchmark/ eval/mirage_ground_truth.yaml tests/test_metrics.py
git commit -m "feat(benchmark): métriques, qualité (précision/rappel), comparaison

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 18: Monitoring — console live + callback LangChain

**Files:**
- Create: `src/redteam/monitoring/live.py`
- Create: `src/redteam/monitoring/callbacks.py`
- Test: `tests/test_live.py`

**Interfaces:**
- Consumes: `TraceEvent` (Task 9).
- Produces:
  - `format_event(event: TraceEvent) -> str` : ligne lisible pour la console (ex. `[verify] F1 medium → confirmed (0.85)`).
  - `LiveConsole(enabled: bool = True)` : `.show(event)` imprime via `rich` si activé (no-op sinon).
  - `callbacks.py` : `TokenCountingHandler` (callback LangChain capturant tokens/latence) — utilisé optionnellement par le backend ; testé a minima par instanciation.

- [ ] **Step 1: Write failing test** `tests/test_live.py`

```python
from redteam.monitoring.trace import TraceEvent
from redteam.monitoring.live import format_event


def test_format_verification_event():
    e = TraceEvent(ts="t", run_id="r", mode="crew", agent="verifier", phase="verify",
                   type="verification", finding_id="F1", severity="medium",
                   status="confirmed", confidence=0.85)
    line = format_event(e)
    assert "F1" in line and "confirmed" in line and "verify" in line
```

- [ ] **Step 2: Run** — `pytest tests/test_live.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/monitoring/live.py`**

```python
"""Affichage temps réel du raisonnement des agents (console rich)."""
from __future__ import annotations

from redteam.monitoring.trace import TraceEvent


def format_event(e: TraceEvent) -> str:
    bits = [f"[{e.phase}]", e.agent]
    if e.type == "verification":
        bits.append(f"{e.finding_id} {e.severity} → {e.status} ({e.confidence:.2f})")
    elif e.type == "tool_call":
        bits.append(f"outil {e.tool} (req={e.http_count})")
    elif e.type == "llm_call":
        bits.append(f"llm {e.model} (in={e.tokens_in} out={e.tokens_out})")
    elif e.type == "strategy_change":
        bits.append(f"↻ {e.rationale}")
    else:
        bits.append(e.type + (f" — {e.rationale}" if e.rationale else ""))
    return " ".join(str(b) for b in bits)


class LiveConsole:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._console = None
        if enabled:
            try:
                from rich.console import Console
                self._console = Console()
            except Exception:
                self.enabled = False

    def show(self, event: TraceEvent) -> None:
        if self.enabled and self._console is not None:
            self._console.print(format_event(event))
```

- [ ] **Step 4: Write `src/redteam/monitoring/callbacks.py`**

```python
"""Callback LangChain optionnel pour capturer tokens et latence des appels LLM.

Non requis par le MockBackend ; utile si l'on branche directement un modèle
LangChain sans passer par FeatherlessBackend.
"""
from __future__ import annotations

import time


class TokenCountingHandler:
    def __init__(self) -> None:
        self.tokens_in = 0
        self.tokens_out = 0
        self.latency_ms = 0
        self._start = 0.0

    def on_llm_start(self, *args, **kwargs) -> None:
        self._start = time.monotonic()

    def on_llm_end(self, response, *args, **kwargs) -> None:
        self.latency_ms = int((time.monotonic() - self._start) * 1000)
        try:
            usage = response.llm_output.get("token_usage", {})
            self.tokens_in += int(usage.get("prompt_tokens", 0))
            self.tokens_out += int(usage.get("completion_tokens", 0))
        except Exception:
            pass
```

- [ ] **Step 5: Run** — `pytest tests/test_live.py -v` — Expected: PASS
- [ ] **Step 6: Commit**

```bash
git add src/redteam/monitoring/live.py src/redteam/monitoring/callbacks.py tests/test_live.py
git commit -m "feat(monitoring): console live + callback tokens/latence

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 19: CLI (orchestration de bout en bout)

**Files:**
- Create: `src/redteam/cli.py`
- Create: `src/redteam/runner.py`
- Test: `tests/test_runner.py`

**Interfaces:**
- Consumes: tout le reste.
- Produces:
  - `runner.py` : `async def run_once(mode, target, scope, guard, backend, trace, run_dir) -> dict` — crawl → build state → run_audit (crew/single) → écrit `report.md`, `report.html`, `state.json` ; renvoie `{confirmed, metrics, report_md}`. `build_state(...)` assemble `AuditState` avec `client_factory`.
  - `prepare_scope(settings) -> (scope, guard)` : charge `config/scope.template.yaml`, injecte `MIRAGE_TARGET` dans `authorized.domains`, **signe**, écrit `scope.yaml`, charge via `load_scope`.
  - `cli.py` (typer) : commandes `scope-show`, `run --mode single|crew --target ...`, `benchmark --modes single,crew`, affichage via `LiveConsole`.

- [ ] **Step 1: Write failing test** `tests/test_runner.py`

```python
import datetime
import json
import os

import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.llm.backend import MockBackend
from redteam.runner import build_state, run_graph


def _scope():
    return Scope(mission="m", mandate_ref="r", client_contact="c",
                 authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
                 window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
                 allowed_intensity=Intensity.ACTIVE, signature="x")


async def test_run_graph_writes_report(tmp_path, monkeypatch):
    guard = ScopeGuard(_scope(), today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="x",
                                    headers={"server": "nginx/1.0"}))
    backend = MockBackend(responses={"Surface map":
        '[{"probe_id":"web.security_headers","target":"http://localhost/","rationale":"r"}]'},
        default="résumé")
    state = build_state(mode="crew", target="http://localhost/", scope=_scope(), guard=guard,
                        backend=backend, trace=None, transport=transport, surface=None,
                        crawl_pages=1)
    out = await run_graph(state, run_dir=str(tmp_path))
    assert os.path.exists(tmp_path / "report.md")
    assert out["metrics"]["confirmed_count"] >= 0
```

- [ ] **Step 2: Run** — `pytest tests/test_runner.py -v` — Expected: FAIL

- [ ] **Step 3: Write `src/redteam/runner.py`**

```python
"""Orchestration de bout en bout : scope → crawl → graphe → rapport + métriques."""
from __future__ import annotations

import datetime
import json
import os
import time
from typing import Any

import httpx

from redteam.agents import crew_graph, single_agent
from redteam.agents.state import AuditState
from redteam.benchmark.metrics import metrics_from_trace
from redteam.report.html import render_html
from redteam.report.markdown import render_markdown
from redteam.safety.audit import AuditLog, export_bundle
from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.tools.crawler import crawl
from redteam.tools.http_client import GuardedHttpClient


def build_state(mode: str, target: str, scope, guard: ScopeGuard, backend, trace,
                transport: httpx.BaseTransport | None = None, surface=None,
                crawl_pages: int = 20, max_replans: int = 1) -> AuditState:
    def client_factory(intensity: Intensity) -> GuardedHttpClient:
        return GuardedHttpClient(guard, intensity,
                                 max_requests=scope.limits.max_requests_per_module,
                                 transport=transport)
    return {
        "run_id": datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), "mode": mode,
        "target": target, "surface": surface, "hypotheses": [], "plan": [],
        "raw_findings": [], "confirmed": [], "replans": 0, "max_replans": max_replans,
        "report_md": "", "backend": backend, "guard": guard, "trace": trace,
        "client_factory": client_factory, "_scope": scope, "_transport": transport,
        "_crawl_pages": crawl_pages,
    }


async def run_graph(state: AuditState, run_dir: str) -> dict:
    os.makedirs(run_dir, exist_ok=True)
    start = time.monotonic()
    # Recon crawl si la surface n'est pas fournie.
    if state.get("surface") is None:
        client = state["client_factory"](Intensity.PASSIVE)
        try:
            state["surface"] = await crawl(client, state["target"],
                                           max_pages=state.get("_crawl_pages", 20))
        finally:
            await client.aclose()
    module = crew_graph if state["mode"] == "crew" else single_agent
    out = await module.run_audit(state)
    duration = time.monotonic() - start

    scope = state.get("_scope")
    summary = out.get("report_md", "")
    events = state["trace"].events() if state.get("trace") is not None else []
    m = metrics_from_trace(events, duration_s=round(duration, 3))
    md = render_markdown(scope=scope, confirmed=out.get("confirmed", []), summary=summary,
                         audit_bundle=None, metrics=m.model_dump())
    with open(os.path.join(run_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(run_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(md))
    with open(os.path.join(run_dir, "state.json"), "w", encoding="utf-8") as fh:
        json.dump({"confirmed": [{"id": v["finding_id"], "title": v["finding"].title,
                                  "status": v["status"], "confidence": v["confidence"]}
                                 for v in out.get("confirmed", [])]}, fh, ensure_ascii=False, indent=2)
    return {"confirmed": out.get("confirmed", []), "metrics": m.model_dump(), "report_md": md}
```

- [ ] **Step 4: Run** — `pytest tests/test_runner.py -v` — Expected: PASS

- [ ] **Step 5: Write `src/redteam/cli.py`**

```python
"""Interface en ligne de commande du PoC Red Team IA."""
from __future__ import annotations

import asyncio
import datetime
import os

import typer
import yaml

from redteam.benchmark.compare import compare_runs
from redteam.benchmark.metrics import RunMetrics
from redteam.config import load_settings
from redteam.llm.backend import FeatherlessBackend, MockBackend
from redteam.monitoring.trace import TraceLog
from redteam.runner import build_state, run_graph
from redteam.safety.audit import AuditLog
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import compute_signature, load_scope

app = typer.Typer(help="Red Team IA — audit cybersécurité adaptatif sous mandat.")

TEMPLATE = "config/scope.template.yaml"


def prepare_scope(target: str):
    """Charge le gabarit, injecte la cible, signe et recharge le scope."""
    with open(TEMPLATE, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    from urllib.parse import urlparse
    host = urlparse(target).hostname or "localhost"
    if host not in data["authorized"]["domains"]:
        data["authorized"]["domains"].append(host)
    data["signature"] = compute_signature(data)
    with open("scope.yaml", "w", encoding="utf-8") as fh:
        yaml.safe_dump(data, fh)
    scope = load_scope("scope.yaml")
    guard = ScopeGuard(scope, today=datetime.date.today())
    return scope, guard


def _backend(settings, mock: bool):
    if mock or not settings.featherless_api_key:
        return MockBackend(default="(mode mock — pas de clé API)")
    return FeatherlessBackend(settings.featherless_api_key, settings.base_url, settings.model)


@app.command("scope-show")
def scope_show():
    settings = load_settings()
    scope, _ = prepare_scope(settings.target)
    typer.echo(f"Mission : {scope.mission}\nPérimètre : {scope.authorized.domains}")


@app.command()
def run(mode: str = "crew", target: str = "", mock: bool = False):
    settings = load_settings()
    target = target or settings.target
    scope, guard = prepare_scope(target)
    run_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join("runs", f"{mode}-{run_id}")
    os.makedirs(run_dir, exist_ok=True)
    audit = AuditLog(os.path.join(run_dir, "audit.jsonl"))
    trace = TraceLog(os.path.join(run_dir, "trace.jsonl"), run_id=run_id, mode=mode, audit=audit)
    state = build_state(mode=mode, target=target, scope=scope, guard=guard,
                        backend=_backend(settings, mock), trace=trace)
    out = asyncio.run(run_graph(state, run_dir=run_dir))
    audit.write_checkpoint(__import__("redteam.safety.signing", fromlist=["default_signer"]).default_signer())
    typer.echo(f"Rapport : {run_dir}/report.md")
    typer.echo(f"Findings confirmés : {out['metrics']['confirmed_count']} | "
               f"faux-positifs écartés : {out['metrics']['discarded_count']}")


@app.command()
def benchmark(modes: str = "single,crew", target: str = "", mock: bool = False):
    settings = load_settings()
    target = target or settings.target
    results: list[RunMetrics] = []
    for mode in modes.split(","):
        mode = mode.strip()
        scope, guard = prepare_scope(target)
        run_id = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + mode
        run_dir = os.path.join("runs", f"bench-{run_id}")
        os.makedirs(run_dir, exist_ok=True)
        trace = TraceLog(os.path.join(run_dir, "trace.jsonl"), run_id=run_id, mode=mode)
        state = build_state(mode=mode, target=target, scope=scope, guard=guard,
                            backend=_backend(settings, mock), trace=trace)
        out = asyncio.run(run_graph(state, run_dir=run_dir))
        results.append(RunMetrics(**out["metrics"]))
    table = compare_runs(results)
    with open("runs/benchmark.md", "w", encoding="utf-8") as fh:
        fh.write(table)
    typer.echo(table)


if __name__ == "__main__":
    app()
```

- [ ] **Step 6: Manual smoke (offline)** — Run: `redteam run --mode crew --mock --target http://localhost:8080` (échouera au crawl si rien n'écoute : attendu ; vérifie que le scope est généré/signé et que le dossier `runs/` est créé). Pour un smoke complet sans cible, s'appuyer sur `tests/test_runner.py`.

- [ ] **Step 7: Commit**

```bash
git add src/redteam/runner.py src/redteam/cli.py tests/test_runner.py
git commit -m "feat(cli): orchestration bout-en-bout (run, benchmark) + scope signé au lancement

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 20: Documentation (FR) + lint final

**Files:**
- Create: `README.md`
- Create: `docs/ARCHITECTURE.md`
- Create: `docs/METHODOLOGIE.md`

**Interfaces:** aucune (documentation).

- [ ] **Step 1: Write `README.md`** — sections : objectif, cadre d'autorisation (cible Mirage, scope signé), installation (`pip install -e ".[dev]"`, `.env`), usage (`redteam run --mode crew|single`, `--mock`, `benchmark`), sorties (`runs/<id>/report.md|html`, `trace.jsonl`, `audit.jsonl`), avertissement légal (usage strictement sous mandat). Inclure un exemple de sortie.

- [ ] **Step 2: Write `docs/ARCHITECTURE.md`** — schéma des couches (safety / llm / tools / agents / monitoring / benchmark / report), le flux `crew` et `single`, le rôle du `ScopeGuard` comme unique porte réseau, le modèle `TraceEvent`, et la correspondance avec les livrables du hackathon (reprendre le tableau §11 de la spec).

- [ ] **Step 3: Write `docs/METHODOLOGIE.md`** — comment les métriques répondent aux 5 questions du brief (mono vs crew, modèle par étape, autonomie bornée par `max_replans`/intensité, crédibilité via Verifier déterministe, qualité via précision/rappel vs ground truth) ; **section limites/échecs/pistes** (dépendance LLM distant, couverture de sondes restreinte, maintien du ground truth, bornes d'autonomie comme choix de sûreté).

- [ ] **Step 4: Run lint + full test suite** — Run: `ruff check src tests && pytest -q` — Expected: lint clean, tous les tests PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/ARCHITECTURE.md docs/METHODOLOGIE.md
git commit -m "docs: README, architecture et méthodologie (FR)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Notes d'exécution transverses

- **Ordre des tâches** : strictement 1→20 (dépendances d'interfaces).
- **Hors ligne** : toute la suite de tests tourne sans réseau ni clé API (MockBackend + httpx.MockTransport).
- **Boucle d'adaptativité (Task 15)** : vérifier que `_route_after_verify` bascule sur `report` dès `replans >= max_replans` pour éviter toute boucle ; `recursion_limit` est un filet de sécurité.
- **CLI `run` checkpoint (Task 19 Step 5)** : l'écriture du checkpoint d'audit nécessite `REDTEAM_SIGNING_KEY` ; sinon capter `SigningKeyError` et prévenir l'utilisateur (le journal reste valide, seul l'ancrage anti-troncature manque).
