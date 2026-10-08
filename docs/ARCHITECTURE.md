# Architecture

Ce document décrit l'architecture du PoC **Red Team IA** : les couches logicielles, les deux
flux d'exécution (`crew` et `single`), le rôle du `ScopeGuard` comme unique porte réseau, le
modèle de traçage `TraceEvent`, et la correspondance avec les livrables du hackathon.

---

## 1. Vue en couches

Le code vit sous `src/redteam/`. Chaque couche a une responsabilité unique ; les dépendances
vont du haut (orchestration) vers le bas (sûreté).

```
┌──────────────────────────────────────────────────────────────┐
│  cli.py            Typer : scope-show | run | benchmark        │
│  runner.py         build_state → crawl recon → run_graph       │
├──────────────────────────────────────────────────────────────┤
│  agents/           Nœuds LangGraph (raisonnement LLM)          │
│    recon · planner · attacker · verifier · reporter            │
│    crew_graph.py (multi-agents) · single_agent.py (généraliste)│
├───────────────┬──────────────────────┬───────────────────────-┤
│  llm/         │  tools/              │  monitoring/            │
│   backend     │   http_client (gate) │   trace (TraceEvent)    │
│   models      │   crawler · probes/  │   live · callbacks      │
│               │   adapters/ (outils) │                         │
├───────────────┴──────────────────────┴───────────────────────-┤
│  benchmark/        metrics · compare (mono vs crew, qualité)   │
│  report/           markdown · html                             │
├──────────────────────────────────────────────────────────────┤
│  safety/  (invariant non négociable)                           │
│    domain · signing · scope · guard (ScopeGuard) · audit       │
└──────────────────────────────────────────────────────────────┘
```

| Couche | Rôle | Fichiers clés |
|---|---|---|
| `safety/` | Invariant de sûreté : périmètre signé, autorisation, audit infalsifiable. | `domain.py`, `signing.py`, `scope.py`, `guard.py`, `audit.py` |
| `llm/` | Abstraction LLM (Featherless/OpenAI-compatible) + mock offline, catalogue modèles↔rôles. | `backend.py`, `models.py` |
| `tools/` | Toute I/O réseau : client budgété et guardé, crawler, sondes de détection, adaptateurs d'outils externes. | `http_client.py`, `crawler.py`, `registry.py`, `probes/`, `adapters/` |
| `agents/` | Nœuds LangGraph de raisonnement ; **aucune I/O réseau directe**. | `state.py`, `prompts.py`, `parsing.py`, `nodes.py`, `crew_graph.py`, `single_agent.py` |
| `monitoring/` | Traçage unifié, rendu live, pont vers l'audit chaîné. | `trace.py`, `live.py`, `callbacks.py` |
| `benchmark/` | Agrégation de métriques, qualité (précision/rappel/F1), comparaison. | `metrics.py`, `compare.py` |
| `report/` | Rapport Markdown + HTML (findings confirmés, preuves, métriques). | `markdown.py`, `html.py` |

**Règle d'isolation clé.** Les agents LLM **décident** (choix de sonde, priorisation,
rédaction) mais ne touchent jamais le réseau. Seuls les outils de `tools/`, en passant par le
client budgété et le `ScopeGuard`, exécutent une action observable.

---

## 2. Le `ScopeGuard` — unique porte réseau

Toute requête HTTP du PoC transite par `tools/http_client.GuardedHttpClient`. Avant chaque
envoi, le client applique la séquence **autorisation → budget → envoi** :

```python
async def request(self, method, url, **kw):
    self._guard.authorize(url, self._intensity)   # ScopeViolation si hors scope
    if self._count >= self._max:                   # budget par exécution
        raise RequestBudgetExceeded(...)
    self._count += 1
    return await self._client.request(method, url, **kw)
```

`safety/guard.ScopeGuard.check()` applique une politique **default-deny** et refuse si la cible :

1. figure dans les **exclusions** (`excluded`) ;
2. n'est **ni** dans les domaines autorisés **ni** dans les plages IP (CIDR) autorisées ;
3. tombe **hors de la fenêtre temporelle** du mandat (`window.start`..`window.end`) ;
4. dépasse le **plafond d'intensité** signé (`allowed_intensity`).

Le périmètre lui-même est un **`Scope` signé** (HMAC via `safety/signing`, clé
`REDTEAM_SIGNING_KEY` avec repli `REDSCOPE_SIGNING_KEY`) : `load_scope` rejette toute altération
post-signature. Comme le crawler et **toutes** les sondes n'accèdent au réseau qu'au travers de
ce client, le `ScopeGuard` est le **point de contrôle unique et incontournable** : aucun chemin
ne permet de contacter une cible non autorisée.

### 2.1 Adaptateurs d'outils externes (`tools/adapters/`)

Pour une couverture réelle, le PoC intègre de vrais outils (`nuclei`, `nmap`, `sqlmap`) sous
forme d'**adaptateurs**. La classe de base `ToolAdapter` **implémente le contrat `Probe`**
(mêmes `id`, `intensity`, `description`, même `run(client, target) -> ProbeResult`) : pour le
reste du système, un adaptateur est une sonde comme une autre, enregistrée dans `registry.py`
(`tool.nuclei`, `tool.nmap` en `active` ; `tool.sqlmap` en `intrusive`).

**Problème de sûreté.** Ces outils sont des **binaires** qui font leurs propres appels réseau :
ils **n'empruntent pas** le `GuardedHttpClient` et échappent donc à l'arbitrage requête-par-
requête du `ScopeGuard`. `ToolAdapter.run` impose un **confinement pré-lancement** en quatre
temps :

1. **Autoriser → avant tout `subprocess`** : `client.guard.authorize(target, client.intensity)`
   (`client.guard`/`client.intensity` exposés en lecture seule sur le client). Hors périmètre =
   `ScopeViolation`, le binaire n'est **jamais** lancé.
2. **Mono-cible** : `build_argv(target)` ne passe qu'**un seul hôte/URL** avec des options qui
   empêchent l'outil de divaguer (nmap réduit au seul hôte ; nuclei reçoit l'URL cible via
   `-target <url>` ; sqlmap `--crawl=0`,
   **jamais** `--dump` ; nmap script `vuln and not dos`, **jamais** la catégorie `dos`).
3. **Bornage** : `timeout` d'exécution (le process est tué au dépassement) et plafond de taille
   de sortie capturée.
4. **Skip propre** : `shutil.which(self.binary) is None` → `ProbeResult(found=False, …)` sans
   erreur. Un outil absent ou qui échoue **ne casse pas l'audit** (hors conteneur, la suite de
   tests reste verte).

> **Limite résiduelle assumée** : une fois le binaire lancé sur l'hôte autorisé, le `ScopeGuard`
> ne peut plus l'arbitrer requête par requête. Le confinement pré-lancement + mono-cible +
> options réduisent fortement ce risque ; il est documenté dans `METHODOLOGIE.md`.

**N findings par run.** Un outil produit souvent **plusieurs** résultats. `ProbeResult` porte
donc une liste `findings: list[Finding]` (en plus du `finding` unique historique des 4 sondes
maison) ; `ProbeResult.all_findings()` unifie les deux. L'`attacker` collecte
`result.all_findings()`.

**Verifier par signature.** Les outils n'étant pas parfaitement déterministes, « preuve
reproductible » devient : **l'outil re-signale le même finding** au rejeu. `verify_findings`
(dans `agents/nodes.py`) groupe les candidats par `module_id`, **re-exécute chaque sonde une
seule fois** par `(module_id, target)`, et confirme un candidat si sa **signature**
`finding_signature(f) = (module_id, target, title)` réapparaît dans `all_findings()` du rejeu —
sinon il est `discarded`. Le `confidence_score` (0.3·LLM + 0.7·preuve) est inchangé.

---

## 3. Flux d'exécution

`runner.build_state()` assemble l'état partagé (`AuditState`), puis `runner.run_graph()` lance
d'abord un **crawl de reconnaissance** (BFS async même-hôte, en intensité `PASSIVE`) pour
produire la carte de surface, avant de déléguer au graphe du mode choisi. En sortie, il calcule
les métriques depuis la trace et écrit `report.md`, `report.html` et `state.json`.

### 3.1 Mode `crew` (`agents/crew_graph.py`)

Graphe LangGraph `StateGraph` avec boucle de replanification bornée :

```
START → recon → planner → attacker → verifier ─┬─(raw_findings & replans < max_replans)→ replan → attacker
                                                └─────────────────────────────────────→ reporter → END
```

1. **Recon** — à partir de la carte de surface, le LLM propose des **hypothèses** (sonde
   suggérée + justification). Repli sûr : si le LLM ne propose rien d'exploitable, toutes les
   sondes sont testées.
2. **Planner** — convertit les hypothèses en `Step`s, **filtrés par `ScopeGuard`** (périmètre +
   plafond d'intensité) ; seules les étapes autorisées restent.
3. **Attacker** — pour chaque `Step`, la **sonde déterministe agit** (via le client guardé) et
   capture l'observation brute.
4. **Verifier** — **rejoue** la sonde ; sans preuve reproductible, le finding est `discarded`
   (= faux-positif évité, compté). `confidence = 0.3·revendication_LLM + 0.7·preuve`.
5. **Boucle adaptative** — tant que `replans < max_replans` et qu'il reste des indices, retour
   au plan via le nœud `replan` qui émet un événement `strategy_change` (matérialise
   l'adaptativité). `_route_after_verify` bascule sur `reporter` dès la borne atteinte, et
   `recursion_limit` sert de filet de sécurité anti-boucle.
6. **Reporter** — le LLM rédige le rapport à partir des **findings confirmés** ; les sections
   déterministes (périmètre, métriques) sont ajoutées par la couche `report/`.

### 3.2 Mode `single` (`agents/single_agent.py`)

Un **unique nœud généraliste** enchaîne `recon → planner → attacker → verifier → reporter` en
une passe, en réutilisant **exactement les mêmes outils et le même Verifier déterministe** que
le mode `crew`. Objectif : une comparaison « toutes choses égales par ailleurs » entre agent
généraliste et équipe spécialisée.

---

## 4. Modèle de traçage — `TraceEvent`

`monitoring/trace.TraceEvent` (modèle Pydantic) est l'unité de mesure. Chaque événement
significatif est journalisé en **JSONL** dans `trace.jsonl` :

```python
class TraceEvent(BaseModel):
    ts: str                 # ISO-8601 UTC
    run_id: str
    mode: str               # "single" | "crew"
    agent: str              # "recon" | "planner" | ... | "single"
    phase: str              # "recon" | "plan" | "act" | "verify" | "report"
    type: str               # llm_call | tool_call | decision | strategy_change
                            # | finding | verification | error
    model: str | None
    prompt_hash: str | None
    tokens_in / tokens_out / latency_ms: int | None
    tool: str | None
    http_count: int | None
    finding_id / severity / status / confidence / rationale: ...
```

`TraceLog.emit()` écrit chaque événement en JSONL **et**, pour les types critiques
(`decision`, `finding`, `verification`, `strategy_change`, `error`), l'appende au **journal
d'audit chaîné** (`safety/audit.AuditLog`, SHA-256). La trace alimente aussi :

- le **rendu live** console (`monitoring/live.py`, `rich`) — suivre le raisonnement en direct ;
- l'**agrégation de métriques** (`benchmark/metrics.metrics_from_trace`) — un run se mesure
  intégralement à partir de sa trace.

### 4.1 Observabilité LangSmith (optionnelle)

Au-delà de la trace locale, le PoC peut publier ses appels LLM vers **LangSmith** :

- **Activation** : `monitoring/langsmith.activate_langsmith()` est appelée par la CLI (`run`,
  `benchmark`) dès qu'une clé `LANGSMITH_API_KEY` est présente. Elle pose
  `LANGSMITH_TRACING=true`, `LANGSMITH_API_KEY` et `LANGSMITH_PROJECT`.
- **Mécanisme** : l'application étant basée sur LangChain/LangGraph, le tracer LangChain
  capture automatiquement les runs du graphe et des `ChatOpenAI`. Le backend
  `FeatherlessBackend.complete` est en plus décoré [`@traceable`](../src/redteam/llm/backend.py)
  : chaque appel LLM devient un run nommé `redteam_llm_complete` avec métadonnées
  (`model`, `layer`).
- **Garantie d'offline** : sans `LANGSMITH_API_KEY`, aucune variable n'est basculée et
  `traceable` est un no-op strict — le PoC reste 100 % hors ligne (testé dans
  `tests/test_langsmith.py`).

---

## 5. Correspondance avec les livrables du hackathon

(Reprise du §11 de la spécification de conception.)

| Livrable attendu | Où |
|---|---|
| Prototype fonctionnel | `src/redteam/` + CLI (`redteam`) |
| Architecture documentée | `docs/ARCHITECTURE.md` (ce document, FR) |
| Démonstration sur cible DPLIANCE | `redteam run --mode crew --target $MIRAGE_TARGET` |
| Monitoring du raisonnement / actions | `monitoring/` (trace JSONL + live + audit chaîné) |
| Benchmark modèles / architectures | `benchmark/` + `eval/mirage_ground_truth.yaml` |
| Exemple de rapport d'audit | `report/` → `report.md` / `report.html` |
| Retour critique (limites, échecs, pistes) | section dédiée dans `docs/METHODOLOGIE.md` |
