# redteam-ia — Spécification de conception (PoC Hackathon)

- **Date :** 2026-10-05
- **Auteur :** hichem@dpliance.com
- **Contexte :** Hackathon Neoloji Technopole – Grand Poitiers × École 42 Angoulême, porté par DPLIANCE.
- **Statut :** Validé pour implémentation (design).

---

## 1. Objectif

Construire un **PoC de « Red Team IA »** : un auditeur cybersécurité *pensé nativement autour de l'IA*
(et non un scanner auquel on ajoute un LLM). Le système explore une cible **autorisée** (une copie du
projet **Mirage** de DPLIANCE), analyse sa surface, **adapte sa stratégie** selon ses observations,
recherche des faiblesses, **vérifie** chaque hypothèse par une preuve reproductible, puis produit un
**rapport clair et justifié**.

Le PoC doit en outre **mesurer et justifier** ses choix : tout est tracé (modèles, prompts, décisions,
appels d'outils, temps, tokens, erreurs, changements de stratégie, findings, faux-positifs) afin de
répondre aux questions de fond du hackathon :

1. plusieurs agents spécialisés sont-ils plus efficaces qu'un agent généraliste ?
2. quels modèles sont pertinents selon l'étape de l'audit ?
3. jusqu'où laisser l'IA auditer en autonomie ?
4. comment vérifier qu'une vulnérabilité est réellement crédible ?
5. comment mesurer objectivement la qualité d'un audit mené par une IA ?

### Principe directeur

> **Le LLM raisonne, priorise et rédige. Les outils déterministes observent et prouvent.**
> Aucune vulnérabilité n'est retenue sans preuve reproductible capturée par un outil.

---

## 2. Périmètre et hypothèses

- **Dans le périmètre** : orchestration multi-agents, mode mono-agent de référence, backend LLM
  Featherless (compatible OpenAI), crawler async, sondes de **détection/collecte de preuves**,
  monitoring/traçage, benchmark comparatif, rapports Markdown + HTML, barrière de périmètre et
  journal d'audit infalsifiable.
- **Hors périmètre** : exploits armés / payloads destructifs, DoS, brute-force réel, altération de
  données, évasion de détection. Les sondes restent dans l'esprit de `redscope` : elles **détectent**
  et **prouvent** (réponses HTTP, en-têtes, reflets), elles n'« arment » rien.
- **Cible** : paramétrable via `MIRAGE_TARGET` (URL/IP). Le scope est **généré puis signé** au
  lancement à partir de `config/scope.template.yaml`. Rien ne s'exécute hors de la cible autorisée.
- **Décisions de conception déjà actées** :
  - Stack **Python** (réutilise la colonne vertébrale éprouvée de `hackingtool/redscope`).
  - Orchestration **LangGraph** (`StateGraph`).
  - **Deux modes commutables** : `single` (agent généraliste) et `crew` (multi-agents spécialisés).
  - Anti-faux-positifs : **agent Verifier + preuve déterministe** (pas de « LLM juge »).
  - Projet **autonome** : les primitives de sûreté de `redscope` sont **copiées et documentées**
    dans `src/redteam/safety/` (pas d'import inter-dépôts), pour un PoC clair et autoportant.

---

## 3. Architecture

### 3.1 Arborescence

```
poc_hackathon/
├── README.md  pyproject.toml  .env.example
├── config/scope.template.yaml        # gabarit → scope.yaml signé au lancement
├── eval/mirage_ground_truth.yaml     # vulnérabilités connues de la cible (benchmark qualité)
├── src/redteam/
│   ├── cli.py                        # typer : scope | run --mode single|crew | benchmark | report
│   ├── config.py                     # settings : clé API, base_url, modèle, MIRAGE_TARGET
│   ├── safety/                       # ← repris de redscope (copie documentée)
│   │   ├── domain.py                 # Intensity, Severity, Finding, Step, Remediation, Module
│   │   ├── signing.py                # HmacSigner + default_signer
│   │   ├── scope.py                  # Scope signé, load_scope, compute_signature
│   │   ├── guard.py                  # ScopeGuard (domaines/IP/fenêtre/intensité/exclusions)
│   │   └── audit.py                  # journal chaîné SHA-256 + checkpoint signé
│   ├── llm/
│   │   ├── backend.py                # LLMBackend (OpenAI-compatible → Featherless) + MockBackend
│   │   └── models.py                 # catalogue modèles ↔ rôles (pour le benchmark)
│   ├── tools/
│   │   ├── http_client.py            # client async budgété + scope-guardé
│   │   ├── crawler.py                # BFS async (scope, budget, robots.txt)
│   │   ├── registry.py               # ProbeRegistry
│   │   └── probes/                   # sondes = détection/preuve
│   │       ├── security_headers.py
│   │       ├── version_disclosure.py
│   │       ├── exposed_endpoints.py
│   │       └── reflected_input.py
│   ├── agents/
│   │   ├── state.py                  # AuditState (TypedDict LangGraph)
│   │   ├── prompts.py                # prompts système par rôle (EN)
│   │   ├── recon.py planner.py attacker.py verifier.py reporter.py
│   │   ├── single_agent.py           # graphe mono-agent (ReAct)
│   │   └── crew_graph.py             # graphe multi-agents
│   ├── monitoring/
│   │   ├── trace.py                  # TraceEvent + TraceLog (JSONL) + pont vers l'audit chaîné
│   │   ├── callbacks.py              # callback LangChain → tokens / latence / modèle
│   │   └── live.py                   # console rich temps réel
│   ├── benchmark/
│   │   ├── runner.py                 # matrice modes × modèles
│   │   ├── metrics.py                # agrégation des métriques
│   │   └── compare.py                # tableaux comparatifs + précision/rappel
│   └── report/
│       ├── markdown.py  html.py      # rapport + section monitoring/benchmark
├── tests/                            # scope, guard, audit (portés) + verifier, crawler, trace
└── docs/
    ├── ARCHITECTURE.md METHODOLOGIE.md
    └── superpowers/specs/2026-10-05-redteam-ia-design.md   # ce document
```

### 3.2 Unités et responsabilités

| Unité | Rôle | Dépend de |
|---|---|---|
| `safety/*` | Invariant de sûreté : scope signé, autorisation, audit infalsifiable. | pydantic, yaml |
| `llm/backend` | Abstraction LLM (Featherless/OpenAI-compatible, mock offline). | langchain-openai |
| `tools/http_client` | Toute I/O réseau ; impose budget + autorisation `ScopeGuard`. | httpx, safety/guard |
| `tools/crawler` | Cartographie la surface (pages/endpoints/headers/empreintes). | http_client |
| `tools/probes/*` | Sondes déterministes : détectent une faiblesse et **capturent une preuve**. | http_client |
| `agents/*` | Nœuds LangGraph (raisonnement LLM) ; ne font **jamais** d'I/O réseau directe. | llm, tools, safety |
| `monitoring/*` | Traçage unifié + rendu live + pont vers l'audit. | safety/audit |
| `benchmark/*` | Exécute la matrice, agrège, compare, calcule précision/rappel. | monitoring, eval |
| `report/*` | Rapport Markdown + HTML (findings confirmés, preuves, remédiation, métriques). | safety/domain |

**Règle d'isolation clé :** les agents LLM ne touchent pas le réseau. Ils **décident** ; seuls les
outils (`tools/*`), passant par le client budgété et le `ScopeGuard`, exécutent une action observable.

---

## 4. Flux d'exécution

### 4.1 Mode `crew` (LangGraph `StateGraph`)

```
Recon → Planner → Attacker → Verifier → [replan ↺ budget] → Reporter
```

1. **Recon** — le crawler (guardé/budgété) construit une **carte de surface** (pages, endpoints,
   en-têtes, empreintes techno). Le LLM en déduit des **hypothèses motivées** (faiblesse candidate +
   sonde suggérée + intensité).
2. **Planner** — le LLM **ordonne et priorise** les hypothèses en `Step`s, filtrés par `ScopeGuard`
   (plafond d'intensité, périmètre, fenêtre). Le plan et sa justification sont tracés.
3. **Attacker** — pour chaque `Step`, **la sonde déterministe agit** (le LLM choisit la sonde et ses
   paramètres ; l'outil exécute la détection sûre et capture l'observation brute).
4. **Verifier** — **rejoue** la sonde de façon déterministe, exige une **preuve reproductible** :
   `confirmed` / `unconfirmed` / `discarded`. Un `discarded` = **faux-positif évité** (compté).
   `confidence = f(revendication_LLM, preuve_déterministe)`.
5. **Boucle adaptative** — si Attacker/Verifier révèlent de nouveaux indices (nouveaux endpoints,
   technologie inattendue), on retourne au **Planner** (dans la limite d'un budget `max_replans`).
   Chaque retour = **événement `strategy_change`** tracé → matérialise l'adaptativité.
6. **Reporter** — le LLM rédige un rapport clair à partir des **findings confirmés + preuves +
   remédiation** ; les sections déterministes (surface, intégrité d'audit, métriques) sont ajoutées.

### 4.2 Mode `single`

Un unique nœud **ReAct généraliste** : même catalogue d'outils, **même Verifier déterministe**, même
traçage. Le prompt généraliste couvre recon+plan+act+verify+report. Objectif : comparaison « toutes
choses égales par ailleurs » avec le mode `crew`.

### 4.3 Sorties d'un run

- `runs/<run_id>/report.md` et `report.html`
- `runs/<run_id>/audit.jsonl` (+ `audit.jsonl.tip` signé)
- `runs/<run_id>/trace.jsonl`
- `runs/<run_id>/state.json` (état final : surface, hypothèses, findings)
- Affichage **live** en console pendant l'exécution.

---

## 5. Backbone de mesure — `TraceEvent`

Chaque événement significatif est journalisé dans `trace.jsonl`. Les actions critiques (décision
intrusive, finding confirmé, refus de périmètre) sont **aussi** appendues au **journal d'audit chaîné**
(infalsifiable) via `monitoring/trace.py`.

```python
class TraceEvent(BaseModel):
    ts: str                 # ISO-8601 UTC
    run_id: str
    mode: str               # "single" | "crew"
    agent: str              # "recon" | "planner" | ... | "single"
    phase: str              # "recon" | "plan" | "act" | "verify" | "report"
    type: str               # llm_call | tool_call | decision | strategy_change
                            # | finding | verification | error
    model: str | None       # id du modèle appelé
    prompt_hash: str | None # SHA-256 du prompt (le prompt complet va dans un store séparé)
    tokens_in: int | None
    tokens_out: int | None
    latency_ms: int | None
    tool: str | None
    http_count: int | None
    finding_id: str | None
    severity: str | None
    status: str | None      # confirmed | unconfirmed | discarded
    confidence: float | None
    rationale: str | None   # justification courte (1 phrase)
```

Le rendu **live** (`monitoring/live.py`, `rich`) affiche en continu : étape courante, agent, modèle,
outil appelé, décision, finding/vérification — pour « suivre le raisonnement des agents ».

---

## 6. Benchmark — répondre aux questions du brief

`benchmark/runner.py` exécute une **matrice modes × modèles** sur la **même cible et le même scope**,
chaque exécution isolée par `run_id`. `metrics.py` agrège :

- temps total (wall-clock) et par phase ;
- tokens entrée/sortie (proxy de coût) ;
- nombre de candidats, de **findings confirmés**, de **faux-positifs écartés** ;
- taux de confirmation, confiance moyenne ;
- **profondeur d'autonomie** (nombre de replanifications) ;
- erreurs et refus de périmètre.

`eval/mirage_ground_truth.yaml` liste les vulnérabilités **connues** de la cible Mirage. La comparaison
findings ↔ ground truth donne **précision / rappel / F1** → *mesure objective de la qualité*.

`compare.py` produit le tableau **mono vs crew** et **modèle A vs B (par rôle)**, répondant
directement aux questions 1, 2, 3 et 5. La question 4 (crédibilité) est répondue par le mécanisme du
§7.

---

## 7. Réduction des faux-positifs / hallucinations

1. **Séparation raisonnement / preuve** : le LLM ne peut pas « déclarer » une vuln ; il peut seulement
   proposer une hypothèse qu'une **sonde déterministe** devra confirmer.
2. **Verifier** : rejoue la sonde ; sans **preuve reproductible** (réponse HTTP, en-tête, reflet), le
   finding est `discarded` et compté comme faux-positif évité.
3. **Score de confiance** : `confidence = w1·revendication_LLM + w2·force_preuve` (la preuve domine).
   Seuil configurable en dessous duquel un finding n'apparaît pas dans le rapport principal.
4. **Traçabilité** : chaque finding du rapport cite sa preuve brute (extrait de réponse) et la sonde
   qui l'a produite — un humain peut rejouer.

---

## 8. Sûreté (invariant non négociable)

- **Scope signé** (`scope.yaml`) : toute modification post-signature est rejetée (`ScopeSignatureError`).
- **`ScopeGuard` sur chaque requête** : le crawler et toutes les sondes passent par
  `tools/http_client`, qui refuse toute cible hors `authorized` / dans `excluded`, hors fenêtre
  temporelle, ou au-dessus du plafond d'intensité.
- **Budget de requêtes** par sonde (anti-emballement).
- **Confirmation explicite** des étapes `intrusive` (option `--yes`).
- **Journal d'audit chaîné SHA-256** + checkpoint signé (anti-troncature) : preuve de ce que l'IA a
  réellement fait, infalsifiable.
- Clé API en `.env` (jamais commitée ; `.env.example` fourni).

---

## 9. Modèles / Featherless

- `llm/backend.py` : client **compatible OpenAI** pointant sur `https://api.featherless.ai/v1`
  (modèle par défaut : `huihui-ai/Huihui-Qwen3.8-27B-abliterated`). Interface `LLMBackend.complete()`
  conservée depuis `redscope` ; `MockBackend` déterministe pour les tests **offline**.
- `llm/models.py` : catalogue de modèles associés à des rôles (ex. un modèle « recon » rapide, un
  modèle « reporter » plus soigné) → le benchmark peut **permuter le modèle par étape** et répondre à
  « quel modèle à quelle étape ».
- La clé fournie est **de test** et vit en variable d'environnement.

---

## 10. Tests

- **Portés de `redscope`** : `test_scope` (signature/altération/clé), `test_guard` (périmètre,
  exclusions, fenêtre, intensité), `test_audit` (chaînage, vérification, checkpoint).
- **Nouveaux** :
  - `test_http_client` : refuse une cible hors scope ; respecte le budget.
  - `test_crawler` : ne sort jamais du périmètre ; respecte la profondeur/budget.
  - `test_verifier` : un finding **sans preuve** est `discarded` ; avec preuve → `confirmed`.
  - `test_trace` : événements bien formés ; pont vers l'audit chaîné intègre.
  - `test_graph_smoke` : un run `crew` et un run `single` complets avec `MockBackend` (offline).
- Tous les tests tournent **hors ligne** (LLM mocké, cible simulée via serveur httpx local).

---

## 11. Livrables du hackathon couverts

| Livrable attendu | Où |
|---|---|
| Prototype fonctionnel | `src/redteam/` + CLI |
| Architecture documentée | `docs/ARCHITECTURE.md` (FR) |
| Démonstration sur cible DPLIANCE | `run --mode crew --target $MIRAGE_TARGET` |
| Monitoring du raisonnement / actions | `monitoring/` (trace JSONL + live + audit chaîné) |
| Benchmark modèles / architectures | `benchmark/` + `eval/mirage_ground_truth.yaml` |
| Exemple de rapport d'audit | `report/` → `report.md` / `report.html` |
| Retour critique (limites, échecs, pistes) | section dédiée dans `docs/METHODOLOGIE.md` |

---

## 12. Conventions

- **Code en anglais** ; **documentation (README, docs/, commentaires explicatifs) en français**.
- Code clair, lisible, documenté (PoC) ; aucune mention « Generated with Claude Code ».
- `ruff` + `pytest` ; Python 3.11+.

---

## 13. Risques et limites connus (à approfondir dans METHODOLOGIE.md)

- Dépendance à un service LLM distant (latence/coût/disponibilité) malgré l'ambition « local ».
- La couverture des sondes est volontairement restreinte (PoC) → rappel limité.
- Le ground truth Mirage doit être tenu à jour pour que les métriques de qualité restent valides.
- L'autonomie est bornée par `max_replans` et le plafond d'intensité : c'est un choix de sûreté, pas
  une limite technique — à discuter comme réponse à la question « jusqu'où laisser l'IA autonome ».
```
