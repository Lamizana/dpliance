# Observabilité LangSmith — récapitulatif d'installation

> Commit : `7631dcd` — *added monitoring via langsmith*
> Documentation complémentaire : `README.md` (§ Observabilité LangSmith) et `docs/ARCHITECTURE.md` (§ 4.1).

## 1. Ce qui a été installé / branché

| Élément | Détail |
|---|---|
| **Dépendance** | `langsmith>=0.14.4` ajoutée à `pyproject.toml` (gestion via `uv`, `uv.lock` mis à jour). |
| **Configuration** | `Settings.langsmith_api_key` / `Settings.langsmith_project` lus depuis `.env` (`config.py`). |
| **Variables d'env** | `LANGSMITH_API_KEY`, `LANGSMITH_PROJECT` (+ alias `LANGSMITH_TRACING`, `LANGCHAIN_TRACING_V2`, `LANGCHAIN_PROJECT`). |
| **Point d'activation** | `monitoring/langsmith.activate_langsmith()` appelée par la CLI (`run`, `benchmark`) **avant le premier appel LLM**. |
| **Instrumentation** | 1) tracer LangChain automatique : runs du graphe LangGraph et des `ChatOpenAI` ; 2) `@traceable` sur `FeatherlessBackend.complete` → run nommé **`redteam_llm_complete`** avec metadata `model` / `layer`. |
| **Garantie offline** | Sans clé API : aucun variable bascule, `traceable` est un no-op strict → le PoC reste 100 % hors ligne. Testé dans `tests/test_langsmith.py` (6 tests). |

**État actuel du `.env`** : projet **`redteam-poc`**, endpoint **EU** (`https://eu.api.smith.langchain.com`) — les traces des audits apparaissent donc sur la page web LangSmith (onglet *Projects* → `redteam-poc`).

## 2. Suites possibles d'exploitation des traces

### 2.1 Explorer et exploiter les traces existantes (sans dev)
- **Vue Project** : filtrer par run, voir l'arborescence des spans (nœuds du graphe → appels LLM), latence, tokens et coût de chaque appel.
- **Comparer les modes** : regarder `single` vs `crew` côte à côte (durée, nombre d'appels, retries) pour étayer le benchmark local (`runs/benchmark.md`).
- **Debug** : inspecter les prompts/outputs réels d'un run en échec, extraire un run problématique comme cas de test.

### 2.2 Enrichir les traces (petits développements)
- **Tags/métadonnées de run** : ajouter `run_id`, `mode` (single/crew), `target` et `mock` via `metadata`/`tags` du `traceable` ou d'un `configure_langchain` — permet de filtrer dans l'UI (aujourd'hui seuls `model` et `layer` sont posés).
- **Feedback utilisateur** : API `feedback` (👍/👎 + catégorie) sur les runs pour noter la qualité des réponses du crew.
- **Dataset automatique** : exporter les prompts/outputs de runs réussis vers un **dataset LangSmith** (skill `langsmith-dataset`) à partir du `eval/mirage_ground_truth.yaml` existant.

### 2.3 Évaluation (levier principal)
- **Évaluateurs** : créer des evaluators LLM-as-judge (qualité du finding, respect du scope, précision du rapport) via le skill `langsmith-evaluator`.
- **Boucle d'éval** : brancher `evaluate()` sur le dataset pour comparer les versions de prompts/modèles de façon reproductible, en complément du benchmark local (`benchmark/metrics.py`).
- **Online eval** : attacher des *run rules* sur le projet `redteam-poc` pour évaluer en continu les audits en production.

### 2.4 Au-delà
- **Prompt Hub** : versionner les prompts du crew (`agents/prompts.py`) et tester des variants via expériences LangSmith.
- **Monitoring** : dashboards d'usage (tokens/coût par modèle), alertes sur taux d'erreur/latence.
- **Sécurité des données** : l'endpoint EU étant renseigné, les données restent en région EU — vérifier que les prompts envoyés (cibles, findings) ne contiennent pas de secrets avant d'élargir le tracing.
