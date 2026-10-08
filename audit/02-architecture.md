# Architecture — schéma et principes

Source : `src/redteam/` (lecture des fichiers `runner.py`, `crew_graph.py`, `single_agent.py`,
`nodes.py`, `state.py`, `registry.py`, `guard.py`, `crawler.py`).

## Schéma global

```mermaid
flowchart TB
    subgraph CLI["CLI (cli.py)"]
        CMD["redteam run / benchmark<br/>--mode single|crew --target … --mock"]
    end

    subgraph SAFETY["couche Safety — mandat obligatoire"]
        SCOPE["scope.yaml<br/>scope.py — cible + fenêtre + limites<br/>signature HMAC (signing.py)"]
        GUARD["ScopeGuard (guard.py)<br/>check() / authorize() — default-deny<br/>host + CIDR + dates + intensity"]
    end

    subgraph RUNNER["runner.py — orchestration"]
        BUILD["build_state() → AuditState"]
        CRAWL["crawl() (crawler.py)<br/>BFS 20 pages / prof. 2<br/>→ SurfaceMap"]
        REPORT["report.md + .html<br/>state.json + métriques"]
    end

    subgraph GRAPH["LangGraph — agents/"]
        direction TB
        subgraph CREW["mode crew (crew_graph.py) — 6 nœuds"]
            RECON["recon (LLM)<br/>SurfaceMap → hypothèses<br/>repli : teste toutes les sondes"]
            PLAN["planner (dét.)<br/>filtre guard + dédup<br/>(module_id, target)"]
            ATTACK["attacker (dét.)<br/>exécute les Step"]
            VERIFY["verifier (dét.)<br/>rejoue + signature de preuve<br/>confidence 0.3·LLM + 0.7·preuve"]
            REPLAN["replan (borné<br/>max_replans=1)"]
            REPORTER["reporter (LLM)<br/>rapport FR"]
            RECON --> PLAN --> ATTACK --> VERIFY
            VERIFY -->|"candidats restants<br/>et replan disponible"| REPLAN --> PLAN
            VERIFY -->|"sinon"| REPORTER
        end
        subgraph SINGLE["mode single (single_agent.py) — 1 nœud, même pipeline"]
            ONE["single : recon → planner →<br/>attacker → verifier → reporter"]
        end
    end

    subgraph STATE["AuditState (state.py) — mémoire partagée"]
        ST["surface · hypotheses · plan ·<br/>raw_findings · confirmed ·<br/>executed_steps · replans · report_md"]
    end

    subgraph TOOLS["tools/ — exécution"]
        REG["PROBES (registry.py)<br/>id → instance"]
        subgraph PROBES["sondes passives (probes/)"]
            P1["security_headers"]
            P2["version_disclosure"]
            P3["exposed_endpoints"]
            P4["reflected_input"]
            P5["availability"]
        end
        subgraph ADAPT["adaptateurs shell (adapters/)"]
            A1["nuclei"]
            A2["nmap"]
            A3["sqlmap<br/>(intrusive → bloqué)"]
        end
        HTTP["GuardedHttpClient<br/>budget max_requests<br/>+ guard avant chaque GET"]
    end

    subgraph LLM["llm/"]
        MOCK["MockBackend (--mock)"]
        FEATH["FeatherlessBackend"]
        PROMPT["prompts.py<br/>RECON/SINGLE/PLANNER/REPORTER"]
    end

    subgraph MONIT["monitoring/"]
        TRACE["trace.jsonl chaîné HMAC<br/>+ audit bundle signé"]
        LIVE["live.py + callbacks.py"]
    end

    subgraph OUT["runs/"]
        R["report.md · report.html<br/>state.json · trace.jsonl · audit.jsonl"]
    end

    CMD --> BUILD
    SCOPE --> GUARD
    BUILD --> CRAWL
    BUILD --> GRAPH
    CRAWL -->|"SurfaceMap"| RECON
    CRAWL -.-> ST
    GRAPH <--> ST
    RECON -.->|"prompt + résumé surface"| PROMPT
    REPORTER -.-> PROMPT
    PROMPT -.-> MOCK
    PROMPT -.-> FEATH
    PLAN --> GUARD
    ATTACK --> REG
    VERIFY --> REG
    PROBES --> HTTP
    ADAPT -->|"subprocess borné<br/>guard.authorize() + which()"| GUARD
    HTTP --> GUARD
    GRAPH --> REPORT --> R
    GRAPH --> TRACE --> OUT
```

## Les 3 principes clés

1. **Couche Safety englobante** : `ScopeGuard` requis par le planner (filtre d'étapes),
   le `GuardedHttpClient` (chaque GET) et les adaptateurs (`authorize()` avant tout
   `subprocess`) — **default-deny** partout, scope scellé HMAC.
2. **LLM ≠ exécution** : `recon`/`reporter` raisonnent via prompts ; `planner`/`attacker`/
   `verifier` sont déterministes. **Aucune finding confirmée sans rejeu** (signature
   `(module_id, target, title)`), confidence = 0,3·LLM + 0,7·preuve.
3. **`AuditState` central** : dictionnaire LangGraph lu/écrit par tous les nœuds ; le mode
   `single` réutilise les **mêmes fonctions de nœuds**, seule l'orchestration diffère
   (1 passe vs boucle replan bornée à 1).

## Détails des nœuds (`agents/nodes.py`)

| Nœud | Type | Rôle |
|---|---|---|
| `recon_node` | LLM | `SurfaceMap` résumée → JSON d'hypothèses `{probe_id, target, rationale}` ; **repli** : si parsing vide → toutes les sondes du registre (raison `"repli"`). |
| `planner_node` | déterministe | Filtre `guard.check(target, intensity)` + anti-rejeu sur `executed_steps` → `plan: list[Step]`. |
| `attacker_node` | déterministe | `probe.run(client_factory(intensity), target)` par étape, trace `tool_call`, collecte `raw_findings`. |
| `verifier_node` | déterministe | Regroupe par `(module_id, target)`, **rejoue chaque sonde une fois**, confirme si signature réapparaît ; `confidence = 0.3·1.0 + 0.7·preuve`. |
| `replan_node` | - | Incrémente `replans` + trace `strategy_change`; routage borné `max_replans`. |
| `reporter_node` | LLM | Rapport FR factuel depuis les findings confirmés uniquement. |

## Cycles du graphe crew (`crew_graph.py`)

```
START → recon → planner → attacker → verifier ─┬─(raw_findings ≠ ∅ ET replans < max)→ replan → planner
                                               └─(sinon)→ reporter → END
```
`recursion_limit: 25` (crew) / `10` (single) — filet anti-boucle infinie.

## Pipeline d'exécution (`runner.py`)

```
build_state → (si surface absente) crawl PASSIVE → graphe → metrics_from_trace
            → report.md / report.html / state.json
```
`client_factory(intensity)` fabrique un `GuardedHttpClient` adéquat (scope, budget,
transport injectable pour les tests).
