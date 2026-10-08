# Outils & prompts — point d'état et axes d'amélioration

Point établi le 08/10/2026 à partir du **code** et des **traces réelles** des 4 runs de
benchmark (`runs/bench-*/trace.jsonl`), pas d'opinions.

---

## 1. État des hacking tools

### 1.1 En place — 8 sondes (registre `PROBES`, `tools/registry.py`)

| Sonde | Type | Intensité | Rôle |
|---|---|---|---|
| `web.security_headers` | maison | **passive** | En-têtes manquants (CSP, HSTS, XFO…) |
| `web.version_disclosure` | maison | **passive** | Fuite de version (Server, X-Powered-By) |
| `web.exposed_endpoints` | maison | active | Endpoints exposés découverts dans la surface |
| `web.reflected_input` | maison | active | Reflet non échappé (candidat XSS réfléchi) |
| `web.availability` | maison | active | Risque DoS sans le déclencher |
| `tool.nuclei` | adaptateur | active | ~6 000 templates (embarqués en image Docker) |
| `tool.nmap` | adaptateur | active | Ports/services + NSE `vuln and not dos` |
| `tool.sqlmap` | adaptateur | **intrusive** | **Bloqué** par le scope (`allowed: active`) |

### 1.2 Planifié — spec + plan approuvés (`docs/superpowers/`)

| Outil | Apport | Bornes de sécurité |
|---|---|---|
| **ffuf** | Découverte de contenu (répertoire, params) | `-rate 20 -t 5 -maxtime 120 -non-recursive`, mono-URL `…/FUZZ`, jamais `-r`/`-X` |
| **testssl.sh** | Protocoles/défauts TLS | `-p` seul, `--connect-timeout 10`, mono-hôte, JSON sur stderr (`result_stream`) |

### 1.3 Recommandations d'ajouts (par priorité)

| Priorité | Outil | Intensité | Apport | Niveau touché |
|---|---|---|---|---|
| **P1** | **httpx** (ProjectDiscovery) | passive | Fingerprint HTTP → **enrichit la `SurfaceMap`** (tech, status, titres) : alimente directement les hypothèses recon | outil + recon |
| **P1** | **wafw00f** | passive | Détecter un WAF **avant** d'envoyer du actif → évite faux positifs / 429 | outil + sécurité |
| **P2** | **katana** ou **gau** (crawl JS) | active | Surface plus profonde (routes JS, API) → rappel ↑ | outil + recon |
| **P2** | Sondes maison **cookies / CORS** | passive | 2 cas du top-10 non couverts, coût nul, 1 fichier chacune | outil |
| **P3** | **whatweb** | passive | Alternative à httpx, doublon partiel | outil |

### 1.4 À évirer (déjà tranché ou hors mandat)

- **nikto** — bruit massif, faux positifs, inadapté à un mandat borné.
- **hydra / sqlmap en `intrusive` / dos** — hors `allowed: active` : le `ScopeGuard` refuse.
- **dalfox (XSS scan)** — intrusif : à négocier avec le mandant (lot « long »).

**Lacunes réelles de couverture** : TLS (→ testssl), découverte de contenu (→ ffuf),
config serveur/proxy — et le **repli « teste tout »** qui compense aujourd'hui l'absence de
suggestions fines côté LLM.

---

## 2. Constats sur les prompts Qwen (issus des traces)

> Constats 1, 2 et 3 **corrigés par le lot P1** (voir §3) — conservés ci-dessous comme
> justification d'origine.

| # | Constat | Preuve dans les traces |
|---|---|---|
| 1 | **`PLANNER_SYSTEM` et `SINGLE_SYSTEM` sont du code mort** | définis dans `prompts.py`, jamais importés — le mode `single` passe par `recon_node` → `RECON_SYSTEM` |
| 2 | **La boucle replan est vide à 100 %** | les 2 runs crew : `strategy_change → "0 étapes dans le périmètre"` — `_replan_node` n'ajoute aucune hypothèse, le LLM n'est jamais rappelé |
| 3 | **Hypothèses non bornées ni dédupliquées** | crew Huihui : 20 hypothèses dont **8× `web.exposed_endpoints`** → 18 tool_calls, précision 0,40 |
| 4 | **Résumé de surface très pauvre** | `nodes.py` : `url [status] server=…` seulement — pas de liens, snippets, en-têtes utiles → hypothèses génériques |
| 5 | **Aucun few-shot, aucune borne de verbosité** | recon Huihui **3 946 tok / 115 s** vs OBLITERATUS **298 tok / 10 s** (même prompt) |
| 6 | **`extract_json_list` fragile** | premier `[` / dernier `]` : un crochet parasite → liste vide → repli « teste tout » silencieux et coûteux |
| 7 | **Reporter sans preuves** | n'envoie que `- [sev] titre` — pas d'evidence ni de remédiation dans le rapport |
| 8 | **Aucun réglage par rôle** | pas de température / max_tokens par rôle ; `MODEL_CATALOG` mono-modèle ; rationales EN alors que le rapport est FR |

---

## 3. Axes d'amélioration des prompts (priorisés)

### P1 — ✅ livré (TDD, 08/10/2026 — 92 tests verts)

| # | Axe | Constat | Fichiers / tests |
|---|---|---|---|
| 1 | **Replan avec rappel LLM + feedback** : `_replan_node` relance `recon_node` avec « déjà exécuté / écarté » | 2 | `crew_graph.py`, `nodes.py` · `test_replan_feedback.py` (3) |
| 2 | **Few-shot + gabarit JSON strict + rationales FR** dans `RECON_SYSTEM` | 3, 5 | `prompts.py` · `test_prompts.py` |
| 3 | **Plafond + diversité** : max 8 hypothèses, **1 par probe_id** | 3 | `prompts.py` |
| 4 | **Prompt généré depuis `PROBES.keys()`** (`build_recon_system()`) + suppression du code mort | 1 | `prompts.py` · `test_prompts.py` (7), `test_registry_integration.py` |

### P2 — suivant

| # | Axe | Constat |
|---|---|---|
| 5 | Enrichir le user message (en-têtes clés, liens, snippets 500 car.) | 4 |
| 6 | Parsing défensif (blocs ```` ```json ````, crochets équilibrés, trace si repli) | 6 |
| 7 | Reporter avec preuves (`title + severity + evidence + remediation`) | 7 |

### P3 — plus tard

| # | Axe | Constat |
|---|---|---|
| 8 | Paramètres par rôle (température ~0,2, max_tokens bornés) + `MODEL_CATALOG` branché | 5, 8 |
| 9 | Tests de non-régression de prompt (fixtures de réponses LLM : succès, format cassé, crochets parasites) | 6 |

---

## 4. Gains attendus du lot P1 (mesurables)

| Indicateur | Avant (traces) | Après (visé) |
|---|---|---|
| Recon Huihui (tokens de sortie) | 3 946 | ≤ 800 |
| Hypothèses crew | 20 (8 doublons d'une même sonde) | ≤ 8, 1 par sonde |
| `tool_calls` crew | 18 | ~10 (−40 %) |
| Replan | **toujours « 0 étapes »** | 2e appel `llm_call` recon tracé avec feedback |
| Précision | 0,40-0,50 | ≥ 0,67 (→ F1 0,57 → ~0,61-0,67) |
| Listes `probe_id` | 2 listes codées-en-dur | générées depuis `PROBES` |

**Ce que ce lot ne fait pas** : augmenter le rappel par magie (plafonné à 0,67 par les 8
sondes) — c'est le rôle du lot ffuf/testssl et des axes P2 (`SurfaceMap` enrichie).

---

## 5. Ordre des lots

1. **Lot P1 prompts — ✅ livré** (08/10, TDD) : `prompts.py` généré, replan adaptatif,
   code mort supprimé.
2. **ffuf + testssl.sh** — tâches 1-4 ✅ (adapters, `result_stream`, registry, prompts) ;
   tâches 5-6 restantes (Dockerfile + docs) : plan
   `docs/superpowers/plans/2026-10-08-tools-ffuf-testssl.md`.
3. **P2 puis P3** — cf. feuille de route du `CAHIER-DES-CHARGES.md`.
