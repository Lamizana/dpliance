# Benchmarks — résultats et lecture

Sources (fichiers du dépôt) :
- `runs/benchmark-huihui.md` — baseline `huihui-ai/Huihui-Qwen3.8-27B-abliterated`
- `runs/benchmark-obliteratus.md` — `OBLITERATUS/Qwen3.8-27B-OBLITERATED`
- `runs/comparaison-modeles.md` — agrégation `llm_call` (latence, tokens)
- `eval/mirage_ground_truth.yaml` — vérité terrain (3 sondes : `web.security_headers`,
  `web.version_disclosure`, `web.reflected_input`)

## 1. Ce qu'on mesure et pourquoi

Sans mesure, le choix du modèle et le choix `crew` vs `single` seraient des **opinions**.
Chaque run est tracé (`trace.jsonl`) → `metrics_from_trace` → `RunMetrics` : durée, appels
LLM, tokens, tool_calls, confirmés/écartés, replans, erreurs. La **qualité** compare les
`module_id` confirmés à la vérité terrain : précision / rappel / F1
(`benchmark/metrics.quality`).

Même cible, même scope signé, même ground truth pour toutes les cellules.

## 2. Crew vs single (intérêt du multi-agents)

**Baseline Huihui** (`runs/benchmark-huihui.md`) :

| mode | durée | tool_calls | confirmés | écartés | replans | précision | rappel | F1 |
|---|---|---|---|---|---|---|---|---|
| single | 1296 s | 13 | 19 | 1 | 0 | 0.40 | 0.67 | **0.50** |
| crew  | 1058 s | 18 | 18 | 1 | 1 | 0.40 | 0.67 | **0.50** |

**Modèle OBLITERATUS** (`runs/benchmark-obliteratus.md`) :

| mode | durée | tool_calls | confirmés | écartés | replans | précision | rappel | F1 |
|---|---|---|---|---|---|---|---|---|
| single | 1014 s | 7 | 10 | 3 | 0 | 0.50 | 0.67 | **0.57** |
| crew  | 360 s  | 5 | 3  | 0 | 1 | 0.67 | 0.67 | **0.67** |

### Verdict : y a-t-il intérêt au mode `crew` ?

**Oui, mais pas pour la raison intuitive.**

- **Qualité** : meilleur F1 observé (0.67 vs 0.57 en single sur OBLITERATUS). Il
  **sélectionne mieux** : 0 faux positif confirmé vs 3 pour single (précision 0.67 vs 0.50).
- **Quantité** : il trouve *moins* de findings bruts (3 vs 10) — le gain n'est pas « plus de
  vulns » mais **« moins de bruit »**.
- **Rapidité** : 360 s vs 1014 s (×2,8) — le planner déterministe filtre tôt ; 2 appels LLM
  dans les deux modes.
- **Autonomie** : la replanification a bien eu lieu (`replans = 1`) — boucle fonctionnelle.

**Conclusion honnête** : le crew améliore la *sélection*, pas le *rappel* (0.67 partout,
plafonné par le registre de sondes, pas par l'orchestration). **Caveat : 1 run par cellule**
= tendance à consolider, pas preuve statistique.

## 3. Q2 — impact du choix du modèle LLM

Dispositif : permutation par la variable `REDTEAM_MODEL` (.env), **aucune ligne de code
modifiée** ; mêmes cibles/scope/ground truth/modes.

### Latence et coût (événements `llm_call`, 4 appels/model)

| métrique | Huihui | OBLITERATUS | écart |
|---|---|---|---|
| Latence moyenne | **52,8 s** | **7,7 s** | ×6,9 plus rapide |
| Latence max | 115,7 s | 10,2 s | — |
| Tokens de sortie | 7531 | 594 | ×12,7 moins verbeux |
| Tokens d'entrée | 2148 | 1643 | −24 % |

### Qualité

| métrique | Huihui | OBLITERATUS |
|---|---|---|
| F1 `single` | 0.50 | **0.57** |
| F1 `crew` | 0.50 | **0.67** |
| Durée `crew` | 1058 s | **360 s** |

### Lecture

1. **Le modèle est un levier mesurable** : une variable d'environnement → latence ÷6,9,
   tokens de sortie ÷12,7.
2. **Qualité impactée aussi** : F1 0.50 → 0.67 (crew) — un modèle plus concis formule mieux
   ses hypothèses de recon.
3. **Valeur de l'infrastructure** : sans traces + vérité terrain, « le modèle semble lent »
   serait resté une intuition.

**Limite assumée** : n = 1 par cellule. L'écart de latence est massif et robuste ; l'écart
de F1 est une tendance.

## 4. Questions ouvertes relevées

- Faire tourner **plusieurs runs par cellule** pour passer de tendance à résultat.
- Brancher le `MODEL_CATALOG` par rôle (`llm/models.py` existe, encore mono-modèle).
- Piste backend local (Ollama/vLLM) : qualité ↔ coût ↔ latence, sans API distante.
- Nettoyer les dossiers `runs/*/root` vides (artefacts Docker en root).
