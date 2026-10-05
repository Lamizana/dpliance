# Méthodologie

Ce document explique **comment le PoC répond, mesures à l'appui, aux cinq questions de fond du
hackathon**, puis dresse un **retour critique** (limites, échecs observés, pistes
d'amélioration).

Le fil conducteur : **tout est tracé** (`trace.jsonl`), et chaque run se mesure intégralement à
partir de sa trace via `benchmark/metrics.metrics_from_trace`, qui produit un objet `RunMetrics`.

---

## 1. Les métriques collectées

`RunMetrics` agrège, par run :

| Métrique | Signification | Source (type d'événement tracé) |
|---|---|---|
| `duration_s` | Temps total (wall-clock). | mesuré par `runner.run_graph` |
| `llm_calls` | Nombre d'appels au LLM. | `llm_call` |
| `tokens_in` / `tokens_out` | Tokens entrée/sortie (proxy de coût). | `llm_call` |
| `tool_calls` | Nombre d'appels d'outils (sondes). | `tool_call` |
| `confirmed_count` | Findings **confirmés** par preuve. | `verification` (`confirmed`) |
| `discarded_count` | **Faux-positifs écartés** par le Verifier. | `verification` (`discarded`) |
| `raw_count` | Candidats = confirmés + écartés. | dérivé |
| `replans` | Profondeur d'autonomie (replanifications). | `strategy_change` |
| `errors` | Erreurs rencontrées. | `error` |

La **qualité** est calculée à part par `benchmark/metrics.quality()` : comparaison des findings
confirmés au **ground truth** (`eval/mirage_ground_truth.yaml`) → **précision / rappel / F1**.

---

## 2. Réponse aux cinq questions

### Q1 — Plusieurs agents spécialisés valent-ils mieux qu'un généraliste ?

`redteam benchmark --modes single,crew` exécute les **deux modes sur la même cible et le même
scope**, chacun isolé par son `run_id`. `benchmark/compare.compare_runs` produit un tableau
Markdown (`runs/benchmark.md`) alignant, ligne par ligne, `duration_s`, `llm_calls`, tokens,
`tool_calls`, `confirmed_count`, `discarded_count`, `replans`, `errors`.

Le mode `single` réutilise **exactement** les mêmes outils et le même Verifier que `crew` : la
comparaison est donc « toutes choses égales par ailleurs ». On lit directement le surcoût
(tokens, temps) de la spécialisation face à son gain (findings confirmés, faux-positifs écartés).

### Q2 — Quels modèles sont pertinents selon l'étape ?

`llm/models.MODEL_CATALOG` associe un **modèle à chaque rôle** (`recon`, `planner`, `reporter`,
`default`). Le benchmark peut **permuter le modèle par étape** sans toucher à l'orchestration.
Comme chaque `llm_call` est tracé avec son `model`, ses `tokens` et sa `latency_ms`, on attribue
coût et latence **à l'étape** où ils sont consommés — base factuelle pour « quel modèle à quelle
étape ». *(Dans le PoC, le catalogue pointe sur le même modèle par défaut ; la mécanique de
permutation est en place et prête à être exploitée.)*

### Q3 — Jusqu'où laisser l'IA auditer en autonomie ?

L'autonomie est **explicitement bornée**, et la borne est **mesurée** :

- `max_replans` plafonne la boucle adaptative ; `_route_after_verify` bascule vers le rapport
  dès que la borne est atteinte (et `recursion_limit` est un filet anti-boucle).
- Chaque replanification émet un `strategy_change`, agrégé en `replans` : on **quantifie**
  combien l'IA a réellement ré-orienté sa stratégie.
- Le **plafond d'intensité** du scope (appliqué par `ScopeGuard`) limite ce que l'IA s'autorise
  à tenter, indépendamment de ce que le LLM propose.

On peut donc faire varier `max_replans` / l'intensité autorisée et observer l'effet sur la
qualité et le coût — c'est la matière du débat « jusqu'où ».

### Q4 — Comment vérifier qu'une vulnérabilité est crédible ?

Par **séparation stricte raisonnement / preuve**, sans « LLM juge » :

1. Le LLM ne peut que **proposer une hypothèse** ; il ne déclare jamais une vulnérabilité.
2. Le **Verifier déterministe rejoue la sonde** (`verify_findings`). Sans preuve reproductible
   (`recheck.found` faux), le finding est `discarded` — un faux-positif évité, compté.
3. Le **score de confiance** fait dominer la preuve :
   `confidence = 0.3·revendication_LLM + 0.7·preuve`. Un finding sans preuve plafonne à 0,3.
4. **Traçabilité** : chaque finding confirmé cite sa **preuve brute** (extrait de réponse) et la
   sonde qui l'a produite — un humain peut rejouer la vérification.

### Q5 — Comment mesurer objectivement la qualité d'un audit IA ?

Les findings confirmés sont comparés aux vulnérabilités **connues** de Mirage
(`eval/mirage_ground_truth.yaml`) pour calculer **précision, rappel et F1** :

- **Précision** = fraction des findings confirmés qui sont de vraies vulnérabilités (peu de
  bruit) ;
- **Rappel** = fraction des vulnérabilités connues effectivement trouvées (bonne couverture) ;
- **F1** = moyenne harmonique des deux.

Couplées aux métriques de coût/temps/autonomie, ces mesures donnent une évaluation **objective
et reproductible** de la qualité, comparable entre modes et entre modèles.

---

## 3. Limites, échecs et pistes d'amélioration

Section critique assumée : ce PoC privilégie la **clarté de la démonstration** et la **sûreté**
à l'exhaustivité.

### Dépendance à un service LLM distant

Malgré l'ambition « local », le raisonnement repose sur Featherless (API distante) : latence,
coût et disponibilité sont des facteurs externes. Le `MockBackend` offline préserve la
reproductibilité des tests et des démos, mais ne mesure **pas** la qualité réelle d'un LLM.
*Piste :* intégrer un backend local (Ollama/vLLM) et comparer qualité ↔ coût ↔ latence.

### Couverture de sondes volontairement restreinte

Quatre sondes de détection seulement (`web.security_headers`, `web.version_disclosure`,
`web.exposed_endpoints`, `web.reflected_input`), toutes non-armées par choix de périmètre. Le
**rappel est donc plafonné** par construction : l'IA ne peut trouver que ce que les sondes
savent observer. *Piste :* enrichir le registre (`tools/probes/`) — la structure `ProbeRegistry`
rend l'ajout mécanique — tout en gardant la discipline détection/preuve.

### Maintien du ground truth

Les métriques de qualité (précision/rappel/F1) ne valent que si `mirage_ground_truth.yaml`
reflète fidèlement la cible déployée. Un ground truth périmé fausse silencieusement les scores.
*Piste :* versionner le ground truth avec la cible et le valider à chaque déploiement de Mirage.

### Bornes d'autonomie : un choix de sûreté, pas une fatalité technique

`max_replans` et le plafond d'intensité **bornent délibérément** l'IA. Ce n'est pas une limite
technique mais un **choix de sûreté** : on préfère un audit prévisible et traçable à une
exploration non bornée. Relever ces bornes est possible et mesurable — c'est précisément l'objet
du débat « jusqu'où laisser l'IA autonome » (Q3), à trancher avec le mandant, pas par défaut.

### Autres limites de PoC

- Le parsing des sorties LLM (`extract_json_list`) tolère les écarts de format mais repose sur un
  **repli** (tester toutes les sondes) qui peut gonfler le nombre d'appels.
- Le checkpoint d'audit anti-troncature exige `REDTEAM_SIGNING_KEY` ; sans clé, le journal chaîné
  reste valide mais **l'ancrage final manque** (l'utilisateur en est averti).
- Le benchmark `MODEL_CATALOG` est prêt à permuter les modèles mais pointe, dans le PoC, sur un
  modèle unique : la réponse quantitative complète à Q2 demande d'y renseigner plusieurs modèles.
