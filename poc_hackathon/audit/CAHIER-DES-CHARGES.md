# Cahier des charges — PoC Red Team IA

**Rapport de mission** · Hackathon Neoloji Technopole — Grand Poitiers × École 42 Angoulême
(porté par DPLIANCE) · 8 octobre 2026

> **Destinataires** : direction DPLIANCE et organisateurs du hackathon.
> Ce document fait le bilan de la mission (réalisations), le rattache point par point aux
> livrables attendus, et propose des recommandations priorisées. Le détail technique se trouve
> dans les documents annexes (voir [Annexes](#annexes)).

---

## 1. Résumé exécutif

**Un prototype fonctionnel d'auditeur cybersécurité piloté par IA a été livré**, testé et
mesuré sur la cible autorisée du hackathon. Le système cartographie une cible, adapte sa
stratégie, exécute des sondes bornées par un périmètre signé, et **n'aucune vulnérabilité
n'est retenue sans preuve reproductible** : c'est la règle qui structure toute l'architecture.

**État d'avancement** : 6 des 7 livrables du cahier des charges sont **livrés et démontrés** ;
le 7e (benchmark) est livré avec une réserve méthodologique assumée (un run par cellule).
Un lot d'outils complémentaires (ffuf, testssl.sh) est **specifié et planifié**, en attente
d'exécution.

**Résultats mesurés** : 65 tests automatiques verts ; le mode multi-agents `crew` atteint un
F1 de **0,67** (vs 0,57 en mono-agent) avec **zéro faux positif confirmé**, et tourne **2,8×
plus vite** ; le changement de modèle LLM a réduit la latence moyenne de **52,8 s à 7,7 s (×6,9)**
sans toucher au code.

**Recommandation principale** : consolider ce qui existe (répéter les benchmarks, livrer le
lot ffuf/testssl) avant d'élargir le périmètre — la valeur prouvée est dans la **sûreté et la
mesure**, pas dans le nombre d'outils.

---

## 2. Contexte et mandat

| Élément | Détail |
|---|---|
| Commanditaire | DPLIANCE, dans le cadre du hackathon Neoloji Technopole |
| Cible | Copie du projet **Mirage** fournie pour l'hackathon (`hackathon.mirage-analytics.com`) |
| Nature du travail | PoC : audit de sécurité **exclusivement sous mandat**, sur périmètre signé |
| Livrable principal | Un outil d'audit IA, sa documentation, ses mesures et son retour critique |

**Cadre d'autorisation — non négociable :**

- Périmètre décrit dans un **scope scellé HMAC** (`config/scope.template.yaml` → `scope.yaml`) ;
  toute altération post-signature est rejetée.
- **`ScopeGuard`** (politique *default-deny*) : domaines/IP autorisés, exclusions, fenêtre
  temporelle, plafond d'intensité. **Toute** requête réseau passe par cette unique porte.
- Journal d'**audit chaîné SHA-256**, ancré par un checkpoint signé : preuve infalsifiable de
  ce que l'IA a fait pendant l'audit.
- Les sondes **détectent et prouvent** (en-têtes, réponses HTTP, reflets d'entrée) ; elles
  n'arment aucun exploit : pas de payload destructif, pas de DoS, pas de brute-force.

Ce cadre n'est pas une couverture : il est la **première exigence** de la mission et il est
vérifiable dans le code (`safety/`) et dans les journaux de chaque run.

---

## 3. Périmètre de la mission

**Engagements pris** (et tenus, voir §4) :

1. Un **prototype exécutable** (CLI `redteam`) réalisant un cycle complet : recon →
   hypothèses → plan → exécution → vérification → rapport.
2. **Deux orchestrations comparables** — mode `crew` (multi-agents avec replanification
   bornée) et mode `single` (mono-agent) — pour répondre à la question « les agents
   spécialisés valent-ils mieux qu'un généraliste ? ».
3. **Monitoring du raisonnement** : chaque décision LLM, appel d'outil et vérification est
   tracée et rattachable à un run.
4. **Un benchmark mesurant** : qualité (précision/rappel/F1 contre une vérité terrain),
   coût (tokens), temps, sur les deux modes et plusieurs modèles.
5. **Un rapport d'audit** exploitable (Markdown + HTML) et un **retour critique** honnête.

**Hors périmètre assumé** : exploitation offensive réelle (aucun exploit armé), couverture
de toutes les vulnérabilités (le rappel est borné par le registre de sondes), autonomie
illimitée (bornes `max_replans` et intensité = choix de sûreté délibérés).

---

## 4. Réalisations — bilan

### ✅ Livré

| Réalisation | Preuve |
|---|---|
| **Prototype fonctionnel** : 8 sondes (5 HTTP maison + `nuclei`, `nmap`, `sqlmap`), 2 modes, CLI `redteam scope-show / run / benchmark` | `src/redteam/` · **65 tests verts** (100 % hors-ligne) |
| **Sûreté** : scope signé HMAC, `ScopeGuard` default-deny, budget de requêtes, intensités bornées, audit chaîné | `src/redteam/safety/`, `tools/http_client.py` |
| **Architecture documentée** (FR) : couches, flux `crew`/`single`, porte réseau unique, modèle de trace | `docs/ARCHITECTURE.md` |
| **Monitoring** : `trace.jsonl` par run, rendu live, journal d'audit infalsifiable | `monitoring/` + `safety/audit.py` |
| **Benchmark + vérité terrain** : métriques recalculables depuis les traces | `benchmark/`, `eval/mirage_ground_truth.yaml`, `runs/benchmark*.md` |
| **Rapports d'audit** : `report.md`, `report.html`, `state.json` par run | `report/`, dossiers `runs/bench-*` |
| **Retour critique** : limites, échecs observés, pistes | `docs/METHODOLOGIE.md` §4 |
| **Documentation de présentation** pour le jury | `docs/DOSSIER-RENDU.md` |

### 🧪 Expérimenté (résultats à consolider)

| Expérience | Résultat |
|---|---|
| **Crew vs single** (same cible, same scope) | Crew : F1 **0,67** vs 0,57 · **0** faux positif confirmé vs 3 · **2,8×** plus rapide (360 s vs 1 014 s) |
| **Impact du modèle LLM** (Huihui → OBLITERATUS, `.env` uniquement) | Latence moy. **52,8 s → 7,7 s (×6,9)** · tokens de sortie **÷12,7** · F1 en hausse (0,50 → 0,67) |
| **Boucle d'autonomie** | Replanification effectivement déclenchée et bornée (`replans = 1`) |

*Réserve méthodologique assumée : un run par cellule — tendance solide, pas preuve
statistique.*

### 🔜 En cours (spécifié, pas encore exécuté)

| Lot | État |
|---|---|
| **Adaptateurs ffuf** (découverte de contenu) et **testssl.sh** (audit TLS) | Spec approuvée + plan d'implémentation de 6 tâches prêt (`docs/superpowers/`) ; bornes de sécurité définies (débit, mono-cible, wordlist versionnée). **Exécution à venir.** |

---

## 5. Correspondance avec les livrables du hackathon

*(Reprise du §11 de la spécification de conception, `docs/superpowers/specs/2026-10-05-redteam-ia-design.md`)*

| Livrable attendu | Où | Statut |
|---|---|---|
| Prototype fonctionnel | `src/redteam/` + CLI (`redteam`) | ✅ **Livré** — 65 tests verts |
| Architecture documentée | `docs/ARCHITECTURE.md` (FR) | ✅ **Livré** |
| Démonstration sur cible DPLIANCE | `run --mode crew --target $MIRAGE_TARGET` | ✅ **Livré** — runs bench exécutés sur la cible (mode crew + single) |
| Monitoring du raisonnement / actions | `monitoring/` (trace JSONL + live + audit chaîné) | ✅ **Livré** |
| Benchmark modèles / architectures | `benchmark/` + `eval/mirage_ground_truth.yaml` | ⚠️ **Livré (partiel)** — fonctionnel, mais 1 run par cellule : à consolider |
| Exemple de rapport d'audit | `report/` → `report.md` / `report.html` | ✅ **Livré** |
| Retour critique (limites, échecs, pistes) | section dédiée dans `docs/METHODOLOGIE.md` | ✅ **Livré** |
| — | — | — |
| *Lot complémentaire (hors §11)* : outils ffuf + testssl.sh | `tools/adapters/` | 🔜 **En cours** — spec + plan approuvés, exécution à venir |

---

## 6. Résultats mesurés (synthèse)

**Qualité des audits** (vérité terrain : 3 sondes connues, `eval/mirage_ground_truth.yaml`) :

| Modèle | Mode | Durée | Confirmés / écartés | Précision | Rappel | F1 |
|---|---|---|---|---|---|---|
| Huihui (baseline) | single | 1 296 s | 19 / 1 | 0,40 | 0,67 | 0,50 |
| Huihui | crew | 1 058 s | 18 / 1 | 0,40 | 0,67 | 0,50 |
| OBLITERATUS | single | 1 014 s | 10 / 3 | 0,50 | 0,67 | 0,57 |
| OBLITERATUS | crew | **360 s** | 3 / 0 | **0,67** | 0,67 | **0,67** |

**Lectures clés :**

1. **Intérêt du mode `crew` : oui, mais pas pour la raison intuitive.** Il ne trouve *pas plus*
   de findings (3 vs 10) — il **sélectionne mieux** (0 faux positif vs 3) et tourne 2,8× plus
   vite. Le gain est en **précision**, pas en volume.
2. **Le modèle LLM est un levier mesurable** : même code, simple variable d'environnement →
   latence ÷6,9, tokens de sortie ÷12,7. Sans le benchmark, ce choix serait resté une
   intuition.
3. **Le rappel est borné par le registre de sondes** (0,67 partout), pas par l'orchestration :
   c'est un choix de couverture, corrigeable par ajout d'outils.

Détail complet : [`DOSSIER-RENDU.md`](../docs/DOSSIER-RENDU.md),
[`runs/comparaison-modeles.md`](../runs/comparaison-modeles.md).

---

## 7. Axes d'amélioration

Format : **constat → impact → effort → priorité**.

| # | Axe | Constat | Impact | Effort | Priorité |
|---|---|---|---|---|---|
| 1 | **Listes de `probe_id` en double** dans `prompts.py` (2 listes codées-en-dur à maintenir) | Ajout d'outil = oubli silencieux possible côté LLM | Rend l'ajout d'outils fiable ; supprime un défaut d'extensibilité latent | Faible (générer depuis `PROBES.keys()`) | **P1** |
| 2 | **Déduplication des findings** — signature `(module_id, cible, titre)` | 2 findings réels d'une même sonde sur une même cible fusionnent | Comptage et F1 plus justes | Faible | **P1** |
| 3 | **Exécution du lot ffuf/testssl** (spec + plan déjà approuvés) | Couverture de contenu et TLS absente | +2 familles de détection ; rappel potentiellement ↑ | Moyen (6 tâches planifiées) | **P1** |
| 4 | **Benchmark à 1 run par cellule** | Tendances non confirmées statistiquement | Crédibilité mesurée des verdicts (crew vs single, modèles) | Faible (×N répétitions) | **P2** |
| 5 | **Rappel plafonné (0,67)** — 8 sondes au registre | L'IA ne trouve que ce que les sondes savent observer | Rappel ↑ si couverture élargie (en-têtes avancés, tech discovery…) | Moyen (ajouts mécaniques) | **P2** |
| 6 | **Titres de parse stables** pour outils non-déterministes (nmap, nuclei) | Findings rejetés au rejeu = faux négatifs du verifier | F1 protégé contre le bruit des binaires | Faible-moyen | **P2** |
| 7 | **Dépendance à l'API LLM distante** (Featherless) | Latence, coût et disponibilité hors contrôle | Réproductibilité et souveraineté (Ollama/vLLM) | Moyen | **P3** |
| 8 | **Confinement pré-lancement des outils externes** | Une fois lancés, `ScopeGuard` ne les arbitre plus requête-par-requête | Durcissement : namespace réseau limité à l'hôte autorisé | Élevé (hors PoC) | **P3** |
| 9 | **Arbitrage des bornes d'autonomie** (`max_replans`, intensité) | Plafond actuel = choix de sûreté, à valider avec le mandant | Décision explicitée, pas laissée au défaut | Décision (pas technique) | **P3** |

---

## 8. Feuille de route recommandée

| Horizon | Objectif | Actions | Critère de succès |
|---|---|---|---|
| **Court** (fin de hackathon) | Stabiliser et prouver | ① Exécuter le plan ffuf/testssl (6 tâches) · ② Répéter chaque cellule de benchmark (×3 à 5) · ③ Nettoyer les artefacts `runs/*/root` | 100 % des tâches du plan en vert ; verdicts bench à ±N runs |
| **Moyen** (sprint suivant) | Corriger la dette d'extensibilité | ① Prompts générés depuis le registre · ② Dédup des findings · ③ Titres de parse stables · ④ +3 à 5 sondes (rappel cible ≥ 0,8) | Ajout d'un outil = 1 fichier + 1 ligne de registre, sans prompt à éditer |
| **Long** (post-PoC) | Élargir sous mandat | ① Backend LLM local (Ollama/vLLM) · ② Confinement réseau OS des binaires · ③ Intensité `intrusive` élargie **après accord mandant** | Latence maîtrisée ; aucune requête hors périmètre y compris pour les outils externes |

**Gouvernance** : toute élévation d'intensité ou d'autonomie est **arbitrée avec le mandant**,
documentée, puis mesurée — jamais activée par défaut.

---

## Annexes

| Document | Contenu |
|---|---|
| [`README.md`](../README.md) | Installation, cadre d'autorisation détaillé, usage de la CLI |
| [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) | Couches, `ScopeGuard`, flux crew/single, modèle de trace |
| [`docs/METHODOLOGIE.md`](../docs/METHODOLOGIE.md) | Réponses aux 5 questions du hackathon + retour critique |
| [`docs/DOSSIER-RENDU.md`](../docs/DOSSIER-RENDU.md) | Dossier de présentation détaillé (archi, benchmarks, expérimentation Q2) |
| [`docs/superpowers/specs/2026-10-05-redteam-ia-design.md`](../docs/superpowers/specs/2026-10-05-redteam-ia-design.md) | Spécification de conception (dont §11 ci-dessus) |
| [`docs/superpowers/specs/2026-10-08-tools-ffuf-testssl-design.md`](../docs/superpowers/specs/2026-10-08-tools-ffuf-testssl-design.md) | Spec du lot en cours (ffuf + testssl.sh) |
| [`docs/superpowers/plans/2026-10-08-tools-ffuf-testssl.md`](../docs/superpowers/plans/2026-10-08-tools-ffuf-testssl.md) | Plan d'exécution (6 tâches) |
| [`runs/benchmark-huihui.md`](../runs/benchmark-huihui.md), [`runs/benchmark-obliteratus.md`](../runs/benchmark-obliteratus.md) | Chiffres bruts des benchmarks |
| [`audit/`](README.md) | Notes de session (état, architecture, axes, benchmarks, carte de surface) |
