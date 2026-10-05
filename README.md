# Red Team IA — PoC

Auditeur cybersécurité **pensé nativement autour de l'IA** : il explore une cible
**autorisée**, en cartographie la surface, **adapte sa stratégie** selon ses observations,
recherche des faiblesses, **vérifie chaque hypothèse par une preuve reproductible**, puis
produit un rapport clair et justifié.

Projet réalisé dans le cadre du hackathon **Neoloji Technopole — Grand Poitiers × École 42
Angoulême**, porté par **DPLIANCE**.

> **Principe directeur.** Le LLM raisonne, priorise et rédige. Les outils déterministes
> observent et prouvent. **Aucune vulnérabilité n'est retenue sans preuve reproductible**
> capturée par un outil.

---

## ⚠️ Cadre d'autorisation (à lire avant toute exécution)

Cet outil réalise des requêtes réseau actives contre une cible. **Son usage est strictement
réservé à un contexte sous mandat.**

- **Uniquement contre des cibles autorisées par DPLIANCE** — en pratique, la copie du projet
  **Mirage** fournie pour le hackathon. Ne jamais le pointer vers un système tiers.
- Le **périmètre est décrit dans un scope signé** (`config/scope.template.yaml` → `scope.yaml`
  scellé par HMAC au lancement). Toute altération post-signature est rejetée.
- Chaque requête réseau passe par le **`ScopeGuard`** (politique *default-deny*) : domaines/IP
  autorisés, exclusions, fenêtre temporelle, plafond d'intensité. Hors périmètre = refus.
- Les sondes **détectent et prouvent** (en-têtes, réponses HTTP, reflets d'entrée). Elles
  **n'arment aucun exploit** : pas de payload destructif, pas de DoS, pas de brute-force réel.
- Toutes les actions sont consignées dans un **journal d'audit chaîné SHA-256** (infalsifiable),
  ancré par un checkpoint signé — preuve de ce que l'IA a réellement fait.

Utiliser ce PoC hors de ce cadre peut être illégal. La responsabilité de disposer d'une
autorisation écrite valide incombe à l'opérateur.

---

## Installation

Python **3.11+** requis.

```bash
pip install -e ".[dev]"
cp .env.example .env   # puis renseigner les variables ci-dessous
```

### Configuration (`.env`)

| Variable | Rôle | Défaut |
|---|---|---|
| `FEATHERLESS_API_KEY` | Clé du backend LLM Featherless (compatible OpenAI). | *(vide → mode mock)* |
| `FEATHERLESS_BASE_URL` | URL de base de l'API. | `https://api.featherless.ai/v1` |
| `REDTEAM_MODEL` | Modèle par défaut. | `huihui-ai/Huihui-Qwen3.8-27B-abliterated` |
| `MIRAGE_TARGET` | Cible autorisée (URL de la copie Mirage). | `http://localhost:8080` |
| `REDTEAM_SIGNING_KEY` | Clé HMAC pour sceller le scope et ancrer l'audit. | *(repli : `REDSCOPE_SIGNING_KEY`)* |

Sans clé Featherless, le PoC bascule automatiquement sur un **backend mock déterministe** et
tourne **entièrement hors ligne** (également forçable avec `--mock`). Toute la suite de tests
s'exécute sans réseau ni clé API.

---

## Usage

Point d'entrée : la commande `redteam` (ou `python -m redteam.cli`).

```bash
# Afficher le périmètre signé qui sera appliqué
redteam scope-show

# Audit complet en mode multi-agents (crew), hors ligne
redteam run --mode crew --target http://localhost:8080 --mock

# Audit mono-agent de référence
redteam run --mode single --target http://localhost:8080 --mock

# Benchmark comparatif mono vs crew sur la même cible
redteam benchmark --modes single,crew --target http://localhost:8080 --mock
```

| Commande | Effet |
|---|---|
| `scope-show` | Prépare, signe et affiche le périmètre (mission + domaines autorisés). |
| `run --mode single\|crew --target <url> [--mock]` | Lance un audit et écrit les sorties dans `runs/<mode>-<id>/`. |
| `benchmark --modes single,crew --target <url> [--mock]` | Exécute chaque mode, agrège les métriques, écrit `runs/benchmark.md`. |

Sans `--mode`, `run` utilise `crew` par défaut ; sans `--target`, la valeur de `MIRAGE_TARGET`
est reprise.

---

## Sorties d'un run

Chaque exécution isole ses artefacts dans `runs/<mode>-<run_id>/` :

| Fichier | Contenu |
|---|---|
| `report.md` | Rapport d'audit : findings confirmés, preuves, périmètre, métriques. |
| `report.html` | Même rapport rendu en HTML autoportant. |
| `trace.jsonl` | Trace unifiée : appels LLM, appels d'outils, décisions, vérifications. |
| `audit.jsonl` | Journal d'audit chaîné SHA-256 (+ `audit.jsonl.tip` signé si clé dispo). |
| `state.json` | État final : findings confirmés (id, titre, statut, confiance). |

Le mode `benchmark` écrit en plus un tableau comparatif dans `runs/benchmark.md`.

### Exemple de sortie console

```
$ redteam run --mode crew --target http://localhost:8080 --mock
Rapport : runs/crew-20261005-143000/report.md
Findings confirmés : 2 | faux-positifs écartés : 1
```

Le rapport Markdown liste les findings confirmés avec leur preuve brute et leur sévérité, suivis
des sections déterministes (périmètre, intégrité d'audit, métriques du run).

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — couches, flux `crew`/`single`, `ScopeGuard`,
  modèle `TraceEvent`, correspondance avec les livrables du hackathon.
- [`docs/METHODOLOGIE.md`](docs/METHODOLOGIE.md) — comment les métriques répondent aux questions
  du hackathon, et une section critique (limites, échecs, pistes d'amélioration).
- [`docs/superpowers/specs/2026-10-05-redteam-ia-design.md`](docs/superpowers/specs/2026-10-05-redteam-ia-design.md)
  — spécification de conception complète.

---

## Développement

```bash
ruff check src tests     # lint
python3 -m pytest -q     # suite de tests (offline)
```

Convention : **code en anglais, documentation en français**. La clé API vit dans `.env`
(jamais commitée).
