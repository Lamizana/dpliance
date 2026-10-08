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

### Périmètre autorisé du hackathon

Seuls les actifs ci-dessous sont dans le périmètre. Ils sont pré-remplis dans
`config/scope.template.yaml`. Tout ce qui n'y figure pas est **hors périmètre** et refusé par
le `ScopeGuard`.

| Actif | Valeur |
| --- | --- |
| Domaines web | `hackathon.mirage-analytics.com`, `ws.hackathon.mirage-analytics.com`, `sdk.hackathon.mirage-analytics.com` |
| Serveur web (IPv4 / IPv6) | `78.232.7.202` / `2001:bc8:1210:17d6:dc00:ff:feee:925e` |
| Base de données | `78.232.49.67`, port `1661` |

> Le port de la base (`1661`) est donné pour information : le `ScopeGuard` valide l'hôte, pas le
> port. Ne testez la base que sur ce port.

**Compte de test** pour l'authentification sur `hackathon.mirage-analytics.com` :

- Identifiant : `hackathon`
- Mot de passe : `password`

Utiliser ce PoC hors de ce cadre peut être illégal. La responsabilité de disposer d'une
autorisation écrite valide incombe à l'opérateur.

---

## Installation

Gestion des dépendances via [**uv**](https://docs.astral.sh/uv/) (installe un Python 3.11
isolé si besoin — plus de conflit avec le Python système).

```bash
# Installer uv (une fois) : https://docs.astral.sh/uv/getting-started/installation/
uv sync                 # crée .venv et installe tout (deps + outils dev) depuis uv.lock
cp .env.example .env     # puis renseigner les variables ci-dessous
```

Les commandes se lancent ensuite via `uv run` (ex. `uv run redteam ...`, `uv run pytest`),
ou en activant l'environnement avec `source .venv/bin/activate`.

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

## Exécution en conteneur (outils réels)

Pour une **couverture réelle**, le PoC s'appuie sur de vrais outils de sécurité via des
**adaptateurs** respectant le contrat `Probe`. Ces outils sont des binaires externes : l'image
Docker fournie (base Debian) les embarque pour un audit complet.

| Adaptateur (id de sonde) | Outil | Intensité | Rôle |
|---|---|---|---|
| `tool.nuclei` | **nuclei** | active | Détection par templates (preuve JSON reproductible). |
| `tool.nmap` | **nmap** | active | Services/versions + scripts NSE `vuln and not dos`. |
| `tool.sqlmap` | **sqlmap** | intrusive | Preuve d'exploitation SQLi (sans `--dump`). |

```bash
# Construire l'image (installe nuclei + nmap + sqlmap + le PoC)
docker build -t redteam-ia .

# Lancer un audit ; .env fournit les clés/cibles, runs/ est monté pour récupérer les sorties
docker run --rm --env-file .env -v "$PWD/runs:/app/runs" \
  redteam-ia run --mode crew --target "$MIRAGE_TARGET"
```

L'`ENTRYPOINT` de l'image est la commande `redteam` : les arguments passés à `docker run`
(`run --mode crew ...`) la complètent directement.

> **Dégradation propre.** Hors conteneur — ou si un outil n'est pas installé — l'adaptateur
> correspondant **se saute proprement** (`found=False`, « binaire non installé »), sans casser
> l'audit ni la suite de tests. La couverture est réduite, mais le PoC reste fonctionnel. Toute
> la suite de tests s'exécute donc **hors conteneur**, sans aucun binaire externe.

Aux côtés de ces adaptateurs, la sonde HTTP maison **`web.availability`** (active) prouve les
**faiblesses menant à un déni de service** (`xmlrpc.php` exposé, absence de rate-limiting
observable, absence d'empreinte de WAF/CDN) **sans mettre la cible en charge** — elle ne requiert
aucun binaire externe.

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

- [`docs/DOSSIER-RENDU.md`](docs/DOSSIER-RENDU.md) — **dossier de rendu hackathon (jury)** :
  architecture, benchmarks expliqués (crew vs single) et expérimentation sur le choix du
  modèle LLM.
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
