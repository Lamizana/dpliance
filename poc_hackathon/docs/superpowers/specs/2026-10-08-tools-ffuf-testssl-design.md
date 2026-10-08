# Adaptateurs ffuf et testssl.sh — Spécification de conception

- **Date :** 2026-10-08
- **Statut :** Validé pour implémentation (design).
- **Dépend de :** `docs/superpowers/specs/2026-10-05-tool-adapters-design.md` (contrat
  `ToolAdapter` et confinement pré-lancement, déjà en place).
- **Cible :** copie Mirage du hackathon (`hackathon.mirage-analytics.com`), périmètre signé
  `config/scope.template.yaml`, intensité maximale `active`.

---

## 1. Objectif

Compléter la couverture d'audit avec **deux outils réels supplémentaires** :

| Outil | Angle aujourd'hui non couvert |
|---|---|
| **ffuf** | Découverte de contenu (chemins/fichiers cachés à la racine) — `nuclei` couvre les signatures, `nmap` les services, les sondes maison les en-têtes/endpoints connus |
| **testssl.sh** | Configuration TLS en profondeur (protocoles obsolètes, cipher faibles, défauts serveur) — `web.version_disclosure`/`tool.nmap` ne donnent qu'une image partielle |

Les deux outils rejoignent le registre des sondes : le LLM peut les proposer (`recon`/`single`),
le `planner` les filtre via le `ScopeGuard`, le `verifier` les rejoue pour confirmer. Aucun
changement d'architecture.

### Hors périmètre (décision ferme)

- Pas de brute-force (`ffuf` n'est utilisé que pour la **découverte** de chemins, pas
  d'authentification ni de fuzzing de paramètres).
- Pas de DoS : bornes de débit et de durée explicites (§3).
- Pas de test TLS « agressif » (pas de cipher longues/obsolètes forcées au-delà de la
  détection, pas de `-fs`/sweep complet) : on **observe** la config, on ne la brute-pas.
- Aucun nouvel outil hors `ffuf`/`testssl.sh` dans ce lot (nikto, wafw00f, hydra… exclus).

---

## 2. Outils intégrés (deuxième lot)

| Adaptateur | Outil | Intensité | Installation (image) | Rôle |
|---|---|---|---|---|
| `tool.ffuf` | ffuf | `active` | binaire GitHub release **épinglé**, arch amd64/arm64 (même pattern que nuclei) | Découverte de contenu, débit borné |
| `tool.testssl` | testssl.sh | `active` | **paquet Debian `testssl.sh`** (présent dans bookworm — pas de clone git) | Audit TLS (protocoles, défauts, en-têtes TLS) |

Intensity : les deux restent sous le plafond signé `allowed_intensity: active`. `tool.sqlmap`
(`intrusive`) reste le seul au palier supérieur, filtré par le planner.

---

## 3. Sûreté — bornes spécifiques

Le confinement générique de `ToolAdapter.run` (`base.py`) s'applique intégralement :
`guard.authorize(target, client.intensity)` **avant tout `subprocess`**, mono-cible, `timeout`,
`max_output`, skip propre si binaire absent. S'ajoutent les bornes **propres à ffuf**, qui
génère lui-même ses requêtes (le budget du `GuardedHttpClient` ne les couvre pas) :

| Outil | Borne | Valeur | Raison |
|---|---|---|---|
| ffuf | `-rate` | 20 req/s | plafond non-DoS |
| ffuf | `-t` | 5 threads | pas de tampon de connexion |
| ffuf | `-maxtime` | 120 s | durée totale bornée |
| ffuf | `-timeout` | 10 s | réponse lente bornée |
| ffuf | `-mc` | codes restreints | filtrer le bruit (pas `-fc` large) |
| ffuf | `-non-recursive` | absent de `-recursion` | ne jamais descendre un arbre |
| ffuf | redirections | **pas** de `-r` | ne pas suivre une redirection hors hôte |
| testssl | durée | `timeout` classe (120 s) + `-connect_timeout 10` | bornage connexion |
| testssl | session | **1 seule URL**, sans mass testing | mono-cible |

`METHODOLOGIE.md` (§ limites) : documenter que les requêtes émises directement par les binaires
ne passent pas par l'arbitrage requête-par-requête du `ScopeGuard` — bornes par options
d'observation + confinement pré-lancement + mono-cible (limite résiduelle déjà assumée pour
nuclei/nmap/sqlmap).

---

## 4. Conception des adaptateurs

### 4.1 `tool.ffuf` — `src/redteam/tools/adapters/ffuf.py`

```python
class FfufAdapter(ToolAdapter):
    id = "tool.ffuf"
    intensity = Intensity.ACTIVE
    binary = "ffuf"
    timeout = 180.0
    wordlist = "/opt/wordlists/ffuf-raft-small.txt"      # remplacé par le fallback si absent
```

**`build_argv(target)`** — construction déterministe, mono-URL, **racine de l'hôte** (la
découverte se fait à la racine, quel que soit le chemin de `target`) :

```python
base = f"{urlparse(target).scheme}://{urlparse(target).hostname}"   # + port si présent
[ "ffuf", "-u", f"{base}/FUZZ", "-w", self.wordlist,
  "-rate", "20", "-t", "5", "-timeout", "10", "-maxtime", "120",
  "-mc", "200,204,301,302,307,401,403,405,500",
  "-non-recursive", "-s",
  "-of", "json", "-o", "-" ]                                        # JSON sur stdout
```

Invariants vérifiés par les tests : un seul hôte dans l'URL, `-rate` présent, aucun `-r`,
aucun `-recursion`, aucun `-X POST` destructif, présence de `-maxtime`.

**Dégradation propre complémentaire** (au-delà du skip « binaire non installé » du base) :
si le wordlist `-w` n'existe pas (image construite sans fallback), `run()` retourne
`ProbeResult(found=False, evidence="wordlist absente (sonde sautée)")` **avant** tout
`subprocess` — jamais de lancement ffuf avec `-w` inexistant (ffuf échouerait de toute façon,
mais on veut une preuve lisible dans le rapport).

**`parse(stdout, target)`** :
1. Tolérance : extraire le premier bloc JSON (`[` … `]`) du flux (ffuf peut écrire des lignes
   d'UI avant le JSON) ; `JSONDecodeError` → `[]`.
2. Pour chaque `results[]` : `input` (mot fuzzé), `status`, `length`.
   - `status ∈ {401, 403}` → `Finding(severity=MEDIUM, title="Endpoint protégé découvert")`
   - `status ∈ {200, 204}` et `length` notable → `Finding(severity=MEDIUM, title="Chemin exposé")`
     (ex. `/admin`, `/.git/` déjà couvert par `web.exposed_endpoints` : le verifier écarte les
     doublons déjà confirmés via la signature `(module_id, target, title)` — module différent,
     donc **déduplication au niveau du rapport** : voir §4.3).
   - redirections `301/302/307` → `Finding(severity=LOW, title="Redirection racine")`
   - `405` → `Finding(severity=LOW, title="Méthode HTTP inattendue")`
3. Chaque `Finding` porte `evidence` = URL complète + `status` + `length` (preuve brute).

### 4.2 `tool.testssl` — `src/redteam/tools/adapters/testssl.py`

```python
class TestsslAdapter(ToolAdapter):
    id = "tool.testssl"
    intensity = Intensity.ACTIVE
    binary = "testssl.sh"
    timeout = 300.0
    result_stream = "stderr"          # voir §4.2.1
```

**`build_argv(target)`** :

```python
[ "testssl.sh", "--quiet", "--color", "0", "--warnings", "off",
  "--connect_timeout", "10", "-p",                # protocoles seulement (pas de sweep de ciphers)
  "--jsonfile", "/dev/stderr",                    # JSON → stderr, affichage écran → stdout
  urlparse(target).hostname ]
```

Port non standard : si `urlparse(target).port` est renseigné, append `:<port>` (testssl accepte
`host:port`). `-p` limite le test aux **protocoles** (TLS 1.0/1.1/1.2/1.3, SNI, compression,
renégociation, Heartbleed/POODLE de base) : reste dans le cadre « on observe, on ne brute
pas », et tient largement dans le `timeout`.

#### 4.2.1 Adaptation du flux de sortie (changement minimal dans `base.py`)

testssl.sh **n'écrit pas** son JSON sur stdout sans mélanger avec l'affichage écran (issue
upstream `testssl/testssl.sh#1290`). On utilise donc `--jsonfile /dev/stderr` et l'on lit le
`stderr` déjà capturé par `_exec`. Ajout dans `ToolAdapter` :

```python
result_stream: str = "stdout"    # classe de base : inchangé pour nuclei/nmap/sqlmap

# dans run() : stream = stderr si self.result_stream == "stderr" else stdout
# puis findings = self.parse(stream, target)
```

Changement **strictement rétrocompatible** (4 lignes, défaut inchangé), testé par
`test_adapter_base.py`.

**`parse(stderr, target)`** :
1. Extraire le tableau JSON flat (une ligne par finding : `id`, `ip`, `port`, `severity`,
   `finding`, parfois `cve`) ; erreur → `[]`.
2. Ne conserver que les `severity ∈ {WARN, MUTUAL, INFO}` **utiles** (filtre sur `id` :
   `protocol`, `server_defaults`, `rc4`, `beast`, `heartbleed`, `poodle`, `robot`,
   `hsts`, ` renegotiation`…), ignore `scanTime`, `scanProblem`, `service` bruits.
3. Mapping sévérité : `WARN` → `MEDIUM`, `MUTUAL`/critique → `HIGH`, `INFO` → `LOW`.
4. `Finding.title = f"TLS : {id}"`, `evidence = finding` (texte brut), `remédiation` = résumé
   OWASP « Transport Security » (`reference` = CWE lié si présent).

### 4.3 Déduplication signalée (hors périmètre de ce lot, notée pour la spec)

ffuf peut redécouvrir des chemins déjà couverts par `web.exposed_endpoints`. Comme la signature
de rejeu inclut `target`, les findings restent séparés. **Noté comme dette** dans
`METHODOLOGIE.md` (axe « dédup par `(module_id, title)` ») ; non traité ici (YAGNI).

---

## 5. Intégration LLM — `src/redteam/agents/prompts.py`

Ajouter `tool.ffuf` et `tool.testssl` **à la liste littérale des `probe_id`** dans
`RECON_SYSTEM` et `SINGLE_SYSTEM`. Sans cette ligne, le LLM ne proposera jamais ces outils
(le repli « tout tester » ne s'applique que si le LLM ne renvoie aucune hypothèse valide — en
pratique il en renvoie toujours, donc le repli ne joue pas).

`PLANNER_SYSTEM` et `REPORTER_SYSTEM` ne listent pas de `probe_id` → inchangés.

---

## 6. Conteneurisation — `Dockerfile`

Après la couche nuclei (même style, non bloquant si le fetch échoue) :

```dockerfile
# ffuf : binaire GitHub release épinglé (arch amd64/arm64)
ARG FFUF_VERSION=v2.1.0
RUN set -eux; ARCH="$(dpkg --print-architecture)"; \
    case "$ARCH" in amd64) FARCH=amd64;; arm64) FARCH=arm64;; esac; \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_${FARCH}.tar.gz" \
      -o /tmp/ffuf.tgz; \
    tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf; chmod +x /usr/local/bin ffuf; \
    ffuf -V; rm /tmp/ffuf.tgz

# testssl.sh : paquet Debian (bookworm), pas de clone
RUN apt-get update && apt-get install -y --no-install-recommends testssl.sh && \
    rm -rf /var/lib/apt/lists/* && testssl.sh --help 2>&1 | head -1

# wordlist ffuf : fetch au build, fallback local si échec
COPY config/wordlists/ /opt/wordlists/
RUN curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt" \
      -o /opt/wordlists/ffuf-raft-small.txt || \
    cp /opt/wordlists/ffuf-fallback.txt /opt/wordlists/ffuf-raft-small.txt
```

- **Fallback embarqué** : `config/wordlists/ffuf-fallback.txt` (~150 chemins courants,
  versionné, garantit un run fonctionnel hors réseau de build).
- Le `COPY config/wordlists/` précède le `RUN` de fetch pour que le fallback soit disponible
  avant toute tentation d'échec.
- Ordre des couches : au-dessus de `COPY . /app` (ne pas invalider le cache du lock) mais
  après `uv sync` uniquement si le contenu change fréquemment → placement après la couche
  nuclei, avant `WORKDIR /app`.

---

## 7. Tests (offline, sans binaires)

Nouveaux fichiers :

| Fichier | Cas couverts |
|---|---|
| `tests/test_adapter_ffuf.py` | `build_argv` mono-hôte + `-rate`/`-maxtime` + aucun `-r`/`-recursion` ; `parse` sur `fixtures/ffuf_sample.json` → titres/sévérités attendus ; `parse("")` → `[]` ; `parse` avec texte parasite + JSON → extraction OK ; wordlist absente → skip `found=False` sans exec |
| `tests/test_adapter_testssl.py` | `build_argv` : `--jsonfile /dev/stderr`, `-p`, host seul, port passé si présent ; `parse` sur `fixtures/testssl_sample.json` → mapping sévérité ; `parse("")` → `[]` |
| `tests/test_adapter_base.py` | **extension** : `result_stream="stderr"` lit le stderr ; défaut `stdout` inchangé (rétrocompatibilité) |

Fixture `fixtures/ffuf_sample.json` : extrait réel formaté (2–3 résultats, dont un 403 et un
200). Fixture `fixtures/testssl_sample.json` : extrait flat JSON (protocol WARN + un INFO
ignoré). Aucun test ne lance de binaire → suite 100 % offline préservée.

---

## 8. Fichiers touchés / créés

| Fichier | Action |
|---|---|
| `src/redteam/tools/adapters/ffuf.py` | **créé** |
| `src/redteam/tools/adapters/testssl.py` | **créé** |
| `src/redteam/tools/adapters/base.py` | **modifié** : attribut `result_stream` (4 lignes, rétrocompatible) |
| `src/redteam/tools/registry.py` | **modifié** : `+ FfufAdapter(), TestsslAdapter()` |
| `src/redteam/agents/prompts.py` | **modifié** : `+ tool.ffuf, tool.testssl` dans `RECON_SYSTEM` et `SINGLE_SYSTEM` |
| `Dockerfile` | **modifié** : ffuf, testssl.sh, wordlist (+fallback) |
| `config/wordlists/ffuf-fallback.txt` | **créé** (~150 entrées) |
| `tests/test_adapter_ffuf.py`, `tests/test_adapter_testssl.py` | **créés** |
| `tests/fixtures/ffuf_sample.json`, `tests/fixtures/testssl_sample.json` | **créés** |
| `tests/test_adapter_base.py` | **modifié** : +2 tests `result_stream` |
| `README.md` (tableau des adaptateurs), `docs/ARCHITECTURE.md` (§2.1), `docs/METHODOLOGIE.md` (§ limites) | **modifiés** |

---

## 9. Critères d'acceptation

1. `uv run ruff check src tests` : 0 erreur.
2. `uv run pytest -q` : suite complète verte (65 existants + ≥ 6 nouveaux), **sans binaires
   installés** (skip propre couvert par `test_adapter_base`).
3. `docker build -t redteam-ia .` : succès, `ffuf -V` et `testssl.sh --help` exécutés au build.
4. Hors conteneur : `redteam run --mode single --target <cible>--mock` → les deux nouveaux
   outils apparaissent en `tool_call` avec `evidence = "… non installé (sonde sautée)"`.
5. Dans le conteneur : run réel sur Mirage → au moins `tool.ffuf` et `tool.testssl` planifiés
   (vérifiable dans `trace.jsonl`), 0 `error`, findings TLS et chemins découverts présents
   dans `report.md`.
6. Bornes vérifiées : `ffuf` ne dépasse pas 120 s ; AUCUNE requête hors hôte autorisé (host
   unique dans l'argv, pas de `-r`).

---

## 10. Conventions

Code en anglais, documentation en français. Pas de clé ni de secret dans l'image (`.env`
exclu par `.dockerignore`). Aucun `git push` sans demande explicite.
