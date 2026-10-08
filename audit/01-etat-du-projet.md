# État du projet — notes de session (08/10/2026)

## Objectif

Implémenter les axes d'amélioration validés du PoC `redteam-ia` : ajout des adaptateurs
**ffuf** (découverte de contenu) et **testssl.sh** (audit TLS), de la spec au plan exécutable.
Langue : français pour la doc, anglais pour le code.

## Ce qui a été fait

1. **Compréhension du projet** — architecture, cible Mirage, cadre de mandat.
2. **Debugs résolus** :
   - `ConnectError` : mauvaise cible (`http://localhost:8080` au lieu de l'URL Mirage) ;
   - `AuthenticationError 401` : clé Featherless invalide → remplacement par clé préfixe `rc_`.
3. **Benchmark exécuté** (modes `single` + `crew`, dans Docker) :
   - `runs/benchmark.md` + dossiers `runs/bench-*` (report.md/html, state.json, trace.jsonl) ;
   - remarque : en mode `benchmark`, aucun `audit.jsonl` n'est généré ;
   - dossiers vides `runs/*/root` à nettoyer (`sudo rm -rf`) — exécution Docker en root.
4. **Axes d'amélioration proposés** (A1–A5, B1–B4, lot C) puis choix utilisateur focalisé sur
   les outils : **ffuf + testssl.sh** retenus ; `wafw00f` et `nikto` refusés ; `sqlmap` reste
   bloqué en `intrusive` (le mandat n'autorise que `active`).
5. **Spec rédigée, relue, approuvée** :
   `docs/superpowers/specs/2026-10-08-tools-ffuf-testssl-design.md`
6. **Plan d'implémentation écrit** (6 tâches, TDD) :
   `docs/superpowers/plans/2026-10-08-tools-ffuf-testssl.md`
   — auto-revu : commandes corrigées en `.venv/bin/…` (uv hors PATH non-interactif),
   82 tests attendus, assertions testssl déterministes.
7. **Documentation de rendu** : `docs/DOSSIER-RENDU.md` (public jury DPLIANCE) + lien README.

## Décisions structurantes

| Sujet | Décision |
|---|---|
| Benchmark | Mode `single` + `crew`, exécution Docker |
| Clé LLM | Featherless, préfixe `rc_`, `.env` mis à jour |
| Cible | `MIRAGE_TARGET=https://hackathon.mirage-analytics.com/fr/` |
| Intensité | `allowed_intensity: active` → sqlmap (`intrusive`) reste bloqué |
| Outils ajoutés | ffuf + testssl.sh uniquement |
| Wordlist ffuf | Fetch au build Docker, avec fallback versionné `config/wordlists/ffuf-fallback.txt` |
| Commits | Jamais de `git push` ; commit seulement sur demande explicite |

## Contraintes de sûreté (spec ffuf/testssl)

- **ffuf** : `-rate 20 -t 5 -timeout 10 -maxtime 120 -non-recursive -mc … -s -of json -o /dev/stdout`,
  mono-URL `scheme://host[:port]/FUZZ`, **jamais** `-r` / `-recursion` / `-X`.
- **testssl.sh** : `-p` seul (protocoles/défauts), `--connect-timeout 10 --openssl-timeout 10`,
  `--jsonfile /dev/stderr`, mono-hôte `host[:port]`.
- Chaque `ToolAdapter.run()` appelle `client.guard.authorize(target, client.intensity)` avant
  tout `subprocess` ; skip propre si `shutil.which()` négatif.
- Nouveau hook `result_stream: str = "stdout"` dans `ToolAdapter` (rétrocompatible) pour lire
  le JSON que testssl écrit sur **stderr**.

## Exécution du plan — état

| Tâche | Objet | État |
|---|---|---|
| 1 | Hook `result_stream` dans `tools/adapters/base.py` + 2 tests | ✅ fait |
| 2 | `adapters/ffuf.py` + 8 tests | ✅ fait |
| 3 | `adapters/testssl.py` + 5 tests | ✅ fait |
| 4 | Enregistrement `registry.py` + ids dans les prompts | ✅ fait (via `build_recon_system()` — généré depuis le registre, plus de liste codée en dur) |
| 5 | Dockerfile (binaires épinglés) + wordlist fallback + `docker build` | ⏳ à faire |
| 6 | Docs (README, ARCHITECTURE, METHODOLOGIE) + `ruff` + `pytest -q` | ⏳ à faire (tests : 92/92 verts) |

**Prochaine étape** : tâches 5-6 du plan ffuf/testssl (build Docker + docs).

## Lot P1 « prompts Qwen » — livré (08/10)

Axes P1 d'`audit/06-outils-et-prompts.md`, implémentés en TDD :

| Axe | Fichiers | Tests |
|---|---|---|
| `RECON_SYSTEM` généré depuis `PROBES` (plafond 8, 1/sonde, few-shot, FR) + suppression du code mort `SINGLE_SYSTEM`/`PLANNER_SYSTEM` | `agents/prompts.py` | `tests/test_prompts.py` (7) |
| **Replan adaptatif** : `_replan_node` relance `recon_node` avec feedback « déjà exécuté / écarté » | `agents/crew_graph.py`, `agents/nodes.py` (`_recon_extra`, `_discarded`), `agents/state.py` | `tests/test_replan_feedback.py` (3) |
| Test d'intégration réaligné sur le prompt généré | `tests/test_registry_integration.py` | — |

Bilan : **92 tests verts** (65 → 92), ruff propre sur les fichiers touchés (I001 restantes =
préexistantes).

## Hypothèses à confirmer

- `testssl.sh` présent dans Debian bookworm (paquet `testssl.sh`) → image Docker.
- `ffuf` absent d'apt → binaire GitHub release épinglé (`FFUF_VERSION=v2.1.0`, amd64/arm64).
- Tests entièrement hors-ligne (aucun accès réseau).
