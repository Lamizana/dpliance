# Axes d'amélioration — ajout d'outils et niveaux touchés

Question : où se branche un nouvel outil dans le pipeline (`recon → planner → attacker →
verifier → reporter`) ?

## Table de correspondance niveau ↔ travail

| Niveau | Fichier | Rôle | Travail pour un nouvel outil | État |
|---|---|---|---|---|
| **1. Outil** | `tools/adapters/` + `registry.py` | Exécution | Écrire l'adaptateur (argv borné, parse → `Finding`) + l'enregistrer dans `PROBES` | Automatique ✅ |
| **2. Recon** | `agents/prompts.py` | LLM propose les hypothèses | **Ajouter le `probe_id` à la liste codée-en-dur** de `RECON_SYSTEM` **et** `SINGLE_SYSTEM` (sinon le LLM ne le propose jamais) | ⚠️ 2 listes manuelles |
| **3. Planner** | `agents/nodes.py:72` | Filtrage scope + idempotence | Rien : `guard.check()` + dédup `(module_id, target)` automatiques | Automatique ✅ |
| **4. Attacker** | `agents/nodes.py:89` | Exécute le plan | Rien : `client_factory(probe.intensity)` + `probe.run()` | Automatique ✅ |
| **5. Verifier** | `agents/nodes.py:143` | Preuve reproductible | Contrainte : titres de parse **stables** — signature `(module_id, target, title)`, sinon finding écarté | Automatique mais piège ⚠️ |
| **6. Reporter** | `agents/nodes.py:160` | Rapport FR | Rien : titre + sévérité suffisent | Automatique ✅ |
| **7. Sécurité** | `safety/guard.py` | Mandat | Choisir l'`intensity` (intrusif = bloqué par `allowed: active`) + `guard.authorize()` dans `run()` | En place ✅ |
| **8. Image** | `Dockerfile` | Livraison | Binaire épinglé + wordlist | Planifié ffuf/testssl 🔜 |

## Les 3 axes de travail

### A. En cours — ffuf + testssl.sh (spec + plan approuvés)

- Spec : `docs/superpowers/specs/2026-10-08-tools-ffuf-testssl-design.md`
- Plan : `docs/superpowers/plans/2026-10-08-tools-ffuf-testssl.md` (6 tâches)
- **ffuf** : découverte de contenu (recon, `intensity: active`), URL mono-hôte
  `scheme://host[:port]/FUZZ`, bornes `-rate 20 -t 5 -timeout 10 -maxtime 120
  -non-recursive`, parse JSON, skip si wordlist absente.
- **testssl.sh** : audit TLS `-p` seul, mono-hôte, JSON sur **stderr** → introduit le hook
  `result_stream: str = "stdout"` dans `ToolAdapter` (base.py).
- Touchent les niveaux 1, 2 (prompts) et 8 (Dockerfile).

### B. Dette structurelle (axe le plus rentable après A)

1. **Listes de `probe_id` en double** (`prompts.py:8` et `:28`) — les générer depuis
   `PROBES.keys()` : sinon chaque outil = 2 oublis silencieux (le repli « teste tout »
   masque l'oubli côté mode nominal).
2. **Dédup des findings** : signature `(module_id, target, title)` empêche 2 findings réels
   d'une même sonde sur la même cible d'être confirmés séparément (dette notée §4.3 de la
   spec).
3. **Prédicibilité du verifier** : outils non-déterministes (`nmap`, `nuclei`) → garantir
   des titres stables au parse, sinon le F1 reste plafonné par des `discarded`.

### C. Outils candidats suivants

| Outil | Niveau(s) | Intensité | Commentaire |
|---|---|---|---|
| `httpx` | 1 + 2 | passive | Enrichir la `SurfaceMap` (technos, statuts) |
| `wafw00f` | 1 + 2 | passive | Refusé au 1er tour (hors besoins) |
| `nikto` | 1 + 2 | active/intrusive | Refusé (bruit, lourd) |
| `testssl` avancé (`--vulnerable`) | 1 + 2 + **7** | intrusive | Nécessite d'élargir le scope signé |
| Fuzz applicatif (params) | 1 + 2 + **7** | intrusive | Pareil : arbitrage mandant obligatoire |

## Règle d'or

Un ajout d'outil conforme au protocole `Probe` (`tools/probes/base.py:26` — `id`,
`intensity`, `async run(client, target) -> ProbeResult`) est **avalé automatiquement** par
planner/attacker/verifier/report. La discipline d'ajout réelle = **argv borné +
`guard.authorize()` + titres de parse stables + enregistrement `PROBES` + les 2 listes de
prompts (+ binaire Docker si nécessaire)**.
