# Adaptateurs d'outils externes — Spécification de conception

- **Date :** 2026-10-05
- **Auteur :** hichem@dpliance.com
- **Dépend de :** le PoC `redteam-ia` (déjà mergé dans `main`).
- **Statut :** Validé pour implémentation (design).

---

## 1. Objectif

Étendre la capacité de détection/exploitation du PoC en **intégrant de vrais outils de
sécurité** (installés via `../hackingtool`) sous forme d'**adaptateurs** qui respectent le
contrat `Probe` existant. Le PoC passe ainsi de 4 sondes HTTP maison à une couverture réelle,
et peut **éprouver** la cible (exploitation confirmée), pas seulement signaler des indices.

Cadre : audit **sous mandat** contre une **réplique de staging** de la cible (conditions
réelles, pas la production). L'échelle d'intensité `passive → active → intrusive` + la
confirmation explicite des étapes intrusives + le scope signé encadrent ce qui est permis.

### Hors périmètre (décision ferme)

Pas de module de **déni de service (DoS/DDoS)**. Un lanceur de DoS est une capacité destructive
indépendante de la cible et n'est pas produit. Le **risque** de déni de service est couvert
autrement (sonde « faiblesse‑disponibilité », §4.4) : on prouve la faiblesse (absence de
rate‑limiting, WAF, xmlrpc exposé, endpoint coûteux) sans couper le service. C'est aligné sur
la méthodo pentest classique (le DoS est exclu des engagements sérieux) et sur le prototype
`redscope` (« pas de DoS, pas de brute‑force réel »).

---

## 2. Outils intégrés (premier lot)

| Adaptateur | Outil | Intensité | Rôle |
|---|---|---|---|
| `tool.nuclei` | nuclei | active | Détection par templates (large couverture, preuve JSON reproductible) |
| `tool.nmap` | nmap `-sV` + NSE `vuln and not dos` | active | Services/versions + détection de vulnérabilités réseau non destructives |
| `tool.sqlmap` | sqlmap | **intrusive** | Preuve d'exploitation SQLi (marqueur d'accès, **pas** de dump de données) |
| `web.availability` | (httpx maison) | active | Faiblesses menant au DoS, prouvées sans couper le service |

`web.availability` n'est PAS un adaptateur d'outil (pas de binaire externe) : c'est une `Probe`
HTTP maison classique, rangée dans `tools/probes/`.

---

## 3. Problème de sûreté central : les outils externes échappent au `ScopeGuard`

Aujourd'hui, toute requête passe par `GuardedHttpClient`, donc rien ne sort du périmètre. Mais
`nuclei`/`nmap`/`sqlmap` sont des **binaires** qui font leurs propres appels réseau : ils ne
passent pas par notre client. Mécanisme de confinement imposé à chaque adaptateur :

1. **Autorisation pré‑lancement.** Avant tout `subprocess`, l'adaptateur appelle
   `guard.authorize(target, intensity)` (→ `ScopeViolation` si hors périmètre/fenêtre/intensité).
   L'outil n'est jamais lancé pour une cible hors scope.
2. **Mono‑cible.** On ne passe à l'outil **qu'un seul hôte/URL autorisé**, avec les options qui
   l'empêchent de divaguer (nmap mono‑hôte ; nuclei sans suivre les redirections hors‑hôte ;
   sqlmap sur l'URL cible, `--crawl=0`). Jamais de liste de cibles.
3. **Bornage.** `timeout` d'exécution, plafond de taille de sortie capturée, détection d'absence
   de l'outil (`shutil.which` → skip propre `found=False`).
4. **Palier intrusif.** `tool.sqlmap` (intrusive) n'est exécuté que si l'`Executor`/CLI confirme
   (`--yes`), via le gate d'intensité déjà en place.

**Limite résiduelle assumée (documentée) :** une fois le binaire lancé sur l'hôte autorisé, le
`ScopeGuard` ne peut plus l'arbitrer requête par requête ; on fait confiance à l'outil pour y
rester. Le confinement pré‑lancement + mono‑cible + options réduisent fortement ce risque.

### Accès au guard depuis l'adaptateur

`Probe.run(self, client, target)` reçoit un `GuardedHttpClient`. On expose sur ce client deux
propriétés en lecture seule — `client.guard` et `client.intensity` — pour que l'adaptateur
puisse `client.guard.authorize(target, client.intensity)` avant de shell‑out. (Petite addition
non intrusive à `http_client.py`.)

---

## 4. Conception des adaptateurs

### 4.0 Base — `tools/adapters/base.py`

```python
class ToolAdapter:                      # implémente le Protocol Probe
    id: str; intensity: Intensity; description: str
    binary: str                         # ex. "nuclei"
    async def run(self, client, target) -> ProbeResult:
        client.guard.authorize(target, client.intensity)     # confinement
        if shutil.which(self.binary) is None:
            return ProbeResult(found=False, evidence=f"{self.binary} non installé")
        argv = self.build_argv(target)                        # options sûres + mono-cible
        rc, out, err = await self._exec(argv, timeout=...)    # subprocess borné
        findings = self.parse(out, target)                    # → list[Finding]
        return ProbeResult(found=bool(findings), evidence=..., findings=findings)
```

Sous‑classes : `build_argv(target)` et `parse(output, target)`.

### 4.1 Extension du contrat `ProbeResult` (N findings par run)

Un outil produit souvent **plusieurs** findings par exécution ; `ProbeResult` n'en porte qu'un.
On étend :
- `ProbeResult.findings: list[Finding] = []` (nouveau), `finding: Finding | None` conservé.
- Helper `ProbeResult.all_findings() -> list[Finding]` = `findings or ([finding] if finding else [])`.
- `attacker_node` collecte `result.all_findings()` (les 4 sondes maison continuent de poser
  `finding` — inchangées).

### 4.2 `tool.nuclei` (active)

- `build_argv` : `nuclei -target <url> -jsonl -silent -no-color -rate-limit <n> -severity low,medium,high,critical` (reste sur l'hôte par défaut).
- `parse` : une ligne JSON → un `Finding` (severity du template ; title = `template-id` ; evidence = `matched-at` + nom du matcher ; remediation = référence du template si dispo).

### 4.3 `tool.nmap` (active)

- `build_argv` : `nmap -sV -Pn -T3 --script "vuln and not dos" -oX - <host>` (host extrait de l'URL ; **jamais** la catégorie `dos`).
- `parse` : XML → `Finding` par service exposant une version (LOW) et par sortie de script `vuln` (severity selon le script ; evidence = extrait du script).

### 4.4 `web.availability` (active, remplaçant responsable du DoS) — `tools/probes/`

Sonde HTTP maison (pas d'outil externe). Détecte et **prouve** des faiblesses de disponibilité
sans couper le service :
- absence d'en‑têtes/indices de **rate‑limiting** (pas de 429 après N requêtes légères sous budget),
- **WAF** non détecté,
- `xmlrpc.php` accessible (amplification/pingback),
- endpoint au **temps de réponse anormalement élevé** (mesure bornée, non répétée).
→ `Finding` HIGH « risque de déni de service » avec preuve + remédiation. Aucune montée en charge.

### 4.5 `tool.sqlmap` (intrusive)

- `build_argv` : `sqlmap -u <url> --batch --crawl=0 --level=2 --risk=1 --technique=BEUST --flush-session --banner` (confirmation d'accès via `--banner`/identifiant anodin ; **jamais** `--dump`, ni exfiltration de données clients).
- `parse` : détecte « parameter X is vulnerable » → `Finding` HIGH/CRITICAL (evidence = paramètre + technique + bannière comme preuve d'accès).
- N'est lancé qu'au palier intrusive confirmé.

---

## 5. Adaptation du Verifier (preuves non déterministes)

Les outils ne sont pas parfaitement déterministes ; « preuve reproductible » devient : **l'outil
re‑signale le même finding** au rejeu. On introduit une **signature de finding** stable :
`(module_id, target, title)` (pour nuclei, `title`=template‑id → stable ; pour sqlmap, le
paramètre injectable).

`verify_findings` (dans `agents/nodes.py`) est ajusté pour **éviter N re‑scans** :
- grouper les findings candidats par `module_id` ;
- re‑exécuter chaque probe **une seule fois** par (module_id, target) ;
- un candidat est `confirmed` si sa **signature** réapparaît dans `all_findings()` du rejeu,
  sinon `discarded` (faux‑positif écarté). `confidence_score` inchangé (0.3·LLM + 0.7·preuve).

Les 4 sondes maison existantes gardent leur comportement (un finding, signature triviale).

---

## 6. Conteneurisation

`Dockerfile` (base Debian/Kali) : installe `nuclei` (go install / binaire), `nmap`, `sqlmap`,
Python 3.11+, puis `pip install -e ".[dev]"`. L'audit tourne dans ce conteneur. `docker run`
documenté dans le README (montage du `.env`, de `runs/`). Les adaptateurs détectent l'absence
d'un outil et se sautent proprement, donc la suite de tests reste exécutable **hors conteneur**.

---

## 7. Tests (hors ligne, sans binaires réels)

- `base` : skip propre si binaire absent ; `authorize` appelé avant exec ; timeout respecté.
- Chaque adaptateur : `parse()` testé sur des **échantillons de sortie réels capturés** (fixtures
  JSON nuclei, XML nmap, log sqlmap) → bons `Finding`s. `_exec` est **mocké** (pas de subprocess
  réel en test).
- `web.availability` : via `httpx.MockTransport` (rate‑limit absent, xmlrpc exposé, etc.).
- Verifier : signature‑match confirme/écarte ; multi‑findings par run couvert ; re‑scan unique
  par probe vérifié.
- `ProbeResult.all_findings()` : compat ascendante (ancien `finding` seul) + nouveau `findings`.
- Confinement : un adaptateur refuse (ScopeViolation) une cible hors scope **avant** tout exec.

Aucun test ne lance de binaire réel ni n'accède au réseau.

---

## 8. Sûreté — invariants (rappel)

- `guard.authorize` **avant** tout lancement d'outil ; mono‑cible ; timeout ; palier intrusif confirmé.
- Pas de DoS/DDoS. sqlmap sans `--dump`. nmap sans scripts `dos`.
- Scope signé et `ScopeGuard` inchangés ; audit chaîné inchangé.
- Limite résiduelle (outil non arbitré après lancement) documentée dans METHODOLOGIE.md.

---

## 9. Fichiers touchés / créés

- Créés : `src/redteam/tools/adapters/__init__.py`, `base.py`, `nuclei.py`, `nmap.py`,
  `sqlmap.py` ; `src/redteam/tools/probes/availability.py` ; `Dockerfile` ; fixtures de test.
- Modifiés : `tools/probes/base.py` (`ProbeResult.findings`/`all_findings`),
  `tools/http_client.py` (propriétés `guard`/`intensity`), `tools/registry.py` (enregistrer les
  nouvelles sondes), `agents/nodes.py` (`attacker_node` multi‑findings, `verify_findings`
  signature‑match + re‑scan unique), docs (README install conteneur, METHODOLOGIE limite
  résiduelle + nouveaux outils).

---

## 10. Conventions

Code anglais, doc française ; pas de mention « Generated with Claude Code » ; ruff + pytest ;
tests hors ligne.
