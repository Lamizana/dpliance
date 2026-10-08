# La « carte de surface » (`SurfaceMap`)

Réponse à la question : *« qu'est-ce que la carte de surface ? »* (comprendre `recon_node`).

## Définition

La carte de surface est la **carte du territoire observé par le crawler** avant que le LLM ne
raisonne. Définie dans `src/redteam/tools/crawler.py:27` :

```python
class Page(BaseModel):
    url: str            # URL visitée
    status: int         # code HTTP (200, 401, 404…)
    headers: dict       # en-têtes de réponse (server, x-powered-by, set-cookie…)
    body_snippet: str   # extrait du corps (2 000 caractères max)

class SurfaceMap(BaseModel):
    pages: list[Page]   # pages réellement visitées
    links: list[str]    # tous les liens href découverts
```

## Production (`crawler.py:36` — `crawl()`)

1. **BFS** (file `deque`) depuis la graine = `--target`.
2. À chaque page : `GET` via `GuardedHttpClient` (donc **sous `ScopeGuard`**) → statut +
   en-têtes + extrait de corps.
3. Extraction des `href` par regex → **seuls les liens du même hébergement** sont suivis
   (`_same_host`), le reste ignoré.
4. Bornes : **20 pages max**, **profondeur 2 max** — déterministe, borné, non-DoS.

## Consommation (`recon_node`, `agents/nodes.py:38`)

Le plan transforme la carte en **texte brut** pour le LLM :

```python
summary = "\n".join(f"{p.url} [{p.status}] server={p.headers.get('server','')}"
                    for p in surface.pages[:30])
res = state["backend"].complete(RECON_SYSTEM, f"Surface map:\n{summary}")
```

Exemple de résumé vu par le modèle :

```
https://hackathon.mirage-analytics.com/fr/ [200] server=nginx
https://hackathon.mirage-analytics.com/fr/auth/login [200] server=nginx
https://hackathon.mirage-analytics.com/old [301] server=nginx
```

C'est ce résumé qui déclenche les hypothèses : `server=nginx` → `tool.nmap`/`tool.testssl`,
`/auth/login` → `web.security_headers`, 301 partout → `tool.ffuf`… Chaque proposition devient
une `Hypothesis(probe_id, target, rationale)`.

## Repli sûr

Si le LLM ne renvoie **aucun JSON valide** (réponse vide, refus, format cassé),
`extract_json_list` → `[]` → `hyps` vide → **toutes les sondes du registre sont testées**
(`nodes.py:51-53`, raison `"repli"`). Le système dégrade en « on teste tout » au lieu de ne
rien faire.

## Rôle dans l'isolation

La carte est le **seul pont entre le réseau réel et le raisonnement LLM** : les agents ne
voient jamais le réseau directement, uniquement ce résumé (règle d'isolation du projet).
