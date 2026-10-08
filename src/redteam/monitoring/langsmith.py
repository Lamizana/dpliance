"""Activation du tracing LangSmith (skill langsmith-trace).

L'app est basée sur LangChain/LangGraph : conformément au skill, il suffit de
poser les variables d'environnement `LANGSMITH_TRACING`, `LANGSMITH_API_KEY`
et `LANGSMITH_PROJECT` pour que les runs du graphe et des appels ChatOpenAI
soient tracés automatiquement. `@traceable` (backend) ajoute des runs nommés
avec métadonnées supplémentaires.

Le tracing reste optionnel : sans clé API, tout est no-op et le PoC continue de
fonctionner 100 % hors ligne.
"""
from __future__ import annotations

import os

from redteam.config import Settings

# Variables posées uniquement quand une clé API est disponible.
_TRACING_ALIASES = {
    "LANGSMITH_TRACING": "true",
    # Alias historique de LangChain ; inoffensif et requis par d'anciens SDK.
    "LANGCHAIN_TRACING_V2": "true",
}


def activate_langsmith(settings: Settings | None = None) -> bool:
    """Active le tracing LangSmith si une clé API est disponible.

    Priorité : clé explicite dans `settings`, sinon variable d'environnement
    déjà posée (`LANGSMITH_API_KEY`). Renvoie True si le tracing est actif.
    """
    key = os.getenv("LANGSMITH_API_KEY")
    if settings is not None and settings.langsmith_api_key:
        key = settings.langsmith_api_key
    if not key:
        return False
    os.environ["LANGSMITH_API_KEY"] = key
    for var, value in _TRACING_ALIASES.items():
        os.environ.setdefault(var, value)

    project = settings.langsmith_project if settings is not None else None
    project = project or os.getenv("LANGSMITH_PROJECT")
    if project:
        os.environ["LANGSMITH_PROJECT"] = project
        os.environ.setdefault("LANGCHAIN_PROJECT", project)
    return True