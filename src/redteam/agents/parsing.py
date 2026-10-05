"""Parsing défensif des sorties LLM : on extrait le premier tableau JSON trouvé.

Un LLM peut entourer sa réponse de texte ; on ne doit jamais crasher sur une
sortie malformée. En cas d'échec, on renvoie une liste vide (l'orchestrateur
tracera alors une absence d'hypothèses plutôt qu'une erreur fatale).
"""
from __future__ import annotations

import json


def extract_json_list(text: str) -> list[dict]:
    start = text.find("[")
    end = text.rfind("]")
    if start == -1 or end == -1 or end < start:
        return []
    try:
        parsed = json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return []
    return [x for x in parsed if isinstance(x, dict)] if isinstance(parsed, list) else []
