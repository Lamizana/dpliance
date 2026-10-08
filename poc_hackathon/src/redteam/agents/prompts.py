"""Prompts système par rôle (en anglais, comme le code).

Les identifiants de sondes listés dans les prompts sont **générés depuis le
registre** (`PROBES`) : ajouter une sonde l'inscrit automatiquement dans le
prompt de recon — aucune liste codée en dur à maintenir (axe P1,
audit/06-outils-et-prompts.md).
"""
from __future__ import annotations

from redteam.tools.registry import PROBES

_MAX_HYPOTHESES = 8

_FEW_SHOT = (
    'Example of a valid answer:\n'
    '[{"probe_id": "web.security_headers", "target": "https://example.com/", '
    '"rationale": "CSP absent de la page d\'authentification"}]\n'
)


def build_recon_system() -> str:
    """Prompt de recon dérivé du registre : bornes, diversité, few-shot, FR."""
    probe_ids = ", ".join(sorted(PROBES))
    return (
        "You are a reconnaissance analyst for an AUTHORIZED security audit. "
        "Given a surface map (pages, headers, technologies), list candidate weaknesses "
        "to verify. Reply ONLY with a JSON array of objects "
        '{"probe_id", "target", "rationale"} where probe_id is one of [' + probe_ids + ']. '
        f"Reply in French, max {_MAX_HYPOTHESES} hypotheses, one per probe_id "
        "(no duplicates). Choose only checks the surface map makes relevant. "
        "Do not invent findings; you only propose checks. "
        + _FEW_SHOT
    )


# Prompt unique pour recon et mode single (le registre fait foi).
RECON_SYSTEM = build_recon_system()

REPORTER_SYSTEM = (
    "You write a clear, factual security audit summary in French, one short paragraph, "
    "based ONLY on the confirmed findings provided. Do not add findings."
)
