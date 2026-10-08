"""Catalogue de modèles par rôle, pour permuter les modèles lors du benchmark."""
from __future__ import annotations

from redteam.config import DEFAULT_MODEL

# rôle logique -> identifiant de modèle Featherless
MODEL_CATALOG: dict[str, str] = {
    "default": DEFAULT_MODEL,
    "recon": DEFAULT_MODEL,
    "planner": DEFAULT_MODEL,
    "reporter": DEFAULT_MODEL,
}


def model_for(role: str) -> str:
    return MODEL_CATALOG.get(role, MODEL_CATALOG["default"])
