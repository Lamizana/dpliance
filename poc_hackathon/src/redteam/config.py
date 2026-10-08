"""Chargement de la configuration depuis l'environnement (voir .env.example)."""
from __future__ import annotations

import os

from pydantic import BaseModel

DEFAULT_MODEL = "huihui-ai/Huihui-Qwen3.8-27B-abliterated"
DEFAULT_BASE_URL = "https://api.featherless.ai/v1"


class Settings(BaseModel):
    featherless_api_key: str | None = None
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    target: str = "http://localhost:8080"
    signing_key: str | None = None


def load_settings() -> Settings:
    return Settings(
        featherless_api_key=os.getenv("FEATHERLESS_API_KEY"),
        base_url=os.getenv("FEATHERLESS_BASE_URL", DEFAULT_BASE_URL),
        model=os.getenv("REDTEAM_MODEL", DEFAULT_MODEL),
        target=os.getenv("MIRAGE_TARGET", "https://hackathon.mirage-analytics.com/fr/"),
        signing_key=os.getenv("REDTEAM_SIGNING_KEY"),
    )
