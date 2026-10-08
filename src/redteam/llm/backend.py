"""Abstraction LLM : backend Featherless (compatible OpenAI) et MockBackend offline.

Le MockBackend renvoie une réponse selon un mot-clé présent dans le prompt
utilisateur, ce qui permet des tests déterministes sans réseau.
"""
from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from pydantic import BaseModel


class LLMResult(BaseModel):
    text: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0


@runtime_checkable
class LLMBackend(Protocol):
    def complete(self, system: str, user: str) -> LLMResult: ...


class MockBackend:
    """Backend déterministe pour tests/démo hors ligne."""

    def __init__(self, responses: dict[str, str] | None = None, default: str = "[mock]"):
        self._responses = responses or {}
        self._default = default

    def complete(self, system: str, user: str) -> LLMResult:
        text = self._default
        for key, value in self._responses.items():
            if key in user:
                text = value
                break
        return LLMResult(text=text, model="mock", tokens_in=len(user), tokens_out=len(text))


class FeatherlessBackend:
    """Backend LLM via l'API Featherless (compatible OpenAI).

    Chaque appel est tracé dans LangSmith sous le nom « redteam_llm_complete »
    (run parent) ; l'appel ChatOpenAI sous-jacent est tracé en run enfant par le
    tracer LangChain dès que le tracing est activé (voir monitoring.langsmith).
    Sans clé LangSmith (tracing désactivé), `traceable` est un no-op sûr.
    """

    def __init__(self, api_key: str, base_url: str, model: str):
        from langchain_openai import ChatOpenAI
        from langsmith import traceable

        self.model = model
        self._llm = ChatOpenAI(model=model, api_key=api_key, base_url=base_url)
        self._traced_complete = traceable(
            self._complete, name="redteam_llm_complete",
            metadata={"model": model, "layer": "llm"},
        )

    def complete(self, system: str, user: str) -> LLMResult:
        return self._traced_complete(system, user)

    def _complete(self, system: str, user: str) -> LLMResult:
        from langchain_core.messages import HumanMessage, SystemMessage

        start = time.monotonic()
        resp = self._llm.invoke([SystemMessage(content=system), HumanMessage(content=user)])
        latency_ms = int((time.monotonic() - start) * 1000)
        usage = getattr(resp, "usage_metadata", None) or {}
        return LLMResult(
            text=str(resp.content), model=self.model,
            tokens_in=int(usage.get("input_tokens", 0)),
            tokens_out=int(usage.get("output_tokens", 0)),
            latency_ms=latency_ms,
        )
