"""Callback LangChain optionnel pour capturer tokens et latence des appels LLM.

Non requis par le MockBackend ; utile si l'on branche directement un modèle
LangChain sans passer par FeatherlessBackend.
"""
from __future__ import annotations

import time


class TokenCountingHandler:
    def __init__(self) -> None:
        self.tokens_in = 0
        self.tokens_out = 0
        self.latency_ms = 0
        self._start = 0.0

    def on_llm_start(self, *args, **kwargs) -> None:
        self._start = time.monotonic()

    def on_llm_end(self, response, *args, **kwargs) -> None:
        self.latency_ms = int((time.monotonic() - self._start) * 1000)
        try:
            usage = response.llm_output.get("token_usage", {})
            self.tokens_in += int(usage.get("prompt_tokens", 0))
            self.tokens_out += int(usage.get("completion_tokens", 0))
        except Exception:
            pass
