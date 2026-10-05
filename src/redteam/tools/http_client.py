"""Client HTTP asynchrone : la SEULE porte de sortie réseau du PoC.

Toute requête est d'abord autorisée par le ScopeGuard (périmètre, fenêtre,
intensité) puis comptée contre un budget par exécution. Les agents LLM
n'accèdent jamais au réseau autrement que par ce client.
"""
from __future__ import annotations

import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard


class RequestBudgetExceeded(Exception):
    pass


class GuardedHttpClient:
    def __init__(self, guard: ScopeGuard, intensity: Intensity, max_requests: int,
                 transport: httpx.BaseTransport | None = None, timeout: float = 10.0):
        self._guard = guard
        self._intensity = intensity
        self._max = max_requests
        self._count = 0
        self._client = httpx.AsyncClient(transport=transport, timeout=timeout,
                                         follow_redirects=True)

    @property
    def count(self) -> int:
        return self._count

    async def request(self, method: str, url: str, **kw) -> httpx.Response:
        self._guard.authorize(url, self._intensity)  # lève ScopeViolation si hors scope
        if self._count >= self._max:
            raise RequestBudgetExceeded(f"Budget de requêtes dépassé (plafond {self._max}).")
        self._count += 1
        return await self._client.request(method, url, **kw)

    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def aclose(self) -> None:
        await self._client.aclose()
