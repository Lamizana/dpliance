"""Crawler BFS asynchrone, borné par scope/budget/profondeur.

Cartographie la surface de la cible (pages, statuts, en-têtes, extraits de
corps). Ne suit que les liens du même hôte que la graine ; les liens hors
périmètre sont ignorés (et seraient de toute façon refusés par le guard).
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel

from redteam.tools.http_client import GuardedHttpClient

_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)


class Page(BaseModel):
    url: str
    status: int
    headers: dict[str, str]
    body_snippet: str


class SurfaceMap(BaseModel):
    pages: list[Page]
    links: list[str]


def _same_host(a: str, b: str) -> bool:
    return urlparse(a).hostname == urlparse(b).hostname


async def crawl(client: GuardedHttpClient, seed: str, max_pages: int = 20,
                max_depth: int = 2) -> SurfaceMap:
    seen: set[str] = set()
    pages: list[Page] = []
    all_links: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(seed, 0)])

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        resp = await client.get(url)
        body = resp.text[:2000]
        pages.append(Page(url=url, status=resp.status_code,
                          headers={k.lower(): v for k, v in resp.headers.items()},
                          body_snippet=body))
        for raw in _HREF.findall(resp.text):
            nxt = urljoin(url, raw)
            all_links.add(nxt)
            if _same_host(seed, nxt) and nxt not in seen:
                queue.append((nxt, depth + 1))

    return SurfaceMap(pages=pages, links=sorted(all_links))
