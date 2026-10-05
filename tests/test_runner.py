import datetime
import os

import httpx

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard
from redteam.safety.scope import Scope, Authorized, Window
from redteam.llm.backend import MockBackend
from redteam.runner import build_state, run_graph


def _scope():
    return Scope(mission="m", mandate_ref="r", client_contact="c",
                 authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
                 window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
                 allowed_intensity=Intensity.ACTIVE, signature="x")


async def test_run_graph_writes_report(tmp_path, monkeypatch):
    guard = ScopeGuard(_scope(), today=datetime.date(2026, 11, 1))
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text="x",
                                    headers={"server": "nginx/1.0"}))
    backend = MockBackend(responses={"Surface map":
        '[{"probe_id":"web.security_headers","target":"http://localhost/","rationale":"r"}]'},
        default="résumé")
    state = build_state(mode="crew", target="http://localhost/", scope=_scope(), guard=guard,
                        backend=backend, trace=None, transport=transport, surface=None,
                        crawl_pages=1)
    out = await run_graph(state, run_dir=str(tmp_path))
    assert os.path.exists(tmp_path / "report.md")
    assert out["metrics"]["confirmed_count"] >= 0
