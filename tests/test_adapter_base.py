import datetime
import httpx
import pytest

from redteam.safety.domain import Intensity, Finding, Severity, Remediation
from redteam.safety.guard import ScopeGuard, ScopeViolation
from redteam.safety.scope import Scope, Authorized, Window
from redteam.tools.http_client import GuardedHttpClient
from redteam.tools.adapters.base import ToolAdapter


def _client(intensity=Intensity.ACTIVE):
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
              allowed_intensity=Intensity.INTRUSIVE, signature="x")
    g = ScopeGuard(s, today=datetime.date(2026, 11, 1))
    return GuardedHttpClient(g, intensity, max_requests=5,
                             transport=httpx.MockTransport(lambda r: httpx.Response(200)))


class _FakeAdapter(ToolAdapter):
    id = "tool.fake"
    intensity = Intensity.ACTIVE
    description = "fake"
    binary = "definitely-not-installed-xyz"

    def build_argv(self, target):
        return [self.binary, target]

    def parse(self, stdout, target):
        return [Finding(module_id=self.id, target=target, severity=Severity.LOW,
                        title="hit", evidence=stdout[:20],
                        remediation=Remediation(summary="s", reference="r"))]


async def test_skips_cleanly_when_binary_absent():
    a = _FakeAdapter()
    res = await a.run(_client(), "http://localhost/")
    assert res.found is False and "non installé" in res.evidence


async def test_authorizes_before_exec(monkeypatch):
    a = _FakeAdapter()
    # out-of-scope target must raise before any exec attempt
    with pytest.raises(ScopeViolation):
        await a.run(_client(), "http://evil.example/")


async def test_parses_findings_from_mocked_exec(monkeypatch):
    a = _FakeAdapter()
    monkeypatch.setattr(a, "_exec", lambda argv: _ok("some-output"))
    # pretend the binary exists
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    res = await a.run(_client(), "http://localhost/")
    assert res.found is True and res.all_findings()[0].title == "hit"


async def test_timeout_returns_not_found(monkeypatch):
    a = _FakeAdapter()
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    async def _boom(argv):
        raise TimeoutError()
    monkeypatch.setattr(a, "_exec", _boom)
    res = await a.run(_client(), "http://localhost/")
    assert res.found is False and "timeout" in res.evidence.lower()


async def _ok(out):
    return (0, out, "")
