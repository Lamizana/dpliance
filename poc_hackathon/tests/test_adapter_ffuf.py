"""Tests hors ligne de l'adaptateur ffuf (aucun binaire requis)."""
from pathlib import Path

import httpx
import pytest

from redteam.safety.domain import Intensity, Severity
from redteam.safety.guard import ScopeGuard, ScopeViolation
from redteam.safety.scope import Authorized, Scope, Window
from redteam.tools.adapters.ffuf import FfufAdapter
from redteam.tools.http_client import GuardedHttpClient

SAMPLE = (Path(__file__).parent / "fixtures" / "ffuf_sample.json").read_text()


def _client(intensity=Intensity.ACTIVE):
    s = Scope(mission="m", mandate_ref="r", client_contact="c",
              authorized=Authorized(domains=["localhost"], ips=[]), excluded=[],
              window=Window(start=__import__("datetime").date(2026, 10, 1),
                            end=__import__("datetime").date(2026, 12, 31)),
              allowed_intensity=Intensity.ACTIVE, signature="x")
    g = ScopeGuard(s, today=__import__("datetime").date(2026, 11, 1))
    return GuardedHttpClient(g, intensity, max_requests=5,
                             transport=httpx.MockTransport(lambda r: httpx.Response(200)))


def test_build_argv_single_host_rate_limited():
    argv = FfufAdapter().build_argv("https://hackathon.mirage-analytics.com/fr/")
    assert "https://hackathon.mirage-analytics.com/FUZZ" in argv   # racine, pas /fr/
    assert "-rate" in argv and "20" in argv
    assert "-t" in argv and "5" in argv
    assert "-maxtime" in argv and "120" in argv
    assert "-non-recursive" in argv
    assert "-r" not in argv            # jamais de follow-redirects (comparaison exacte)
    assert "-recursion" not in argv
    assert "-X" not in argv            # aucun verb destructif
    # un seul argument porte le marqueur FUZZ (plan : argv.count("FUZZ") —
    # équivalent sous-chaîne, le marqueur est dans l'URL -u, pas en élément exact)
    assert sum("FUZZ" in a for a in argv) == 1


def test_build_argv_keeps_port_and_drops_path():
    argv = FfufAdapter().build_argv("http://localhost:8080/deep/path")
    assert "http://localhost:8080/FUZZ" in argv
    assert not any("deep" in a for a in argv)


def test_parse_maps_statuses_to_severities():
    fs = FfufAdapter().parse(SAMPLE, "https://hackathon.mirage-analytics.com/")
    assert len(fs) == 4                      # le 404 est ignoré
    by_status = {f.evidence.split("→")[1].split("(")[0].strip(): f for f in fs}
    assert by_status["403"].severity is Severity.MEDIUM
    assert by_status["403"].title == "Endpoint protégé découvert"
    assert by_status["200"].severity is Severity.MEDIUM
    assert by_status["200"].title == "Chemin exposé"
    assert by_status["301"].severity is Severity.LOW
    assert by_status["405"].severity is Severity.LOW
    assert all(f.module_id == "tool.ffuf" for f in fs)


def test_parse_tolerates_ui_noise():
    dirty = "INFO: fetching...\n" + SAMPLE + "\n-- statistics --"
    fs = FfufAdapter().parse(dirty, "https://hackathon.mirage-analytics.com/")
    assert len(fs) == 4


def test_parse_empty_and_invalid():
    assert FfufAdapter().parse("", "http://localhost/") == []
    assert FfufAdapter().parse("no json here", "http://localhost/") == []


def test_intensity_is_active_not_intrusive():
    assert FfufAdapter().intensity is Intensity.ACTIVE


async def test_missing_wordlist_skips_before_exec(monkeypatch):
    a = FfufAdapter()
    a.wordlist = "/nonexistent/wordlist.txt"
    calls = {"n": 0}

    async def _exec(argv):
        calls["n"] += 1
        return (0, "", "")

    monkeypatch.setattr(a, "_exec", _exec)
    monkeypatch.setattr("redteam.tools.adapters.base.shutil.which", lambda b: "/usr/bin/" + b)
    res = await a.run(_client(), "http://localhost/")
    assert res.found is False and "wordlist" in res.evidence
    assert calls["n"] == 0


async def test_wordlist_missing_still_authorizes():
    a = FfufAdapter()
    a.wordlist = "/nonexistent/wordlist.txt"
    with pytest.raises(ScopeViolation):          # hors scope → refus AVANT tout
        await a.run(_client(), "http://evil.example/")
