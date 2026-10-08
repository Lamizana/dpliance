"""Tests hors ligne de l'adaptateur testssl.sh (aucun binaire requis)."""
from pathlib import Path

from redteam.safety.domain import Intensity, Severity
from redteam.tools.adapters.testssl import TestsslAdapter

SAMPLE = (Path(__file__).parent / "fixtures" / "testssl_sample.json").read_text()


def test_build_argv_bounded_protocols_only():
    argv = TestsslAdapter().build_argv("https://hackathon.mirage-analytics.com/fr/")
    assert "testssl.sh" in argv
    assert "-p" in argv                       # protocoles seulement, pas de sweep
    assert "--jsonfile" in argv and "/dev/stderr" in argv
    assert "--connect-timeout" in argv and "10" in argv
    assert "--openssl-timeout" in argv and "10" in argv
    assert "--quiet" in argv and "--color" in argv
    # mono-cible : l'hôte seul, jamais le chemin /fr/
    assert argv[-1] == "hackathon.mirage-analytics.com"
    assert not any(a.startswith("http") for a in argv)


def test_build_argv_appends_port():
    argv = TestsslAdapter().build_argv("https://localhost:8443/x")
    assert argv[-1] == "localhost:8443"


def test_result_stream_is_stderr():
    assert TestsslAdapter().result_stream == "stderr"
    assert TestsslAdapter().intensity is Intensity.ACTIVE


def test_parse_maps_severities_and_filters_noise():
    fs = TestsslAdapter().parse(SAMPLE, "https://hackathon.mirage-analytics.com/")
    titles = [f.title for f in fs]
    assert len(fs) == 4                                  # protocol x2, server_defaults, hsts
    assert titles.count("TLS : protocol") == 2           # TLS 1.0 + 1.1, même titre
    assert "TLS : hsts" in titles
    assert not any("scanTime" in t for t in titles)       # id hors allowlist -> ignoré
    assert not any("heartbleed" in t for t in titles)     # severity OK -> ignorée
    by_title = {f.title: f for f in fs}
    assert by_title["TLS : protocol"].severity is Severity.MEDIUM   # WARN -> MEDIUM
    assert by_title["TLS : hsts"].severity is Severity.MEDIUM
    assert all(f.module_id == "tool.testssl" for f in fs)


def test_parse_empty_and_invalid():
    assert TestsslAdapter().parse("", "https://localhost/") == []
    assert TestsslAdapter().parse("garbage", "https://localhost/") == []
    assert TestsslAdapter().parse("[]", "https://localhost/") == []
