from pathlib import Path
from redteam.safety.domain import Severity
from redteam.tools.adapters.nuclei import NucleiAdapter

SAMPLE = (Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl").read_text()


def test_build_argv_is_single_target():
    argv = NucleiAdapter().build_argv("http://localhost/")
    assert "nuclei" in argv[0]
    assert "http://localhost/" in argv
    assert "-jsonl" in argv


def test_parse_maps_severity_and_title():
    fs = NucleiAdapter().parse(SAMPLE, "http://localhost/")
    assert len(fs) == 2
    crit = [f for f in fs if f.severity is Severity.CRITICAL]
    assert crit and "CVE-2021-12345" in crit[0].title
    assert "http" in crit[0].evidence


def test_parse_tolerates_garbage():
    assert NucleiAdapter().parse("not json\n\n{bad", "http://localhost/") == []


def test_parse_dedups_identical_signature():
    # Même template-id + info.name (donc même titre/signature), matched-at différent :
    # un seul finding doit survivre (dédoublonnage par signature dans un run).
    jsonl = (
        '{"template-id": "dup-tmpl", "info": {"name": "Dup Finding", "severity": "high"}, '
        '"matched-at": "http://localhost/a"}\n'
        '{"template-id": "dup-tmpl", "info": {"name": "Dup Finding", "severity": "high"}, '
        '"matched-at": "http://localhost/b"}\n'
    )
    fs = NucleiAdapter().parse(jsonl, "http://localhost/")
    assert len(fs) == 1
    assert "dup-tmpl" in fs[0].title
    assert "http://localhost/a" in fs[0].evidence  # première occurrence conservée
