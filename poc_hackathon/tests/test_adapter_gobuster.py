from redteam.safety.domain import Severity
from redteam.tools.adapters.gobuster import GobusterAdapter, WORDLIST

SAMPLE = """admin                  (Status: 200) [Size: 123]
.git                   (Status: 200) [Size: 300]
old                    (Status: 301) [Size: 0] [--> /new/]
garbage line
"""


def test_build_argv_is_single_target_and_bounded():
    argv = GobusterAdapter().build_argv("http://localhost/")
    assert argv[:3] == ["gobuster", "dir", "-u"]
    assert "http://localhost/" in argv
    assert str(WORDLIST) in argv and "-r" not in argv and "-x" not in argv
    assert "-t" in argv and "--delay" in argv


def test_wordlist_shipped_and_limited():
    lines = [ln for ln in WORDLIST.read_text().splitlines() if ln.strip()]
    assert 0 < len(lines) <= 100  # budget : borné, rejouable par le Verifier


def test_parse_maps_status_to_severity():
    fs = GobusterAdapter().parse(SAMPLE, "http://localhost/")
    assert len(fs) == 3
    sev = {f.title: f.severity for f in fs}
    assert sev["Chemin exposé : /admin"] is Severity.MEDIUM
    assert sev["Chemin exposé : /.git"] is Severity.HIGH
    assert sev["Chemin exposé : /old"] is Severity.LOW
    assert "statut 200" in fs[0].evidence


def test_parse_dedups_signature_and_tolerates_garbage():
    dup = "admin (Status: 200) [Size: 1]\nadmin (Status: 200) [Size: 9]\n"
    assert len(GobusterAdapter().parse(dup, "http://localhost/")) == 1
    assert GobusterAdapter().parse("not a result\n{bad", "http://localhost/") == []
