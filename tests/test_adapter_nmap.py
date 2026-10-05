from pathlib import Path
from redteam.tools.adapters.nmap import NmapAdapter

SAMPLE = (Path(__file__).parent / "fixtures" / "nmap_sample.xml").read_text()


def test_build_argv_single_host_no_dos():
    argv = NmapAdapter().build_argv("https://localhost:443/x")
    assert "localhost" in argv          # host, not full URL
    assert any("not dos" in a for a in argv)  # dos scripts excluded
    assert "-sV" in argv


def test_parse_reports_service_and_script():
    fs = NmapAdapter().parse(SAMPLE, "https://localhost/")
    titles = " ".join(f.title.lower() for f in fs)
    assert "nginx" in titles or "1.18.0" in " ".join(f.evidence for f in fs)
    assert any("vuln" in f.title.lower() or "cve" in f.title.lower() for f in fs)


def test_parse_tolerates_empty():
    assert NmapAdapter().parse("", "https://localhost/") == []
