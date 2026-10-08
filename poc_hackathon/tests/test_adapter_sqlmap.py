from pathlib import Path

from redteam.safety.domain import Intensity, Severity
from redteam.tools.adapters.sqlmap import SqlmapAdapter

SAMPLE = (Path(__file__).parent / "fixtures" / "sqlmap_sample.txt").read_text()


def test_is_intrusive_and_never_dumps():
    a = SqlmapAdapter()
    assert a.intensity is Intensity.INTRUSIVE
    argv = a.build_argv("http://localhost/item?id=1")
    assert "--dump" not in argv and "--dump-all" not in argv
    assert "--batch" in argv and "http://localhost/item?id=1" in argv


def test_parse_detects_injectable_param():
    fs = SqlmapAdapter().parse(SAMPLE, "http://localhost/item?id=1")
    assert len(fs) >= 1
    f = fs[0]
    assert f.severity in (Severity.HIGH, Severity.CRITICAL)
    assert "id" in f.evidence and ("inject" in f.evidence.lower() or "blind" in f.evidence.lower())


def test_parse_no_injection_returns_empty():
    assert SqlmapAdapter().parse("[INFO] all tested parameters do not appear to be injectable",
                                 "http://localhost/x") == []
