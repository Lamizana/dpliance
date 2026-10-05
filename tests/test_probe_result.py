from redteam.safety.domain import Finding, Severity, Remediation
from redteam.tools.probes.base import ProbeResult


def _f(title):
    return Finding(module_id="m", target="t", severity=Severity.LOW, title=title,
                   evidence="e", remediation=Remediation(summary="s", reference="r"))


def test_all_findings_prefers_list():
    r = ProbeResult(found=True, evidence="x", findings=[_f("a"), _f("b")])
    assert [f.title for f in r.all_findings()] == ["a", "b"]


def test_all_findings_falls_back_to_single():
    r = ProbeResult(found=True, evidence="x", finding=_f("solo"))
    assert [f.title for f in r.all_findings()] == ["solo"]


def test_all_findings_empty_when_nothing():
    assert ProbeResult(found=False, evidence="x").all_findings() == []
