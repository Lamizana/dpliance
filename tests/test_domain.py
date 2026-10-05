from redteam.safety.domain import Intensity, Severity, Finding, Remediation


def test_intensity_rank_orders_passive_below_intrusive():
    assert Intensity.PASSIVE.rank < Intensity.ACTIVE.rank < Intensity.INTRUSIVE.rank


def test_finding_roundtrips():
    f = Finding(module_id="m", target="t", severity=Severity.HIGH, title="x",
                evidence="e", remediation=Remediation(summary="s", reference="r"))
    assert f.severity is Severity.HIGH
