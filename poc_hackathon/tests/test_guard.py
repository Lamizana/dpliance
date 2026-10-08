import datetime
import pytest

from redteam.safety.domain import Intensity
from redteam.safety.guard import ScopeGuard, ScopeViolation
from redteam.safety.scope import Scope, Authorized, Window

TODAY = datetime.date(2026, 11, 1)


def _guard(**over):
    scope = Scope(
        mission="m", mandate_ref="r", client_contact="c",
        authorized=Authorized(domains=["localhost"], ips=["127.0.0.1/32"]),
        excluded=over.get("excluded", []),
        window=Window(start=datetime.date(2026, 10, 1), end=datetime.date(2026, 12, 31)),
        allowed_intensity=over.get("intensity", Intensity.ACTIVE), signature="x",
    )
    return ScopeGuard(scope, today=TODAY)


def test_in_scope_allowed():
    assert _guard().check("http://localhost/x", Intensity.PASSIVE).allowed


def test_out_of_scope_refused():
    assert not _guard().check("http://evil.example/x", Intensity.PASSIVE).allowed


def test_excluded_refused():
    g = _guard(excluded=["localhost"])
    assert not g.check("http://localhost/x", Intensity.PASSIVE).allowed


def test_intensity_ceiling():
    assert not _guard().check("http://localhost", Intensity.INTRUSIVE).allowed


def test_authorize_raises_out_of_scope():
    with pytest.raises(ScopeViolation):
        _guard().authorize("http://evil.example", Intensity.PASSIVE)
