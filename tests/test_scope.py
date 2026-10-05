import datetime
import pytest
import yaml

from redteam.safety.domain import Intensity
from redteam.safety.signing import HmacSigner
from redteam.safety.scope import load_scope, compute_signature, ScopeSignatureError

KEY = HmacSigner(b"test-key")


def _scope_dict():
    return {
        "mission": "Audit Mirage", "mandate_ref": "REF-1", "client_contact": "x@d.fr",
        "authorized": {"domains": ["localhost", "*.mirage.local"], "ips": ["127.0.0.1/32"]},
        "excluded": ["admin.mirage.local"],
        "window": {"start": "2026-10-01", "end": "2026-12-31"},
        "allowed_intensity": "active", "sandbox": {},
    }


def _write_signed(tmp_path):
    data = _scope_dict()
    data["signature"] = compute_signature(data, signer=KEY)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


def test_load_valid_scope(tmp_path):
    scope = load_scope(str(_write_signed(tmp_path)), signer=KEY)
    assert scope.allowed_intensity is Intensity.ACTIVE
    assert scope.window.end == datetime.date(2026, 12, 31)


def test_tampered_scope_rejected(tmp_path):
    p = _write_signed(tmp_path)
    data = yaml.safe_load(p.read_text())
    data["authorized"]["domains"].append("victim.example")
    p.write_text(yaml.safe_dump(data))
    with pytest.raises(ScopeSignatureError):
        load_scope(str(p), signer=KEY)
