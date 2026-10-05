from redteam.safety.signing import HmacSigner


def test_sign_verify_roundtrip():
    s = HmacSigner(b"k")
    sig = s.sign(b"hello")
    assert s.verify(b"hello", sig)
    assert not s.verify(b"tampered", sig)
