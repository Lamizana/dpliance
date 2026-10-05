from redteam.config import load_settings


def test_load_settings_from_env(monkeypatch):
    monkeypatch.setenv("FEATHERLESS_API_KEY", "rc_x")
    monkeypatch.setenv("MIRAGE_TARGET", "http://localhost:8080")
    s = load_settings()
    assert s.featherless_api_key == "rc_x"
    assert s.target == "http://localhost:8080"
    assert s.model  # a une valeur par défaut
