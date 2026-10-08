from redteam.llm.backend import MockBackend


def test_mock_backend_returns_configured_response():
    be = MockBackend(responses={"recon": "surface analysée"}, default="[mock]")
    out = be.complete("sys", "recon de la cible")
    assert out.text == "surface analysée"
    assert out.model == "mock"


def test_mock_backend_default():
    be = MockBackend()
    assert be.complete("s", "inconnu").text == "[mock]"
