"""Tests du tracing LangSmith : activation conditionnelle et no-op hors ligne."""
import os

import pytest

from redteam.config import Settings
from redteam.llm.backend import FeatherlessBackend, LLMResult
from redteam.monitoring.langsmith import activate_langsmith

LS_VARS = ("LANGSMITH_API_KEY", "LANGSMITH_TRACING", "LANGSMITH_PROJECT",
           "LANGCHAIN_TRACING_V2", "LANGCHAIN_PROJECT")


@pytest.fixture
def clean_env(monkeypatch):
    """Fait vivre le test dans une copie d'environnement sans variables LangSmith.

    `activate_langsmith` mute `os.environ` directement : substituer l'attribut
    par une copie garantit qu'aucune pollution ne subsiste entre tests.
    """
    monkeypatch.setattr(os, "environ", {
        k: v for k, v in os.environ.items() if k not in LS_VARS
    })


def test_activate_without_key_is_noop(clean_env):
    assert activate_langsmith(Settings()) is False
    # Aucune variable bascule : le PoC reste hors ligne.
    assert "LANGSMITH_TRACING" not in os.environ


def test_activate_with_key_sets_env_vars(clean_env):
    settings = Settings(langsmith_api_key="lsv2_pt_test", langsmith_project="redteam-ia")
    assert activate_langsmith(settings) is True
    assert os.environ["LANGSMITH_API_KEY"] == "lsv2_pt_test"
    assert os.environ["LANGSMITH_TRACING"] == "true"
    assert os.environ["LANGSMITH_PROJECT"] == "redteam-ia"


def test_activate_prefers_settings_key_over_env(clean_env):
    os.environ["LANGSMITH_API_KEY"] = "lsv2_pt_env"
    assert activate_langsmith(Settings(langsmith_api_key="lsv2_pt_settings")) is True
    assert os.environ["LANGSMITH_API_KEY"] == "lsv2_pt_settings"


def test_activate_without_project_keeps_default(clean_env):
    os.environ["LANGSMITH_PROJECT"] = "mon-projet"
    assert activate_langsmith(Settings(langsmith_api_key="lsv2_pt_x")) is True
    assert os.environ["LANGSMITH_PROJECT"] == "mon-projet"


class _FakeResponse:
    content = "réponse simulée"

    def __init__(self):
        self.usage_metadata = {"input_tokens": 7, "output_tokens": 2}


class _StubLLM:
    def invoke(self, messages):
        return _FakeResponse()


def test_featherless_backend_complete_passthrough_offline(clean_env):
    """Sans tracing actif, `traceable` est un no-op : le backend se comporte identiquement."""
    be = FeatherlessBackend(api_key="rc_x", base_url="http://localhost", model="m")
    be._llm = _StubLLM()
    out = be.complete("sys", "user")
    assert isinstance(out, LLMResult)
    assert out.text == "réponse simulée"
    assert out.tokens_in == 7
    assert out.tokens_out == 2
    assert out.model == "m"