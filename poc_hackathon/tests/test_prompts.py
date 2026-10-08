"""Prompt recon généré depuis le registre : bornes, few-shot, pas de code mort.

Régression des axes P1 (audit/06-outils-et-prompts.md) :
- la liste des probe_id est dérivée de PROBES (pas de liste codée en dur) ;
- le prompt impose plafond + diversité des hypothèses ;
- il contient un exemple few-shot au format attendu ;
- SINGLE_SYSTEM / PLANNER_SYSTEM (code mort) n'existent plus.
"""

from redteam.agents import prompts
from redteam.agents.prompts import RECON_SYSTEM, build_recon_system
from redteam.tools.registry import PROBES


def test_recon_prompt_lists_every_registered_probe():
    for probe_id in PROBES:
        assert probe_id in RECON_SYSTEM, f"{probe_id} absent du prompt recon"


def test_recon_prompt_is_generated_from_registry():
    assert RECON_SYSTEM == build_recon_system()
    # Aucune liste de probe_id codée en dur ne doit subsister dans le prompt final :
    # le registre est la seule source de vérité.
    assert "tool.nuclei" in build_recon_system()  # tautologie protégée par le test ci-dessus


def test_recon_prompt_bounds_hypotheses():
    lower = RECON_SYSTEM.lower()
    assert "max 8" in lower, "plafond d'hypothèses absent"
    assert "one per probe" in lower or "1 per probe" in lower, "règle de diversité absente"


def test_recon_prompt_has_fewshot_example():
    # Exemple complet au format {probe_id, target, rationale}
    assert '"probe_id"' in RECON_SYSTEM, "gabarit JSON absent"
    assert "Example" in RECON_SYSTEM or "example" in RECON_SYSTEM, "few-shot absent"


def test_recon_prompt_forbids_invented_findings():
    lower = RECON_SYSTEM.lower()
    assert "do not invent" in lower or "never invent" in lower


def test_dead_prompts_removed():
    assert not hasattr(prompts, "SINGLE_SYSTEM"), "SINGLE_SYSTEM (code mort) toujours présent"
    assert not hasattr(prompts, "PLANNER_SYSTEM"), "PLANNER_SYSTEM (code mort) toujours présent"


def test_build_recon_system_tracks_registry_growth(monkeypatch):
    """Ajouter une sonde au registre l'ajoute automatiquement au prompt."""
    fake = dict(PROBES)
    fake["web.future_probe"] = object()
    monkeypatch.setitem(PROBES, "web.future_probe", fake["web.future_probe"])
    assert "web.future_probe" in build_recon_system()
