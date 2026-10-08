from redteam.agents.parsing import extract_json_list


def test_extract_clean_list():
    assert extract_json_list('[{"a": 1}]') == [{"a": 1}]


def test_extract_list_with_surrounding_text():
    text = 'Voici les hypothèses :\n[{"probe_id": "web.x"}]\nMerci.'
    assert extract_json_list(text) == [{"probe_id": "web.x"}]


def test_extract_garbage_returns_empty():
    assert extract_json_list("pas de json ici") == []
