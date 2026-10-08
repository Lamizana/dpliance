je veux des slides, dabord lui demander en html puis en pdf slide


## Problemes

- La boucle replan est vide à 100 % : les 2 runs crew ont fait strategy_change → "0 étapes dans le périmètre" (_replan_node n'ajoute aucune nouvelle hypothèse, il incrémente un compteur). Le LLM n'est jamais rappelé avec un feedback → l'adaptabilité promise ne fonctionne pas.

- Pas de température / max_tokens par rôle, MODEL_CATALOG mono-modèle, aucune langue imposée aux rationales (anglais dans les traces, rapport FR).


- PLANNER_SYSTEM et SINGLE_SYSTEM sont du code mort — définis dans prompts.py:14,24, jamais importés (nodes.py n'utilise que RECON_SYSTEM + REPORTER_SYSTEM). Le mode single passe par recon_node → RECON_SYSTEM.