# Rapport d'audit — Red Team IA

- **Mission :** Audit Red Team IA — cible Mirage (hackathon Neoloji)
- **Mandat :** HACKATHON-NEOLOJI-2026

**Synthèse :** Les en-têtes de sécurité sont manquants, la version logicielle est divulguée et des fichiers ou endpoints sensibles sont exposés.

## Métriques

- **run_id :** 20261008-095139
- **mode :** crew
- **duration_s :** 359.79
- **llm_calls :** 2
- **tokens_in :** 767
- **tokens_out :** 216
- **tool_calls :** 5
- **raw_count :** 3
- **confirmed_count :** 3
- **discarded_count :** 0
- **replans :** 1
- **errors :** 0

## Findings confirmés

### [HIGH] F3 — Fichiers/endpoints sensibles exposés

- **Cible :** https://hackathon.mirage-analytics.com/fr/auth/login
- **Confiance :** 1.00
- **Preuve :** accessibles (200) : /.git/config, /.env, /server-status, /phpinfo.php
- **Remédiation (OWASP — Sensitive Data Exposure) :** Bloquer l'accès public à ces chemins (403/404).

### [MEDIUM] F1 — En-têtes de sécurité manquants

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** en-têtes manquants : strict-transport-security, content-security-policy, x-frame-options, x-content-type-options
- **Remédiation (OWASP Secure Headers Project) :** Ajouter HSTS, CSP, X-Frame-Options, X-Content-Type-Options.

### [LOW] F2 — Divulgation de version logicielle

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** server: nginx/1.29.3
- **Remédiation (OWASP Testing Guide — Fingerprinting) :** Masquer les numéros de version dans les en-têtes.

