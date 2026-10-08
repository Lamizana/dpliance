# Rapport d'audit — Red Team IA

- **Mission :** Audit Red Team IA — cible Mirage (hackathon Neoloji)
- **Mandat :** HACKATHON-NEOLOJI-2026

**Synthèse :** L'audit révèle l'absence d'en-têtes de sécurité et de toute limitation de débit observable, ainsi que la divulgation de la version logicielle. Aucune empreinte de WAF n'a été détectée, tandis que les informations relatives à SSH, aux algorithmes SHA-1 HMAC, à la version TLS et aux en-têtes HTTP manquants ont été signalées.

## Métriques

- **run_id :** 20261008-093445
- **mode :** single
- **duration_s :** 1014.088
- **llm_calls :** 2
- **tokens_in :** 876
- **tokens_out :** 378
- **tool_calls :** 7
- **raw_count :** 13
- **confirmed_count :** 10
- **discarded_count :** 3
- **replans :** 0
- **errors :** 0

## Findings confirmés

### [MEDIUM] F1 — En-têtes de sécurité manquants

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** en-têtes manquants : strict-transport-security, content-security-policy, x-frame-options, x-content-type-options
- **Remédiation (OWASP Secure Headers Project) :** Ajouter HSTS, CSP, X-Frame-Options, X-Content-Type-Options.

### [MEDIUM] F3 — Aucune limitation de débit observable

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** Aucune limitation de débit observable; Aucune empreinte de WAF détectée
- **Remédiation (OWASP — Denial of Service Cheat Sheet) :** Appliquer une limitation de débit par IP/clé au niveau du proxy ou de l'application.

### [LOW] F2 — Divulgation de version logicielle

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** server: nginx/1.29.3
- **Remédiation (OWASP Testing Guide — Fingerprinting) :** Masquer les numéros de version dans les en-têtes.

### [LOW] F4 — Aucune empreinte de WAF détectée

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** Aucune limitation de débit observable; Aucune empreinte de WAF détectée
- **Remédiation (OWASP — Denial of Service Cheat Sheet) :** Placer un WAF/CDN devant le service pour absorber les pics de trafic malveillant.

### [INFO] F5 — WAF Detection [waf-detect]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 10 résultat(s)
- **Remédiation (https://github.com/Ekultek/WhatWaf) :** Corriger selon le template nuclei.

### [INFO] F6 — SSH Auth Methods - Detection [ssh-auth-methods]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 10 résultat(s)
- **Remédiation (https://nmap.org/nsedoc/scripts/ssh-auth-methods.html) :** Corriger selon le template nuclei.

### [INFO] F7 — SSH SHA-1 HMAC Algorithms Enabled [ssh-sha1-hmac-algo]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 10 résultat(s)
- **Remédiation (https://forums.ivanti.com/s/article/How-to-disable-SSH-SHA-1-HMAC-algorithms?language=en_US) :** Corriger selon le template nuclei.

### [INFO] F8 — SSH Server Software Enumeration [ssh-server-enumeration]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 10 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

### [INFO] F9 — TLS Version - Detect [tls-version]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 10 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

### [INFO] F13 — HTTP Missing Security Headers [http-missing-security-headers]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 10 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

