# Rapport d'audit — Red Team IA

- **Mission :** Audit Red Team IA — cible Mirage (hackathon Neoloji)
- **Mandat :** HACKATHON-NEOLOJI-2026

**Synthèse :** L’audit confirme des expositions de fichiers/endpoints sensibles (haute criticité), des en-têtes de sécurité manquants et l’absence de limitation de débit observable (moyenne), ainsi qu’une divulgation de version logicielle et l’absence d’empreinte WAF détectée (faible) ; plusieurs constats informatifs portent sur la détection de technologies, de WAF, de SSH, de TLS, de llms.txt, d’adresses e-mail, d’Angular, de Nginx et des en-têtes HTTP.

## Métriques

- **run_id :** 20261008-082618
- **mode :** single
- **duration_s :** 1296.116
- **llm_calls :** 2
- **tokens_in :** 1078
- **tokens_out :** 4473
- **tool_calls :** 13
- **raw_count :** 20
- **confirmed_count :** 19
- **discarded_count :** 1
- **replans :** 0
- **errors :** 0

## Findings confirmés

### [HIGH] F4 — Fichiers/endpoints sensibles exposés

- **Cible :** https://hackathon.mirage-analytics.com/fr/auth/login
- **Confiance :** 1.00
- **Preuve :** accessibles (200) : /.git/config, /.env, /server-status, /phpinfo.php
- **Remédiation (OWASP — Sensitive Data Exposure) :** Bloquer l'accès public à ces chemins (403/404).

### [HIGH] F5 — Fichiers/endpoints sensibles exposés

- **Cible :** https://hackathon.mirage-analytics.com/fr/subscribe
- **Confiance :** 1.00
- **Preuve :** accessibles (200) : /.git/config, /.env, /server-status, /phpinfo.php
- **Remédiation (OWASP — Sensitive Data Exposure) :** Bloquer l'accès public à ces chemins (403/404).

### [HIGH] F6 — Fichiers/endpoints sensibles exposés

- **Cible :** https://hackathon.mirage-analytics.com/fr/app
- **Confiance :** 1.00
- **Preuve :** accessibles (200) : /.git/config, /.env, /server-status, /phpinfo.php
- **Remédiation (OWASP — Sensitive Data Exposure) :** Bloquer l'accès public à ces chemins (403/404).

### [MEDIUM] F1 — En-têtes de sécurité manquants

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** en-têtes manquants : strict-transport-security, content-security-policy, x-frame-options, x-content-type-options
- **Remédiation (OWASP Secure Headers Project) :** Ajouter HSTS, CSP, X-Frame-Options, X-Content-Type-Options.

### [MEDIUM] F2 — En-têtes de sécurité manquants

- **Cible :** https://hackathon.mirage-analytics.com/en/
- **Confiance :** 1.00
- **Preuve :** en-têtes manquants : strict-transport-security, content-security-policy, x-frame-options, x-content-type-options
- **Remédiation (OWASP Secure Headers Project) :** Ajouter HSTS, CSP, X-Frame-Options, X-Content-Type-Options.

### [MEDIUM] F7 — Aucune limitation de débit observable

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** Aucune limitation de débit observable; Aucune empreinte de WAF détectée
- **Remédiation (OWASP — Denial of Service Cheat Sheet) :** Appliquer une limitation de débit par IP/clé au niveau du proxy ou de l'application.

### [LOW] F3 — Divulgation de version logicielle

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** server: nginx/1.29.3
- **Remédiation (OWASP Testing Guide — Fingerprinting) :** Masquer les numéros de version dans les en-têtes.

### [LOW] F8 — Aucune empreinte de WAF détectée

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** Aucune limitation de débit observable; Aucune empreinte de WAF détectée
- **Remédiation (OWASP — Denial of Service Cheat Sheet) :** Placer un WAF/CDN devant le service pour absorber les pics de trafic malveillant.

### [INFO] F9 — WAF Detection [waf-detect]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (https://github.com/Ekultek/WhatWaf) :** Corriger selon le template nuclei.

### [INFO] F10 — SSH Auth Methods - Detection [ssh-auth-methods]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (https://nmap.org/nsedoc/scripts/ssh-auth-methods.html) :** Corriger selon le template nuclei.

### [INFO] F11 — SSH Server Software Enumeration [ssh-server-enumeration]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

### [INFO] F12 — SSH SHA-1 HMAC Algorithms Enabled [ssh-sha1-hmac-algo]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (https://forums.ivanti.com/s/article/How-to-disable-SSH-SHA-1-HMAC-algorithms?language=en_US) :** Corriger selon le template nuclei.

### [INFO] F13 — TLS Version - Detect [tls-version]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

### [INFO] F14 — llms.txt - Enumeration [llms-file-enum]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

### [INFO] F15 — Email Extractor [email-extractor]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

### [INFO] F16 — Angular detect [angular-detect]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (https://github.com/angular/angular) :** Corriger selon le template nuclei.

### [INFO] F17 — Nginx version detect [nginx-version]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

### [INFO] F19 — Wappalyzer Technology Detection [tech-detect]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

### [INFO] F20 — HTTP Missing Security Headers [http-missing-security-headers]

- **Cible :** https://hackathon.mirage-analytics.com/fr/
- **Confiance :** 1.00
- **Preuve :** nuclei: 11 résultat(s)
- **Remédiation (nuclei) :** Corriger selon le template nuclei.

