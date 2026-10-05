from redteam.safety.domain import Finding, Severity, Remediation
from redteam.report.markdown import render_markdown


def _conf():
    f = Finding(module_id="web.security_headers", target="http://localhost/",
                severity=Severity.MEDIUM, title="En-têtes manquants", evidence="HSTS absent",
                remediation=Remediation(summary="ajouter HSTS", reference="OWASP"))
    return [{"finding": f, "status": "confirmed", "confidence": 0.85,
             "evidence": "HSTS absent", "finding_id": "F1"}]


def test_markdown_lists_confirmed_finding():
    md = render_markdown(scope=None, confirmed=_conf(), summary="résumé",
                         audit_bundle=None, metrics={"duration_s": 1.2})
    assert "En-têtes manquants" in md and "F1" in md and "0.85" in md
