"""Génération du rapport d'audit en Markdown (findings confirmés + preuves)."""
from __future__ import annotations

from typing import Any

_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render_markdown(scope: Any, confirmed: list[dict], summary: str,
                    audit_bundle: dict | None, metrics: dict) -> str:
    lines: list[str] = ["# Rapport d'audit — Red Team IA", ""]
    if scope is not None:
        lines += [f"- **Mission :** {scope.mission}", f"- **Mandat :** {scope.mandate_ref}", ""]
    lines += [f"**Synthèse :** {summary}", ""]
    lines += ["## Métriques", ""]
    for k, v in metrics.items():
        lines.append(f"- **{k} :** {v}")
    lines.append("")
    if not confirmed:
        lines += ["## Aucun finding confirmé", "", "Aucune preuve reproductible sur le périmètre.", ""]
    else:
        lines += ["## Findings confirmés", ""]
        for v in sorted(confirmed, key=lambda x: _ORDER.get(x["finding"].severity.value, 9)):
            f = v["finding"]
            lines += [
                f"### [{f.severity.value.upper()}] {v['finding_id']} — {f.title}",
                "",
                f"- **Cible :** {f.target}",
                f"- **Confiance :** {v['confidence']:.2f}",
                f"- **Preuve :** {v['evidence']}",
                f"- **Remédiation ({f.remediation.reference}) :** {f.remediation.summary}",
                "",
            ]
    if audit_bundle is not None:
        lines += ["## Intégrité de l'audit", "",
                  f"- **Entrées journalisées :** {audit_bundle.get('count', 0)}",
                  f"- **Empreinte de fin :** {audit_bundle.get('tip_hash', '')}",
                  f"- **Statut :** {audit_bundle.get('integrity_status', 'n/a')}", ""]
    return "\n".join(lines) + "\n"
