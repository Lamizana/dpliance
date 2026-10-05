"""Enveloppe HTML minimale et lisible autour du rapport Markdown."""
from __future__ import annotations

import html


def render_html(markdown_text: str, title: str = "Rapport Red Team IA") -> str:
    body = html.escape(markdown_text)
    return (
        "<!doctype html><html lang='fr'><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto;"
        "padding:0 1rem;line-height:1.5}pre{white-space:pre-wrap;background:#f6f8fa;"
        "padding:1rem;border-radius:8px}</style></head>"
        f"<body><pre>{body}</pre></body></html>"
    )
