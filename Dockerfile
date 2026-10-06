# Image d'audit « outils réels » : Debian + nuclei / nmap / sqlmap + le PoC redteam-ia.
# Les adaptateurs détectent l'absence d'un binaire et se sautent proprement ; cette image
# fournit les trois outils pour une couverture complète.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# Outils système : nmap, sqlmap, git + CA, et de quoi récupérer nuclei.
# Python n'est pas installé via apt : uv fournit un interpréteur géré et isolé
# (épinglé par .python-version), ce qui évite tout conflit avec le Python système.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        sqlmap \
        ca-certificates \
        curl \
        unzip \
        git \
    && rm -rf /var/lib/apt/lists/*

# uv : gestionnaire de paquets/environnement (binaire statique depuis l'image officielle).
COPY --from=ghcr.io/astral-sh/uv:0.8.16 /uv /uvx /bin/

# nuclei : binaire précompilé depuis les releases GitHub (évite la toolchain Go ;
# le Go de Debian bookworm est trop ancien pour `go install nuclei@latest`).
# Détection d'architecture (amd64/arm64) + dernière version publiée.
RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    VER="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep -o '"tag_name": *"v[^"]*"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')"; \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${VER}/nuclei_${VER}_linux_${ARCH}.zip" -o /tmp/nuclei.zip; \
    unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin; \
    chmod +x /usr/local/bin/nuclei; \
    rm /tmp/nuclei.zip; \
    nuclei -version

# Pré-embarquer la base de templates au build (sinon nuclei la télécharge au 1er run
# et dépasse le timeout de l'adaptateur). Non bloquant si le fetch échoue.
RUN nuclei -update-templates 2>&1 | tail -3 || echo "prefetch templates échoué — fallback runtime"

WORKDIR /app

# Environnement reproductible : uv crée un venv et installe EXACTEMENT ce que fige
# uv.lock (--frozen échoue si le lock est périmé). Les dépendances sont installées
# avant le code source pour garder la couche en cache tant que le lock ne change pas.
ENV UV_LINK_MODE=copy \
    UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    UV_PROJECT_ENVIRONMENT=/app/.venv
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-install-project

COPY . /app
RUN uv sync --frozen

# Le venv uv en tête de PATH : « redteam » et les outils (pytest, ruff) sont dispo directement.
ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["redteam"]
