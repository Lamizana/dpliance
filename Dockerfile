# Image d'audit « outils réels » : Debian + nuclei / nmap / sqlmap + le PoC redteam-ia.
# Les adaptateurs détectent l'absence d'un binaire et se sautent proprement ; cette image
# fournit les trois outils pour une couverture complète.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# Outils système : Python, nmap, sqlmap, Go (pour installer nuclei), git + CA.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        nmap \
        sqlmap \
        golang-go \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# nuclei : installé via `go install` directement dans /usr/local/bin (sur le PATH).
RUN GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

WORKDIR /app
COPY . /app

# Debian bookworm marque son Python « externally managed » ; --break-system-packages
# est attendu pour une image dédiée et jetable.
RUN pip install --break-system-packages -e ".[dev]"

ENTRYPOINT ["redteam"]
