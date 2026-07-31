# Dockerfile — Orion v2.0 node image (workers + master share it)
#
# Stage 1 builds the Go security tools; stage 2 is a slim Python runtime that
# copies those binaries in. Keeps the final image lean while still shipping the
# real toolchain the workers execute.

# ---- stage 1: build the Go tools ------------------------------------------- #
FROM golang:1.24-bookworm AS tools
ENV GOBIN=/out
RUN mkdir -p /out && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/hahwul/dalfox/v2@latest

# ---- stage 2: python runtime ----------------------------------------------- #
FROM python:3.12-slim-bookworm

# masscan from Debian repos; ca-certificates for TLS.
RUN apt-get update && \
    apt-get install -y --no-install-recommends masscan ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Go tool binaries.
COPY --from=tools /out/ /usr/local/bin/

WORKDIR /app
COPY requirements.txt pyproject.toml README.md ./
COPY orion ./orion
RUN pip install --no-cache-dir -r requirements.txt redis>=5.0 && \
    pip install --no-cache-dir -e .

# Refresh nuclei templates at build time so workers start ready.
RUN nuclei -update-templates || true

# Non-root runtime user (defence in depth).
RUN useradd -m orion
USER orion

ENTRYPOINT []
CMD ["orion-worker", "--help"]
