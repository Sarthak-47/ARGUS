# Argus in a container — includes Semgrep (which has no native Windows build) and
# the dependency auditors, so the full static engine works out of the box.
#
#   docker build -t argus .
#   docker run --rm -v "$PWD:/src" argus scan /src --no-llm
#
# Mount the repo you want to scan at /src. For Phase-2 attacks against a running
# app, pass --network host (Linux) and: argus attack --url http://localhost:PORT
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Argus" \
      org.opencontainers.image.description="AI-powered security audit agent" \
      org.opencontainers.image.source="https://github.com/Sarthak-47/ARGUS"

# git is needed for repo ingestion + history scanning.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Install Argus plus the optional static-analysis tooling that works on Linux.
RUN pip install --no-cache-dir -e ".[semgrep,audit]"

# Non-root by default.
RUN useradd -m argus && chown -R argus:argus /app
USER argus

WORKDIR /src
ENTRYPOINT ["argus"]
CMD ["--help"]
