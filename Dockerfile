# Sn1per MCP Server - introspection image.
#
# Introspection and read-only use. This image does not contain Sn1per and cannot scan.
#
# It starts the MCP server over stdio so that a client or a directory can run
# `initialize` and `tools/list`; the scan tools refuse with `scan_disabled`.
#   docker build -t sn1per-mcp:0.9.0 .
#   docker run -i --rm sn1per-mcp:0.9.0
# To use the server with a real Sn1per install, run it on the Sn1per host or follow
# the recipes in docs/remote.md. No image is published.

# python:3.13-slim, multi-arch index digest pinned on 2026-10-12.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f

LABEL org.opencontainers.image.title="Sn1per MCP Server" \
      org.opencontainers.image.description="Run scoped, authorized Sn1per pentest, recon and attack surface scans from AI agents; read findings." \
      org.opencontainers.image.version="0.9.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/1N3/sn1per-mcp" \
      io.modelcontextprotocol.server.name="com.sn1persecurity/sn1per-mcp"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY pyproject.toml README.md LICENSE NOTICE MANIFEST.in /build/
COPY src /build/src
RUN pip install --no-cache-dir /build \
    && mkdir -p /usr/share/doc/sn1per-mcp \
    && cp /build/LICENSE /build/NOTICE /usr/share/doc/sn1per-mcp/ \
    && rm -rf /build \
    && groupadd --gid 10001 sn1per-mcp \
    && useradd --uid 10001 --gid 10001 --home-dir /app --create-home \
       --shell /usr/sbin/nologin sn1per-mcp \
    && chmod 0700 /app

USER 10001:10001
WORKDIR /app
ENV HOME=/app \
    SNIPER_SCAN_ENABLED=false

ENTRYPOINT ["sn1per-mcp"]
