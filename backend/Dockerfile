FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    zip \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Self-host API-docs assets (Swagger UI + ReDoc). Removes the runtime dependency
# on cdn.jsdelivr.net so the Caddy CSP can drop the external origin allowance,
# and avoids the upstream MIME-mismatch issue that nosniff rejects.
RUN mkdir -p /app/static \
    && curl -fsSL -o /app/static/redoc.standalone.js \
         https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js \
    && curl -fsSL -o /app/static/swagger-ui-bundle.js \
         https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui-bundle.js \
    && curl -fsSL -o /app/static/swagger-ui.css \
         https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/swagger-ui.css

# ── Velociraptor offline collectors (U1, ~150 MB) ───────────────────────────
# Bundle the Linux builder + a pre-warmed datastore holding the cached Windows
# binary tool, so RUNTIME generation repacks Windows collectors fully OFFLINE
# (no download), the way air-gapped Velociraptor servers work. Both binaries are
# version-pinned + SHA-256-verified (supply chain). Validated end-to-end against
# v0.76.6 in docs/u1-collector-spike.md. Keep VELOCIRAPTOR_VERSION here in sync
# with the backend's VELOCIRAPTOR_VERSION env (stamped on every package).
ARG VELOCIRAPTOR_VERSION=0.76.6
ARG VR_LINUX_SHA256=9b1c439834a562a96cbef886f26a93521d16b020fd96777fb30e01f88947af18
ARG VR_WINDOWS_SHA256=1e82175822aa9ffdfd7bc177599642f3db55159d0a2f38bb0fcc6722f15573cd
# macOS (Apple Silicon). Velociraptor can't repack Mach-O, so macOS packages
# ship a generic collector + this binary; no datastore warm-up is needed for it.
ARG VR_DARWIN_ARM_SHA256=4518998f95de31d4ee5734dfbcdd60f834c43a1b9fc6f9a1f372d8099172a496
RUN set -eu; mkdir -p /opt/velociraptor/datastore; cd /opt/velociraptor; \
    base="https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_VERSION}"; \
    curl -fsSL -o velociraptor-linux-amd64        "${base}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-amd64"; \
    curl -fsSL -o velociraptor-windows-amd64.exe  "${base}/velociraptor-v${VELOCIRAPTOR_VERSION}-windows-amd64.exe"; \
    curl -fsSL -o velociraptor-darwin-arm64       "${base}/velociraptor-v${VELOCIRAPTOR_VERSION}-darwin-arm64"; \
    echo "${VR_LINUX_SHA256}  velociraptor-linux-amd64"          | sha256sum -c -; \
    echo "${VR_WINDOWS_SHA256}  velociraptor-windows-amd64.exe"  | sha256sum -c -; \
    echo "${VR_DARWIN_ARM_SHA256}  velociraptor-darwin-arm64"    | sha256sum -c -; \
    chmod +x velociraptor-linux-amd64; \
    printf 'OS: Windows\nArtifacts:\n  Generic.Client.Info: {}\nTarget: ZIP\nOptCollectorTemplate: "warmup"\n' > /tmp/warm.yaml; \
    ./velociraptor-linux-amd64 --nobanner collector /tmp/warm.yaml --datastore /opt/velociraptor/datastore >/dev/null 2>&1; \
    rm -f /tmp/warm.yaml /opt/velociraptor/datastore/warmup; \
    ls /opt/velociraptor/datastore/public/* >/dev/null   # fail the build if the Windows tool wasn't cached

COPY . .

# Non-root user — same uid/storage layout as v1 so volumes are interchangeable.
RUN useradd -m -u 1001 fenrir && chown -R fenrir:fenrir /app \
    && mkdir -p /quarantine && chown fenrir:fenrir /quarantine \
    && mkdir -p /evidence && chown fenrir:fenrir /evidence \
    && mkdir -p /branding/incidents && chown -R fenrir:fenrir /branding \
    && mkdir -p /generated_reports && chown fenrir:fenrir /generated_reports \
    && mkdir -p /asset_logs && chown fenrir:fenrir /asset_logs \
    && mkdir -p /app/data && chown fenrir:fenrir /app/data \
    && chown -R fenrir:fenrir /opt/velociraptor
USER fenrir

EXPOSE 8000
# Single worker on purpose — bootstrap + audit seed must be serialised. Scale via
# horizontal replicas behind Caddy, not in-process workers.
# --proxy-headers + --forwarded-allow-ips: the backend only receives traffic from
# Caddy on the internal network, so trust X-Forwarded-For and rewrite request.client
# to the real client IP (audit logs, rate-limiting, etc. were recording Caddy's IP).
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips=*"]
