# ── age, built from source ────────────────────────────────────────────────────
# Distro age packages lag on Go / x/crypto security fixes (Debian's was built with
# go1.24.4), so build a pinned release with a current toolchain + x/crypto. Module
# downloads are verified against sum.golang.org. Bump AGE_VERSION / XCRYPTO_VERSION
# with the same 14-day cooldown as the Python deps.
FROM golang:1.26.8-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS age-build
ARG AGE_VERSION=v1.3.2
ARG XCRYPTO_VERSION=v0.57.0
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
WORKDIR /src
RUN go mod init agebuild \
    && go get filippo.io/age/cmd/age@${AGE_VERSION} golang.org/x/crypto@${XCRYPTO_VERSION} \
    && go build -ldflags "-s -w" -o /out/age filippo.io/age/cmd/age \
    && /out/age --version

# ── Stage 1: fetch + verify build-time downloads (never shipped) ─────────────
# Everything that needs the network or download tooling (curl, gnupg) happens
# here; the runtime stage below copies only the verified results.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS fetch
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# PGDG apt signing key, pinned by fingerprint (used by the runtime stage's apt).
ARG PGDG_KEY_FPR=B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
RUN curl -fsSL -o /tmp/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && gpg --show-keys --with-colons /tmp/apt.postgresql.org.asc | grep -q "^fpr:::::::::${PGDG_KEY_FPR}:"

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
WORKDIR /opt/velociraptor
RUN set -eu; mkdir -p /opt/velociraptor/datastore; \
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

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

WORKDIR /app

# libmagic1: MIME detection. postgresql-client-16 comes from the official PGDG
# repo so the manual-backup pg_dump MATCHES the postgres:16 server — Debian
# trixie's own client is 17, whose dumps emit `SET transaction_timeout`, which a
# 16 server rejects, so scripts/restore.sh (ON_ERROR_STOP=1) could not restore
# any manual backup. The repo key was fingerprint-verified in the fetch stage.
# `apt-get upgrade`: the base digest is pinned and upstream image rebuilds lag
# Debian security fixes (OpenSSL, PCRE2), so a --no-cache rebuild takes them.
COPY --from=fetch /tmp/apt.postgresql.org.asc /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
RUN . /etc/os-release \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" \
         > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
         libmagic1 \
         postgresql-client-16 \
    && rm -rf /var/lib/apt/lists/*

# Hash-locked install: every artifact must match requirements.lock, generated from
# requirements.txt + constraints.txt by scripts/lock-python.sh (`make lock`).
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY --from=fetch /opt/velociraptor /opt/velociraptor
# age: encrypts manual DB dumps to BACKUP_AGE_RECIPIENT (public key only).
COPY --from=age-build /out/age /usr/local/bin/age

# App code. Includes static/ — the Swagger UI + ReDoc assets, vendored from the
# npm registry (sha512-verified; see static/SHA256SUMS), so neither the build nor
# the browser needs cdn.jsdelivr.net.
COPY . .
WORKDIR /app/static
RUN sha256sum -c SHA256SUMS
WORKDIR /app

# Non-root user — same uid/storage layout as v1 so volumes are interchangeable.
# Only the data mount points belong to the app user; the code (/app) and the
# Velociraptor binaries + datastore (/opt/velociraptor) stay root-owned, so a
# compromised process cannot rewrite them (the rootfs is read-only in compose too;
# collector builds use a per-build scratch copy of the datastore).
RUN useradd -m -u 1001 fenrir \
    && mkdir -p /quarantine && chown fenrir:fenrir /quarantine \
    && mkdir -p /evidence && chown fenrir:fenrir /evidence \
    && mkdir -p /branding/incidents && chown -R fenrir:fenrir /branding \
    && mkdir -p /generated_reports && chown fenrir:fenrir /generated_reports \
    && mkdir -p /asset_logs && chown fenrir:fenrir /asset_logs \
    && mkdir -p /app/data && chown fenrir:fenrir /app/data \
    && chown -R root:fenrir /opt/velociraptor && chmod -R u=rwX,g=rX,o= /opt/velociraptor
USER 1001:1001

EXPOSE 8000
# Single worker on purpose — bootstrap + audit seed must be serialised. Scale via
# horizontal replicas behind Caddy, not in-process workers.
# --proxy-headers rewrites request.client to the real client IP from X-Forwarded-For
# (audit logs, rate limiting) — but ONLY for peers in FORWARDED_ALLOW_IPS, which
# compose pins to Caddy's address. Never `*`: any container could then forge its IP.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers"]
