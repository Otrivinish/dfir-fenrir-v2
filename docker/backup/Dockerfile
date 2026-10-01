# DFIR-FENRIR v2 — backup sidecar: pg_dump (same Postgres 16 as the server) + age.
# The scripts are baked in (not bind-mounted): a single-file bind mount pins the
# old inode, so an edited script silently never reached the running container.
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

FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
COPY --from=age-build /out/age /usr/local/bin/age
COPY backup.sh scheduler.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/backup.sh /usr/local/bin/scheduler.sh
# Root only for the one-time /backups ownership fix; compose drops every capability
# except CHOWN + FSETID. See scheduler.sh.
ENTRYPOINT ["/bin/sh", "/usr/local/bin/scheduler.sh"]
