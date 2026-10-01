# Pinned (supply chain): Caddy core + the DuckDNS DNS-01 plugin at exact versions.
# Bump all three together; see scripts/refresh-digests.sh for base-image digests.
FROM caddy:2.11.4-builder@sha256:369218c81ca6d6af249981221b3a5c764d886dd5b058f51d144066de13f2418d AS caddy-builder
# grpc is bumped past Caddy 2.11.4's own pin to clear High advisories
# (GHSA-2v4p-qf9q-27wj, GHSA-hrxh-6v49-42gf, GHSA-vp52-pcj8-j9qc); it pulls
# golang.org/x/text ≥ v0.41.0, which also clears GO-2026-5970. Do NOT pin x/text
# separately: a lower pin makes `go get` silently fall back to an older grpc.
# 2.11.4 is the latest Caddy release — drop the grpc line once Caddy ships it.
RUN xcaddy build v2.11.4 \
    --with github.com/caddy-dns/duckdns@v0.5.0 \
    --with google.golang.org/grpc@v1.83.2

# Caddy is a pure TLS-terminating reverse proxy. The SPA is served by the
# dedicated `frontend` container (nginx static); Caddy reverse-proxies to it.
FROM caddy:2.11.4-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b
COPY --from=caddy-builder /usr/bin/caddy /usr/bin/caddy
# The template IS the config (single source of truth; see entrypoint.sh).
COPY Caddyfile.template /etc/caddy/Caddyfile
COPY entrypoint.sh /entrypoint.sh
# Runs as uid 10001 with ALL capabilities dropped. The binary's file capability
# (cap_net_bind_service=ep) must go: with an empty bounding set, execve of a
# file-capability binary fails with EPERM. Binding 80/443 needs no capability —
# Docker sets net.ipv4.ip_unprivileged_port_start=0 in container namespaces.
RUN chmod +x /entrypoint.sh && setcap -r /usr/bin/caddy \
    && FENRIR_SITE_ADDR=localhost FENRIR_TLS_BLOCK="tls internal" \
       caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null   # fail the build on a Caddyfile syntax error
USER 10001:10001
ENTRYPOINT ["/entrypoint.sh"]
