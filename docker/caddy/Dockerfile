FROM caddy:2-builder AS caddy-builder
RUN xcaddy build --with github.com/caddy-dns/duckdns

# Caddy is a pure TLS-terminating reverse proxy. The SPA is served by the
# dedicated `frontend` container (nginx static); Caddy reverse-proxies to it.
FROM caddy:2-alpine
COPY --from=caddy-builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile.template /etc/caddy/Caddyfile.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
