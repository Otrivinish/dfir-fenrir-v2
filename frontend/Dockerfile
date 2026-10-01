# ── Build the Vite SPA ─────────────────────────────────────────────────────
# Node 24 = active LTS (20 reached end-of-life 2026-04-30). Build stage only.
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# ── Serve the static dist via hardened, non-root nginx ─────────────────────
# nginx-unprivileged runs as uid 101 (nginx) and writes its pid/temp under
# /tmp + /var/cache/nginx, so it is compatible with a read_only rootfs +
# tmpfs mounts (see docker-compose.yml). It serves static files only and sets
# NO security headers — the edge Caddy owns TLS, CSP, HSTS, etc.
# nginx 1.30 = current stable line (1.27 reached end-of-life 2025-06).
FROM nginxinc/nginx-unprivileged:1.30-alpine@sha256:ed04ec1ff34502c339ee5c3ae3f855442398edc1d05591e2b98981dcbbd20b1e
COPY --chown=101:101 --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 3000
