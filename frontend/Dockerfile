# ── Build the Vite SPA ─────────────────────────────────────────────────────
FROM node:20-alpine AS build
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
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY --chown=101:101 --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 3000
