#!/bin/sh
set -e

DOMAIN="${DOMAIN:-localhost}"
EMAIL="${LETSENCRYPT_EMAIL:-}"
TOKEN="${DUCKDNS_TOKEN:-}"
CERT_FILE="${TLS_CERT_FILE:-}"
KEY_FILE="${TLS_KEY_FILE:-}"
OUTPUT="/etc/caddy/Caddyfile"

# TLS mode priority:
#   1. BYO cert     — TLS_CERT_FILE + TLS_KEY_FILE explicitly set
#   2. Auto-gen     — /certs/server.crt + /certs/server.key exist (from generate-certs.sh)
#   3. DuckDNS      — DOMAIN (not localhost) + LETSENCRYPT_EMAIL + DUCKDNS_TOKEN all set
#   4. Internal     — Caddy's built-in self-signed CA (fallback)

if [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ]; then
    SITE_ADDR=":443"
    TLS_BLOCK="    tls $CERT_FILE $KEY_FILE"
    GLOBAL_EMAIL=""
    echo "[caddy-entrypoint] TLS mode: BYO certificate ($CERT_FILE)"
elif [ -f "/certs/server.crt" ] && [ -f "/certs/server.key" ]; then
    SITE_ADDR=":443"
    TLS_BLOCK="    tls /certs/server.crt /certs/server.key"
    GLOBAL_EMAIL=""
    echo "[caddy-entrypoint] TLS mode: generated certificate (/certs/server.crt)"
elif [ "$DOMAIN" != "localhost" ] && [ -n "$TOKEN" ] && [ -n "$EMAIL" ]; then
    SITE_ADDR="$DOMAIN"
    TLS_BLOCK="    tls $EMAIL {
        dns duckdns $TOKEN
    }"
    GLOBAL_EMAIL="    email $EMAIL"
    echo "[caddy-entrypoint] TLS mode: Let's Encrypt via DuckDNS DNS-01 for $DOMAIN"
else
    SITE_ADDR="$DOMAIN"
    TLS_BLOCK="    tls internal"
    GLOBAL_EMAIL=""
    echo "[caddy-entrypoint] TLS mode: internal self-signed CA (domain: $DOMAIN)"
fi

cat > "$OUTPUT" << CADDYEOF
{
$GLOBAL_EMAIL
}

$SITE_ADDR {

$TLS_BLOCK

    @notdocs not path /api/docs* /api/redoc*

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Resource-Policy "same-origin"
        Permissions-Policy "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()"
        -Server
    }

    # SPA CSP — no CDNs, no remote scripts. \`'unsafe-inline'\` on style-src only
    # (React/Vite injects style attributes; removing it requires build-time nonces).
    # frame-src 'self' — Admin → API Docs iframes same-origin /api/docs.
    header @notdocs Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss: ws:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; frame-src 'self'; worker-src 'self' blob:; manifest-src 'self'; upgrade-insecure-requests"

    handle /api/docs* {
        # API-docs assets are self-hosted under /api/_static/ — no CDN origins needed.
        # 'unsafe-inline' stays because the FastAPI helpers emit inline <script>/<style>.
        header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
        reverse_proxy backend:8000
    }
    handle /api/redoc* {
        header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
        reverse_proxy backend:8000
    }
    handle /api/openapi.json {
        reverse_proxy backend:8000
    }

    handle /api/warroom/ws/* {
        reverse_proxy backend:8000 {
            flush_interval -1
        }
    }
    handle /api/notifications/ws {
        reverse_proxy backend:8000 {
            flush_interval -1
        }
    }

    handle /api/* {
        reverse_proxy backend:8000
    }

    handle /download/* {
        reverse_proxy backend:8000
    }

    handle {
        reverse_proxy frontend:3000
    }

    log {
        output file /data/caddy-access.log {
            roll_size 100mb
            roll_keep 5
        }
        format json
    }
}

:80 {
    redir https://{host}{uri} permanent
}
CADDYEOF

exec caddy run --config "$OUTPUT" --adapter caddyfile
