#!/bin/sh
# DFIR-FENRIR v2 — Caddy entrypoint: pick the TLS mode, then run the one Caddyfile.
#
# The config itself lives in /etc/caddy/Caddyfile (docker/caddy/Caddyfile.template).
# This script only exports the {$FENRIR_*} placeholders it references and never
# writes a file, so the container can run with a read-only root filesystem.
#
#   entrypoint.sh            → caddy run
#   entrypoint.sh validate   → caddy validate (used by tests; same mode logic)
#
# TLS_MODE (explicit is best; `auto` keeps older .env files working):
#   selfsigned  server.crt + server.key from generate-certs.sh
#   byo         your own certificate: TLS_CERT_FILE + TLS_KEY_FILE (files in ./certs)
#   acme        public DNS name → Let's Encrypt via HTTP-01/TLS-ALPN-01 (80+443 reachable)
#   duckdns     DuckDNS name   → Let's Encrypt via DNS-01 (needs DUCKDNS_TOKEN)
#   internal    Caddy's own self-signed CA (fallback)
#   auto        byo → duckdns → selfsigned → internal, first whose inputs exist.
#               (DuckDNS outranks stale generated certs, so configuring it takes effect.)
#
# Certificate files are NOT bind-mounted from ./certs (which also holds ca.crt):
# scripts/caddy-volume-prep.sh installs them into the caddy-config volume at
# /config/tls, owned by Caddy's uid with the key at 0400. A TLS_CERT_FILE /
# TLS_KEY_FILE written as /certs/<name> resolves to /config/tls/<name>.
#
# Every mode pins `protocols tls1.3` (TLS 1.3-only edge — user security baseline).
# The block MUST stay multi-line: Caddy rejects `{ protocols tls1.3 }` on one line.
set -eu

DOMAIN="${DOMAIN:-localhost}"
EMAIL="${LETSENCRYPT_EMAIL:-}"
TOKEN="${DUCKDNS_TOKEN:-}"
# The DuckDNS token is a secret file, not an environment variable.
[ -z "$TOKEN" ] && [ -s /run/secrets/duckdns_token ] && TOKEN="$(cat /run/secrets/duckdns_token)"
CERT_FILE="${TLS_CERT_FILE:-}"
KEY_FILE="${TLS_KEY_FILE:-}"
MODE="${TLS_MODE:-auto}"
CONFIG=/etc/caddy/Caddyfile
TLS_DIR=/config/tls
case "$CERT_FILE" in /certs/*) CERT_FILE="$TLS_DIR/${CERT_FILE#/certs/}";; esac
case "$KEY_FILE"  in /certs/*) KEY_FILE="$TLS_DIR/${KEY_FILE#/certs/}";;  esac

die() { echo "[caddy-entrypoint] ERROR: $*" >&2; exit 1; }

if [ "$MODE" = "auto" ]; then
    if   [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ]; then MODE=byo
    elif [ "$DOMAIN" != "localhost" ] && [ -n "$TOKEN" ] && [ -n "$EMAIL" ]; then MODE=duckdns
    elif [ -f "$TLS_DIR/server.crt" ] && [ -f "$TLS_DIR/server.key" ]; then MODE=selfsigned
    else MODE=internal; fi
fi

tls_block() {  # $1 = directive arguments, $2 = optional extra line inside the block
    printf 'tls %s {\n\t\tprotocols tls1.3\n%s\t}' "$1" "${2:+		$2
}"
}

FENRIR_GLOBAL_EMAIL=""
FENRIR_SITE_ADDR="$DOMAIN"            # only requests for DOMAIN are served
case "$MODE" in
    byo)
        [ -n "$CERT_FILE" ] && [ -n "$KEY_FILE" ] || die "TLS_MODE=byo needs TLS_CERT_FILE and TLS_KEY_FILE"
        [ -r "$CERT_FILE" ] && [ -r "$KEY_FILE" ] || die "TLS_MODE=byo: $CERT_FILE / $KEY_FILE not readable (run scripts/caddy-volume-prep.sh --apply)"
        FENRIR_TLS_BLOCK="$(tls_block "$CERT_FILE $KEY_FILE")" ;;
    selfsigned)
        [ -r "$TLS_DIR/server.crt" ] && [ -r "$TLS_DIR/server.key" ] || die "TLS_MODE=selfsigned needs $TLS_DIR/server.crt + .key (run ./generate-certs.sh, then scripts/caddy-volume-prep.sh --apply)"
        FENRIR_TLS_BLOCK="$(tls_block "$TLS_DIR/server.crt $TLS_DIR/server.key")" ;;
    acme)
        [ "$DOMAIN" != "localhost" ] && [ -n "$EMAIL" ] || die "TLS_MODE=acme needs a public DOMAIN and LETSENCRYPT_EMAIL"
        FENRIR_TLS_BLOCK="$(tls_block "$EMAIL")"
        FENRIR_GLOBAL_EMAIL="email $EMAIL" ;;
    duckdns)
        [ "$DOMAIN" != "localhost" ] && [ -n "$TOKEN" ] && [ -n "$EMAIL" ] || die "TLS_MODE=duckdns needs DOMAIN, LETSENCRYPT_EMAIL and DUCKDNS_TOKEN"
        FENRIR_TLS_BLOCK="$(tls_block "$EMAIL" "dns duckdns $TOKEN")"
        FENRIR_GLOBAL_EMAIL="email $EMAIL" ;;
    internal)
        FENRIR_TLS_BLOCK="$(tls_block internal)" ;;
    *)
        die "unknown TLS_MODE '$MODE' (selfsigned|byo|acme|duckdns|internal|auto)" ;;
esac
export FENRIR_GLOBAL_EMAIL FENRIR_SITE_ADDR FENRIR_TLS_BLOCK DOMAIN
echo "[caddy-entrypoint] TLS mode: $MODE (site: $FENRIR_SITE_ADDR, TLS 1.3 only)"

if [ "${1:-}" = "validate" ]; then
    exec caddy validate --config "$CONFIG" --adapter caddyfile
fi
exec caddy run --config "$CONFIG" --adapter caddyfile
