#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# DFIR-FENRIR v2 — Generate self-signed TLS certificates
#
# Creates a local CA and server certificate with SANs for your DOMAIN.
# Run this ONCE before "docker compose up" when using self-signed mode.
#
# Usage:
#   ./generate-certs.sh                  # reads DOMAIN from .env (default: localhost)
#   ./generate-certs.sh 192.168.0.1    # override with IP or hostname
#   ./generate-certs.sh --migrate-only   # only move a legacy certs/ca.key → ca/ca.key
#
# Output:
#   certs/ca.crt          ← Import this into your browser to trust FENRIR
#   ca/ca.key             ← CA private key — in ./ca (mode 700), NEVER mounted into
#                           any container. (Legacy certs/ca.key is moved there: the
#                           ./certs dir is mounted into the internet-facing Caddy.)
#   certs/server.crt      ← Server certificate (used by Caddy)
#   certs/server.key      ← Server private key (used by Caddy)
#
# After running, start FENRIR normally:
#   docker compose up -d --build
#
# Caddy will detect certs/server.crt and use it automatically.
# ─────────────────────────────────────────────────────────────────────────────
set -e

CERT_DIR="$(cd "$(dirname "$0")" && pwd)/certs"
CA_DIR="$(cd "$(dirname "$0")" && pwd)/ca"
CA_CERT="$CERT_DIR/ca.crt"
CA_KEY="$CA_DIR/ca.key"
SRV_CERT="$CERT_DIR/server.crt"
SRV_KEY="$CERT_DIR/server.key"
DAYS_CA=3650      # CA valid for 10 years
DAYS_SRV=825      # Server cert valid for ~2 years (max browser trust)

# ── Keep the CA private key out of ./certs (idempotent migration) ────────────
mkdir -p "$CA_DIR" && chmod 700 "$CA_DIR"
if [ -f "$CERT_DIR/ca.key" ] && [ -f "$CA_KEY" ]; then
    echo "ERROR: both certs/ca.key and ca/ca.key exist — keep the one that signed certs/ca.crt, remove the other." >&2
    exit 1
elif [ -f "$CERT_DIR/ca.key" ]; then
    mv "$CERT_DIR/ca.key" "$CA_KEY" && chmod 600 "$CA_KEY"
    echo "  [migrate] moved CA private key certs/ca.key → ca/ca.key (never mounted into a container)"
fi
rm -f "$CERT_DIR/ca.srl"
[ "${1:-}" = "--migrate-only" ] && exit 0

# ── Determine domain / IP ────────────────────────────────────────────────────
if [ -n "${1:-}" ]; then
    DOMAIN="$1"
elif [ -f "$(dirname "$0")/.env" ]; then
    DOMAIN=$(grep -E "^DOMAIN=" "$(dirname "$0")/.env" | cut -d= -f2 | tr -d '[:space:]"'"'" || echo "localhost")
    [ -z "$DOMAIN" ] && DOMAIN="localhost"
else
    DOMAIN="localhost"
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  DFIR-FENRIR v2 — TLS Certificate Generator                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Domain/IP: $DOMAIN"
echo "  Output:    $CERT_DIR/"
echo ""

mkdir -p "$CERT_DIR"

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl is required but not installed."
    echo "  Ubuntu/Debian: sudo apt install -y openssl"
    echo "  Alpine:        apk add openssl"
    exit 1
fi

if [ -f "$CA_CERT" ] && [ -f "$CA_KEY" ]; then
    echo "  [skip] CA already exists — reusing $CA_CERT"
else
    echo "  [1/4] Generating CA private key..."
    openssl ecparam -genkey -name prime256v1 -out "$CA_KEY" 2>/dev/null

    echo "  [2/4] Generating CA certificate..."
    # nameConstraints: this CA gets imported into analysts' browsers, so limit
    # what it can ever vouch for — the FENRIR name, localhost and private-range
    # IPs — so a stolen CA key cannot mint trusted certs for any other site.
    NC="critical,permitted;DNS:localhost,permitted;IP:127.0.0.0/255.0.0.0"
    NC="$NC,permitted;IP:10.0.0.0/255.0.0.0,permitted;IP:172.16.0.0/255.240.0.0,permitted;IP:192.168.0.0/255.255.0.0"
    if ! echo "$DOMAIN" | grep -qE '^[0-9.]+$' && [ "$DOMAIN" != "localhost" ]; then NC="$NC,permitted;DNS:$DOMAIN"; fi
    openssl req -new -x509 -sha256 -key "$CA_KEY" -out "$CA_CERT" -days $DAYS_CA \
        -subj "/C=XX/O=DFIR-FENRIR/CN=FENRIR Local CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "nameConstraints=$NC" 2>/dev/null
fi

SAN="DNS:localhost,IP:127.0.0.1"

if echo "$DOMAIN" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    SAN="$SAN,IP:$DOMAIN"
elif [ "$DOMAIN" != "localhost" ]; then
    SAN="$SAN,DNS:$DOMAIN"
fi

LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
if [ -n "$LAN_IP" ] && [ "$LAN_IP" != "127.0.0.1" ]; then
    if ! echo "$SAN" | grep -q "$LAN_IP"; then
        SAN="$SAN,IP:$LAN_IP"
        echo "  [info] Auto-detected LAN IP: $LAN_IP (added to certificate)"
    fi
fi

echo "  [info] SANs: $SAN"

echo "  [3/4] Generating server private key and CSR..."
openssl ecparam -genkey -name prime256v1 -out "$SRV_KEY" 2>/dev/null

openssl req -new -sha256 -key "$SRV_KEY" \
    -subj "/C=XX/O=DFIR-FENRIR/CN=$DOMAIN" \
    -out "$CERT_DIR/server.csr" 2>/dev/null

echo "  [4/4] Signing server certificate with CA..."
openssl x509 -req -sha256 \
    -in "$CERT_DIR/server.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAserial "$CA_DIR/ca.srl" -CAcreateserial \
    -out "$SRV_CERT" -days $DAYS_SRV \
    -extfile <(printf "subjectAltName=$SAN\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") \
    2>/dev/null

rm -f "$CERT_DIR/server.csr" "$CA_DIR/ca.srl"

chmod 600 "$CA_KEY" "$SRV_KEY"
chmod 700 "$CERT_DIR"      # owner-only; Caddy gets its copy via scripts/caddy-volume-prep.sh
chmod 644 "$CA_CERT" "$SRV_CERT"

echo ""
echo "  ✓ Certificates generated successfully!"
echo ""
echo "  Import certs/ca.crt into your browser to trust FENRIR."
echo "  Then run: scripts/caddy-volume-prep.sh --apply && docker compose up -d --build"
echo ""
