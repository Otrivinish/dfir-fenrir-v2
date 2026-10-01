#!/usr/bin/env bash
# DFIR-FENRIR v2 — internal PKI for service-to-service TLS (encrypt in transit).
#
# A SEPARATE internal CA (never the browser-trusted one from generate-certs.sh),
# name-constrained to the compose service names, issues one leaf per service:
#
#   postgres         serverAuth             Postgres TLS (clients verify-full)
#   redis            serverAuth+clientAuth  Redis TLS; mTLS (its healthcheck is a client)
#   backend          serverAuth+clientAuth  uvicorn TLS behind Caddy (mTLS); Redis client
#   analysis-worker  serverAuth             worker TLS (the backend verifies it)
#   caddy            clientAuth             Caddy → backend mTLS client
#
# CA key: ./ca/internal (0700), never mounted. Leaves + CA cert: ./secrets/tls_*
# (0444 in the 0700 dir), mounted per service as compose secrets.
#
# Idempotent: a leaf is (re)issued only when missing, not signed by the current CA,
# or expiring within RENEW_DAYS — so re-running (setup.sh does) renews in time, and
# scripts/posture-check.sh fails 30 days before any expiry. After renewal, recreate
# the services: docker compose up -d --force-recreate.
#   scripts/internal-pki.sh           # dry run: show what would be issued
#   scripts/internal-pki.sh --apply   # issue / renew
set -euo pipefail
cd "$(dirname "$0")/.."
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
CA_DIR=ca/internal; OUT=secrets
CA_KEY="$CA_DIR/ca.key"; CA_CRT="$OUT/tls_ca.crt"
CA_DAYS=3650; LEAF_DAYS=365; RENEW_DAYS=30

# name  SAN  EKU
LEAVES=(
  "postgres         DNS:postgres         serverAuth"
  "redis            DNS:redis            serverAuth,clientAuth"
  "backend          DNS:backend          serverAuth,clientAuth"
  "analysis-worker  DNS:analysis-worker  serverAuth"
  "caddy            DNS:caddy            clientAuth"
)

install_0444() { chmod 0444 "$1.tmp" && mv "$1.tmp" "$1"; }

if [ -s "$CA_KEY" ] && [ -s "$CA_CRT" ]; then
  echo "  internal CA       keep ($(openssl x509 -in "$CA_CRT" -noout -enddate | cut -d= -f2))"
else
  echo "  internal CA       create (EC P-256, ${CA_DAYS} d, name-constrained to the service names)"
  if [ "$APPLY" -eq 1 ]; then
    mkdir -p "$CA_DIR" "$OUT"; chmod 700 "$CA_DIR" "$OUT"
    (umask 077; openssl ecparam -genkey -name prime256v1 -out "$CA_KEY" 2>/dev/null)
    NC="critical,permitted;DNS:postgres,permitted;DNS:redis,permitted;DNS:backend,permitted;DNS:analysis-worker,permitted;DNS:caddy"
    openssl req -new -x509 -sha256 -key "$CA_KEY" -out "$CA_CRT.tmp" -days "$CA_DAYS" \
      -subj "/O=DFIR-FENRIR/CN=FENRIR Internal Service CA" \
      -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -addext "nameConstraints=$NC" 2>/dev/null
    install_0444 "$CA_CRT"
  fi
fi

for spec in "${LEAVES[@]}"; do
  read -r name san eku <<<"$spec"
  crt="$OUT/tls_$name.crt"; key="$OUT/tls_$name.key"
  why=""
  if [ ! -s "$crt" ] || [ ! -s "$key" ]; then why="missing"
  elif [ ! -s "$CA_CRT" ] || ! openssl verify -CAfile "$CA_CRT" "$crt" >/dev/null 2>&1; then why="not signed by the current CA"
  elif ! openssl x509 -in "$crt" -noout -checkend $((RENEW_DAYS * 86400)) >/dev/null; then why="expires within ${RENEW_DAYS} d"
  fi
  if [ -z "$why" ]; then echo "  $(printf '%-17s' "$name") keep ($(openssl x509 -in "$crt" -noout -enddate | cut -d= -f2))"; continue; fi
  echo "  $(printf '%-17s' "$name") issue ($why) — $san, $eku, ${LEAF_DAYS} d"
  [ "$APPLY" -eq 1 ] || continue
  (umask 077
   openssl ecparam -genkey -name prime256v1 -out "$key.tmp" 2>/dev/null
   openssl req -new -sha256 -key "$key.tmp" -subj "/O=DFIR-FENRIR/CN=$name" -out "$OUT/$name.csr" 2>/dev/null)
  openssl x509 -req -sha256 -in "$OUT/$name.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" \
    -CAserial "$CA_DIR/ca.srl" -CAcreateserial -days "$LEAF_DAYS" -out "$crt.tmp" \
    -extfile <(printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n' "$san" "$eku") 2>/dev/null
  rm -f "$OUT/$name.csr"
  install_0444 "$crt"; install_0444 "$key"
done
[ "$APPLY" -eq 1 ] || echo "Dry run — re-run with --apply to issue/renew."
