#!/usr/bin/env bash
# DFIR-FENRIR v2 — one-command setup.
# Idempotent + offline-safe: creates .env, generates any missing secrets,
# makes local TLS certs (self-signed mode), builds + starts the stack, and
# prints the first-run setup token. Safe to re-run — never overwrites an
# existing secret or running data.
#
# Usage:
#   ./setup.sh                 # full setup / resume
#   ./setup.sh --print-token   # just re-show the first-run setup token
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
ENV_FILE="$ROOT/.env"
TOKEN_PATH="/app/data/bootstrap_token.txt"

have() { command -v "$1" >/dev/null 2>&1; }
say()  { printf '\033[36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

dc() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"
  elif have docker-compose; then docker-compose "$@"
  else die "Docker Compose not found."; fi
}

# Secret generators — prefer openssl, fall back to python3.
gen_hex() {  # $1 = byte count → 2*N hex chars
  if   have openssl; then openssl rand -hex "$1"
  elif have python3; then python3 -c "import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))" "$1"
  else die "Need openssl or python3 to generate secrets."; fi
}
gen_b64() {  # $1 = byte count → base64 (single line)
  if   have openssl; then openssl rand -base64 "$1" | tr -d '\n'
  elif have python3; then python3 -c "import os,base64,sys; print(base64.b64encode(os.urandom(int(sys.argv[1]))).decode())" "$1"
  else die "Need openssl or python3 to generate secrets."; fi
}

env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true; }

# Set KEY=VALUE only if the key is missing, empty, or still a change_me_ placeholder.
fill() {
  local key="$1" val="$2" cur
  if ! grep -qE "^${key}=" "$ENV_FILE"; then
    printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"; ok "added $key"; return
  fi
  cur="$(env_get "$key")"
  case "$cur" in
    ""|change_me_*)
      awk -F= -v k="$key" -v v="$val" '$1==k{print k"="v; next}{print}' "$ENV_FILE" > "$ENV_FILE.tmp" \
        && mv "$ENV_FILE.tmp" "$ENV_FILE"
      ok "generated $key" ;;
    *) say "$key already set — kept" ;;
  esac
}

print_token() {
  local t dom
  t="$(dc exec -T backend cat "$TOKEN_PATH" 2>/dev/null | tr -d '\r\n' || true)"
  if [ -n "$t" ]; then
    dom="$(env_get DOMAIN)"; [ -n "$dom" ] || dom=localhost
    printf '\n\033[32m── First-run setup ──\033[0m\n'
    printf '  Open:  https://%s/setup\n' "$dom"
    printf '  Token: %s\n\n' "$t"
  else
    warn "No bootstrap token — setup is likely already complete (an admin user exists)."
  fi
}

# ── --print-token / --help shortcuts ──
case "${1:-}" in
  --print-token) print_token; exit 0 ;;
  -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
  "") : ;;
  *) die "Unknown arg: $1 (try --help)" ;;
esac

# ── preflight ──
have docker || die "Docker not found — install Docker first."
dc version >/dev/null 2>&1 || die "Docker Compose not available."

# ── 1. .env ──
if [ ! -f "$ENV_FILE" ]; then
  cp "$ROOT/.env.example" "$ENV_FILE"; ok "created .env from .env.example"
else
  say ".env exists — filling only blank/placeholder secrets"
fi

# ── 2. secrets (idempotent) ──
fill POSTGRES_PASSWORD "$(gen_hex 24)"   # URL-safe (rides in DATABASE_URL)
fill REDIS_PASSWORD    "$(gen_hex 24)"
fill SECRET_KEY        "$(gen_hex 64)"
fill EVIDENCE_KEK      "$(gen_hex 32)"   # 32 bytes → AES-256 KEK; backend won't boot without it
fill AUDIT_SIGNING_KEY "$(gen_b64 32)"   # 32-byte Ed25519 seed, base64

# ── 3. TLS — self-signed only (skip for BYO cert / DuckDNS) ──
DOMAIN="$(env_get DOMAIN)"; [ -n "$DOMAIN" ] || DOMAIN=localhost
if [ -z "$(env_get TLS_CERT_FILE)" ] && [ -z "$(env_get DUCKDNS_TOKEN)" ]; then
  if [ ! -f "$ROOT/certs/server.crt" ]; then
    say "generating self-signed TLS certs for $DOMAIN"
    ./generate-certs.sh >/dev/null
    ok "certs written (import certs/ca.crt into your browser to trust FENRIR locally)"
  else
    say "certs/server.crt exists — kept"
  fi
else
  say "external TLS configured (BYO cert / DuckDNS) — skipping cert generation"
fi

# ── 4. build + start ──
say "building + starting the stack (first run can take a few minutes)…"
dc up -d --build

# ── 5. wait for health, then surface the setup token ──
if have curl; then
  say "waiting for the backend to become healthy…"
  for i in $(seq 1 60); do
    if curl -sk "https://localhost/api/health" 2>/dev/null | grep -q '"status":"ok"'; then
      ok "backend healthy"; break
    fi
    sleep 2
    if [ "$i" -eq 60 ]; then
      warn "health check timed out — check 'docker compose logs backend', then './setup.sh --print-token'"
    fi
  done
else
  warn "curl not found — skipping health poll"; sleep 8
fi

print_token
ok "done. Re-run ./setup.sh any time — it won't overwrite secrets or running data."
