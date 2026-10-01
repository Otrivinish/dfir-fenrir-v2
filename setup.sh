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

env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true; }

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
  (umask 077; cp "$ROOT/.env.example" "$ENV_FILE"); ok "created .env from .env.example"
else
  say ".env exists — keeping it"
fi
# .env is owner-only, always (the umask is scoped to the .env writes above so it
# can't leak into cert generation).
chmod 600 "$ENV_FILE"

# ── 2. secrets → ./secrets files (idempotent) ──
# Generates any missing secret, imports legacy values still in .env (and blanks
# them there), and renders the Redis ACL. Never overwrites an existing secret.
# The evidence KEK in ./secrets/evidence_kek is irreplaceable: back it up offline.
"$ROOT/scripts/secrets.sh" --apply
# Internal service-to-service TLS (Postgres, Redis, worker, Caddy→backend mTLS):
# creates the internal CA once; renews any leaf within 30 days of expiry.
"$ROOT/scripts/internal-pki.sh" --apply
if [ -z "$(env_get BACKUP_AGE_RECIPIENT)" ]; then
  warn "BACKUPS ARE NOT ENCRYPTED: BACKUP_AGE_RECIPIENT is empty in .env."
  warn "  Generate an age key OFFLINE (age-keygen -o fenrir-backup.agekey), keep the key in"
  warn "  your password manager, and set BACKUP_AGE_RECIPIENT=<its age1… public key>."
fi

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
say "building the stack (first run can take a few minutes)…"
dc build
# Caddy runs non-root with no capabilities: hand it its volumes + TLS files.
"$ROOT/scripts/caddy-volume-prep.sh" --apply >/dev/null && ok "caddy volumes prepared"
# Least-privilege DB roles: a fresh volume gets them at initdb; an existing database
# (e.g. upgraded from before the role split) needs them BEFORE `migrate` runs. The
# role script is idempotent, so it is simply (re)applied every time.
say "starting postgres + applying DB roles…"
dc up -d postgres
for i in $(seq 1 60); do
  [ "$(docker inspect --format '{{.State.Health.Status}}' "$(dc ps -q postgres)" 2>/dev/null)" = healthy ] && break
  sleep 2
done
"$ROOT/scripts/db-roles.sh" --apply >/dev/null && ok "DB roles, ownership and grants applied"
say "starting the stack…"
dc up -d

# ── 5. wait for health, then surface the setup token ──
if have curl; then
  say "waiting for the backend to become healthy…"
  for i in $(seq 1 60); do
    # The edge only serves https://$DOMAIN — ask for exactly that name, via loopback.
    if curl -sk --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/health" 2>/dev/null | grep -q '"status":"ok"'; then
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
