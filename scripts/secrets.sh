#!/usr/bin/env bash
# DFIR-FENRIR v2 — service secrets as files (Docker Compose `secrets:`).
#
# Secrets live in ./secrets/<name> — dir 0700 (owner only on the host), files 0444
# (a compose file-secret is a bind mount that keeps host modes, so each service's
# non-root uid must be able to read its own file; the 0700 dir keeps other host
# users out). Nothing secret travels in environment variables any more, so it is
# not in `docker inspect`, not in /proc/*/environ and not inherited by children.
#
# For each secret: keep the existing file; else import the legacy value from .env;
# else generate a fresh one. Then render secrets/redis_acl (Redis ACL users with
# only the commands/keys FENRIR uses; the password is stored as a SHA-256).
# With --apply, migrated keys are blanked in .env AFTER the file is verified.
#
# Idempotent: re-running changes nothing once migrated. Dry run by default.
#   scripts/secrets.sh           # show what would happen
#   scripts/secrets.sh --apply   # do it
set -euo pipefail
cd "$(dirname "$0")/.."
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
DIR=secrets
ENV_FILE=.env

have() { command -v "$1" >/dev/null 2>&1; }
gen_hex() { if have openssl; then openssl rand -hex "$1"; else python3 -c "import secrets,sys; print(secrets.token_hex(int(sys.argv[1])))" "$1"; fi; }
gen_b64() { if have openssl; then openssl rand -base64 "$1" | tr -d '\n'; else python3 -c "import os,base64,sys; print(base64.b64encode(os.urandom(int(sys.argv[1]))).decode())" "$1"; fi; }
env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d= -f2- || true; }
say() { printf '  %-18s %s\n' "$1" "$2"; }

# name  .env key            generator (hex bytes | b64 bytes | empty-ok)
SPECS=(
  "postgres_password  POSTGRES_PASSWORD  hex:24"
  "redis_password     REDIS_PASSWORD     hex:24"
  "secret_key         SECRET_KEY         hex:64"
  "evidence_kek       EVIDENCE_KEK       hex:32"
  "audit_signing_key  AUDIT_SIGNING_KEY  b64:32"
  "worker_token       WORKER_TOKEN       hex:32"
  "pg_migrator_password  -             hex:24"
  "pg_app_password       -             hex:24"
  "pg_monitor_password   -             hex:24"
  "pg_backup_password    -             hex:24"
  "duckdns_token      DUCKDNS_TOKEN      empty"
)

[ "$APPLY" -eq 1 ] && { mkdir -p "$DIR"; chmod 700 "$DIR"; }
echo "Secrets in ./$DIR (dir 0700, files 0444)$([ "$APPLY" -eq 0 ] && echo ' — DRY RUN')"
MIGRATED=()
for spec in "${SPECS[@]}"; do
  read -r name key gen <<<"$spec"
  f="$DIR/$name"
  legacy="$(env_get "$key")"; case "$legacy" in change_me_*) legacy="";; esac
  if [ -s "$f" ] || { [ -f "$f" ] && [ "$gen" = empty ]; }; then
    say "$name" "keep existing file"
    if [ -n "$legacy" ]; then
      if [ "$legacy" = "$(cat "$f")" ]; then MIGRATED+=("$key")
      else say "" "WARNING: .env $key differs from $f — file wins; .env left untouched, resolve manually"; fi
    fi
    continue
  fi
  if [ -n "$legacy" ]; then value="$legacy"; how="import from .env $key"; MIGRATED+=("$key")
  else case "$gen" in
      hex:*) value="$(gen_hex "${gen#hex:}")"; how="generate";;
      b64:*) value="$(gen_b64 "${gen#b64:}")"; how="generate";;
      empty) value=""; how="create empty (set a value to enable)";;
    esac
  fi
  say "$name" "$how"
  if [ "$APPLY" -eq 1 ]; then
    (umask 077; printf '%s' "$value" > "$f.tmp") && chmod 0444 "$f.tmp" && mv "$f.tmp" "$f"
  fi
done

# Redis ACL — default user disabled; `fenrir` gets exactly the commands and key
# prefixes the backend uses (incl. EVAL/EVALSHA/SCRIPT LOAD for the rate limiter —
# without them the limiter would silently fail open — and INCRBY, which is what
# redis-py's incr() actually sends); `healthcheck` may only PING.
if [ "$APPLY" -eq 1 ]; then
  pw_sha="$(printf '%s' "$(cat "$DIR/redis_password")" | sha256sum | cut -d' ' -f1)"
  acl="user default off resetpass resetkeys resetchannels -@all
user fenrir on #$pw_sha resetchannels ~session:* ~login_fail:* ~totp_fail:* ~pending_totp:* ~rl:* -@all +get +set +del +incr +incrby +expire +hmget +hset +eval +evalsha +script|load +ping +client|setinfo
user healthcheck on nopass resetchannels -@all +ping"
  if [ "$(cat "$DIR/redis_acl" 2>/dev/null)" != "$acl" ]; then
    (umask 077; printf '%s\n' "$acl" > "$DIR/redis_acl.tmp") && chmod 0444 "$DIR/redis_acl.tmp" && mv "$DIR/redis_acl.tmp" "$DIR/redis_acl"
    say redis_acl "rendered (password stored as SHA-256)"
    echo "  NOTE: secrets are single-file bind mounts — apply with: docker compose up -d --force-recreate redis"
  else say redis_acl "up to date"; fi
else say redis_acl "render from redis_password"; fi

# Blank migrated keys in .env — only values that are now verified in their file.
if [ "${#MIGRATED[@]}" -gt 0 ]; then
  if [ "$APPLY" -eq 1 ]; then
    for key in "${MIGRATED[@]}"; do
      (umask 077; awk -F= -v k="$key" '$1==k{print k"="; next}{print}' "$ENV_FILE" > "$ENV_FILE.tmp") && mv "$ENV_FILE.tmp" "$ENV_FILE"
    done
    chmod 600 "$ENV_FILE"
    echo "  .env: blanked ${MIGRATED[*]} (values now only in ./$DIR)"
  else echo "  .env: would blank ${MIGRATED[*]}"; fi
fi
[ "$APPLY" -eq 0 ] && echo "Re-run with --apply to make these changes."
exit 0
