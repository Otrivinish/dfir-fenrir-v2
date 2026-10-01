#!/usr/bin/env bash
# DFIR-FENRIR v2 — prove a DB backup actually restores (non-destructive).
#
# Restores a dump from the backup volume into a THROWAWAY database with
# ON_ERROR_STOP=1 (exactly like scripts/restore.sh), reports table + audit-row
# counts, then drops the throwaway DB. The live `fenrir` database is never
# touched. Safe to run any number of times.
#
# Usage:
#   scripts/verify-restore.sh                          # newest dump
#   scripts/verify-restore.sh fenrir_backup_<ts>.sql.gz[.age]
#   AGE_IDENTITY=~/fenrir-backup.agekey scripts/verify-restore.sh   # .age dumps
set -euo pipefail
cd "$(dirname "$0")/.."

FILE="${1:-$(docker compose exec -T backup sh -c 'ls -1t /backups/fenrir_backup_*.sql.gz /backups/fenrir_backup_*.sql.gz.age 2>/dev/null | head -1' | tr -d '\r')}"
FILE="$(basename "$FILE")"
[ -n "$FILE" ] || { echo "no dumps found in /backups" >&2; exit 1; }
DB="verify_restore_$(date -u +%Y%m%d%H%M%S)"
PSQL=(docker compose exec -T postgres psql -U fenrir -v ON_ERROR_STOP=1 -q)

cleanup() { "${PSQL[@]}" -d postgres -c "DROP DATABASE IF EXISTS $DB" >/dev/null 2>&1 || true; }
trap cleanup EXIT

decrypt() {  # stream the dump, decrypting .age on the host with the offline identity
  if [[ "$FILE" == *.age ]]; then
    [ -n "${AGE_IDENTITY:-}" ] && [ -f "$AGE_IDENTITY" ] || { echo "$FILE is age-encrypted: set AGE_IDENTITY=<identity file>" >&2; exit 2; }
    command -v age >/dev/null || { echo "age not installed on this host" >&2; exit 2; }
    docker compose exec -T backup cat "/backups/$FILE" | age -d -i "$AGE_IDENTITY" | gunzip -c
  else
    docker compose exec -T backup sh -c "gunzip -c '/backups/$FILE'"
  fi
}

echo "Verifying restore of $FILE into throwaway DB $DB ..."
"${PSQL[@]}" -d postgres -c "CREATE DATABASE $DB" >/dev/null
decrypt | "${PSQL[@]}" -d "$DB" >/dev/null
tables="$("${PSQL[@]}" -d "$DB" -Atc "select count(*) from information_schema.tables where table_schema='public'")"
audit="$("${PSQL[@]}" -d "$DB" -Atc "select count(*) from audit_logs")"
echo "OK: $FILE restored — $tables tables, $audit audit_logs rows (throwaway DB dropped)."
