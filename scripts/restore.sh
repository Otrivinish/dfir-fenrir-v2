#!/usr/bin/env bash
#
# DFIR-FENRIR v2 — restore tooling (GS-6, ISO 22301 business continuity).
#
# Wraps the manual procedure in docs/backup-restore.md §5 with guards:
#   • DRY-RUN by default — prints the plan and changes NOTHING (CLAUDE.md WhatIf rule).
#   • Destructive steps run only with --apply, and then require a typed confirmation
#     (or --yes for unattended use).
#   • Idempotent: the DB dump is `--clean --if-exists` (drops+recreates); the evidence
#     copy is copy-new-only (cp -an). Safe to re-run.
#   • Offline-safe: docker compose + psql + cp only; no network.
#
# Restores the PostgreSQL database (from a gzip pg_dump) and/or the evidence volume
# (from the copy-new-only mirror created by docker/backup/backup.sh).
#
# IMPORTANT: the evidence mirror is CIPHERTEXT. It is useless without the matching
# EVIDENCE_KEK — that key is NOT in any backup. Ensure the deployment's .env has the
# EVIDENCE_KEK that was active when the backup was taken (see backup-restore.md §4).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$REPO_ROOT")}"

DO_DB=0 ; DO_EVIDENCE=0 ; ANY_SCOPE=0
APPLY=0 ; ASSUME_YES=0 ; FILE=""

usage() {
  cat <<EOF
Usage: scripts/restore.sh [--db] [--evidence] [--file <dump.sql.gz>] [--apply] [--yes]

  (no flags)      DRY RUN — restore BOTH db + evidence, plan only, no changes.
  --db            Restore the database only.
  --evidence      Restore the evidence volume only.
                  (give both, or neither, to restore both.)
  --file <name>   Specific DB dump basename in the backup volume
                  (default: newest fenrir_backup_*.sql.gz).
  --apply         Actually perform the restore (otherwise dry-run).
  --yes           Skip the interactive confirmation (unattended; implies you've
                  already reviewed a --dry-run). Only meaningful with --apply.
  -h, --help      This help.

DESTRUCTIVE: --apply drops & recreates the database. Always review a dry-run first.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --db)       DO_DB=1 ; ANY_SCOPE=1 ;;
    --evidence) DO_EVIDENCE=1 ; ANY_SCOPE=1 ;;
    --file)     FILE="${2:-}" ; shift ;;
    --apply)    APPLY=1 ;;
    --yes)      ASSUME_YES=1 ;;
    -h|--help)  usage ; exit 0 ;;
    *) echo "Unknown option: $1" >&2 ; usage ; exit 2 ;;
  esac
  shift
done
# Default scope = both.
if [ "$ANY_SCOPE" -eq 0 ]; then DO_DB=1 ; DO_EVIDENCE=1 ; fi

log()  { printf '[restore] %s\n' "$*"; }
die()  { printf '[restore] ERROR: %s\n' "$*" >&2 ; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
docker compose ps >/dev/null 2>&1 || die "docker compose not available / not in a compose project ($REPO_ROOT)"

# ── Resolve the DB dump (newest by default) ─────────────────────────────────
if [ "$DO_DB" -eq 1 ]; then
  if [ -z "$FILE" ]; then
    FILE="$(docker compose exec -T backup sh -c 'ls -1t /backups/fenrir_backup_*.sql.gz 2>/dev/null | head -1 | xargs -r basename' | tr -d '\r')"
    [ -n "$FILE" ] || die "no DB backups (fenrir_backup_*.sql.gz) found in the backup volume"
  fi
  docker compose exec -T backup sh -c "test -f /backups/$FILE" \
    || die "DB dump not found in backup volume: $FILE"
fi

# ── Plan ────────────────────────────────────────────────────────────────────
echo "──────────────────────────────────────────────────────────────"
log "Project:        $PROJECT"
log "Restore DB:       $([ "$DO_DB" -eq 1 ] && echo "yes  (dump: $FILE)" || echo no)"
log "Restore evidence: $([ "$DO_EVIDENCE" -eq 1 ] && echo "yes  (from /backups/evidence-mirror, copy-new-only)" || echo no)"
log "Mode:           $([ "$APPLY" -eq 1 ] && echo 'APPLY (destructive)' || echo 'DRY RUN (no changes)')"
echo "──────────────────────────────────────────────────────────────"
if [ "$DO_DB" -eq 1 ]; then
  log "DB restore will: stop backend+analysis-worker → psql < (gunzip dump, --clean --if-exists) → restart"
fi
if [ "$DO_EVIDENCE" -eq 1 ]; then
  log "Evidence restore will: cp -an /backups/evidence-mirror → evidence volume (adds missing files only)"
  log "REMINDER: evidence is ciphertext — the running deployment MUST have the matching EVIDENCE_KEK."
fi

if [ "$APPLY" -eq 0 ]; then
  echo
  log "DRY RUN complete — nothing changed. Re-run with --apply to perform the restore."
  exit 0
fi

# ── Confirm ───────────────────────────────────────────────────────────────
if [ "$ASSUME_YES" -eq 0 ]; then
  echo
  printf '[restore] This DROPS & RECREATES the database. Type RESTORE to proceed: '
  read -r reply
  [ "$reply" = "RESTORE" ] || die "aborted (confirmation not given)"
fi

# ── Execute ─────────────────────────────────────────────────────────────────
log "Stopping backend + analysis-worker…"
docker compose stop backend analysis-worker >/dev/null

if [ "$DO_DB" -eq 1 ]; then
  log "Restoring database from $FILE…"
  docker compose exec -T backup sh -c "gunzip -c '/backups/$FILE'" \
    | docker compose exec -T postgres psql -U fenrir -d fenrir -v ON_ERROR_STOP=1 >/dev/null
  log "Database restored."
fi

if [ "$DO_EVIDENCE" -eq 1 ]; then
  log "Restoring evidence files (copy-new-only)…"
  docker compose run --rm --no-deps \
    -v "${PROJECT}_backup-data:/backups:ro" \
    --entrypoint sh backend \
    -c 'cp -an /backups/evidence-mirror/. /evidence/ 2>/dev/null || true; echo "[restore] evidence files now: $(find /evidence -type f 2>/dev/null | wc -l)"'
fi

log "Restarting backend + analysis-worker…"
docker compose up -d backend analysis-worker >/dev/null

echo
log "Restore complete. Verify:"
log "  curl -sk https://localhost/api/health        # backend up"
log "  curl -sk https://localhost/api/auth/setup-check   # {\"needs_setup\": false}"
log "  Then verify a known evidence item decrypts under the current EVIDENCE_KEK (backup-restore.md §5.3)."
