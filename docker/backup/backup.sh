#!/bin/sh
# DFIR-FENRIR v2 — one backup run: evidence-volume mirror, then PostgreSQL dump.
#
# Fails loudly: any dump error exits non-zero and leaves NO success marker and
# no half-written dump. Retention never deletes the history of a stalled job.
#
# Uses --clean --if-exists so the dump restores cleanly into a database that
# already contains tables (idempotent restore).
set -eu
# shellcheck disable=SC3040  # BusyBox ash (this image's /bin/sh) supports pipefail
set -o pipefail

KEEP=14                                   # always keep at least this many of our own dumps
ts()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(ts)] $*"; }

# DB credentials: the postgres_password secret file → a private .pgpass on tmpfs
# (libpq refuses group/world-readable pgpass files). Nothing in the environment.
if [ -r /run/secrets/postgres_password ]; then
    pw="$(sed 's/\\/\\\\/g; s/:/\\:/g' /run/secrets/postgres_password)"
    ( umask 077; printf 'postgres:5432:fenrir:%s:%s\n' "${PGUSER:-fenrir_backup}" "$pw" > /tmp/.pgpass )
    unset pw
    export PGPASSFILE=/tmp/.pgpass
fi

# ── 1. Evidence-volume mirror (ISO/IEC 27037 §6.9.2 — protect evidence from loss) ──
# Runs FIRST so a dump or prune problem can never skip it. Master blobs are
# write-once and already AES-256-GCM encrypted at rest, so the mirror is
# copy-new-only: each ciphertext blob + .nonce sidecar is copied exactly once and
# NEVER auto-pruned (§6.1 retention). Files modified in the last 10 minutes are
# skipped — the backend writes evidence in place, and copy-new-only would keep a
# truncated copy forever. The mirror is USELESS without EVIDENCE_KEK, which is
# NOT in this backup and must be preserved separately (docs/backup-restore.md §4).
if [ -d /evidence ]; then
    MIRROR="/backups/evidence-mirror"
    mkdir -p "$MIRROR"
    log "Mirroring /evidence (copy-new-only, files idle ≥10 min)..."
    errors=0
    IFS='
'   # newline-only splitting: safe for any filename without a newline
    for f in $(cd /evidence && find . -type f -mmin +10); do
        dest="$MIRROR/$f"
        [ -e "$dest" ] && continue
        mkdir -p "$(dirname "$dest")"
        # NOT `cp -p`: that hands the copy to the backend's uid 1001, and the backend
        # mounts /backups — it could then overwrite the very mirror that protects
        # evidence from it. Root-owned 0444 copies; only the timestamp is kept.
        if cp "/evidence/$f" "$dest.part" && touch -r "/evidence/$f" "$dest.part" \
            && chmod 0444 "$dest.part" && mv "$dest.part" "$dest"; then :
        else rm -f "$dest.part"; errors=$((errors + 1)); fi
    done
    unset IFS
    # Re-seal anything in the mirror that is not root-owned read-only (repairs copies
    # made by the old `cp -p`). Idempotent; a no-op once the mirror is clean.
    find "$MIRROR" -type f \( ! -user 0 -o -perm /0222 \) -exec chown 0:0 {} + -exec chmod 0444 {} + 2>/dev/null \
        || log "WARN: could not re-seal every mirror file."
    [ "$errors" -eq 0 ] || log "WARN: $errors evidence file(s) could not be mirrored this run."
    log "Evidence mirror: $(find "$MIRROR" -type f | wc -l) files total."
else
    log "WARN: /evidence not mounted — evidence NOT backed up this run."
fi

# ── 2. Database dump → (age-encrypt) → temp file → atomic rename ──────────────
# With BACKUP_AGE_RECIPIENT set the dump is encrypted to that PUBLIC key; the
# private identity is kept OFFLINE by the operator, so nobody on this host — not
# even root — can read the backups. pipefail makes this fail CLOSED: if age
# fails, nothing (and never a plaintext fallback) is written.
OUT="/backups/fenrir_backup_$(date -u +%Y-%m-%d_%H-%M-%S).sql.gz"
RECIPIENT="${BACKUP_AGE_RECIPIENT:-}"
[ -n "$RECIPIENT" ] && OUT="$OUT.age"
trap 'rm -f "$OUT.tmp"' EXIT
log "Starting DB dump..."
if [ -n "$RECIPIENT" ]; then
    pg_dump -h postgres -U "${PGUSER:-fenrir_backup}" -d fenrir --clean --if-exists --no-owner | gzip | age -r "$RECIPIENT" > "$OUT.tmp"
else
    log "WARN: BACKUP_AGE_RECIPIENT is not set — this dump is NOT encrypted (see .env.example)."
    pg_dump -h postgres -U "${PGUSER:-fenrir_backup}" -d fenrir --clean --if-exists --no-owner | gzip > "$OUT.tmp"
fi
mv "$OUT.tmp" "$OUT"
ts > /backups/.last_success
log "DB backup saved: $OUT"

# ── 3. Retention — never fatal, never touches the backend's (uid 1001) dumps ──
# Only root-owned dumps are ours to prune (the sticky dir forbids the rest), the
# newest $KEEP are always kept, and beyond that only dumps older than 14 days go.
set +e
own="$(find /backups -maxdepth 1 -type f -user 0 -name 'fenrir_backup_*.sql.gz*' 2>/dev/null)"
if [ -n "$own" ]; then
    # shellcheck disable=SC2086  # filenames are generated above: no spaces
    ls -1t $own | tail -n +$((KEEP + 1)) | while read -r f; do
        if [ -n "$(find "$f" -mtime +14 2>/dev/null)" ]; then
            rm -f "$f" && log "Pruned $f"
        fi
    done
fi
log "Backup run complete."
