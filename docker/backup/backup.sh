#!/bin/sh
# DFIR-FENRIR v2 — Daily backup: PostgreSQL dump + evidence-volume mirror.
#
# Uses --clean --if-exists so the resulting dump can be restored cleanly
# into a database that already contains tables (idempotent restore).
TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)
BACKUP_FILE="/backups/fenrir_backup_${TIMESTAMP}.sql"
echo "[$(date)] Starting backup..."
pg_dump -h postgres -U fenrir -d fenrir --clean --if-exists --no-owner > "$BACKUP_FILE"
gzip "$BACKUP_FILE"
echo "[$(date)] DB backup saved: ${BACKUP_FILE}.gz"
# Keep only last 14 days of DB dumps
find /backups -name "fenrir_backup_*.sql.gz" -mtime +14 -delete
echo "[$(date)] Old DB backups cleaned (>14d)."

# ── Evidence-volume mirror (ISO/IEC 27037 §6.9.2 — protect evidence from loss) ──
# Master blobs are write-once and already AES-256-GCM encrypted at rest, so the
# mirror is copy-new-only (cp -an): every ciphertext blob + .nonce sidecar is copied
# exactly once and NEVER auto-pruned (§6.1 retention). The mirror is USELESS without
# EVIDENCE_KEK — that key lives in .env, is NOT in this backup, and must be preserved
# separately (see docs/backup-restore.md §4).
TS_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [ -d /evidence ]; then
  MIRROR="/backups/evidence-mirror"
  mkdir -p "$MIRROR"
  echo "[$TS_UTC] Mirroring /evidence (copy-new-only)..."
  # BusyBox-safe incremental copy: walk files relative to /evidence and copy
  # only those not already in the mirror (immutable blobs → copied exactly once).
  ( cd /evidence && find . -type f | while IFS= read -r f; do
      dest="$MIRROR/$f"
      [ -e "$dest" ] && continue
      mkdir -p "$(dirname "$dest")"
      cp -p "$f" "$dest"
    done )
  echo "[$TS_UTC] Evidence mirror: $(find "$MIRROR" -type f 2>/dev/null | wc -l) files total."
else
  echo "[$TS_UTC] WARN: /evidence not mounted — evidence NOT backed up this run."
fi
