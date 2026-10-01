#!/usr/bin/env bash
# DFIR-FENRIR v2 — encrypt legacy plaintext DB dumps with age (one-off migration).
#
# Every fenrir_backup_*.sql.gz in the backup volume is encrypted to
# BACKUP_AGE_RECIPIENT (from .env) as <name>.age, keeping the original owner
# (root = sidecar dumps, 1001 = backend manual dumps — so each side can still prune
# its own) and timestamp. The plaintext is removed ONLY after its .age replacement
# exists, is non-empty and starts with the age header.
#
# Idempotent: already-encrypted dumps are skipped. Dry run by default.
#   scripts/encrypt-legacy-backups.sh           # list what would be encrypted
#   scripts/encrypt-legacy-backups.sh --apply   # encrypt, then remove the plaintext
set -euo pipefail
cd "$(dirname "$0")/.."
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
PROJECT="${COMPOSE_PROJECT_NAME:-dfir-fenrir-v2}"
RECIPIENT="$(grep -E '^BACKUP_AGE_RECIPIENT=' .env 2>/dev/null | cut -d= -f2- || true)"
[ -n "$RECIPIENT" ] || { echo "BACKUP_AGE_RECIPIENT is not set in .env — nothing to encrypt to." >&2; exit 1; }
IMAGE="$(docker compose config --images | grep -E 'backup' | head -1)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "backup image $IMAGE not built — run: docker compose build backup" >&2; exit 1; }

# Root for this one-shot only, with just CHOWN + FOWNER (sticky /backups: replace
# files owned by uid 1001 and keep their owner/mtime), no network.
docker run --rm --network none --user 0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges:true -v "${PROJECT}_backup-data:/backups" \
    -e R="$RECIPIENT" -e APPLY="$APPLY" --entrypoint sh "$IMAGE" -euc '
    n=0
    for f in /backups/fenrir_backup_*.sql.gz; do
        [ -f "$f" ] || continue
        n=$((n + 1))
        if [ "$APPLY" != 1 ]; then echo "would encrypt  $(basename "$f")  (owner $(stat -c %u:%g "$f"))"; continue; fi
        age -r "$R" -o "$f.age.tmp" "$f"
        if [ -s "$f.age.tmp" ] && head -c 21 "$f.age.tmp" | grep -q "age-encryption.org/v1"; then
            chown "$(stat -c %u:%g "$f")" "$f.age.tmp"; chmod 0644 "$f.age.tmp"; touch -r "$f" "$f.age.tmp"
            mv "$f.age.tmp" "$f.age" && rm -f "$f"
            echo "encrypted      $(basename "$f").age"
        else
            rm -f "$f.age.tmp"; echo "FAILED         $(basename "$f") — plaintext kept" >&2; exit 1
        fi
    done
    [ "$n" -gt 0 ] || echo "no plaintext dumps — nothing to do"
    [ "$n" -eq 0 ] || [ "$APPLY" = 1 ] || echo "Dry run — re-run with --apply to encrypt and remove the plaintext."'
