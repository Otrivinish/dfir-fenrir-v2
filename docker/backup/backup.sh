#!/bin/sh
# DFIR-FENRIR v2 — one backup run: evidence-volume mirror, then PostgreSQL dump.
#
#   backup.sh                                   the scheduled run (scheduler.sh)
#   backup.sh mirror-rebuild                    KEK rotation: build /backups/evidence-mirror.next
#                                               alongside the current mirror (resumable)
#   backup.sh mirror-swap  [--apply [--yes]]    KEK rotation: once the rotation tool's mirror-verify
#                                               has recorded .next, retire the old mirror (renamed,
#                                               kept) and put .next in service
#   backup.sh mirror-purge [--apply [--yes]]    delete retired mirrors (evidence-mirror.retired-*)
#   The mirror-* modes are dry runs without --apply; --apply asks for a typed word unless --yes.
#   Procedure: docs/evidence-kek-rotation.md.
#
# Fails loudly: any dump error exits non-zero and leaves NO success marker and
# no half-written dump. Retention never deletes the history of a stalled job.
# Refuses to write an unencrypted dump: BACKUP_AGE_RECIPIENT must be set (encrypt at rest).
# Skips the whole run (no dump, no success marker) while a KEK rotation runs or did not finish.
# After the dump: the mirror copies of exhibits destroyed more than MIRROR_PURGE_GRACE_DAYS (default
# 30) days ago are purged, with a receipt the backend records in each exhibit's custody log.
#
# Uses --clean --if-exists so the dump restores cleanly into a database that
# already contains tables (idempotent restore).
set -eu
# shellcheck disable=SC3040  # BusyBox ash (this image's /bin/sh) supports pipefail
set -o pipefail
# ROT-M3: no pathname expansion anywhere. Every list below comes from find output and is split on
# newlines only; a file name holding "*" or "?" (the backend writes names derived from uploads) must
# never expand into other paths, least of all under an rm.
set -f
NL='
'

KEEP=14                                   # always keep at least this many of our own dumps
ts()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(ts)] $*"; }
die() { log "REFUSED: $*"; exit 2; }

EVID=/evidence
MIRROR=/backups/evidence-mirror
LOCK=.kek-rotation.lock

# Files the mirror copies: everything under /evidence except in-progress writes (.staging/,
# *.partial: G1 stage 3a) and KEK-rotation state (journals and the lock: G1 stage 4). Extra find
# tests (e.g. -mmin +10) are passed as arguments. Output: ./relative/path, one per line.
evidence_files() {
    (cd "$EVID" && find . -path ./.staging -prune -o -type f ! -name '*.partial' \
        ! -name '*.keyslot' ! -name '*.keyslot.tmp' ! -name '*.rewrite' ! -name '*.rewrite.tmp' \
        ! -name "$LOCK" "$@" -print)
}

# True while a KEK rotation runs or did not finish (the lock, or a journal next to a file): a
# re-wrap rewrites files in place, and a copy-once mirror would keep a half-done copy forever.
# A journal is recognised by name AND content (R3-1): a regular file named *.keyslot / *.rewrite that
# starts with FENRKSJ1 / FENRRWJ1. Each name reaches the check as an argument, never word-split.
rotation_in_progress() {
    [ -e "$EVID/$LOCK" ] && return 0
    [ -n "$(cd "$EVID" && find . -path ./.staging -prune -o -type f \( \
        \( -name '*.keyslot' -exec sh -c '[ "$(head -c 8 "$1")" = FENRKSJ1 ]' _ {} \; -print \) -o \
        \( -name '*.rewrite' -exec sh -c '[ "$(head -c 8 "$1")" = FENRRWJ1 ]' _ {} \; -print \) \) \
        2>/dev/null | head -n 1)" ]
}

# One root-owned 0444 copy, atomically (.part, then rename). NOT `cp -p`: that hands the copy to
# the backend's uid 1001, and the backend mounts /backups — it could then overwrite the very
# mirror that protects evidence from it. Only the timestamp is kept.
mirror_copy() {   # $1 = mirror root, $2 = path relative to /evidence
    dest="$1/$2"
    mkdir -p "$(dirname "$dest")"
    if cp "$EVID/$2" "$dest.part" && touch -r "$EVID/$2" "$dest.part" \
        && chmod 0444 "$dest.part" && mv -f "$dest.part" "$dest"; then return 0; fi
    rm -f "$dest.part"
    return 1
}

confirm() {   # $1 = word the operator must type, $2 = --yes to skip
    [ "${2:-}" = "--yes" ] && return 0
    [ -t 0 ] || die "--apply needs a typed confirmation on a terminal (or add --yes)"
    printf 'Type %s to continue, anything else aborts: ' "$1"
    read -r answer
    [ "$answer" = "$1" ] || die "confirmation did not match; nothing was changed"
}

# ── KEK rotation: rebuild the mirror ALONGSIDE the old one, verify, then retire (spec §6.4) ──
# In-place key-slot re-wraps and v0 → v2 rewrites never reach the copy-once mirror, so after a
# rotation it holds copies that only the OLD key opens. Never delete first: build .next, let the
# rotation tool verify it (every file opens with NEW and matches its hash; it writes the marker
# and the custody records), then swap; the old mirror is kept until mirror-purge.
mirror_rebuild() {
    [ -d "$EVID" ] || die "/evidence is not mounted"
    rotation_in_progress && die "a KEK rotation is running or did not finish (lock or journal under /evidence): finish or recover it first"
    next="$MIRROR.next"
    rm -f "$next.verified"                 # the file set may change: an earlier verification is void
    mkdir -p "$next"
    log "Rebuilding the evidence mirror alongside the current one: $next"
    errors=0; copied=0
    IFS='
'
    for f in $(evidence_files); do         # no idle filter: the stack is stopped for the rotation
        f="${f#./}"
        # Resumable: a copy with the source's size and mtime is kept, anything else recopied.
        if [ -f "$next/$f" ] && [ "$(stat -c '%s %Y' "$next/$f")" = "$(stat -c '%s %Y' "$EVID/$f")" ]; then continue; fi
        if mirror_copy "$next" "$f"; then copied=$((copied + 1)); else errors=$((errors + 1)); fi
    done
    unset IFS
    # Gone from /evidence: drop it from .next only. ROT-M3: each name reaches rm as an argument of
    # find -exec, never through word splitting.
    (cd "$next" && find . -type f -exec sh -c 'for f; do [ -e "$0/$f" ] || { rm -f -- "$f" &&
        echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] removed ${f#./} from .next (no longer in /evidence)"; }; done' "$EVID" {} +)
    log "Mirror rebuild: $copied copied, $errors failed, $(find "$next" -type f | wc -l) files in $next."
    [ "$errors" -eq 0 ] || { log "ERROR: $errors file(s) could not be copied; run mirror-rebuild again."; exit 1; }
    log "Next: python -m evidence.rotation mirror-verify --mirror $next ... (backend image), then mirror-swap."
}

mirror_swap() {   # $1 = --apply, $2 = --yes
    next="$MIRROR.next"; mark="$next.verified"
    [ -d "$next" ] || die "no $next: run mirror-rebuild first"
    [ -f "$mark" ] || die "$next has not been verified: run the rotation tool's mirror-verify --apply first"
    rotation_in_progress && die "a KEK rotation is running or did not finish"
    want="$(sed -n 's/.*"listing_sha256": *"\([0-9a-f]\{64\}\)".*/\1/p' "$mark")"
    have="$( (cd "$next" && find . -type f) | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
    [ -n "$want" ] && [ "$want" = "$have" ] || die "$next changed after it was verified (file list differs): verify it again"
    retired="$MIRROR.retired-$(date -u +%Y-%m-%dT%H%M%SZ)"
    if [ "${1:-}" != "--apply" ]; then
        log "DRY RUN: would rename $MIRROR -> $retired and $next -> $MIRROR (add --apply)"
        return 0
    fi
    confirm swap "${2:-}"
    if [ -e "$MIRROR" ]; then mv "$MIRROR" "$retired"; fi
    mv "$next" "$MIRROR"
    mv -f "$mark" "$MIRROR.verified"
    log "Mirror swapped: $MIRROR is the verified rebuild; the old mirror is kept as $retired (mirror-purge deletes it)."
}

# Only a directory whose whole name is evidence-mirror.retired-YYYY-MM-DDTHHMMSSZ (what mirror-swap
# creates) is ever a retired mirror (ROT-M3); anything else under that prefix is reported, never removed.
is_retired_mirror() {
    case "$1" in
        /backups/evidence-mirror.retired-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) return 0 ;;
    esac
    return 1
}

mirror_purge() {   # $1 = --apply, $2 = --yes
    list="$(find /backups -maxdepth 1 -type d -name 'evidence-mirror.retired-*' | LC_ALL=C sort)"
    [ -n "$list" ] || { log "No retired mirror to purge."; return 0; }
    [ -d "$MIRROR" ] && [ -f "$MIRROR.verified" ] || die "the current mirror is not a verified rebuild: refusing to purge the retired ones"
    IFS="$NL"
    for d in $list; do
        if is_retired_mirror "$d"; then log "retired mirror: $d ($(find "$d" -type f | wc -l) files)"
        else log "WARN: $d is not named like a retired mirror: left alone"; fi
    done
    if [ "${1:-}" != "--apply" ]; then
        unset IFS
        log "DRY RUN: nothing deleted (add --apply). Purge only when nothing in a retired mirror must still be retained and the old KEK is being destroyed (docs/evidence-kek-rotation.md §7)."
        return 0
    fi
    confirm purge "${2:-}"
    for d in $list; do
        is_retired_mirror "$d" || continue
        rm -rf -- "$d" && log "purged $d"
    done
    unset IFS
}

case "${1:-}" in
    "")             ;;                      # the scheduled run, below
    mirror-rebuild) mirror_rebuild; exit 0 ;;
    mirror-swap)    mirror_swap "${2:-}" "${3:-}"; exit 0 ;;
    mirror-purge)   mirror_purge "${2:-}" "${3:-}"; exit 0 ;;
    *)              echo "usage: backup.sh [mirror-rebuild | mirror-swap [--apply [--yes]] | mirror-purge [--apply [--yes]]]" >&2
                    exit 2 ;;
esac

# ROT-M1: a KEK rotation re-wraps files in place and changes rows: a dump taken meanwhile (or a mirror
# copy) would not match the evidence volume (R100). Skip the WHOLE run — no mirror, no dump, no success
# marker (the health check turns red after 26 h and the scheduler retries every hour).
skip_if_rotating() {   # $1 = when
    if [ -d "$EVID" ] && rotation_in_progress; then
        log "SKIPPED ($1): a KEK rotation is running or did not finish (lock or journal under /evidence). No mirror, no dump, no success marker this run."
        exit 0
    fi
}
skip_if_rotating "start of run"

# Encrypt at rest (ROT-L10): never write a plaintext dump. Without an age recipient the run fails loudly
# before it touches anything.
if [ -z "${BACKUP_AGE_RECIPIENT:-}" ]; then
    log "ERROR: BACKUP_AGE_RECIPIENT is not set: refusing to write an unencrypted database dump (see .env.example). No mirror, no dump, no success marker."
    exit 1
fi

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
    mkdir -p "$MIRROR"
    log "Mirroring /evidence (copy-new-only, files idle ≥10 min)..."
    errors=0
    IFS="$NL"   # newline-only splitting (and set -f): safe for any filename without a newline
    # In-progress writes and KEK-rotation state are never mirrored (evidence_files).
    for f in $(evidence_files -mmin +10); do
        [ -e "$MIRROR/$f" ] && continue
        mirror_copy "$MIRROR" "$f" || errors=$((errors + 1))
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

# ── 2. Database dump → age-encrypt → temp file → atomic rename ──────────────
# The dump is encrypted to the BACKUP_AGE_RECIPIENT PUBLIC key; the private identity
# is kept OFFLINE by the operator, so nobody on this host — not even root — can read
# the backups. pipefail makes this fail CLOSED: if age fails, nothing (and never a
# plaintext fallback) is written. ROT-M1: the rotation check runs again right before
# the dump (a rotation may have started while the mirror ran).
skip_if_rotating "before the dump"
OUT="/backups/fenrir_backup_$(date -u +%Y-%m-%d_%H-%M-%S).sql.gz.age"
trap 'rm -f "$OUT.tmp"' EXIT
log "Starting DB dump..."
pg_dump -h postgres -U "${PGUSER:-fenrir_backup}" -d fenrir --clean --if-exists --no-owner | gzip | age -r "$BACKUP_AGE_RECIPIENT" > "$OUT.tmp"
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

# ── 4. Disposed exhibits: purge their mirror copies after a grace period (owner, 2026-10-04) ──
# The mirror is copy-once and never pruned, so a destroyed exhibit's ciphertext would stay in it for
# ever. Once an exhibit has been destroyed for MIRROR_PURGE_GRACE_DAYS (default 30) its mirror copies
# (the file, a v0 .nonce sidecar, its photos) are deleted. Least privilege: this container owns the
# mirror and reads the evidence rows with its read-only DB role; it cannot write the audit chain, so it
# writes a receipt (root-owned 0444, /backups/mirror-purge-receipts/) that the backend checks and
# records as one `evidence_mirror_purged` custody row per exhibit. Never fatal; never on a rotation.
mirror_grace_purge() {
    grace="${MIRROR_PURGE_GRACE_DAYS:-30}"
    case "$grace" in ''|*[!0-9]*) log "WARN: MIRROR_PURGE_GRACE_DAYS must be a whole number of days (got '$grace'): mirror purge skipped."; return 0 ;; esac
    [ -d "$MIRROR" ] || return 0
    rotation_in_progress && { log "WARN: KEK rotation in progress: mirror purge skipped."; return 0; }
    rows="$(psql -h postgres -U "${PGUSER:-fenrir_backup}" -d fenrir -X -A -t -v ON_ERROR_STOP=1 -c \
        "SELECT id || ' ' || to_char(disposed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
           FROM evidence WHERE status = 'destroyed' AND disposed_at IS NOT NULL
            AND disposed_at < now() - make_interval(days => $grace) ORDER BY id")" \
        || { log "WARN: could not read the destroyed exhibits: mirror purge skipped."; return 0; }
    [ -n "$rows" ] || return 0
    rid="$(cat /proc/sys/kernel/random/uuid)"
    items=""; total=0; failed=0
    IFS="$NL"
    for row in $rows; do
        eid="${row%% *}"; destroyed_at="${row#* }"
        case "$eid" in
            [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
            *) log "WARN: unexpected evidence id from the database: skipped"; continue ;;
        esac
        # Every stored file of an exhibit is named by its id: <incident>/<id>__<name>.enc (+ .nonce),
        # emails/<id>.eml.enc, webhistory/<id>.db.enc, or sits in a directory named by it
        # (photos/<id>/<photo>.enc). -name / -path take the id literally (hex and dashes only, checked
        # above). The names reach stat / rm only as arguments of find -exec (never word-split: a stored
        # name may hold any character but "/").
        set -- -type f \( -name "${eid}__*" -o -name "${eid}.*" -o -path "*/${eid}/*" \)
        n="$(cd "$MIRROR" && find . "$@" -exec sh -c 'for f; do echo x; done' _ {} + | wc -l)"
        [ "$n" -gt 0 ] || continue
        bytes="$(cd "$MIRROR" && find . "$@" -exec stat -c %s -- {} + | awk '{s += $1} END {print s + 0}')"
        (cd "$MIRROR" && find . "$@" -exec rm -f -- {} +)
        left="$(cd "$MIRROR" && find . "$@" -exec sh -c 'for f; do echo x; done' _ {} + | wc -l)"
        (cd "$MIRROR" && find . -depth -type d -name "$eid" -exec rmdir -- {} + 2>/dev/null) || true
        failed=$((failed + left)); n=$((n - left))
        [ "$n" -gt 0 ] || continue
        items="${items}item ${eid} ${destroyed_at} ${n} ${bytes}${NL}"
        total=$((total + n))
        log "mirror purge: exhibit $eid (destroyed $destroyed_at): $n file(s), $bytes bytes"
    done
    unset IFS
    [ "$failed" -eq 0 ] || log "WARN: $failed mirror file(s) of destroyed exhibits could not be deleted; retried next run."
    [ -n "$items" ] || return 0
    dir=/backups/mirror-purge-receipts
    mkdir -p "$dir"
    name="$dir/$(date -u +%Y-%m-%dT%H%M%SZ)-$rid.receipt"
    if { printf 'FENRIR-MIRROR-PURGE-RECEIPT v1\nreceipt_id %s\npurged_at %s\ngrace_days %s\n' "$rid" "$(ts)" "$grace"
         printf '%s' "$items"; } > "$name.tmp" && chmod 0444 "$name.tmp" && mv "$name.tmp" "$name"; then
        log "mirror purge: $total file(s) deleted; receipt $name (the backend records it in the custody logs)"
    else
        rm -f "$name.tmp"
        log "ERROR: mirror purge deleted $total file(s) but could not write its receipt: record it by hand ($rid)."
    fi
}
mirror_grace_purge
log "Backup run complete."
