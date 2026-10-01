#!/usr/bin/env bash
# DFIR-FENRIR v2 — prepare Caddy's volumes for a non-root, capability-free Caddy.
#
# Caddy runs as uid/gid 10001 with every capability dropped, so it can neither
# chown its volumes nor read root- or operator-owned key files. This one-shot:
#   1. chowns the caddy-data / caddy-config volumes to 10001 (ACME account +
#      certificates, Caddy's internal CA, autosave), and
#   2. installs the TLS files from ./certs (self-signed or BYO — everything except
#      the ca.* files) into caddy-config:/tls, owned by 10001, keys at 0400.
# ./certs itself is then never mounted into the internet-facing container.
#
# Re-run after ./generate-certs.sh or after replacing a BYO certificate.
# Idempotent. Uses the Docker access you already have (no sudo).
#   scripts/caddy-volume-prep.sh           # dry run: show what would happen
#   scripts/caddy-volume-prep.sh --apply   # do it
set -euo pipefail
cd "$(dirname "$0")/.."

APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
PROJECT="${COMPOSE_PROJECT_NAME:-dfir-fenrir-v2}"
CADDY_UID=10001
IMAGE="${PROJECT}-caddy"

FILES=""
for f in certs/*.crt certs/*.key certs/*.pem; do      # everything except the CA files
  [ -f "$f" ] || continue
  case "$(basename "$f")" in ca.*) continue;; esac
  FILES="${FILES:+$FILES }$(basename "$f")"
done
echo "Caddy volumes : ${PROJECT}_caddy-data, ${PROJECT}_caddy-config → owner ${CADDY_UID}:${CADDY_UID}"
echo "TLS files     : ${FILES:-(none — fine for acme / duckdns / internal modes)} → caddy-config:/tls"
if [ "$APPLY" -eq 0 ]; then echo "Dry run — re-run with --apply to make these changes."; exit 0; fi

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "image $IMAGE not built — run: docker compose build caddy" >&2; exit 1; }
# Let compose create the volumes (so they carry its labels) without starting anything.
docker compose create --no-recreate caddy >/dev/null 2>&1 || true

# Root for this one-shot only, with just the three capabilities it needs, no network.
docker run --rm --network none --user 0 --cap-drop ALL \
    --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    -v "${PROJECT}_caddy-data:/data" -v "${PROJECT}_caddy-config:/config" \
    -v "$PWD/certs:/src:ro" -e FILES="$FILES" -e U="$CADDY_UID" \
    --entrypoint sh "$IMAGE" -c '
        set -eu
        chown -R "$U:$U" /data /config
        install -d -o "$U" -g "$U" -m 0700 /config/tls
        for f in $FILES; do
            case "$f" in *.key) m=0400;; *) m=0444;; esac
            install -o "$U" -g "$U" -m "$m" "/src/$f" "/config/tls/$f"
        done
        ls -ln /config/tls'
echo "Done."
