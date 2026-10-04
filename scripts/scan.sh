#!/usr/bin/env bash
# DFIR-FENRIR v2 — supply-chain scan of everything the stack runs.
#
#   hadolint  Dockerfile lint                      (config: .hadolint.yaml)
#   grype     known vulnerabilities in each image  (config: .grype.yaml — dated exceptions)
#   dockle    image hygiene / CIS image checks     (config: .dockleignore)
#   syft      SBOM per image (SPDX JSON)           (--sbom)
#
# Scanners never get the Docker socket (that would make them root-equivalent on
# the host): images are exported with `docker save` and mounted read-only. Tools
# are pinned by digest. Grype's vulnerability DB is cached in the volume
# `fenrir-grype-db`; with --offline the cached DB is used without network.
#
# Fails (non-zero) on any hadolint error, any dockle FATAL, or any fixable
# High/Critical vulnerability that is not excepted in .grype.yaml.
#   scripts/scan.sh [--sbom] [--offline]
# Reports: scan-reports/<UTC timestamp>/
set -uo pipefail
cd "$(dirname "$0")/.." || exit 99

GRYPE=anchore/grype:v0.118.0@sha256:8a93fc48da96bd6ec5981279d099b69de11541dc68fdf222fb9161f8ff284af7
SYFT=anchore/syft:v1.51.1@sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c
HADOLINT=hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d
DOCKLE=goodwithtech/dockle:v0.4.15@sha256:eade932f793742de0aa8755406c7677cd7696f8675b6180926f7eeffa7abe6b9

SBOM=0; OFFLINE=0
for a in "$@"; do case "$a" in --sbom) SBOM=1;; --offline) OFFLINE=1;; *) echo "unknown arg $a" >&2; exit 2;; esac; done
FAILS=0
OUT="scan-reports/$(date -u +%Y-%m-%dT%H-%M-%SZ)"; mkdir -p "$OUT"

# ── 0. Exception hygiene: every .grype.yaml exception must be unexpired ──────
TODAY="$(date -u +%Y-%m-%d)"
while read -r exp; do
  if [[ "$exp" < "$TODAY" ]]; then echo "FAIL  .grype.yaml exception expired on $exp — upgrade or renew with evidence"; FAILS=$((FAILS+1)); fi
done < <(grep -oE 'expires: [0-9]{4}-[0-9]{2}-[0-9]{2}' .grype.yaml | cut -d' ' -f2)
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
note() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ── 1. Dockerfiles ──────────────────────────────────────────────────────────
note "hadolint"
for f in backend/Dockerfile analysis-worker/Dockerfile frontend/Dockerfile docker/caddy/Dockerfile docker/*/Dockerfile; do
  [ -f "$f" ] || continue
  if docker run --rm -i -v "$PWD/.hadolint.yaml:/.config/hadolint.yaml:ro" "$HADOLINT" hadolint --config /.config/hadolint.yaml - < "$f" > "$TMP/h.txt" 2>&1; then
    echo "  OK    $f"
  else echo "  FAIL  $f"; sed 's/^/        /' "$TMP/h.txt"; FAILS=$((FAILS+1)); fi
done | sort -u

# ── 2. Images ───────────────────────────────────────────────────────────────
mapfile -t IMAGES < <(docker compose config --images | sort -u)
docker volume create fenrir-grype-db >/dev/null
GRYPE_ENV=(-e GRYPE_DB_CACHE_DIR=/db)
[ "$OFFLINE" -eq 1 ] && GRYPE_ENV+=(-e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_DB_VALIDATE_AGE=false)

for img in "${IMAGES[@]}"; do
  name="$(echo "${img%@*}" | tr '/:' '__')"
  note "$img"
  docker image inspect "$img" >/dev/null 2>&1 || { echo "  SKIP  not present locally (build/pull first)"; continue; }
  docker save "$img" -o "$TMP/img.tar"

  docker run --rm "${GRYPE_ENV[@]}" -v fenrir-grype-db:/db -v "$TMP/img.tar:/img.tar:ro" \
      -v "$PWD/.grype.yaml:/.grype.yaml:ro" "$GRYPE" docker-archive:/img.tar -c /.grype.yaml \
      -o json > "$OUT/grype-$name.json" 2>"$TMP/g.err"
  if [ ! -s "$OUT/grype-$name.json" ]; then echo "  FAIL  grype did not run:"; tail -3 "$TMP/g.err" | sed 's/^/        /'; FAILS=$((FAILS+1))
  else
    # Policy: fail only on High/Critical that HAVE a fix and are not excepted in .grype.yaml,
    # and on an image-scoped exception ("[image <name:tag>]" reason) applied to another image.
    python3 - "$OUT/grype-$name.json" "$img" > "$TMP/g.txt" <<'PY2'
import json, re, sys, collections
d = json.load(open(sys.argv[1]))
image = sys.argv[2].split("@")[0]
SCOPE = re.compile(r"\[image ([^\]]+)\]")
stray = sorted({(s[1], m["vulnerability"]["id"], m["artifact"]["name"])
                for m in d.get("ignoredMatches", []) for r in m.get("appliedIgnoreRules", [])
                if (s := SCOPE.match(r.get("reason") or "")) and s[1] != image})
sev = collections.Counter(m["vulnerability"]["severity"] for m in d["matches"])
bad = sorted({(m["vulnerability"]["severity"], m["vulnerability"]["id"], m["artifact"]["name"], m["artifact"]["version"],
               ",".join(m["vulnerability"]["fix"].get("versions", [])))
              for m in d["matches"] if m["vulnerability"]["severity"] in ("High", "Critical")
              and m["vulnerability"]["fix"]["state"] == "fixed"})
print(f"{sum(sev.values())} findings ({', '.join(f'{k} {v}' for k, v in sorted(sev.items()))}); "
      f"{len(d.get('ignoredMatches', []))} excepted; {len(bad)} fixable High/Critical"
      + (f"; {len(stray)} excepted by another image's exception" if stray else ""))
for b in bad: print(f"        {b[0]:8} {b[1]:20} {b[2]} {b[3]} → fix {b[4]}")
for st in stray: print(f"        scoped to {st[0]}, not {image}: {st[1]} {st[2]}")
sys.exit(1 if bad or stray else 0)
PY2
    if [ $? -eq 0 ]; then echo "  OK    grype: $(head -1 "$TMP/g.txt")"
    else echo "  FAIL  grype: $(head -1 "$TMP/g.txt")"; tail -n +2 "$TMP/g.txt" | head -15; FAILS=$((FAILS+1)); fi
  fi

  docker run --rm -v "$TMP/img.tar:/img.tar:ro" -v "$PWD/.dockleignore:/.dockleignore:ro" -w / \
      "$DOCKLE" --input /img.tar --exit-code 1 --exit-level fatal \
      --accept-file settings.py --accept-key KEY_SHA512 > "$OUT/dockle-$name.txt" 2>&1
  # (accepted: pdfminer's settings.py filename and nginx's KEY_SHA512 checksum ENV
  #  trip dockle's credential heuristic CIS-DI-0010 — neither holds a secret.)
  if [ $? -eq 0 ]; then echo "  OK    dockle: $(grep -cE '^(WARN|INFO)' "$OUT/dockle-$name.txt") warn/info, no FATAL"
  else echo "  FAIL  dockle FATAL:"; grep -E '^FATAL' -A2 "$OUT/dockle-$name.txt" | sed 's/^/        /'; FAILS=$((FAILS+1)); fi

  if [ "$SBOM" -eq 1 ]; then
    docker run --rm -v "$TMP/img.tar:/img.tar:ro" "$SYFT" docker-archive:/img.tar -o spdx-json > "$OUT/sbom-$name.spdx.json" 2>/dev/null \
      && echo "  SBOM  $OUT/sbom-$name.spdx.json"
  fi
  rm -f "$TMP/img.tar"
done

note "Result: $FAILS failing check(s) — reports in $OUT"
exit "$FAILS"
