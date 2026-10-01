#!/usr/bin/env bash
# DFIR-FENRIR v2 — pin every base image to an immutable digest (supply chain).
#
# Rewrites each `FROM name:tag[@sha256:…]` in the Dockerfiles and each
# `image: name:tag[@sha256:…]` in docker-compose.yml to `name:tag@sha256:<current>`,
# where <current> is the registry's digest for that tag today. The tag stays for
# readability; the digest is what Docker actually pulls, so a re-pushed or
# hijacked tag can never change what we build.
#
# Monthly cadence (and before a release): run, review the diff, rebuild, then
# `make scan`. Our own images (dfir-fenrir-v2-*) are skipped.
#   scripts/refresh-digests.sh           # dry run: show current → latest
#   scripts/refresh-digests.sh --apply   # write the new digests
set -euo pipefail
cd "$(dirname "$0")/.."
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1

FILES=(backend/Dockerfile analysis-worker/Dockerfile frontend/Dockerfile docker/caddy/Dockerfile docker-compose.yml)
[ -f docker/backup/Dockerfile ] && FILES+=(docker/backup/Dockerfile)

APPLY="$APPLY" python3 - "${FILES[@]}" <<'PY'
import os, re, subprocess, sys
apply = os.environ["APPLY"] == "1"
pat = re.compile(r'^(?P<pre>\s*(?:FROM\s+|image:\s*))(?P<ref>[^\s@#]+)(?:@(?P<dig>sha256:[0-9a-f]{64}))?(?P<post>.*)$', re.I)
cache, changed = {}, 0
for path in sys.argv[1:]:
    lines, out = open(path).read().split("\n"), []
    for line in lines:
        m = pat.match(line)
        if not m or m["ref"].startswith("dfir-fenrir-v2") or m["ref"].lower() == "scratch" or ":" not in m["ref"]:
            out.append(line); continue
        ref = m["ref"]
        if ref not in cache:
            cache[ref] = subprocess.run(["bash", "-c", f'docker buildx imagetools inspect --raw "{ref}" | sha256sum'],
                                        capture_output=True, text=True, check=True).stdout.split()[0]
        new = "sha256:" + cache[ref]
        state = "unchanged" if m["dig"] == new else ("PINNED" if not m["dig"] else "UPDATED")
        print(f"{state:9} {path:28} {ref:45} {new[:19]}…")
        if m["dig"] != new: changed += 1
        out.append(f'{m["pre"]}{ref}@{new}{m["post"]}')
    if apply: open(path, "w").write("\n".join(out))
print(f"\n{changed} reference(s) {'rewritten' if apply else 'would change — re-run with --apply'}.")
PY
