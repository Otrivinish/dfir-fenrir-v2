#!/usr/bin/env bash
# DFIR-FENRIR v2 — functional smoke test over the public API (through Caddy).
#
# Drives the paths the container hardening can break: auth, incidents, artifact
# → analysis-worker, PCAP, evidence collect/verify/seal/export/download,
# Velociraptor collector generation (all platforms), forensic timeline + web
# history imports (/tmp users), manual backup, signed audit export, audit
# anchors, readiness and WebSocket routing.
#
# Idempotent: reuses ONE incident titled "[SMOKE] container hardening" and only
# appends test records to it (the wrong-target-hash upload is refused and stores
# nothing; it adds only an evidence_collect_rejected audit row). The phase-gate step uses its own dark incident,
# "[SMOKE] phase gates" (tag smoke-phase-gates), kept in C/E/R: it only sends
# moves the gates refuse, so nothing changes (the move into Post-Incident is sent
# only while GET …/gates shows Gate 1 unmet). Needs an admin API token:
#   FENRIR_TOKEN=fnr_v1_...  scripts/smoke-test.sh
#   FENRIR_TOKEN_FILE=path   scripts/smoke-test.sh
#   scripts/smoke-test.sh --big   # + 1 GiB evidence and 500 MiB PCAP (memory sizing)
# Exit code = number of FAILed steps.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIG=0; [ "${1:-}" = "--big" ] && BIG=1
TOKEN="${FENRIR_TOKEN:-}"
[ -z "$TOKEN" ] && [ -n "${FENRIR_TOKEN_FILE:-}" ] && TOKEN="$(tr -d '\r\n' < "$FENRIR_TOKEN_FILE")"
[ -n "$TOKEN" ] || { echo "Set FENRIR_TOKEN or FENRIR_TOKEN_FILE (admin API token)." >&2; exit 99; }
DOMAIN="$(grep -E '^DOMAIN=' "$ROOT/.env" 2>/dev/null | cut -d= -f2- || true)"; DOMAIN="${DOMAIN:-localhost}"
BASE="https://$DOMAIN"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CURL=(curl -sk --resolve "$DOMAIN:443:127.0.0.1" --max-time 600)
AUTH=(-H "Authorization: Bearer $TOKEN")

PASS=0; FAIL=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
# api METHOD PATH [curl args…] → prints HTTP code; body in $TMP/body
api() { local m="$1" p="$2"; shift 2; "${CURL[@]}" "${AUTH[@]}" -X "$m" -o "$TMP/body" -w '%{http_code}' "$@" "$BASE$p"; }
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    d = d[int(k)] if isinstance(d, list) else d.get(k)
print("" if d is None else d)' "$TMP/body" "$1" 2>/dev/null; }
detail() { head -c 300 "$TMP/body" | tr '\n' ' '; }
check() { # expected-code label code
  if [ "$3" = "$1" ]; then pass "$2 ($3)"; return 0; fi
  fail "$2 → $3, want $1: $(detail)"; return 1
}
RUN="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "Smoke test against $BASE — run $RUN"

# ── Liveness + auth ────────────────────────────────────────────────────────
c=$("${CURL[@]}" -o "$TMP/body" -w '%{http_code}' "$BASE/api/health"); check 200 "GET /api/health (anonymous)" "$c"
c=$(api GET /api/version); check 200 "GET /api/version" "$c"
c=$(api GET "/api/incidents?limit=1"); check 200 "Bearer token accepted" "$c"
c=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -H "Authorization: Bearer fnr_v1_invalid" "$BASE/api/incidents?limit=1")
check 401 "invalid token rejected" "$c"
# Failed login exercises the lockout counters in Redis (INCRBY + EXPIRE under the ACL).
c=$("${CURL[@]}" -o "$TMP/body" -w '%{http_code}' -H 'Content-Type: application/json' \
     -d '{"username":"smoke-no-such-user","password":"wrong-password-xx"}' "$BASE/api/auth/login")
check 401 "failed login rejected cleanly (lockout counter)" "$c"

# ── Incident (find or create) ──────────────────────────────────────────────
# I4: title, severity, incident_type, detection_method and detected_at are required at create.
NOW_Z="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
INTAKE="\"incident_type\":\"other\",\"detection_method\":\"other\",\"detected_at\":\"$NOW_Z\""
c=$(api POST /api/incidents -H 'Content-Type: application/json' -d '{"title":"[SMOKE] must be refused"}')
check 422 "create without the required intake fields refused" "$c" \
  && grep -q '"required_fields_missing"' "$TMP/body" && pass "refusal names required_fields_missing"
TITLE="[SMOKE] container hardening"
api GET "/api/incidents?limit=200" >/dev/null
INC="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next((i["id"] for i in d.get("items",[]) if i.get("title")==sys.argv[2]),""))' "$TMP/body" "$TITLE")"
if [ -z "$INC" ]; then
  c=$(api POST /api/incidents -H 'Content-Type: application/json' -d "{\"title\":\"$TITLE\",\"severity\":\"low\",$INTAKE,\"description\":\"Automated smoke-test incident (scripts/smoke-test.sh).\"}")
  check 201 "create smoke incident" "$c" && INC="$(jget id)"
else pass "reuse smoke incident $INC"; fi
[ -n "$INC" ] || { echo "no incident — aborting"; exit 98; }
I="/api/incidents/$INC"
c=$(api GET "$I/start-checks"); check 200 "GET incident-start checks (I4)" "$c"

# ── Phase gates (own dark incident, kept in C/E/R; only refused moves, so nothing changes) ─
GTAG="smoke-phase-gates"
# Only an open one can be reused (a closed one stays closed; the step then makes a new one).
api GET "/api/incidents?tag=$GTAG&status=open&limit=50" >/dev/null
GINC="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next((i["id"] for i in d.get("items",[]) if i.get("title")==sys.argv[2]),""))' "$TMP/body" "[SMOKE] phase gates")"
if [ -z "$GINC" ]; then
  c=$(api POST /api/incidents -H 'Content-Type: application/json' -d "{\"title\":\"[SMOKE] phase gates\",\"severity\":\"low\",$INTAKE,\"phase\":\"containment_eradication_recovery\",\"dark_operation\":true,\"tags\":[\"$GTAG\"],\"description\":\"Automated smoke-test incident for the phase gates (scripts/smoke-test.sh). Keep it in C/E/R.\"}")
  check 201 "create gate smoke incident" "$c" && GINC="$(jget id)"
else pass "reuse gate smoke incident $GINC"; fi
if [ -n "$GINC" ]; then
  G="/api/incidents/$GINC"
  G1_UNMET=0
  c=$(api GET "$G/gates"); check 200 "GET phase gates" "$c" \
    && { [ "$(python3 -c 'import json,sys; g={x["gate"]: x for x in json.load(open(sys.argv[1]))["items"]}; print(set(g) == {"post_incident","close"} and g["post_incident"]["met"] is False and "recovered_at_missing" in [u["key"] for u in g["post_incident"]["unmet"]])' "$TMP/body")" = "True" ] \
         && { G1_UNMET=1; pass "Gate 1 unmet, lists recovered_at_missing"; } || fail "unexpected gate status: $(detail)"; }
  c=$(api GET "$G"); ph="$(jget phase)"
  if [ "$ph" = "containment_eradication_recovery" ] && [ "$(jget status)" = "open" ]; then
    # Only while Gate 1 is unmet is the move refused; otherwise it would really move the incident.
    if [ "$G1_UNMET" = 1 ]; then
      c=$(api PATCH "$G" -H 'Content-Type: application/json' -d '{"phase":"post_incident"}')
      check 409 "move to Post-Incident blocked by Gate 1" "$c" && { [ "$(jget code)" = "gate_unmet" ] && pass "409 code gate_unmet" || fail "code $(jget code): $(detail)"; }
      c=$(api PATCH "$G" -H 'Content-Type: application/json' -d '{"phase":"post_incident","phase_reason":"smoke test: reason without the override flag"}')
      check 409 "a reason without override_gate does not override" "$c"
    else
      echo "  NOTE skipped the refused-move checks: Gate 1 is not shown unmet on $GINC, so a move to Post-Incident could succeed"
    fi
    c=$(api PATCH "$G" -H 'Content-Type: application/json' -d '{"phase":"preparation"}')
    check 409 "move to Preparation refused" "$c" && { [ "$(jget code)" = "phase_transition_invalid" ] && pass "409 code phase_transition_invalid" || fail "code $(jget code): $(detail)"; }
  else fail "gate smoke incident $GINC is no longer an open C/E/R incident (phase $ph) — move it back to C/E/R"; fi
fi

# ── Artifact → analysis worker ─────────────────────────────────────────────
printf 'MZ\x90\x00smoke %s http://evil.example.com/payload 10.66.66.66 powershell -enc AAAA\n' "$RUN" > "$TMP/smoke.bin"
c=$(api POST "$I/artifacts" -F "file=@$TMP/smoke.bin;filename=smoke.bin" -F "description=smoke $RUN")
if check 201 "upload artifact (quarantine write)" "$c"; then
  ART="$(jget id)"
  for tool in file-type hashes strings ioc-extract yara; do
    c=$(api POST "$I/artifacts/$ART/analyze/$tool"); check 200 "worker analyze/$tool" "$c"
  done
fi

# ── Incident YARA scan (backend → worker /analyze/yara-inline) ─────────────
api GET "/api/yara" >/dev/null
if ! grep -q '"smoke_evil_url"' "$TMP/body"; then
  c=$(api POST /api/yara -H 'Content-Type: application/json' \
       -d '{"name":"smoke_evil_url","description":"smoke-test rule","rule_content":"rule smoke_evil_url { strings: $a = \"evil.example.com\" condition: $a }"}')
  check 201 "create smoke YARA rule" "$c"
fi
c=$(api POST "$I/yara/scan"); check 200 "incident YARA scan via worker" "$c" \
  && { [ "$(jget matches_found)" -gt 0 ] 2>/dev/null && [ "$(jget errors)" = "[]" ] \
         && pass "YARA scan found matches with no worker errors" || fail "YARA scan: $(detail)"; }

# ── PDF → analysis worker (pdfminer) + exif (exiftool) ─────────────────────
python3 - "$TMP/smoke.pdf" <<'PY'
import sys
stream = b"BT /F1 12 Tf 20 100 Td (smoke http://evil.example.com/pdf) Tj ET"
objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R"
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
out, offs = bytearray(b"%PDF-1.4\n"), []
for i, o in enumerate(objs, 1):
    offs.append(len(out)); out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
xref = len(out)
out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offs)
out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
open(sys.argv[1], "wb").write(out)
PY
c=$(api POST "$I/artifacts" -F "file=@$TMP/smoke.pdf;filename=smoke.pdf" -F "description=smoke pdf $RUN")
if check 201 "upload PDF artifact" "$c"; then
  PDF="$(jget id)"
  c=$(api POST "$I/artifacts/$PDF/analyze/pdf"); check 200 "worker analyze/pdf (pdfminer)" "$c" \
    && { grep -q "evil.example.com" "$TMP/body" && pass "pdfminer extracted the PDF text" || fail "pdf text not extracted: $(detail)"; }
  c=$(api POST "$I/artifacts/$PDF/analyze/exif"); check 200 "worker analyze/exif (exiftool)" "$c"
fi

# ── PCAP → analysis worker (tshark) ────────────────────────────────────────
python3 - "$TMP/smoke.pcap" <<'PY'
import struct, sys
ip  = bytes.fromhex("4500003c1c4640004011b1e6c0a80001c0a80002")
udp = struct.pack("!HHHH", 5353, 53, 40, 0)
dns = bytes.fromhex("abcd01000001000000000000") + b"\x04evil\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
frame = b"\x00"*12 + b"\x08\x00" + ip + udp + dns
with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    f.write(struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame)
PY
c=$(api POST "$I/pcap" -F "file=@$TMP/smoke.pcap;filename=smoke.pcap"); check 201 "PCAP analysis via worker" "$c"

# ── Evidence: collect → verify → seal → export → download ──────────────────
evidence_cycle() {  # file label
  local f="$1" label="$2" ev dl sha
  sha="$(sha256sum "$f" | cut -d' ' -f1)"
  c=$(api POST "$I/evidence/digital" -F "file=@$f;filename=$(basename "$f")" -F "name=smoke $label $RUN" \
       -F "identifier=SMOKE-$label-$RUN" -F "acquisition_tool=smoke-test.sh" -F "acquisition_tool_version=1" \
       -F "acquisition_hash_source=$sha" -F "acquisition_hash_target=$sha" -F "system_state=off" \
       -F 'device_types=["computer"]' -F "handling_mode=collect" -F "lawful_basis=consent")
  check 201 "evidence collect $label (KEK encrypt)" "$c" || return
  ev="$(jget id)"
  [ "$(jget upload_hash_check)" = "match" ] && pass "evidence $label upload_hash_check = match" \
    || fail "evidence $label upload_hash_check = '$(jget upload_hash_check)', want match"
  c=$(api POST "$I/evidence/$ev/verify"); check 200 "evidence verify $label (KEK decrypt)" "$c" \
    && { [ "$(jget ok)" = "True" ] && pass "evidence $label hash matches" || fail "evidence $label hash mismatch: $(detail)"; }
  c=$(api POST "$I/evidence/$ev/seal" -H 'Content-Type: application/json' -d '{"confirm":true}'); check 200 "evidence seal $label" "$c"
  c=$(api POST "$I/evidence/exports" -H 'Content-Type: application/json' \
       -d "{\"item_ids\":[\"$ev\"],\"recipient\":\"smoke\",\"purpose\":\"smoke test $RUN\",\"acknowledgments\":\"smoke\"}")
  if check 201 "evidence export bundle $label" "$c"; then
    dl="$(jget download_url)"
    c=$("${CURL[@]}" -o "$TMP/export.zip" -w '%{http_code}' "$BASE$dl"); check 200 "evidence export download $label" "$c"
  fi
}
head -c 65536 /dev/urandom > "$TMP/evidence.bin"
evidence_cycle "$TMP/evidence.bin" small
# A target hash that doesn't match the uploaded bytes is refused before anything is encrypted
# or written (C3): 422 hash_mismatch, nothing stored, one evidence_collect_rejected audit row.
c=$(api POST "$I/evidence/digital" -F "file=@$TMP/evidence.bin;filename=evidence-wrong-target.bin" \
     -F "name=smoke wrong target $RUN" -F "identifier=SMOKE-wrong-target-$RUN" \
     -F "acquisition_hash_target=$(printf '%064d' 0)")
check 422 "evidence collect with a wrong target hash refused" "$c" \
  && { [ "$(jget code)" = "hash_mismatch" ] && pass "422 code hash_mismatch" || fail "code $(jget code): $(detail)"; }
if [ "$BIG" -eq 1 ]; then
  # just under the backend's 1 GiB evidence cap (an exact 1 GiB file is rejected by design)
  head -c $((1023*1024*1024)) /dev/urandom > "$TMP/evidence-1g.bin"; evidence_cycle "$TMP/evidence-1g.bin" 1023MiB; rm -f "$TMP/evidence-1g.bin"
  python3 - "$TMP/big.pcap" <<'PY'
import os, struct, sys
payload = os.urandom(1400)
frame = b"\x00"*12 + b"\x08\x00" + bytes.fromhex("45000570000040004011000ac0a80001c0a80002") + struct.pack("!HHHH", 1234, 80, 1400+8, 0) + payload
with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    rec = struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame
    for _ in range((500*1024*1024) // len(rec)): f.write(rec)
PY
  c=$(api POST "$I/pcap" -F "file=@$TMP/big.pcap;filename=big.pcap"); check 201 "PCAP 500 MiB via worker" "$c"; rm -f "$TMP/big.pcap"
fi

# ── Velociraptor collectors (writes the datastore; one-time download) ──────
for plat in windows macos_arm; do
  c=$(api POST "$I/collections" -H 'Content-Type: application/json' -d "{\"name\":\"smoke-$plat\",\"profile\":\"triage\",\"platform\":\"$plat\"}")
  if check 201 "collector generate $plat" "$c"; then
    dl="$(jget download_url)"; [ -z "$dl" ] && dl="$(jget package.download_url)"
    if [ -n "$dl" ]; then
      c=$("${CURL[@]}" -o "$TMP/coll.zip" -w '%{http_code}' "$BASE$dl"); check 200 "collector download $plat" "$c"
    else fail "collector $plat: no download_url in response: $(detail)"; fi
  fi
done

# ── Forensic timeline import (.db → tempfile) + web history (sqlite) ───────
python3 - "$TMP/History.db" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.executescript("""
CREATE TABLE urls(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR, visit_count INTEGER DEFAULT 0,
  typed_count INTEGER DEFAULT 0, last_visit_time INTEGER, hidden INTEGER DEFAULT 0);
CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER DEFAULT 0,
  segment_id INTEGER, visit_duration INTEGER DEFAULT 0);
CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid VARCHAR, current_path LONGVARCHAR, target_path LONGVARCHAR,
  start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER,
  interrupt_reason INTEGER, end_time INTEGER, opened INTEGER, referrer VARCHAR, tab_url VARCHAR, mime_type VARCHAR);
CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term LONGVARCHAR, normalized_term LONGVARCHAR);
INSERT INTO urls VALUES(1,'http://evil.example.com/payload','payload',1,0,13370000000000000,0);
INSERT INTO visits VALUES(1,1,13370000000000000,0,1,0,0);
""")
db.commit(); db.close()
PY
c=$(api POST "$I/forensic/timeline-import/parse" -F "file=@$TMP/History.db;filename=History.db"); check 200 "timeline-import parse .db (tempfile)" "$c"
c=$(api POST "$I/webhistory" -F "file=@$TMP/History.db;filename=History" -F "browser=chrome"); check 201 "web-history import (tempfile)" "$c"

# ── Manual backup (backend pg_dump) ────────────────────────────────────────
c=$(api POST /api/admin/backups/run); check 202 "manual backup triggered" "$c"
ok=0; st=""
for _ in $(seq 1 30); do
  sleep 2; api GET /api/admin/backups >/dev/null
  st="$(python3 -c 'import json,sys; b=json.load(open(sys.argv[1])).get("backups",[]); print(max((x.get("created_at","") for x in b), default=""))' "$TMP/body")"
  [[ "$st" > "$RUN" || "$st" == "$RUN" ]] && { ok=1; break; }
done
[ "$ok" -eq 1 ] && pass "manual backup completed" || fail "no backup newer than $RUN (newest: ${st:-none})"

# ── Signed audit-log export + anchors ──────────────────────────────────────
c=$(api POST "$I/audit-log/exports" -H 'Content-Type: application/json' -d "{\"purpose\":\"smoke test $RUN\"}")
if check 201 "signed audit-log export" "$c"; then
  dl="$(jget download_url)"
  c=$("${CURL[@]}" -o "$TMP/audit.zip" -w '%{http_code}' "$BASE$dl"); check 200 "audit export download" "$c"
fi
c=$(api GET /api/admin/audit/anchors); check 200 "list audit anchors" "$c" \
  && { n="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("items",[])))' "$TMP/body")"; [ "$n" -gt 0 ] && pass "$n audit anchor(s) recorded" || fail "no audit anchors"; }

# ── Readiness (read-only; computed fresh, shown never enforced) ────────────
c=$(api GET /api/readiness); check 200 "GET readiness" "$c" \
  && { [ "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); c=d.get("checks",[]); print(len(c) >= 11 and all({"id","level","status","csf"} <= set(x) for x in c) and "blockers_failing" in d.get("summary",{}))' "$TMP/body")" = "True" ] \
         && pass "readiness lists its checks with a summary" || fail "readiness body: $(detail)"; }

# ── Contacts directory (E2; read-only list) ────────────────────────────────
c=$(api GET /api/contacts); check 200 "GET contacts directory" "$c" \
  && { [ "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(set(d) == {"items","next_cursor"})' "$TMP/body")" = "True" ] \
         && pass "contacts directory returns {items, next_cursor}" || fail "contacts body: $(detail)"; }

# ── WebSocket routing through Caddy (no cookie → must reach backend, not 404/502) ─
c=$("${CURL[@]}" -o /dev/null -w '%{http_code}' --http1.1 --max-time 5 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
     -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: c21va2V0ZXN0a2V5MDAwMA==' "$BASE/api/notifications/ws" || true)
case "$c" in 404|502|503|000) fail "WS /api/notifications/ws routed badly ($c)";; *) pass "WS /api/notifications/ws reaches backend ($c)";; esac

printf '\n\033[1mSmoke summary:\033[0m %d pass, %d fail\n' "$PASS" "$FAIL"
exit "$FAIL"
