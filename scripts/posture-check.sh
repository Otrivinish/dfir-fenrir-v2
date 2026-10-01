#!/usr/bin/env bash
# DFIR-FENRIR v2 — container security posture check (READ-ONLY).
#
# Asserts the hardening baseline from harderning-plan.md against the RUNNING
# stack: secrets out of container env/argv, caps/no-new-privileges/read-only/
# limits/log rotation per service, health, TLS 1.3-only edge, network
# reachability matrix, backup freshness, image drift, CA-key exposure and a
# live rate limiter. Changes nothing; safe to run any time, any number of times.
#
# Usage:  scripts/posture-check.sh            # full check
#         scripts/posture-check.sh --no-burst # skip the anonymous 429 burst
# Exit code = number of FAILed checks (0 = posture OK).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 99
PROJECT="dfir-fenrir-v2"
BURST=1; [ "${1:-}" = "--no-burst" ] && BURST=0

PASS=0; FAIL=0; SKIP=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$*"; SKIP=$((SKIP+1)); }
section() { printf '\n\033[1m%s\033[0m\n' "$*"; }

env_get() { grep -E "^$1=" .env 2>/dev/null | head -n1 | cut -d= -f2- || true; }
DOMAIN="$(env_get DOMAIN)"; DOMAIN="${DOMAIN:-localhost}"

# Running containers of this compose project → service name map.
mapfile -t CONTAINERS < <(docker ps --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}}' | sort)
svc_of() { docker inspect "$1" --format '{{index .Config.Labels "com.docker.compose.service"}}'; }
cid_of() {  # service → running container name
  local s="$1" c
  for c in "${CONTAINERS[@]}"; do [ "$(svc_of "$c")" = "$s" ] && { echo "$c"; return; }; done
}

# ── 1. Secrets ─────────────────────────────────────────────────────────────
section "1. Secrets (values never printed)"
SECRET_NAMES="POSTGRES_PASSWORD REDIS_PASSWORD SECRET_KEY EVIDENCE_KEK AUDIT_SIGNING_KEY DUCKDNS_TOKEN PGPASSWORD"
declare -a SECRET_VALUES=()
for k in $SECRET_NAMES; do
  v="$(env_get "$k")"
  case "$v" in ""|change_me_*) ;; *) SECRET_VALUES+=("$v");; esac
done
if [ -d secrets ]; then
  for f in secrets/*; do
    [ -f "$f" ] || continue
    case "$f" in *.acl|*acl) continue;; esac   # ACL file holds only a sha256 of the password
    v="$(tr -d '\r\n' < "$f")"; [ -n "$v" ] && SECRET_VALUES+=("$v")
  done
fi
if [ "${#SECRET_VALUES[@]}" -eq 0 ]; then
  skip "no secret values found in .env / secrets/ to compare against"
else
  for c in "${CONTAINERS[@]}"; do
    blob="$(docker inspect "$c" --format '{{json .Config.Env}}{{json .Config.Cmd}}{{json .Config.Entrypoint}}{{json .Args}}{{json .Config.Healthcheck}}')"
    leak=0
    for v in "${SECRET_VALUES[@]}"; do grep -qF -- "$v" <<<"$blob" && leak=$((leak+1)); done
    # secret-named vars that actually carry a value (an empty placeholder is harmless)
    names="$(docker inspect "$c" --format '{{range .Config.Env}}{{println .}}{{end}}' | grep -E "^($(echo $SECRET_NAMES | tr ' ' '|')|DATABASE_URL)=." | cut -d= -f1 | tr '\n' ' ')"
    if [ "$leak" -eq 0 ] && [ -z "$names" ]; then pass "$c: no secret values or secret-named vars in env/argv/healthcheck"
    else fail "$c: $leak secret value(s) exposed; secret-named vars: ${names:-none}"; fi
  done
  hostleak=0
  for v in "${SECRET_VALUES[@]}"; do ps -eo args= | grep -v grep | grep -qF -- "$v" && hostleak=$((hostleak+1)); done
  [ "$hostleak" -eq 0 ] && pass "no secret value visible in host process list (ps)" || fail "$hostleak secret value(s) visible in host 'ps'"
fi
m="$(stat -c %a .env 2>/dev/null || echo missing)"
[ "$m" = "600" ] && pass ".env mode 600" || fail ".env mode is $m (want 600)"
if [ -d secrets ]; then
  m="$(stat -c %a secrets)"; [ "$m" = "700" ] && pass "secrets/ mode 700" || fail "secrets/ mode is $m (want 700)"
fi

# ── 2. Runtime hardening per container ─────────────────────────────────────
section "2. Runtime hardening (CIS Docker §5)"
ROOT_OK="backup"                      # needs root for first-run chown of /backups
for c in "${CONTAINERS[@]}"; do
  s="$(svc_of "$c")"
  read -r user capdrop secopt ro mem pids logmax < <(docker inspect "$c" --format \
    '{{if .Config.User}}{{.Config.User}}{{else}}root{{end}} {{json .HostConfig.CapDrop}} {{json .HostConfig.SecurityOpt}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.Memory}} {{if .HostConfig.PidsLimit}}{{.HostConfig.PidsLimit}}{{else}}0{{end}} {{if index .HostConfig.LogConfig.Config "max-size"}}{{index .HostConfig.LogConfig.Config "max-size"}}{{else}}none{{end}}')
  probs=()
  grep -q '"ALL"' <<<"$capdrop" || probs+=("cap_drop!=ALL")
  grep -q 'no-new-privileges' <<<"$secopt" || probs+=("no-new-privileges missing")
  [ "$ro" = "true" ] || probs+=("rootfs writable")
  [ "$mem" -gt 0 ] 2>/dev/null || probs+=("no mem limit")
  [ "$pids" -gt 0 ] 2>/dev/null || probs+=("no pids limit")
  [ "$logmax" != "none" ] || probs+=("no log rotation")
  case "$user" in root|0|0:*) [[ " $ROOT_OK " == *" $s "* ]] || probs+=("runs as root");; esac
  [ "${#probs[@]}" -eq 0 ] && pass "$c (user=$user)" || fail "$c: ${probs[*]}"
done

# ── 3. Health ───────────────────────────────────────────────────────────────
section "3. Health"
for c in "${CONTAINERS[@]}"; do
  h="$(docker inspect "$c" --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}')"
  case "$h" in healthy) pass "$c healthy";; none) fail "$c has no healthcheck";; *) fail "$c is $h";; esac
done
be="$(cid_of backend)"; am="$(cid_of audit-monitor)"
if [ -n "$be" ] && [ -n "$am" ]; then
  [ "$(docker inspect "$be" --format '{{.Image}}')" = "$(docker inspect "$am" --format '{{.Image}}')" ] \
    && pass "backend and audit-monitor run the same image" || fail "audit-monitor image differs from backend (drift)"
fi

# ── 4. Edge TLS / headers ──────────────────────────────────────────────────
section "4. Edge (https://$DOMAIN via 127.0.0.1:443)"
# openssl prints "Protocol: TLSv1.2" even for a REFUSED handshake — judge by the
# negotiated cipher on the "New, <proto>, Cipher is <x>" line instead.
t12="$(timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" -tls1_2 </dev/null 2>/dev/null | grep -E '^New, ' | head -1)"
t13="$(timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$DOMAIN" -tls1_3 </dev/null 2>/dev/null | grep -E '^New, ' | head -1)"
grep -qE '^New, TLSv1\.2, Cipher is [A-Z0-9]' <<<"$t12" && fail "TLS 1.2 accepted ($t12)" || pass "TLS 1.2 rejected"
grep -qE '^New, TLSv1\.3, Cipher is [A-Z0-9]' <<<"$t13" && pass "TLS 1.3 negotiated" || fail "TLS 1.3 handshake failed ($t13)"
hdrs="$(curl -sk -o /dev/null -D - --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" 2>/dev/null)"
csp="$(grep -i '^content-security-policy:' <<<"$hdrs")"
if grep -qiE "connect-src[^;]*(wss:|ws:)" <<<"$csp"; then fail "CSP connect-src allows ws:/wss: to any host"
elif [ -n "$csp" ]; then pass "CSP connect-src restricted to 'self'"; else fail "no CSP header"; fi
grep -qi '^strict-transport-security:' <<<"$hdrs" && pass "HSTS present" || fail "HSTS missing"
ca="$(cid_of caddy)"
if [ -n "$ca" ]; then
  docker exec "$ca" sh -c 'ls /certs/ca.key >/dev/null 2>&1' && fail "local CA private key visible inside caddy" || pass "local CA key not visible inside caddy"
fi
if [ "$BURST" -eq 1 ]; then
  n429=0
  for _ in $(seq 1 45); do
    code="$(curl -sk -o /dev/null -w '%{http_code}' --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/api/auth/policy")"
    [ "$code" = "429" ] && n429=$((n429+1))
  done
  [ "$n429" -gt 0 ] && pass "rate limiter alive (anonymous burst → $n429× 429)" || fail "no 429 after 45 anonymous requests (limiter failing open?)"
else skip "rate-limit burst (--no-burst)"; fi

# ── 5. Network reachability matrix ─────────────────────────────────────────
section "5. Network reachability (DENY = must not connect)"
probe() {  # container host port → rc 0 when a TCP connection succeeds
  docker exec "$1" sh -c '
    if command -v nc >/dev/null 2>&1; then nc -z -w 2 "$0" "$1"
    elif command -v python3 >/dev/null 2>&1; then python3 -c "import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 2)" "$0" "$1" 2>/dev/null
    else exit 2; fi' "$2" "$3" >/dev/null 2>&1
}
expect() {  # svc host port ALLOW|DENY
  local c; c="$(cid_of "$1")"; [ -n "$c" ] || { skip "$1 not running"; return; }
  if probe "$c" "$2" "$3"; then got=ALLOW; else got=DENY; fi
  [ "$got" = "$4" ] && pass "$1 → $2:$3 $got" || fail "$1 → $2:$3 is $got (want $4)"
}
INET=1.1.1.1
expect caddy backend 8000 ALLOW
expect caddy frontend 3000 ALLOW
expect caddy postgres 5432 DENY
expect caddy redis 6379 DENY
expect frontend postgres 5432 DENY
expect frontend redis 6379 DENY
expect analysis-worker postgres 5432 DENY
expect analysis-worker "$INET" 443 DENY
expect postgres "$INET" 443 DENY
expect redis "$INET" 443 DENY
expect backup "$INET" 443 DENY
expect backend postgres 5432 ALLOW
expect backend redis 6379 ALLOW
expect backend analysis-worker 8001 ALLOW
expect backup postgres 5432 ALLOW
be_c="$(cid_of backend)"
if [ -n "$be_c" ]; then  # the worker must authenticate its caller, not trust the network
  code="$(docker exec "$be_c" python -c "
import ssl, urllib.request as u
c = ssl.create_default_context(cafile='/run/secrets/tls_ca_crt')
try: print(u.urlopen(u.Request('https://analysis-worker:8001/analyze/hashes', data=b'{}', headers={'Content-Type': 'application/json'}), timeout=5, context=c).status)
except Exception as e: print(getattr(e, 'code', e))" 2>&1)"
  [ "$code" = "401" ] && pass "analysis-worker rejects unauthenticated calls (401)" || fail "analysis-worker answered an unauthenticated call with $code"
fi
expect audit-monitor postgres 5432 ALLOW
expect audit-monitor "$INET" 443 DENY

# ── 6. Backups ──────────────────────────────────────────────────────────────
section "6. Backups"
bk="$(cid_of backup)"
if [ -n "$bk" ]; then
  last="$(docker exec "$bk" sh -c 'cat /backups/.last_success 2>/dev/null' || true)"
  if [ -z "$last" ]; then fail "no /backups/.last_success marker"
  else
    age=$(( $(date -u +%s) - $(date -u -d "$last" +%s 2>/dev/null || echo 0) ))
    [ "$age" -lt $((26*3600)) ] && pass "last successful backup $last (${age}s ago)" || fail "last successful backup $last is older than 26 h"
  fi
  plain="$(docker exec "$bk" sh -c 'ls /backups/fenrir_backup_*.sql.gz 2>/dev/null | wc -l')"
  enc="$(docker exec "$bk" sh -c 'ls /backups/fenrir_backup_*.sql.gz.age 2>/dev/null | wc -l')"
  [ "$enc" -gt 0 ] && pass "$enc age-encrypted dump(s) present" || fail "no age-encrypted dumps"
  [ "$plain" -eq 0 ] && pass "no plaintext dumps" || fail "$plain plaintext dump(s) in /backups"
else skip "backup container not running"; fi

# ── 7. Database least privilege (probes are no-ops or rolled back) ──────────
section "7. Database least privilege"
dbprobe() {  # role secret sql → psql output (password via stdin, never argv)
  docker exec -i "$(cid_of backend)" sh -c 'read -r PGPASSWORD; export PGPASSWORD; psql -h postgres -U "$0" -d fenrir -Atqc "$1" 2>&1' "$1" "$3" < "secrets/$2"
}
dbexpect() {  # label role secret sql expected-substring
  if [ ! -r "secrets/$3" ] || [ -z "$(cid_of backend)" ]; then skip "$1 (no secrets/$3 or backend)"; return; fi
  out="$(dbprobe "$2" "$3" "$4")"
  grep -q -- "$5" <<<"$out" && pass "$1" || fail "$1 — got: $(head -c 120 <<<"$out" | tr '\n' ' ')"
}
dbexpect "app cannot UPDATE audit_logs (append-only by privilege)" fenrir_app pg_app_password "UPDATE audit_logs SET action=action WHERE false" "permission denied"
dbexpect "app cannot drop the append-only trigger"                  fenrir_app pg_app_password "BEGIN; DROP TRIGGER trg_audit_logs_append_only ON audit_logs; ROLLBACK;" "must be owner"
dbexpect "app cannot COPY ... TO PROGRAM"                           fenrir_app pg_app_password "COPY (SELECT 1) TO PROGRAM 'true'" "permission denied"
dbexpect "app cannot write audit anchors"                           fenrir_app pg_app_password "BEGIN; DELETE FROM audit_anchor WHERE false; ROLLBACK;" "permission denied"
dbexpect "superuser refused over the network (pg_hba)"              fenrir postgres_password "SELECT 1" "pg_hba.conf rejects"
dbexpect "backup role is read-only"                                 fenrir_backup pg_backup_password "BEGIN; DELETE FROM audit_anchor WHERE false; ROLLBACK;" "permission denied"

# ── 8. Encryption in transit (internal hops) ───────────────────────────────
section "8. Internal TLS"
fe="$(cid_of frontend)"; be="$(cid_of backend)"; rd="$(cid_of redis)"
if [ -n "$fe" ]; then
  docker exec "$fe" sh -c 'wget -q -O- -T 5 http://backend:8000/api/health >/dev/null 2>&1' \
    && fail "backend answers plaintext HTTP" || pass "backend refuses plaintext HTTP"
fi
if [ -n "$be" ]; then
  out="$(docker exec "$be" python -c "
import ssl, urllib.request as u
c = ssl.create_default_context(cafile='/run/secrets/tls_ca_crt')
try: u.urlopen('https://backend:8000/api/health', timeout=5, context=c); print('ACCEPTED')
except Exception as e: print('refused')" 2>&1)"
  [ "$out" = "refused" ] && pass "backend requires a client certificate (mTLS)" || fail "backend accepted TLS without a client certificate"
  out="$(docker exec -i "$be" sh -c 'read -r PGPASSWORD; export PGPASSWORD; psql "host=postgres dbname=fenrir user=fenrir_app sslmode=disable" -Atc "select 1" 2>&1' < secrets/pg_app_password)"
  grep -q "no encryption" <<<"$out" && pass "Postgres refuses plaintext connections" || fail "Postgres plaintext: $(head -c 100 <<<"$out")"
  out="$(docker exec -i "$be" sh -c 'read -r PGPASSWORD; export PGPASSWORD; psql "host=postgres dbname=fenrir user=fenrir_app sslmode=verify-full sslrootcert=/run/secrets/tls_ca_crt" -Atc "select version from pg_stat_ssl where pid = pg_backend_pid()" 2>&1' < secrets/pg_app_password)"
  [ "$out" = "TLSv1.3" ] && pass "Postgres session is TLSv1.3 (verify-full)" || fail "Postgres TLS: $out"
fi
if [ -n "$rd" ]; then
  docker exec "$rd" sh -c 'redis-cli -h redis --no-auth-warning --user healthcheck --pass x ping 2>/dev/null | grep -q PONG' \
    && fail "Redis answers plaintext" || pass "Redis refuses plaintext (TLS-only port)"
fi
if [ -d secrets ]; then
  for c in secrets/tls_*.crt; do
    [ -f "$c" ] || continue
    if openssl x509 -in "$c" -noout -checkend $((30*86400)) >/dev/null 2>&1; then pass "$(basename "$c") valid > 30 days"
    else fail "$(basename "$c") expires within 30 days — run scripts/internal-pki.sh --apply"; fi
  done
fi

printf '\n\033[1mSummary:\033[0m %d pass, %d fail, %d skip\n' "$PASS" "$FAIL" "$SKIP"
exit "$FAIL"
