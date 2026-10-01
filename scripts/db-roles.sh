#!/usr/bin/env bash
# DFIR-FENRIR v2 — apply the least-privilege Postgres role model to a RUNNING db.
#
# Runs docker/postgres/10-fenrir-roles.sh (the same script a fresh volume runs at
# initdb) inside the postgres container, over the local socket, as the bootstrap
# superuser. Use it once to migrate an existing database, after a restore (restored
# objects come back owned by the restoring superuser), or to rotate a role password
# (edit ./secrets/pg_<role>_password, re-run, then recreate that service).
# Idempotent. Dry run by default: shows the current roles and object owners.
#   scripts/db-roles.sh           # show current state
#   scripts/db-roles.sh --apply   # apply roles, ownership and grants
set -euo pipefail
cd "$(dirname "$0")/.."
Q=(docker compose exec -T postgres psql -U fenrir -d fenrir -Atq)
echo "Roles:";  "${Q[@]}" -c "select '  '||rolname||' login='||rolcanlogin||' super='||rolsuper from pg_roles where rolname like 'fenrir%' order by 1"
echo "Object owners in schema public:"
"${Q[@]}" -c "select '  '||o||': '||n||' relations' from (select pg_get_userbyid(c.relowner) o, count(*) n from pg_class c join pg_namespace ns on ns.oid=c.relnamespace where ns.nspname='public' and c.relkind in ('r','S','v','m','p') group by 1) t order by 1"
if [ "${1:-}" != "--apply" ]; then echo "Dry run — re-run with --apply to apply docker/postgres/10-fenrir-roles.sh."; exit 0; fi
docker compose exec -T postgres sh /docker-entrypoint-initdb.d/10-fenrir-roles.sh
