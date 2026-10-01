#!/bin/sh
# DFIR-FENRIR v2 — least-privilege Postgres roles (idempotent; safe to re-run).
#
# Runs as the bootstrap superuser over the LOCAL socket, inside the postgres
# container: automatically on a fresh volume (docker-entrypoint-initdb.d), and via
# scripts/db-roles.sh for existing databases, after a restore, or to rotate a role
# password (edit its secret file, re-run).
#
#   fenrir           bootstrap superuser (OID 10 — cannot be demoted); pg_hba only
#                    lets it in over the local socket: break-glass + restore.
#   fenrir_owner     NOLOGIN — owns every object in schema public.
#   fenrir_migrator  the `migrate` one-shot; member of fenrir_owner, runs DDL as it.
#   fenrir_app       the backend: DML only. audit_logs = SELECT + INSERT (DB-enforced
#                    append-only, independent of the trigger); audit_anchor = SELECT.
#                    Not an owner, so it can never drop the append-only trigger.
#   fenrir_monitor   audit-monitor: read audit_logs, write audit_anchor.
#   fenrir_backup    backup sidecar: pg_read_all_data (read-only).
#
# Passwords come from /run/secrets/pg_*_password and reach psql on STDIN (never
# argv); the session sets log_statement = none so they are never logged.
set -eu

pw() {  # secret → SQL string literal body (single quotes doubled)
    sed "s/'/''/g" "/run/secrets/$1" | tr -d '\n'
}

psql -v ON_ERROR_STOP=1 --no-psqlrc -q -U "${POSTGRES_USER:-fenrir}" -d "${POSTGRES_DB:-fenrir}" <<SQL
SET log_statement = 'none';
SET client_min_messages = warning;

DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fenrir_owner')    THEN CREATE ROLE fenrir_owner NOLOGIN;    END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fenrir_migrator') THEN CREATE ROLE fenrir_migrator LOGIN;   END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fenrir_app')      THEN CREATE ROLE fenrir_app LOGIN;        END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fenrir_monitor')  THEN CREATE ROLE fenrir_monitor LOGIN;    END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'fenrir_backup')   THEN CREATE ROLE fenrir_backup LOGIN;     END IF;
END \$\$;
ALTER ROLE fenrir_owner    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE fenrir_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$(pw pg_migrator_password)';
ALTER ROLE fenrir_app      LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$(pw pg_app_password)';
ALTER ROLE fenrir_monitor  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$(pw pg_monitor_password)';
ALTER ROLE fenrir_backup   LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$(pw pg_backup_password)';
GRANT fenrir_owner TO fenrir_migrator;
GRANT pg_read_all_data TO fenrir_backup;

-- Database + schema: nobody but these roles may connect; only the owner may create.
REVOKE ALL ON DATABASE fenrir FROM PUBLIC;
GRANT CONNECT ON DATABASE fenrir TO fenrir_migrator, fenrir_app, fenrir_monitor, fenrir_backup;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO fenrir_owner;
GRANT USAGE ON SCHEMA public TO fenrir_app, fenrir_monitor, fenrir_backup;

-- Ownership → fenrir_owner (the bootstrap superuser can't be REASSIGNed). Tables
-- carry their indexes and column-owned sequences; extension members are skipped.
DO \$\$
DECLARE r record;
BEGIN
  FOR r IN SELECT c.oid::regclass AS obj,
                  CASE c.relkind WHEN 'S' THEN 'SEQUENCE' WHEN 'v' THEN 'VIEW'
                                 WHEN 'm' THEN 'MATERIALIZED VIEW' ELSE 'TABLE' END AS kind
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','S')
              AND c.relowner <> 'fenrir_owner'::regrole
              AND NOT EXISTS (SELECT FROM pg_depend d WHERE d.objid = c.oid AND d.deptype IN ('a','i','e'))
            ORDER BY c.relkind = 'S'
  LOOP
    EXECUTE format('ALTER %s %s OWNER TO fenrir_owner', r.kind, r.obj);
  END LOOP;
  FOR r IN SELECT p.oid::regprocedure AS fn
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proowner <> 'fenrir_owner'::regrole
              AND NOT EXISTS (SELECT FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO fenrir_owner', r.fn);
  END LOOP;
END \$\$;

-- fenrir_app: data, not structure — now and for every future owner-created object.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fenrir_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO fenrir_app;
ALTER DEFAULT PRIVILEGES FOR ROLE fenrir_owner IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO fenrir_app;
ALTER DEFAULT PRIVILEGES FOR ROLE fenrir_owner IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO fenrir_app;

-- Tamper evidence (GS-8): audit_logs is append-only FOR THE APP by privilege, not
-- just by trigger; the anchors that prove the chain are read-only to the app.
DO \$\$ BEGIN
  IF to_regclass('public.audit_logs') IS NOT NULL THEN
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM fenrir_app;
    GRANT SELECT ON audit_logs TO fenrir_monitor;
  END IF;
  IF to_regclass('public.audit_anchor') IS NOT NULL THEN
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit_anchor FROM fenrir_app;
    GRANT SELECT, INSERT ON audit_anchor TO fenrir_monitor;
  END IF;
END \$\$;
SQL
echo "[fenrir-roles] roles, ownership and grants applied"
