-- DFIR-FENRIR v2 — Database Initialization (fresh volume only)
-- Extensions (need the bootstrap superuser, so they are created here, once).
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Roles, ownership and grants: docker/postgres/10-fenrir-roles.sh (least privilege —
-- no blanket GRANT ALL here).
