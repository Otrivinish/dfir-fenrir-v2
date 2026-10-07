"""Async SQLAlchemy engine + session factory."""
import re
import ssl

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from core.config import settings


class Base(DeclarativeBase):
    pass


# Pool sizing — SQLAlchemy defaults (5 base + 10 overflow = 15 conns) are too
# tight when CPU-bound work runs in threads (each waiting handler still holds
# its DB session and connection). 20 + 10 fits comfortably under a default PG
# max_connections of 100 even with 3 backend replicas. pool_recycle keeps
# long-lived conns from going stale behind firewalls / NAT timeouts.
def _db_ssl_context() -> ssl.SSLContext | None:
    """verify-full TLS 1.3 to Postgres, anchored on the internal CA."""
    if not settings.db_ssl_ca:
        return None
    ctx = ssl.create_default_context(cafile=settings.db_ssl_ca)   # CERT_REQUIRED + hostname check
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


_ssl = _db_ssl_context()
engine = create_async_engine(
    settings.database_url,
    connect_args={"ssl": _ssl} if _ssl else {},
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=1800,
    future=True,
)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


# The per-boot DDL takes ACCESS EXCLUSIVE locks (ALTER TABLE takes it even when there is
# nothing to change). Behind a busy table it would wait forever, and every later query on
# that table would queue behind it. Wait at most this long for any one lock; then the run
# fails loudly and, being one transaction, rolls back whole (core/migrate.py, SQLSTATE 55P03).
MIGRATE_LOCK_TIMEOUT = "5s"


async def init_db() -> None:
    """Create tables on first boot + run idempotent in-place migrations.

    v2 uses SQLAlchemy `create_all` (no Alembic yet). `create_all` only creates
    *missing* tables, so anything that mutates an existing table lives in
    `_INPLACE_MIGRATIONS` below — each statement is idempotent (`IF EXISTS` /
    `IF NOT EXISTS` patterns) and safe to run on every boot.
    """
    # Import models so SQLAlchemy registers them before create_all
    import models  # noqa: F401
    role = settings.db_owner_role
    if role and not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise ValueError(f"invalid DB_OWNER_ROLE {role!r}")
    async with engine.begin() as conn:
        await conn.execute(text(f"SET LOCAL lock_timeout = '{MIGRATE_LOCK_TIMEOUT}'"))
        if role:
            # Transaction-scoped: every object created below is owned by the owner role.
            await conn.execute(text(f"SET LOCAL ROLE {role}"))
        await conn.run_sync(lambda sync_conn: Base.metadata.create_all(sync_conn, checkfirst=True))
        for stmt in _INPLACE_MIGRATIONS:
            await conn.execute(text(stmt))
        if role:
            for stmt in _PRIVILEGE_MIGRATIONS:
                await conn.execute(text(stmt))


# Re-asserted on every migrate run (default privileges would otherwise hand the app
# full DML on freshly created tables): GS-8 tamper evidence enforced by privilege.
_PRIVILEGE_MIGRATIONS: list[str] = [
    "REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM fenrir_app",
    "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit_anchor FROM fenrir_app",
    "GRANT SELECT ON audit_logs TO fenrir_monitor",
    "GRANT SELECT, INSERT ON audit_anchor TO fenrir_monitor",
]


# ── Idempotent in-place migrations ────────────────────────────────────────
# When a real migration tool (Alembic) lands, this disappears.

def _add_check_if_missing(table: str, name: str, expr: str) -> str:
    """CHECK constraint added only when pg_constraint doesn't have it yet, so a re-run takes no
    ACCESS EXCLUSIVE lock and doesn't re-scan the table (Wave C fix-up L7). A changed rule needs
    a NEW constraint name; this never alters an existing one. Constants only (no user input)."""
    return f"""
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conrelid = '{table}'::regclass AND conname = '{name}') THEN
            ALTER TABLE {table} ADD CONSTRAINT {name} CHECK ({expr});
        END IF;
    END $$
    """


def _widen_to_bigint(table: str, column: str) -> str:
    """int4 → BIGINT, only while the column is still `integer`, so a re-run takes no lock (the type
    change rewrites the table under ACCESS EXCLUSIVE). Constants only (no user input)."""
    return f"""
    DO $$
    BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = current_schema() AND table_name = '{table}'
                     AND column_name = '{column}' AND data_type = 'integer') THEN
            ALTER TABLE {table} ALTER COLUMN {column} TYPE BIGINT;
        END IF;
    END $$
    """


_INPLACE_MIGRATIONS: list[str] = [
    # Incidents: drop csf_function (moved to report-level only); remap legacy
    # NCISS severity values onto the internal Low/Med/High/Critical scale.
    "ALTER TABLE incidents DROP COLUMN IF EXISTS csf_function",
    "UPDATE incidents SET severity = 'critical' WHERE severity IN ('emergency', 'severe')",
    "UPDATE incidents SET severity = 'low'      WHERE severity = 'baseline'",

    # Audit log v1 → v2: forensic-context fields + versioned hash chain.
    # Existing rows get hash_version='v1' via the column DEFAULT; new rows write 'v2'.
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS outcome         VARCHAR(16)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS session_id      UUID REFERENCES user_sessions(id)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS role_at_time    VARCHAR(32)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS resource_label  VARCHAR(255)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_method  VARCHAR(8)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_path    VARCHAR(512)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS request_id      VARCHAR(36)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash_version    VARCHAR(8) NOT NULL DEFAULT 'v1'",
    "CREATE INDEX IF NOT EXISTS ix_audit_logs_session_id ON audit_logs(session_id)",
    "CREATE INDEX IF NOT EXISTS ix_audit_logs_request_id ON audit_logs(request_id)",

    # Dashboard metrics: occurred_at (analyst-supplied event time) and
    # contained_at (analyst-declared; no longer auto-set on entering C/E/R).
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS occurred_at  TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS contained_at TIMESTAMP WITH TIME ZONE",
    # detected_at (analyst-supplied: when the incident was detected).
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS detected_at  TIMESTAMP WITH TIME ZONE",
    # Eradication / recovery milestones (analyst-declared). Nullable, no backfill.
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS eradicated_at TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS recovered_at  TIMESTAMP WITH TIME ZONE",
    # Who closed the incident (set by POST …/close, cleared on re-open). Nullable, no
    # backfill: incidents closed before this column have no closer on record. Partial
    # index so ON DELETE SET NULL from users doesn't scan incidents.
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS closed_by_id UUID REFERENCES users(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_incidents_closed_by_id ON incidents(closed_by_id) WHERE closed_by_id IS NOT NULL",
    # Legal reminders (legal/reminders.py): last reminder stage sent per deadline. Only when
    # the column is first created, deadlines already overdue start at stage 3 (overdue sent),
    # so deploying doesn't fire a burst of reminders for old deadlines; later runs are no-ops.
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'regulatory_deadlines' AND column_name = 'reminder_stage'
        ) THEN
            ALTER TABLE regulatory_deadlines ADD COLUMN reminder_stage SMALLINT NOT NULL DEFAULT 0;
            UPDATE regulatory_deadlines SET reminder_stage = 3
            WHERE deadline_at <= now() AND status NOT IN ('completed', 'waived');
        END IF;
    END $$
    """,

    # Incident type classification (CISA/SOC category).
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS incident_type VARCHAR(32)",

    # Triage state — analyst's investigation-confidence assessment.
    # Distinct from severity (impact) and phase (response posture).
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS triage_state VARCHAR(24) NOT NULL DEFAULT 'suspected'",
    "CREATE INDEX IF NOT EXISTS ix_incidents_triage_state ON incidents(triage_state)",

    # Evidence: optional link to a scoped Entity (collected from a specific asset).
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS entity_id UUID REFERENCES entities(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_evidence_entity_id ON evidence(entity_id)",

    # Human-readable incident reference numbers (INC-0001, INC-0002, …).
    # Sequence guarantees uniqueness without app-level locking.
    "CREATE SEQUENCE IF NOT EXISTS incident_seq START 1",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS incident_number INTEGER",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_incident_number ON incidents(incident_number) WHERE incident_number IS NOT NULL",
    # Back-fill existing rows in created_at order (no-op if already numbered).
    """
    DO $$ DECLARE r RECORD; BEGIN
      FOR r IN SELECT id FROM incidents WHERE incident_number IS NULL ORDER BY created_at, id ASC LOOP
        UPDATE incidents SET incident_number = nextval('incident_seq') WHERE id = r.id;
      END LOOP;
    END $$
    """,

    # Immutable incident reference (incidents/reference.py). Existing incidents keep the
    # INC-NNNN they have always shown (lpad only below 1000: lpad() would truncate 10000).
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ref VARCHAR(32)",
    """
    UPDATE incidents
       SET ref = 'INC-' || CASE WHEN incident_number >= 1000 THEN incident_number::text
                                ELSE lpad(incident_number::text, 4, '0') END
     WHERE ref IS NULL AND incident_number IS NOT NULL
    """,
    "ALTER TABLE incidents ALTER COLUMN ref SET NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_ref ON incidents(ref)",
    """
    CREATE OR REPLACE FUNCTION incidents_ref_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.ref IS DISTINCT FROM OLD.ref THEN
        RAISE EXCEPTION 'incidents.ref is immutable (% -> %)', OLD.ref, NEW.ref
          USING ERRCODE = 'check_violation';
      END IF;
      RETURN NEW;
    END $$
    """,
    "CREATE OR REPLACE TRIGGER trg_incidents_ref_immutable BEFORE UPDATE OF ref ON incidents "
    "FOR EACH ROW EXECUTE FUNCTION incidents_ref_immutable()",

    # IOC enhancements: analyst-assessed malicious flag + optional entity link.
    "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS malicious BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS entity_id UUID REFERENCES entities(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_iocs_entity_id ON iocs(entity_id)",

    # Analyst-assessed confidence (0–100) + freeform tags. Auto-source tags
    # (pcap/artifact/yara/bulk-import) are injected by the creating route.
    "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS confidence INTEGER NOT NULL DEFAULT 50",
    "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS tags       JSONB   NOT NULL DEFAULT '[]'",

    # Respond actions: analyst-supplied time when the action was actually performed.
    "ALTER TABLE respond_actions ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMP WITH TIME ZONE",
    # C1: the entity / IOC an action targets + the template it came from. Nullable and NOT
    # backfilled: older actions keep only their free-text target (no name-matching guesses).
    # Partial indexes so ON DELETE SET NULL from entities/iocs, the containment lookup and
    # the ?entity_id= / ?ioc_id= filters don't scan respond_actions.
    "ALTER TABLE respond_actions ADD COLUMN IF NOT EXISTS entity_id UUID REFERENCES entities(id) ON DELETE SET NULL",
    "ALTER TABLE respond_actions ADD COLUMN IF NOT EXISTS ioc_id UUID REFERENCES iocs(id) ON DELETE SET NULL",
    "ALTER TABLE respond_actions ADD COLUMN IF NOT EXISTS template_id VARCHAR(64)",
    "CREATE INDEX IF NOT EXISTS ix_respond_actions_entity_id ON respond_actions(entity_id) WHERE entity_id IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS ix_respond_actions_ioc_id ON respond_actions(ioc_id) WHERE ioc_id IS NOT NULL",

    # C2: Entities is the single scope list; affected_systems becomes a frozen legacy table
    # behind the /affected-systems compatibility layer. Each row is copied ONCE into entities
    # as compromised and stamped with the entity it became (migrated_entity_id). The copy runs
    # only in the migrate run that first adds the stamp column, so later runs never re-flag an
    # entity an analyst cleared, nor re-create one an analyst deleted (its ON DELETE SET NULL
    # clears the stamp). An existing entity for (incident, type, value) is only flagged (and
    # gets attributes.system_type when it has none). Type map = affected_systems/routes.py
    # SYSTEM_TYPE_TO_ENTITY_TYPE; the original system_type is kept in attributes.
    # DISTINCT ON: two rows mapping to one entity (e.g. a workstation and a server with the
    # same name) can't hit the same conflict row twice.
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'affected_systems' AND column_name = 'migrated_entity_id'
        ) THEN
            ALTER TABLE affected_systems
                ADD COLUMN migrated_entity_id UUID REFERENCES entities(id) ON DELETE SET NULL;
            WITH src AS (
                SELECT a.id, a.incident_id, btrim(a.name) AS value, a.name, a.notes, a.system_type,
                       a.created_at, u.id AS user_id,
                       CASE a.system_type
                           WHEN 'workstation'    THEN 'host'
                           WHEN 'server'         THEN 'host'
                           WHEN 'mobile'         THEN 'host'
                           WHEN 'network_device' THEN 'network_range'
                           WHEN 'cloud_resource' THEN 'service'
                           WHEN 'application'    THEN 'service'
                           WHEN 'database'       THEN 'service'
                           ELSE 'other'
                       END AS etype
                FROM affected_systems a
                LEFT JOIN users u ON u.username = a.created_by_username
                WHERE a.migrated_entity_id IS NULL AND btrim(a.name) <> ''
            ), up AS (
                INSERT INTO entities (id, incident_id, type, value, name, description, criticality,
                                      attributes, compromised, added_by_id, added_at, updated_at)
                SELECT DISTINCT ON (incident_id, etype, value)
                       gen_random_uuid(), incident_id, etype, value, name, notes, 'high',
                       CASE WHEN system_type IS NULL THEN '{}'::json
                            ELSE json_build_object('system_type', system_type) END,
                       TRUE, user_id, created_at, now()
                FROM src
                ORDER BY incident_id, etype, value, created_at, id
                ON CONFLICT (incident_id, type, value) DO UPDATE SET
                    compromised = TRUE,
                    attributes  = CASE WHEN (entities.attributes::jsonb ->> 'system_type') IS NOT NULL
                                         OR (EXCLUDED.attributes::jsonb ->> 'system_type') IS NULL
                                       THEN entities.attributes
                                       ELSE (entities.attributes::jsonb || EXCLUDED.attributes::jsonb)::json END
                RETURNING id, incident_id, type, value
            )
            UPDATE affected_systems a SET migrated_entity_id = up.id
              FROM src JOIN up ON up.incident_id = src.incident_id
                              AND up.type = src.etype AND up.value = src.value
             WHERE a.id = src.id;
            ANALYZE entities;
        END IF;
    END $$
    """,
    "CREATE INDEX IF NOT EXISTS ix_affected_systems_migrated_entity_id ON affected_systems(migrated_entity_id) "
    "WHERE migrated_entity_id IS NOT NULL",
    # C2: the entity a timeline event happened on. Nullable, NO backfill from hostname
    # (no name-matching guesses). Partial index for ON DELETE SET NULL from entities.
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS entity_id UUID REFERENCES entities(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_timeline_events_entity_id ON timeline_events(entity_id) WHERE entity_id IS NOT NULL",

    # Handoff package: structured investigation-state fields aligned with v1.
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS current_hypothesis    TEXT",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS hypothesis_confidence INTEGER NOT NULL DEFAULT 50",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS key_findings          TEXT",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS warnings              TEXT",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS threads               JSONB NOT NULL DEFAULT '[]'",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS ruled_out             JSONB NOT NULL DEFAULT '[]'",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS pending               JSONB NOT NULL DEFAULT '[]'",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS next_steps            JSONB NOT NULL DEFAULT '[]'",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS open_questions        JSONB NOT NULL DEFAULT '[]'",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS snapshot_data         JSONB NOT NULL DEFAULT '{}'",

    # Evidence: legal-hold flag (LE-package builder filter + future destroy/return guard).
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT FALSE",
    "CREATE INDEX IF NOT EXISTS ix_evidence_legal_hold ON evidence(legal_hold)",

    # IOC tri-state status (malicious / clean / unknown): relax `malicious` to
    # nullable and treat NULL as the new "unknown" state. The pre-trichotomy
    # binary UI conflated "clean" with "not yet reviewed", so legacy FALSE
    # rows added before the migration cutoff are mapped to NULL. The cutoff
    # guard keeps the UPDATE idempotent — analysts marking Clean after the
    # cutoff stay Clean across future boots.
    "ALTER TABLE iocs ALTER COLUMN malicious DROP NOT NULL",
    "ALTER TABLE iocs ALTER COLUMN malicious DROP DEFAULT",
    "UPDATE iocs SET malicious = NULL WHERE malicious = FALSE AND added_at < '2026-05-24'",

    # Auto-created hash IOCs from artifact uploads were stored with the
    # non-canonical type 'hash'; the IocType literal accepts only
    # hash_md5 / hash_sha1 / hash_sha256, so list_iocs serialisation crashed.
    # Remap by hash length (idempotent — after first run no rows match).
    "UPDATE iocs SET type = 'hash_sha256' WHERE type = 'hash' AND length(value) = 64",
    "UPDATE iocs SET type = 'hash_md5'    WHERE type = 'hash' AND length(value) = 32",

    # Closure checklist soft-delete flag (Step 06). DELETE flips this to FALSE
    # so the seed loop doesn't resurrect dismissed defaults on next list call.
    "ALTER TABLE closure_checklist_items ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE",

    # Lessons Learned: plain-text narrative fields driven from the Reports tab.
    # Preferred by the report renderer over the structured lists when set.
    "ALTER TABLE lessons_learned ADD COLUMN IF NOT EXISTS report_what_worked_well         TEXT",
    "ALTER TABLE lessons_learned ADD COLUMN IF NOT EXISTS report_what_could_improve       TEXT",
    "ALTER TABLE lessons_learned ADD COLUMN IF NOT EXISTS report_security_recommendations TEXT",
    "ALTER TABLE lessons_learned ADD COLUMN IF NOT EXISTS report_remediation_short        TEXT",
    "ALTER TABLE lessons_learned ADD COLUMN IF NOT EXISTS report_remediation_medium       TEXT",
    "ALTER TABLE lessons_learned ADD COLUMN IF NOT EXISTS report_remediation_long         TEXT",

    # Chain-of-Custody wizards: ISO/IEC 27037 + EU evidence handling.
    # ── Evidence — Wizard A acquisition fields (all nullable, additive) ──
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS lawful_basis             VARCHAR(32)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS lawful_basis_note        TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_tool         VARCHAR(128)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_tool_version VARCHAR(64)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_tool_sha256  VARCHAR(64)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_params       TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_hash_source  VARCHAR(64)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_hash_target  VARCHAR(64)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS write_blocker_used       BOOLEAN",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS write_blocker_serial     VARCHAR(128)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS system_state             VARCHAR(16)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS live_justification       TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS network_isolated         BOOLEAN",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS witness_user_id          UUID REFERENCES users(id)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS witness_name             VARCHAR(128)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS coc_sealed               BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS coc_sealed_at            TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS coc_sealed_by_id         UUID REFERENCES users(id)",
    "CREATE INDEX IF NOT EXISTS ix_evidence_coc_sealed ON evidence(coc_sealed)",

    # ── LePackage — Wizard C handoff fields ──
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS eio_reference          VARCHAR(128)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS issuing_state          VARCHAR(64)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS executing_state        VARCHAR(64)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS mla_reference          VARCHAR(128)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS recipient_name         VARCHAR(256)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS recipient_role         VARCHAR(128)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS recipient_id_ref       VARCHAR(128)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS recipient_organisation VARCHAR(256)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS recipient_address      TEXT",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS delivery_channel       VARCHAR(32)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS delivery_notes         TEXT",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS sender_declaration     TEXT",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS signature_kind         VARCHAR(32) DEFAULT 'ed25519'",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS acknowledgment_token   VARCHAR(64)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS acknowledged_at        TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS acknowledged_by_name   VARCHAR(256)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS acknowledged_ip        VARCHAR(64)",
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS acknowledged_notes     TEXT",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_le_packages_ack_token ON le_packages(acknowledgment_token) WHERE acknowledgment_token IS NOT NULL",

    # External-custodian fields — chain of custody can cover real-world parties
    # (couriers, external counsel, LE pre-handoff) that don't have platform accounts.
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS current_custodian_external_name    VARCHAR(256)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS current_custodian_external_org     VARCHAR(256)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS current_custodian_external_contact VARCHAR(256)",

    # U1 X.509 collection encryption — per-package RSA private key (wrapped under
    # EVIDENCE_KEK) + cert fingerprint. Table is created by create_all; these add
    # the columns to instances that predate the encryption feature.
    "ALTER TABLE collection_packages ADD COLUMN IF NOT EXISTS enc_private_key  TEXT",
    "ALTER TABLE collection_packages ADD COLUMN IF NOT EXISTS cert_fingerprint VARCHAR(64)",

    # Collection-wizard slice (ISO/IEC 27037 §7) — branch-aware capture. All
    # additive + nullable, so existing evidence rows are untouched. See
    # docs/coc-collection-wizard-slice.md.
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS device_types                  JSON",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS handling_mode                 VARCHAR(16)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS decision_factors              JSON",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_scope             VARCHAR(16)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS logical_acquisition_rationale TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS system_time_offset            VARCHAR(128)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS screen_state                  TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS changes_made                  TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS device_details                JSON",

    # 27041 validation slice (Slice B) — method/tool validation + competence.
    # Additive + nullable; soft-scored. See docs/coc-27041-validation-slice.md.
    "ALTER TABLE users    ADD COLUMN IF NOT EXISTS qualifications                   TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_tool_validated       BOOLEAN",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_tool_validation_ref  VARCHAR(256)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquisition_tool_validation_date VARCHAR(32)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS collected_by_qualifications      TEXT",

    # GS-4 trusted timestamping — RFC 3161 token on the seal (optional/best-effort).
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS seal_tst       TEXT",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS seal_tst_time  VARCHAR(32)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS seal_tsa       VARCHAR(256)",

    # GS-10 two-person disposal — second approver for legal-hold disposals
    # (SWGDE/ACPO two-person integrity). Nullable; only required when legal_hold.
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS dispose_witness_id UUID REFERENCES users(id)",

    # GS-12 DEFR/DES collector-role taxonomy (ISO/IEC 27037 §3.7/§3.8). Nullable.
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS collected_as_role VARCHAR(8)",

    # C3 evidence intake integrity. acquired_at = when the image was taken / item seized;
    # nullable and NOT backfilled (collected_at is the registration time; copying it would
    # invent an acquisition time). upload_hash_check = the typed target hash vs the stored
    # hash of the uploaded bytes. Its one-shot backfill runs only in the migrate run that
    # first adds the column: digital items with a target hash get 'match' when it equals
    # the stored MD5 / SHA-1 / SHA-256, else 'mismatch' (target hashes of an E01/AFF4
    # container's media show up here, which is correct). Items without one stay NULL.
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS acquired_at TIMESTAMP WITH TIME ZONE",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'evidence' AND column_name = 'upload_hash_check'
        ) THEN
            ALTER TABLE evidence ADD COLUMN upload_hash_check VARCHAR(16);
            UPDATE evidence
               SET upload_hash_check = CASE
                       WHEN lower(btrim(acquisition_hash_target)) IN (lower(md5), lower(sha1), lower(sha256))
                       THEN 'match' ELSE 'mismatch' END
             WHERE kind = 'digital_file' AND btrim(coalesce(acquisition_hash_target, '')) <> '';
        END IF;
    END $$
    """,
    _add_check_if_missing("evidence", "ck_evidence_upload_hash_check",
                          "upload_hash_check IS NULL "
                          "OR upload_hash_check IN ('match', 'mismatch', 'not_checked', 'container_media')"),

    # C4 custody transfer with recipient acceptance. An internal transfer is a request until
    # the recipient accepts; these three hold it and are all NULL when nothing is pending
    # (CHECK). No backfill: no transfer can be pending before C4. Partial indexes on both new
    # FKs (the recipient's "awaiting me" look-up and the FK check on a user delete).
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS pending_custodian_id UUID REFERENCES users(id)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS pending_transfer_by_id UUID REFERENCES users(id)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS pending_transfer_requested_at TIMESTAMP WITH TIME ZONE",
    "CREATE INDEX IF NOT EXISTS ix_evidence_pending_custodian_id ON evidence(pending_custodian_id) "
    "WHERE pending_custodian_id IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS ix_evidence_pending_transfer_by_id ON evidence(pending_transfer_by_id) "
    "WHERE pending_transfer_by_id IS NOT NULL",
    _add_check_if_missing("evidence", "ck_evidence_pending_transfer",
                          "(pending_custodian_id IS NULL) = (pending_transfer_by_id IS NULL) "
                          "AND (pending_custodian_id IS NULL) = (pending_transfer_requested_at IS NULL)"),

    # C5 Timeline Import from an exhibit, with honest timestamps. forensic_imports gets the exhibit
    # it parsed, the parser version and the source timezone. Its evidence_id one-shot backfill runs
    # only in the migrate run that first adds the column, and links an old import ONLY when its
    # SHA-256 equals the SHA-256 of exactly one evidence row of the same incident (no other
    # guessing; an analyst's later change is never undone). parser_version / source_tz stay NULL on
    # old imports (they were parsed before either existed). timeline_events gets the exhibit, the
    # import run + event index (partial UNIQUE: re-promoting is a no-op) and time_basis (NULL =
    # legacy / analyst-entered; 'missing' is never stored: untimestamped events aren't promoted).
    # iocs gets the exhibit an indicator was found in. FKs SET NULL + partial indexes.
    "ALTER TABLE forensic_imports ADD COLUMN IF NOT EXISTS parser_version VARCHAR(32)",
    "ALTER TABLE forensic_imports ADD COLUMN IF NOT EXISTS source_tz VARCHAR(64)",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'forensic_imports' AND column_name = 'evidence_id'
        ) THEN
            ALTER TABLE forensic_imports
                ADD COLUMN evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL;
            UPDATE forensic_imports f SET evidence_id = m.evidence_id
              FROM (SELECT f2.id AS import_id, (array_agg(e.id))[1] AS evidence_id
                      FROM forensic_imports f2
                      JOIN evidence e ON e.incident_id = f2.incident_id
                                     AND lower(btrim(e.sha256)) = lower(btrim(f2.sha256_hash))
                     WHERE btrim(coalesce(f2.sha256_hash, '')) <> ''
                     GROUP BY f2.id
                    HAVING count(*) = 1) m
             WHERE f.id = m.import_id;
        END IF;
    END $$
    """,
    "CREATE INDEX IF NOT EXISTS ix_forensic_imports_evidence_id ON forensic_imports(evidence_id) "
    "WHERE evidence_id IS NOT NULL",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS forensic_import_id UUID "
    "REFERENCES forensic_imports(id) ON DELETE SET NULL",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS import_event_index INTEGER",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS time_basis VARCHAR(16)",
    "CREATE INDEX IF NOT EXISTS ix_timeline_events_evidence_id ON timeline_events(evidence_id) "
    "WHERE evidence_id IS NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_timeline_events_import_event "
    "ON timeline_events(forensic_import_id, import_event_index) WHERE forensic_import_id IS NOT NULL",
    _add_check_if_missing("timeline_events", "ck_timeline_events_time_basis",
                          "time_basis IS NULL OR time_basis IN ('explicit', 'assumed_tz', 'inferred_year')"),
    # Wave C fix-up M3: timeline_events.forensic_import_id was ON DELETE SET NULL, so deleting an
    # import (e.g. a raw DELETE) unlinked its promoted events and made their facts editable. Now
    # RESTRICT. Guarded via pg_constraint: dropped and re-added only while the FK isn't RESTRICT
    # yet (confdeltype 'r'); a fresh database gets RESTRICT from the model. Re-runs are no-ops.
    """
    DO $$
    DECLARE fk RECORD;
    BEGIN
        SELECT c.conname, c.confdeltype INTO fk
          FROM pg_constraint c
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
         WHERE c.conrelid = 'timeline_events'::regclass AND c.contype = 'f'
           AND c.confrelid = 'forensic_imports'::regclass
           AND cardinality(c.conkey) = 1 AND a.attname = 'forensic_import_id';
        IF FOUND AND fk.confdeltype = 'r' THEN
            RETURN;
        END IF;
        IF FOUND THEN
            EXECUTE format('ALTER TABLE timeline_events DROP CONSTRAINT %I', fk.conname);
        END IF;
        ALTER TABLE timeline_events ADD CONSTRAINT timeline_events_forensic_import_id_fkey
            FOREIGN KEY (forensic_import_id) REFERENCES forensic_imports(id) ON DELETE RESTRICT;
    END $$
    """,
    "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_iocs_evidence_id ON iocs(evidence_id) WHERE evidence_id IS NOT NULL",
    # Wave C fix-up M1: did a parser cap cut the import's output, and how many source records were
    # read. Nullable, NO backfill (older imports were parsed without counting; NULL = unknown).
    "ALTER TABLE forensic_imports ADD COLUMN IF NOT EXISTS truncated BOOLEAN",
    "ALTER TABLE forensic_imports ADD COLUMN IF NOT EXISTS total_seen INTEGER",

    # GS-8 tamper monitoring — make audit_logs append-only at the DB layer so
    # "the application cannot modify the log" is demonstrable, not promised
    # (ISO/IEC 27037 §5.3.2 + 27002). No code path UPDATEs/DELETEs audit rows, so
    # this breaks nothing. A DB superuser can still DROP this trigger — a separate,
    # privileged, audited act, unreachable from an app-level compromise.
    """CREATE OR REPLACE FUNCTION fenrir_audit_logs_append_only() RETURNS trigger
         LANGUAGE plpgsql AS $$
       BEGIN
         RAISE EXCEPTION 'audit_logs is append-only (GS-8): % blocked', TG_OP
           USING ERRCODE = 'insufficient_privilege';
       END; $$""",
    "DROP TRIGGER IF EXISTS trg_audit_logs_append_only ON audit_logs",
    """CREATE TRIGGER trg_audit_logs_append_only
         BEFORE UPDATE OR DELETE ON audit_logs
         FOR EACH ROW EXECUTE FUNCTION fenrir_audit_logs_append_only()""",

    # Unified incident "Files" store — generalises entity_files so a file can be
    # incident-level (no entity) or linked to one, and deleting an entity unlinks
    # rather than destroys the file. DROP NOT NULL + re-point FK to SET NULL.
    # (drop-if-exists then add = idempotent across restarts.)
    "ALTER TABLE entity_files ALTER COLUMN entity_id DROP NOT NULL",
    "ALTER TABLE entity_files DROP CONSTRAINT IF EXISTS entity_files_entity_id_fkey",
    """ALTER TABLE entity_files ADD CONSTRAINT entity_files_entity_id_fkey
         FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE SET NULL""",

    # Browser history: downloads extraction added after the uploads table
    # already existed in deployed instances -- create_all won't ALTER an
    # existing table, so the new counter column needs an explicit migration.
    "ALTER TABLE browser_history_uploads ADD COLUMN IF NOT EXISTS download_count INTEGER NOT NULL DEFAULT 0",
    # Same reason, for the optional Firefox formhistory.sqlite artifact link.
    "ALTER TABLE browser_history_uploads ADD COLUMN IF NOT EXISTS form_history_artifact_id UUID "
    "REFERENCES artifacts(id) ON DELETE SET NULL",

    # Email analyzer redesign: full raw header capture, live SPF/DMARC/DKIM
    # cross-check against the header's own claim (not blind trust), and a
    # batch_id grouping analyses created by one bulk-import run.
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS raw_headers TEXT",
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS auth_verified JSON",
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS batch_id UUID",
    "CREATE INDEX IF NOT EXISTS ix_email_analysis_batch_id ON email_analysis(batch_id)",

    # Email analyzer: sanitized body preview (plain text + nh3-sanitized HTML,
    # never the raw attacker HTML -- see email_analyzer/parser.py).
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS body_text TEXT",
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS body_html TEXT",

    # E2: a responder's out-of-band contact methods (ContactMethod list, as incident stakeholders).
    # Existing profiles get the empty list from the DEFAULT; no backfill. org_contacts (the
    # contacts directory) is a new table, created by create_all.
    "ALTER TABLE responder_profiles ADD COLUMN IF NOT EXISTS oob_contact_methods JSON NOT NULL DEFAULT '[]'",

    # E4: Files screenshots selectable as report figures. Existing files default to not included.
    "ALTER TABLE entity_files ADD COLUMN IF NOT EXISTS include_in_report BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE entity_files ADD COLUMN IF NOT EXISTS report_caption VARCHAR(512)",

    # E-fix L5: a report figure's SHA-256 and image type, stored when it is picked. Existing figures
    # stay NULL (report data hashes those on the fly); no backfill.
    "ALTER TABLE entity_files ADD COLUMN IF NOT EXISTS report_sha256 VARCHAR(64)",
    "ALTER TABLE entity_files ADD COLUMN IF NOT EXISTS report_mime VARCHAR(16)",

    # F4 (R12): le_packages.signature_kind's database DEFAULT said 'ed25519' (added above, before
    # the label was found wrong), but the LE manifest is HMAC-SHA-256. The API always sets the value
    # (DE-fix-1 M4); this aligns the DEFAULT for any other writer. Only the DEFAULT changes: stored
    # rows keep the label they were written with (court records; docs/reports.md §3). Guarded on the
    # catalog so a re-run is a no-op and takes no lock; a fresh database (column from create_all,
    # no DEFAULT) gets it too.
    """
    DO $$
    BEGIN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'le_packages' AND column_name = 'signature_kind'
              AND column_default IS DISTINCT FROM '''hmac-sha256''::character varying'
        ) THEN
            ALTER TABLE le_packages ALTER COLUMN signature_kind SET DEFAULT 'hmac-sha256';
        END IF;
    END $$
    """,

    # G4 — run records for Defender and Velociraptor (R03); the exhibit's clock offset applied (R35).
    # All columns are additive and nullable, with NO backfill: rows made before G4 keep NULL (= not
    # recorded). Unlike C5's forensic_imports backfill, old Defender imports are not linked to an
    # exhibit by hash: a link writes a custody-log row, which a migration can't.
    #  - evidence.system_time_offset_seconds: the structured clock offset (device clock minus true
    #    UTC, seconds; CHECK within +/-100 years). The free-text system_time_offset stays as it is.
    #  - forensic_imports / defender_pdf_imports.clock_offset_seconds: the offset applied at parse
    #    time (a snapshot; changing the exhibit later never rewrites an import or its facts).
    #  - defender_pdf_imports: evidence_id (FK SET NULL + partial index), parser_name, parser_version.
    #  - timeline_events: defender_import_id (FK RESTRICT, as forensic_import_id; partial UNIQUE with
    #    import_event_index so re-promoting is a no-op), recorded_event_time + clock_offset_seconds
    #    (CHECK: both or neither), and CHECK that an event names at most one import run.
    #  - collection_packages: container_sha256 + container_size (the container as received) and
    #    evidence_id (FK SET NULL + partial index).
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS system_time_offset_seconds BIGINT",
    _add_check_if_missing("evidence", "ck_evidence_system_time_offset_seconds",
                          "system_time_offset_seconds IS NULL "
                          "OR system_time_offset_seconds BETWEEN -3155760000 AND 3155760000"),
    "ALTER TABLE forensic_imports ADD COLUMN IF NOT EXISTS clock_offset_seconds BIGINT",
    "ALTER TABLE defender_pdf_imports ADD COLUMN IF NOT EXISTS evidence_id UUID " +
    "REFERENCES evidence(id) ON DELETE SET NULL",
    "ALTER TABLE defender_pdf_imports ADD COLUMN IF NOT EXISTS parser_name VARCHAR(64)",
    "ALTER TABLE defender_pdf_imports ADD COLUMN IF NOT EXISTS parser_version VARCHAR(32)",
    "ALTER TABLE defender_pdf_imports ADD COLUMN IF NOT EXISTS clock_offset_seconds BIGINT",
    "CREATE INDEX IF NOT EXISTS ix_defender_pdf_imports_evidence_id ON defender_pdf_imports(evidence_id) " +
    "WHERE evidence_id IS NOT NULL",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS defender_import_id UUID " +
    "REFERENCES defender_pdf_imports(id) ON DELETE RESTRICT",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS recorded_event_time TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS clock_offset_seconds BIGINT",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_timeline_events_defender_import_event " +
    "ON timeline_events(defender_import_id, import_event_index) WHERE defender_import_id IS NOT NULL",
    _add_check_if_missing("timeline_events", "ck_timeline_events_clock_offset",
                          "(recorded_event_time IS NULL) = (clock_offset_seconds IS NULL)"),
    _add_check_if_missing("timeline_events", "ck_timeline_events_one_import_run",
                          "forensic_import_id IS NULL OR defender_import_id IS NULL"),
    "ALTER TABLE collection_packages ADD COLUMN IF NOT EXISTS container_sha256 VARCHAR(64)",
    "ALTER TABLE collection_packages ADD COLUMN IF NOT EXISTS container_size BIGINT",
    "ALTER TABLE collection_packages ADD COLUMN IF NOT EXISTS evidence_id UUID " +
    "REFERENCES evidence(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_collection_packages_evidence_id ON collection_packages(evidence_id) " +
    "WHERE evidence_id IS NOT NULL",

    # G3 — register-first Email, Browser history and PCAP (R02). Additive and nullable, NO backfill:
    # analyses made before G3 keep NULL (= no run record; they were analysed before registration).
    #  - email_analysis: input_sha256, analyser_name / _version, exhibit_link (registered |
    #    sha256_match | from_evidence; CHECK) + a partial index on the existing evidence_id.
    #  - pcap_analyses: evidence_id (FK SET NULL + partial index), the same run-record columns, the
    #    clock offset applied (snapshot) and the stored timeline candidates (JSON).
    #  - browser_history_uploads: form_history_evidence_id (FK SET NULL), parser_name / _version,
    #    exhibit_link, clock_offset_seconds (+ partial indexes on both exhibit FKs).
    #  - timeline_events: pcap_analysis_id / browser_history_upload_id (FK RESTRICT, as the other run
    #    FKs) + source_record_id; partial UNIQUE (pcap run, candidate idx) and (upload, record) so
    #    re-promoting is a no-op; a NEW CHECK that an event names at most one run of the four (the G4
    #    two-run CHECK is left as it is) and one that each new run FK carries its key.
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS input_sha256 VARCHAR(64)",
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS analyser_name VARCHAR(64)",
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS analyser_version VARCHAR(32)",
    "ALTER TABLE email_analysis ADD COLUMN IF NOT EXISTS exhibit_link VARCHAR(16)",
    _add_check_if_missing("email_analysis", "ck_email_analysis_exhibit_link",
                          "exhibit_link IS NULL OR exhibit_link IN ('registered', 'sha256_match', 'from_evidence')"),
    "CREATE INDEX IF NOT EXISTS ix_email_analysis_evidence_id ON email_analysis(evidence_id) " +
    "WHERE evidence_id IS NOT NULL",
    "ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL",
    "ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS input_sha256 VARCHAR(64)",
    "ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS analyser_name VARCHAR(64)",
    "ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS analyser_version VARCHAR(32)",
    "ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS exhibit_link VARCHAR(16)",
    "ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS clock_offset_seconds BIGINT",
    "ALTER TABLE pcap_analyses ADD COLUMN IF NOT EXISTS timeline_candidates JSON",
    _add_check_if_missing("pcap_analyses", "ck_pcap_analyses_exhibit_link",
                          "exhibit_link IS NULL OR exhibit_link IN ('registered', 'sha256_match', 'from_evidence')"),
    "CREATE INDEX IF NOT EXISTS ix_pcap_analyses_evidence_id ON pcap_analyses(evidence_id) " +
    "WHERE evidence_id IS NOT NULL",
    "ALTER TABLE browser_history_uploads ADD COLUMN IF NOT EXISTS form_history_evidence_id UUID " +
    "REFERENCES evidence(id) ON DELETE SET NULL",
    "ALTER TABLE browser_history_uploads ADD COLUMN IF NOT EXISTS parser_name VARCHAR(64)",
    "ALTER TABLE browser_history_uploads ADD COLUMN IF NOT EXISTS parser_version VARCHAR(32)",
    "ALTER TABLE browser_history_uploads ADD COLUMN IF NOT EXISTS exhibit_link VARCHAR(16)",
    "ALTER TABLE browser_history_uploads ADD COLUMN IF NOT EXISTS clock_offset_seconds BIGINT",
    _add_check_if_missing("browser_history_uploads", "ck_browser_history_uploads_exhibit_link",
                          "exhibit_link IS NULL OR exhibit_link IN ('registered', 'sha256_match', 'from_evidence')"),
    "CREATE INDEX IF NOT EXISTS ix_browser_history_uploads_evidence_id ON browser_history_uploads(evidence_id) " +
    "WHERE evidence_id IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS ix_browser_history_uploads_form_history_evidence_id " +
    "ON browser_history_uploads(form_history_evidence_id) WHERE form_history_evidence_id IS NOT NULL",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS pcap_analysis_id UUID " +
    "REFERENCES pcap_analyses(id) ON DELETE RESTRICT",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS browser_history_upload_id UUID " +
    "REFERENCES browser_history_uploads(id) ON DELETE RESTRICT",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS source_record_id UUID",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_timeline_events_pcap_event " +
    "ON timeline_events(pcap_analysis_id, import_event_index) WHERE pcap_analysis_id IS NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_timeline_events_webhistory_record " +
    "ON timeline_events(browser_history_upload_id, source_record_id) WHERE browser_history_upload_id IS NOT NULL",
    _add_check_if_missing("timeline_events", "ck_timeline_events_one_run_g3",
                          "num_nonnulls(forensic_import_id, defender_import_id, pcap_analysis_id, "
                          "browser_history_upload_id) <= 1"),
    _add_check_if_missing("timeline_events", "ck_timeline_events_g3_run_key",
                          "(pcap_analysis_id IS NULL OR import_event_index IS NOT NULL) "
                          "AND (browser_history_upload_id IS NULL OR source_record_id IS NOT NULL)"),

    # G1 stage 3a (R81) — byte sizes of stored files, and of the bundles that embed them, become
    # BIGINT: int4 stops at 2 GiB and G2 lifts the 1 GiB upload cap. One-shot, guarded on the
    # current type. Each is a table rewrite under ACCESS EXCLUSIVE, but the tables are tiny
    # (2026-10-04: evidence 71 rows / 344 kB, entity_files 16 / 120 kB, custody_exports 44 /
    # 184 kB, le_packages 4 / 176 kB), well inside the 5 s lock_timeout.
    _widen_to_bigint("evidence", "file_size_bytes"),
    _widen_to_bigint("entity_files", "file_size"),
    _widen_to_bigint("custody_exports", "file_size"),
    _widen_to_bigint("le_packages", "total_bytes"),

    # G5 — working copies with their own hashes (R08), legal hold set / released through its own
    # endpoint (R09). Additive and nullable, NO backfill: rows made before G5 keep NULL, which the API
    # reads as "export" (export_id set) or "legacy record" (a "Record copy" row whose sha256 is a
    # re-hash of the master, so it never counts as a verified copy). Nothing is rewritten.
    #  - evidence: the current hold (since, by, reason); history stays in the custody log.
    #  - evidence_copies: kind (download | lab_copy; CHECK), per-exhibit copy_seq (partial UNIQUE)
    #    + copy_identifier "<exhibit>-WC-n", status (CHECK), the copy's sha1 / md5 (sha256 exists),
    #    the one-time download link (SHA-256 of the token + expiry), transfer times, bytes sent, end
    #    reason, destination note, the lab copy's tool, and altered_at (an examination found the copy
    #    changed).
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS legal_hold_since TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS legal_hold_by_id UUID REFERENCES users(id)",
    "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS legal_hold_reason TEXT",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS kind VARCHAR(16)",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS copy_seq INTEGER",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS copy_identifier VARCHAR(160)",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS status VARCHAR(20)",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS sha1 VARCHAR(40)",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS md5 VARCHAR(32)",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS token_hash VARCHAR(64)",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS download_started_at TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS bytes_sent BIGINT",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS end_reason VARCHAR(32)",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS destination_note TEXT",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS copy_tool VARCHAR(256)",
    "ALTER TABLE evidence_copies ADD COLUMN IF NOT EXISTS altered_at TIMESTAMP WITH TIME ZONE",
    _add_check_if_missing("evidence_copies", "ck_evidence_copies_kind",
                          "kind IS NULL OR kind IN ('download', 'lab_copy')"),
    _add_check_if_missing("evidence_copies", "ck_evidence_copies_status",
                          "status IS NULL OR status IN ('issued', 'downloading', 'complete', 'aborted', "
                          "'failed_integrity', 'verified', 'mismatch')"),
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_copies_copy_seq ON evidence_copies(evidence_id, copy_seq) " +
    "WHERE copy_seq IS NOT NULL",

    # G-fix B (L26) — a mail relay hop imported from an email analysis with a run record (G3) names that
    # run, so its provenance (analyser, version, input SHA-256) fills the LE Timeline.csv like the other
    # runs. Additive and nullable, NO backfill (hops imported before keep NULL; their analysis still
    # records them in headers.hops[].timeline_event_id). FK RESTRICT like the other run FKs (there is no
    # email-analysis delete route); a partial index for the FK; and a NEW one-run CHECK over the five run
    # FKs (the G3 four-run CHECK is left as it is). Safe on the live table: every existing row has the
    # new column NULL and already satisfies the four-run CHECK, so validating it (1 056 rows / 18 MB on
    # 2026-10-04) takes milliseconds under the 5 s lock_timeout.
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS email_analysis_id UUID " +
    "REFERENCES email_analysis(id) ON DELETE RESTRICT",
    "CREATE INDEX IF NOT EXISTS ix_timeline_events_email_analysis_id ON timeline_events(email_analysis_id) " +
    "WHERE email_analysis_id IS NOT NULL",
    _add_check_if_missing("timeline_events", "ck_timeline_events_one_run_gfixb",
                          "num_nonnulls(forensic_import_id, defender_import_id, pcap_analysis_id, "
                          "browser_history_upload_id, email_analysis_id) <= 1"),

    # H1 (R06) — the quarantine is encrypted at rest. Additive and nullable: artifacts.nonce_hex holds the
    # v2 nonce prefix (14 lower-case hex, the CHECK) and NULL marks a legacy plaintext file, which every row
    # made before H1 is until `python -m artifacts.encrypt_quarantine --apply` migrates it (no backfill here:
    # the tool encrypts the file and sets the column in one transaction). forensic_imports.source_artifact_id
    # names the artifact a from-artifact import parsed (the delete guard's reference); it is backfilled once,
    # when the column is created, from the forensic_import_create audit rows (details.source_artifact) of
    # the same incident. Tiny tables (2026-10-05: 94 artifacts, a handful of imports): the ADD COLUMN and
    # CHECK validation take milliseconds under the 5 s lock_timeout.
    "ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS nonce_hex VARCHAR(24)",
    _add_check_if_missing("artifacts", "ck_artifacts_nonce_hex_h1", "nonce_hex IS NULL OR nonce_hex ~ '^[0-9a-f]{14}$'"),
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'forensic_imports' AND column_name = 'source_artifact_id'
        ) THEN
            ALTER TABLE forensic_imports
                ADD COLUMN source_artifact_id UUID REFERENCES artifacts(id) ON DELETE SET NULL;
            UPDATE forensic_imports f SET source_artifact_id = a.id
              FROM audit_logs l
              JOIN artifacts a ON a.id::text = l.details->>'source_artifact'
             WHERE l.action = 'forensic_import_create'
               AND l.resource_id = f.id::text
               AND a.incident_id = f.incident_id;
        END IF;
    END $$
    """,
    "CREATE INDEX IF NOT EXISTS ix_forensic_imports_source_artifact_id ON forensic_imports(source_artifact_id) "
    "WHERE source_artifact_id IS NOT NULL",

    # H2 (R05) — case notes are append-only in the DB, not only in the app: any UPDATE or DELETE of a
    # case_notes row raises (corrections are new rows). The table itself comes from create_all (new, empty
    # on first run). CREATE OR REPLACE FUNCTION takes no table lock; the trigger is created only while
    # pg_trigger lacks it, so a re-run takes no lock on case_notes at all. TRUNCATE is not granted to
    # fenrir_app. A DB owner can still drop the trigger -- a separate, privileged act (as GS-8).
    """CREATE OR REPLACE FUNCTION fenrir_case_notes_append_only() RETURNS trigger
         LANGUAGE plpgsql AS $$
       BEGIN
         RAISE EXCEPTION 'case_notes is append-only (H2): % blocked', TG_OP
           USING ERRCODE = 'insufficient_privilege';
       END; $$""",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger
                       WHERE tgrelid = 'case_notes'::regclass AND tgname = 'trg_case_notes_append_only') THEN
            CREATE TRIGGER trg_case_notes_append_only
                BEFORE UPDATE OR DELETE ON case_notes
                FOR EACH ROW EXECUTE FUNCTION fenrir_case_notes_append_only();
        END IF;
    END $$
    """,

    # H4 (R10) — supporting documents (entity_files) carry the server's hashes of the original and the exhibit
    # they were registered as. Additive and nullable, NO backfill here: new uploads get the hashes from the
    # writer's single pass; existing rows are hashed once by `python -m files.backfill_hashes --apply` (it
    # decrypts each file). evidence_id is SET NULL (the file outlives its exhibit row; evidence rows are never
    # deleted in practice). Lower-case hex CHECKs; tiny table (2026-10-05: 16 rows / 120 kB), so the ADD COLUMNs
    # and CHECK validation take milliseconds under the 5 s lock_timeout; the index name is create_all's.
    "ALTER TABLE entity_files ADD COLUMN IF NOT EXISTS sha256 VARCHAR(64)",
    "ALTER TABLE entity_files ADD COLUMN IF NOT EXISTS sha1 VARCHAR(40)",
    "ALTER TABLE entity_files ADD COLUMN IF NOT EXISTS md5 VARCHAR(32)",
    "ALTER TABLE entity_files ADD COLUMN IF NOT EXISTS evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_entity_files_evidence_id ON entity_files(evidence_id)",
    _add_check_if_missing("entity_files", "ck_entity_files_hashes_h4",
                          "(sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$') AND (sha1 IS NULL OR sha1 ~ '^[0-9a-f]{40}$') "
                          "AND (md5 IS NULL OR md5 ~ '^[0-9a-f]{32}$')"),

    # I1 (R21) — the recovery tracker is one NEW table, `recovery_records`, made by create_all (checkfirst: an
    # existing table is never touched) with its CHECKs, UNIQUE(entity_id) and FKs (incident / entity / users all
    # RESTRICT). Nothing existing is altered, so there is no statement here and no backfill: a system with no row
    # reads as not_started.

    # I2 (R22) — stakeholder notification tracker. Two NEW tables from create_all (`incident_severity_levels`,
    # `stakeholder_notifications`, with their CHECKs / UNIQUEs / FKs) and one additive column. GUARDED ONE-SHOT:
    # everything below runs only in the migrate run that first adds stakeholder_matrix_rules.incident_types (a
    # fresh database gets the column from create_all and has nothing to backfill); later runs are a catalog read.
    #   1. incident_types JSON NOT NULL DEFAULT '[]' (constant default: metadata-only, no rewrite).
    #   2. Every incident without a level row gets one: its CURRENT severity, reached at detected_at, else
    #      created_at (source 'backfill'). Earlier escalations aren't known; they aren't invented.
    #   3. Every OPEN incident gets one pending obligation per matrix rule of its current severity (all existing
    #      rules have no type filter): the rule snapshot, due = reached + SLA. Ones already overdue are stamped
    #      reminder_sent_at = now, so the reminder loop doesn't fire a burst for old incidents. Closed incidents
    #      get none (their record stays as it was).
    # Not audited (a migration has no actor); the app audits every later change. Tiny tables (2026-10-06: 4 rules,
    # 119 incidents, 13 open), well inside the 5 s lock_timeout.
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'stakeholder_matrix_rules' AND column_name = 'incident_types'
        ) THEN
            ALTER TABLE stakeholder_matrix_rules ADD COLUMN incident_types JSON NOT NULL DEFAULT '[]';
            INSERT INTO incident_severity_levels (id, incident_id, severity, reached_at, source, created_at)
            SELECT gen_random_uuid(), i.id, i.severity, COALESCE(i.detected_at, i.created_at), 'backfill', now()
              FROM incidents i
             WHERE NOT EXISTS (SELECT 1 FROM incident_severity_levels l WHERE l.incident_id = i.id);
            INSERT INTO stakeholder_notifications
                   (id, incident_id, rule_id, severity, role, category, required, notify_within_minutes,
                    clock_start_at, due_at, status, reminder_sent_at, created_at, updated_at)
            SELECT gen_random_uuid(), i.id, r.id, r.severity, r.role, r.category, r.required, r.notify_within_minutes,
                   l.reached_at, l.reached_at + make_interval(mins => r.notify_within_minutes), 'pending',
                   CASE WHEN l.reached_at + make_interval(mins => r.notify_within_minutes) <= now() THEN now() END,
                   now(), now()
              FROM incidents i
              JOIN incident_severity_levels l ON l.incident_id = i.id AND l.severity = i.severity
              JOIN stakeholder_matrix_rules r ON r.severity = i.severity
             WHERE i.status <> 'closed';
        END IF;
    END $$
    """,

    # I3 (R24, R60) — playbook fixes. Additive, nullable, no backfill of review dates (null = never reviewed, so
    # Readiness `playbooks_core` fails until someone marks the core templates reviewed). Archived tasks are the
    # Done/Skipped history of a replaced plan. Tiny tables (2026-10-06: 16 templates, 35 tasks):
    # metadata-only ADD COLUMNs, well inside the 5 s lock_timeout.
    "ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS last_reviewed_at TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS last_reviewed_by_id UUID REFERENCES users(id)",
    "ALTER TABLE playbook_tasks ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE playbook_tasks ADD COLUMN IF NOT EXISTS archived_by_id UUID REFERENCES users(id)",
    "ALTER TABLE playbook_tasks ADD COLUMN IF NOT EXISTS archive_reason TEXT",
    # I3 — playbook_templates.incident_types. GUARDED ONE-SHOT: only the migrate run that first adds the column
    # sets the seeded system templates' default types (the same values as playbook/seeds.py, which a fresh
    # database gets from the seeder instead). Custom templates and the general frameworks stay [].
    """
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'playbook_templates' AND column_name = 'incident_types'
        ) THEN
            ALTER TABLE playbook_templates ADD COLUMN incident_types JSON NOT NULL DEFAULT '[]';
            UPDATE playbook_templates t SET incident_types = d.types::json
              FROM (VALUES
                ('cisa_vuln_resp',           '["vulnerability_exploitation"]'),
                ('ransomware_containment',   '["ransomware"]'),
                ('credential_stuffing',      '["credential_compromise"]'),
                ('phishing_takedown',        '["phishing"]'),
                ('anomalous_data_egress',    '["data_breach"]'),
                ('oauth_app_revocation',     '["credential_compromise", "unauthorized_access"]'),
                ('insider_exfiltration',     '["insider_threat"]'),
                ('ddos_mitigation',          '["ddos"]'),
                ('bec_response',             '["bec"]'),
                ('network_intrusion',        '["unauthorized_access"]'),
                ('malware_infection',        '["malware"]'),
                ('data_breach_notification', '["data_breach"]'),
                ('cloud_compromise',         '["unauthorized_access", "credential_compromise"]'),
                ('ai_device_code_phishing',  '["phishing", "credential_compromise"]')
              ) AS d(key, types)
             WHERE t.key = d.key AND t.is_system;
        END IF;
    END $$
    """,

    # I4 (R25) — intake fields and the Dark Operation decision marker. Additive and nullable, no backfill:
    # existing incidents keep null (detected_at_source null = recorded before I4; dark_operation_decided_at
    # null = never decided, so a phishing/BEC start check warns until someone decides). Metadata-only ADD
    # COLUMNs on a small table, well inside the 5 s lock_timeout.
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS detected_at_source VARCHAR(16)",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS functional_impact VARCHAR(16)",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS information_impact VARCHAR(16)",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS recoverability VARCHAR(16)",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS severity_rationale TEXT",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS alert_reference VARCHAR(256)",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS dark_operation_decided_at TIMESTAMP WITH TIME ZONE",

    # I5 (R23) — gates v2. One NEW table from create_all, `incident_gate_sign_offs` (CHECKs, FKs RESTRICT),
    # append-only in the DB like case_notes (H2): the function is CREATE OR REPLACE (no table lock) and the
    # trigger is created only while pg_trigger lacks it. Three additive nullable / constant-default columns
    # (metadata-only, no rewrite, no backfill): the closure-checklist N/A state + reason, and a Respond
    # action's defer reason. The N/A-vs-checked CHECK is added once (tiny table: 2026-10-06, 97 rows).
    "ALTER TABLE closure_checklist_items ADD COLUMN IF NOT EXISTS not_applicable BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE closure_checklist_items ADD COLUMN IF NOT EXISTS na_reason TEXT",
    _add_check_if_missing("closure_checklist_items", "ck_closure_items_na_not_checked",
                          "NOT (checked AND not_applicable)"),
    "ALTER TABLE respond_actions ADD COLUMN IF NOT EXISTS defer_reason TEXT",
    """CREATE OR REPLACE FUNCTION fenrir_gate_sign_offs_append_only() RETURNS trigger
         LANGUAGE plpgsql AS $$
       BEGIN
         RAISE EXCEPTION 'incident_gate_sign_offs is append-only (I5): % blocked', TG_OP
           USING ERRCODE = 'insufficient_privilege';
       END; $$""",
    """
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger
                       WHERE tgrelid = 'incident_gate_sign_offs'::regclass
                         AND tgname = 'trg_gate_sign_offs_append_only') THEN
            CREATE TRIGGER trg_gate_sign_offs_append_only
                BEFORE UPDATE OR DELETE ON incident_gate_sign_offs
                FOR EACH ROW EXECUTE FUNCTION fenrir_gate_sign_offs_append_only();
        END IF;
    END $$
    """,

    # J1 (R26) — SIEM intake dedup. One NEW table from create_all, `siem_alerts` (CHECKs on source / outcome /
    # content_key, FK incidents ON DELETE CASCADE, two lookup indexes), made with checkfirst: nothing existing is
    # altered, so there is no statement here and no backfill (earlier SIEM incidents have no row and are never
    # matched as re-fires). J2 adds no schema: the reminder email reuses B4's reminder_stage and I2's
    # reminder_sent_at claims as its once-only marker, and its org switch is a platform_settings row.

    # J3 (R30) — optional lessons-learned meeting minutes. Additive nullable TEXT, no default, no backfill
    # (existing records keep null = no minutes recorded): a metadata-only ADD COLUMN on a small table, well
    # inside the 5 s lock_timeout.
    "ALTER TABLE lessons_learned ADD COLUMN IF NOT EXISTS meeting_minutes TEXT",

    # J4 (R32, R33) + J5 (R31). All additive and nullable (or with a constant default), no backfill:
    # older rows keep "no link" / "not promoted" / "no IC transfer". ADD COLUMN ... REFERENCES briefly
    # takes SHARE ROW EXCLUSIVE on the referenced small tables; the two CHECKs scan timeline_events /
    # decisions once (2026-10-06: a few thousand rows), all well inside the 5 s lock_timeout.
    # Partial indexes keep ON DELETE SET NULL and the reverse-link lookups off a full scan; the partial
    # UNIQUE indexes make promoting the same message twice to the same kind of record a 409.
    "ALTER TABLE respond_actions ADD COLUMN IF NOT EXISTS decision_id UUID REFERENCES decisions(id) ON DELETE SET NULL",
    "ALTER TABLE respond_actions ADD COLUMN IF NOT EXISTS task_id UUID REFERENCES playbook_tasks(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_respond_actions_decision_id ON respond_actions(decision_id) WHERE decision_id IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS ix_respond_actions_task_id ON respond_actions(task_id) WHERE task_id IS NOT NULL",
    "ALTER TABLE playbook_tasks ADD COLUMN IF NOT EXISTS handoff_id UUID REFERENCES incident_handoffs(id) ON DELETE SET NULL",
    "CREATE INDEX IF NOT EXISTS ix_playbook_tasks_handoff_id ON playbook_tasks(handoff_id) WHERE handoff_id IS NOT NULL",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS transfer_ic BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE incident_handoffs ADD COLUMN IF NOT EXISTS ic_transferred_at TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS promoted_from_kind VARCHAR(16)",
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS promoted_from_id UUID",
    "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS promoted_from_kind VARCHAR(16)",
    "ALTER TABLE decisions ADD COLUMN IF NOT EXISTS promoted_from_id UUID",
    _add_check_if_missing("timeline_events", "ck_timeline_events_promoted_from_j4",
                          "(promoted_from_kind IS NULL AND promoted_from_id IS NULL) OR "
                          "(promoted_from_kind IN ('warroom', 'comment') AND promoted_from_id IS NOT NULL)"),
    _add_check_if_missing("decisions", "ck_decisions_promoted_from_j4",
                          "(promoted_from_kind IS NULL AND promoted_from_id IS NULL) OR "
                          "(promoted_from_kind IN ('warroom', 'comment') AND promoted_from_id IS NOT NULL)"),
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_timeline_events_promoted_from ON timeline_events(promoted_from_kind, promoted_from_id) " +
    "WHERE promoted_from_id IS NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_decisions_promoted_from ON decisions(promoted_from_kind, promoted_from_id) " +
    "WHERE promoted_from_id IS NOT NULL",

    # K1 (R36) — a Disclosure package's purpose. Existing rows are LE packages: the constant default fills them
    # without a rewrite (PG 11+: metadata-only ADD COLUMN), and the CHECK scans le_packages once (one row per
    # package built; small), well inside the 5 s lock_timeout.
    "ALTER TABLE le_packages ADD COLUMN IF NOT EXISTS purpose VARCHAR(24) NOT NULL DEFAULT 'law_enforcement'",
    _add_check_if_missing("le_packages", "ck_le_packages_purpose_k1",
                          "purpose IN ('internal', 'law_enforcement', 'regulator')"),

    # K3 (R39) — the analyst's "key event" flag on a timeline event. The constant default fills existing rows
    # without a rewrite (metadata-only ADD COLUMN), well inside the 5 s lock_timeout.
    "ALTER TABLE timeline_events ADD COLUMN IF NOT EXISTS is_key BOOLEAN NOT NULL DEFAULT false",
    # K2 (R38) — time in phase is read from the append-only audit log (incident_create / _update / _close /
    # _reopen rows), on every snapshot. A partial index over the incident rows keeps that (and the gates'
    # last-re-opened lookup) off a full scan. Building it takes SHARE on audit_logs (inserts wait; about
    # 3 000 rows on 2026-10-07, milliseconds); IF NOT EXISTS makes a re-run a no-op.
    "CREATE INDEX IF NOT EXISTS ix_audit_logs_incident_resource ON audit_logs(resource_id, action) " +
    "WHERE resource_type = 'incident'",
]
