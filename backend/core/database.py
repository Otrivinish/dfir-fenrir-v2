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
]
