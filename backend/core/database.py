"""Async SQLAlchemy engine + session factory."""
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
engine = create_async_engine(
    settings.database_url,
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
    async with engine.begin() as conn:
        await conn.run_sync(lambda sync_conn: Base.metadata.create_all(sync_conn, checkfirst=True))
        for stmt in _INPLACE_MIGRATIONS:
            await conn.execute(text(stmt))


# ── Idempotent in-place migrations ────────────────────────────────────────
# When a real migration tool (Alembic) lands, this disappears.

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
    # contained_at (auto-set on CER phase transition, editable after).
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS occurred_at  TIMESTAMP WITH TIME ZONE",
    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS contained_at TIMESTAMP WITH TIME ZONE",

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
]
