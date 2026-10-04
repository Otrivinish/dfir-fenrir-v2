"""All ORM models. Single file while the count stays manageable."""
import uuid
from datetime import date, datetime, timezone

from sqlalchemy import (BigInteger, Boolean, Column, Date, DateTime, Float, ForeignKey,
                        Integer, JSON, Numeric, SmallInteger, String, Table, Text,
                        UniqueConstraint)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from core.database import Base


def utcnow() -> datetime:
    """Timezone-aware UTC now. Use for new timestamptz columns."""
    return datetime.now(timezone.utc)


def utc_today() -> date:
    """Today's date in UTC: the one "today" for date-only columns (e.g. the on-call rota)."""
    return utcnow().date()


# ─── Association: user ↔ team ────────────────────────────────────────────────

user_team = Table(
    "user_team",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("team_id", UUID(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True),
)

# ─── Association: incident ↔ team ────────────────────────────────────────────
# Controls per-incident visibility. An incident with no teams is visible to all
# authenticated users. An incident with ≥1 team is visible only to members of
# those teams (and admins).

incident_teams = Table(
    "incident_teams",
    Base.metadata,
    Column("incident_id", UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("team_id",     UUID(as_uuid=True), ForeignKey("teams.id",    ondelete="CASCADE"), primary_key=True),
)


# ─── User ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username        = Column(String(64),  unique=True, nullable=False, index=True)
    email           = Column(String(255), unique=True, nullable=False, index=True)
    full_name       = Column(String(255))
    hashed_password = Column(String(255), nullable=False)
    auth_provider   = Column(String(32),  nullable=False, default="local")  # local | entra | oidc | saml (reserved)

    # Platform role
    role            = Column(String(32),  nullable=False, default="analyst")  # admin | analyst | viewer

    # ISO/IEC 27037 Annex A / 27041 — DEFR competence/qualifications statement.
    # Snapshotted onto evidence/examination records at action time (Slice B).
    qualifications  = Column(Text)

    # TOTP
    totp_secret_enc = Column(String(255))                    # Fernet ciphertext
    totp_enabled    = Column(Boolean,     nullable=False, default=False)
    force_totp_enrol = Column(Boolean,    nullable=False, default=False)

    # State
    is_active            = Column(Boolean,  nullable=False, default=True)
    force_password_change = Column(Boolean, nullable=False, default=False)

    # Audit
    created_at      = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at   = Column(DateTime(timezone=True))

    # Relationships
    teams           = relationship("Team", secondary=user_team, back_populates="members")


# ─── Team ────────────────────────────────────────────────────────────────────

class Team(Base):
    __tablename__ = "teams"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name        = Column(String(128), unique=True, nullable=False)
    description = Column(Text)
    color       = Column(String(7),   nullable=False, default="#22d3ee")
    created_at  = Column(DateTime,    default=datetime.utcnow, nullable=False)

    members     = relationship("User", secondary=user_team, back_populates="teams")


# ─── Sessions ────────────────────────────────────────────────────────────────

class UserSession(Base):
    __tablename__ = "user_sessions"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id         = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    token_hash      = Column(String(64),  unique=True, nullable=False, index=True)  # sha256 of opaque token
    label           = Column(String(64))                                            # user-set device name
    ip_address      = Column(String(64))
    user_agent      = Column(String(512))
    country         = Column(String(64))
    city            = Column(String(128))

    created_at      = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    last_seen_at    = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    expires_at      = Column(DateTime(timezone=True), nullable=False)
    revoked_at      = Column(DateTime(timezone=True))
    revoke_reason   = Column(String(64))                       # "user" | "admin" | "expired" | "rotated"


# ─── API tokens (Bearer auth for MCP clients / scripts / integrations) ──────
# Same RBAC as cookie sessions. Plain token shown once at issue; only the
# sha256 fingerprint lives in DB. Role is set at issue time and capped to the
# issuing user's current role — re-checked on every request, so demoting a
# user automatically downgrades their tokens.

class ApiToken(Base):
    __tablename__ = "api_tokens"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id         = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    name            = Column(String(128), nullable=False)              # human label
    token_hash      = Column(String(64),  unique=True, nullable=False, index=True)
    token_prefix    = Column(String(16),  nullable=False)              # first chars for display ("fnr_v1_abc…")
    role            = Column(String(32),  nullable=False)              # admin | analyst | viewer (cap, ≤ user.role)

    created_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_used_at    = Column(DateTime(timezone=True))
    expires_at      = Column(DateTime(timezone=True))                  # null = no expiry
    revoked_at      = Column(DateTime(timezone=True))
    revoke_reason   = Column(String(64))                               # "user" | "admin" | "rotated"


# ─── Operational role catalog ────────────────────────────────────────────────
# Per FENRIR2 standards alignment: seeded with CISA IR roles; admin-extensible.

class OperationalRole(Base):
    __tablename__ = "operational_roles"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key         = Column(String(64),  unique=True, nullable=False)   # machine id, e.g. "incident_commander"
    label       = Column(String(128), nullable=False)                # display, e.g. "Incident Commander"
    description = Column(Text)
    is_system   = Column(Boolean,     nullable=False, default=False) # seeded CISA roles can't be deleted
    is_active   = Column(Boolean,     nullable=False, default=True)
    sort_order  = Column(Integer,     nullable=False, default=100)
    created_at  = Column(DateTime,    default=datetime.utcnow, nullable=False)


# ─── Audit log (tamper-evident hash chain) ───────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp     = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id       = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    username      = Column(String(64))                       # denormalised for fast display
    action        = Column(String(64),  nullable=False)      # login_success, login_fail, totp_enable, ...
    resource_type = Column(String(64))                       # user, session, team, ...
    resource_id   = Column(String(255))
    details       = Column(JSON, default=dict)
    ip_address    = Column(String(64))
    user_agent    = Column(String(512))

    # Forensic context — populated automatically by audit middleware/deps when present.
    outcome        = Column(String(16))                       # success | failure | denied
    session_id     = Column(UUID(as_uuid=True), ForeignKey("user_sessions.id"), index=True)
    role_at_time   = Column(String(32))                       # actor role at the moment of action
    resource_label = Column(String(255))                      # denormalised display label
    request_method = Column(String(8))                        # GET | POST | PATCH | …
    request_path   = Column(String(512))                      # actual URL path of the request
    request_id     = Column(String(36), index=True)           # uuid; groups multi-row actions

    # Hash chain
    hash_version  = Column(String(8),   nullable=False, default="v2")
    row_hash      = Column(String(64),  nullable=False)
    prev_hash     = Column(String(64),  nullable=False)      # "0"*64 for genesis


class EmailAnalysis(Base):
    """U8.1 — a parsed + scored email (phishing triage). The raw message is kept as a
    quarantine Artifact (source_artifact_id) so attachments can be re-extracted and the
    message minted as Evidence without storing bytes here. URLs/attachments/hops live in
    JSON until the analyst promotes them."""
    __tablename__ = "email_analysis"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id       = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                               nullable=False, index=True)
    source_artifact_id = Column(UUID(as_uuid=True), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True)
    evidence_id        = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    batch_id           = Column(UUID(as_uuid=True), nullable=True, index=True)  # groups a bulk-import run

    subject       = Column(Text)
    from_display  = Column(String(512))
    from_addr     = Column(String(512))
    reply_to      = Column(String(512))
    return_path   = Column(String(512))
    message_id    = Column(String(998))
    date_hdr      = Column(String(256))

    verdict   = Column(String(8), nullable=False, default="green")  # green | amber | red
    score     = Column(Integer, nullable=False, default=0)          # 0–100
    findings  = Column(JSON, nullable=False, default=list)          # [{code,severity,title,detail,layer,points}]
    headers   = Column(JSON, nullable=False, default=dict)          # hops + auth + notable header map
    raw_headers   = Column(Text, nullable=True)                     # full verbatim header block
    auth_verified = Column(JSON, nullable=True)                     # live SPF/DMARC/DKIM cross-check vs. the header's own claim
    body_text = Column(Text, nullable=True)                         # plain-text body, for the UI preview
    body_html = Column(Text, nullable=True)                         # SANITIZED html body only -- never raw attacker HTML
    urls      = Column(JSON, nullable=False, default=list)          # [{url,defanged,host,display_text,promoted_ioc_id?}]
    attachments = Column(JSON, nullable=False, default=list)        # [{filename,declared_type,true_type,size,md5,sha256,entropy,flags,artifact_id?}]

    # G3 (R02) run record: the analysis is OF its exhibit (evidence_id) — registered as an unsealed
    # draft by the upload (exhibit_link 'registered'), an upload whose SHA-256 equals exactly one
    # active exhibit ('sha256_match'), or a picked exhibit re-verified ('from_evidence') — with the
    # SHA-256 of the bytes analysed and the analyser + version. No quarantine copy (source_artifact_id
    # NULL). All NULL on analyses before G3: those were analysed first and, at most, registered later
    # from their quarantine copy ("Register as exhibit", the legacy mint).
    input_sha256     = Column(String(64))
    analyser_name    = Column(String(64))
    analyser_version = Column(String(32))
    exhibit_link     = Column(String(16))     # registered | sha256_match | from_evidence (CHECK)

    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_by    = Column(String(64))
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class AuditAnchor(Base):
    """GS-8 — periodic, externally-anchored proof of the audit chain head.

    Each row certifies the chain head at `anchored_at`: the segment since the prior
    anchor was verified (`verify_ok`), and `head_row_hash` was RFC-3161 timestamped
    (`tst`, best-effort). Consecutive anchors cover the whole log; `row_count`
    monotonicity catches deletions. Its own table — never extends the audit chain.
    """
    __tablename__ = "audit_anchor"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    anchored_at   = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    head_row_id   = Column(UUID(as_uuid=True), nullable=True)   # null only if log empty
    head_row_ts   = Column(DateTime, nullable=True)             # naive UTC, mirrors audit_logs.timestamp
    head_row_hash = Column(String(64), nullable=False)
    row_count     = Column(Integer, nullable=False, default=0)
    verify_ok     = Column(Boolean, nullable=False, default=True)
    verify_detail = Column(Text, nullable=True)
    tst           = Column(Text, nullable=True)        # base64 RFC-3161 token over head_row_hash
    tst_time      = Column(String(32), nullable=True)  # asserted TSA time (ISO 8601 Z)
    tsa           = Column(String(256), nullable=True)

    @property
    def has_tst(self) -> bool:
        return bool(self.tst)


# ─── Incident ────────────────────────────────────────────────────────────────
# Standards alignment (per CLAUDE.md § Standards alignment):
#   severity     — NCISS scale
#   phase        — NIST SP 800-61 R3 phase
#   csf_function — NIST CSF 2.0 function
#   tlp          — TLP 2.0 marking

class Incident(Base):
    __tablename__ = "incidents"

    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_number  = Column(Integer, unique=True, nullable=True, index=True)
    title            = Column(String(200), nullable=False)
    description      = Column(Text)

    # Immutable incident reference, assigned once at creation (incidents/reference.py):
    # PREFIX-YYYY-NNNNN; pre-existing incidents keep INC-NNNN. A DB trigger rejects changes.
    ref              = Column(String(32), unique=True, nullable=False)

    # Standards-aligned enums (stored as strings; validated at the schema layer).
    # severity: internal Low/Medium/High/Critical (mapped to NCISS at report time).
    # phase:    NIST SP 800-61 R3 phase name.
    # tlp:      TLP 2.0 marking.
    severity      = Column(String(16), nullable=False, default="medium")
    phase         = Column(String(40), nullable=False, default="detection_and_analysis")
    tlp           = Column(String(16), nullable=False, default="amber")
    status        = Column(String(16), nullable=False, default="open", index=True)
    # Analyst's investigation-confidence assessment. Distinct from severity (impact)
    # and phase (response posture). Values: suspected (default) / confirmed /
    # false_positive / benign_positive.
    triage_state  = Column(String(24), nullable=False, default="suspected", index=True)

    reporter      = Column(String(128))
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)

    incident_type = Column(String(32))          # CISA/SOC incident category

    # Out-of-Band / dark operation fields.
    # dark_operation suppresses notifications and increases access logging.
    # oob_passphrase is generated on demand for human-to-human identity verification.
    dark_operation = Column(Boolean, nullable=False, default=False)
    oob_passphrase = Column(String(64))

    # Timestamps — timezone-aware UTC (timestamptz).
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    closed_at     = Column(DateTime(timezone=True))
    # Who signed the incident off as closed (POST …/close); cleared on re-open.
    closed_by_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    occurred_at   = Column(DateTime(timezone=True))   # analyst-supplied: when the incident actually occurred
    detected_at   = Column(DateTime(timezone=True))   # analyst-supplied: when the incident was detected
    # Response milestones — analyst-declared (never auto-set); see incidents/routes.py.
    contained_at  = Column(DateTime(timezone=True))
    eradicated_at = Column(DateTime(timezone=True))
    recovered_at  = Column(DateTime(timezone=True))

    # Detection and affected scope
    detection_method = Column(String(32))   # siem_alert | user_report | threat_hunting | external_notification | automated_scan | pen_test | other

    # Freeform analyst tags — normalised to lowercase-dashed at the API boundary.
    # Capped at 20 by core.tags. See `normalize_tags()` for the canonical helper.
    tags          = Column(JSON, nullable=False, default=list)

    # Access control — teams that may view this incident. Empty = no restriction.
    teams = relationship("Team", secondary="incident_teams", lazy="selectin")


# ─── Affected systems (per-incident) ─────────────────────────────────────────
# Frozen legacy table (C2): Entities is the single scope list and "affected systems" are
# its compromised entities. Nothing writes here any more; each row was copied once into
# entities by the C2 migration and stamped with the entity it became, so old ids still
# resolve through the /affected-systems compatibility layer. Kept for rollback.

class AffectedSystem(Base):
    __tablename__ = "affected_systems"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id         = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    name                = Column(String(255), nullable=False)
    system_type         = Column(String(32))   # workstation | server | network_device | cloud_resource | application | database | mobile | other
    notes               = Column(Text)
    created_at          = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by_username = Column(String(64))
    migrated_entity_id  = Column(UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True)


# ─── IOC (per-incident indicator of compromise) ──────────────────────────────
# 800-61 R3 vocabulary: "indicator of compromise". Dedup is per-incident on
# (type, value); the same indicator can legitimately appear in multiple
# incidents. Cross-incident correlation is a separate FENRIR2 item.

class IOC(Base):
    __tablename__ = "iocs"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id   = Column(UUID(as_uuid=True),
                           ForeignKey("incidents.id", ondelete="CASCADE"),
                           nullable=False, index=True)

    # Type vocabulary validated at the Pydantic layer (IocType literal).
    type          = Column(String(32),   nullable=False, index=True)
    value         = Column(String(2048), nullable=False)
    notes         = Column(Text)
    source        = Column(String(256))                  # e.g. "manual", "alert:1234"
    # Tri-state status: True = malicious, False = clean, NULL = unknown
    # (analyst hasn't reviewed). Pre-trichotomy data migrated FALSE → NULL once
    # in core/database.py.
    malicious     = Column(Boolean,      nullable=True,  default=None)
    confidence    = Column(Integer,      nullable=False, default=50)   # 0–100; UI bands <30 / 30–70 / >70
    tags          = Column(JSON,         nullable=False, default=list) # freeform list[str]; auto-source tag injected on auto-create
    entity_id     = Column(UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True, index=True)
    # C5 — the exhibit (evidence item, same incident) the indicator was found in. Partial index in
    # core/database.py.
    evidence_id   = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)

    added_by_id   = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    added_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("incident_id", "type", "value", name="uq_ioc_incident_type_value"),
    )


# ─── IOC ↔ timeline event link (many-to-many within an incident) ─────────────
class IocTimelineLink(Base):
    __tablename__ = "ioc_timeline_links"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_id            = Column(UUID(as_uuid=True),
                              ForeignKey("iocs.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    timeline_event_id = Column(UUID(as_uuid=True),
                              ForeignKey("timeline_events.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    created_by_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at        = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("ioc_id", "timeline_event_id", name="uq_ioc_timeline_link"),
    )


# ─── Entity (asset in scope of an incident) ──────────────────────────────────
# Distinct from IOC: an IOC is "this is a sign of badness"; an Entity is
# "this thing exists in our environment and is relevant to the incident"
# (host, user, service, etc). Cross-incident dossier/correlation is a
# separate FENRIR2 item.

class Entity(Base):
    __tablename__ = "entities"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id   = Column(UUID(as_uuid=True),
                           ForeignKey("incidents.id", ondelete="CASCADE"),
                           nullable=False, index=True)

    # Type vocabulary validated at the Pydantic layer (EntityType literal).
    type          = Column(String(32),   nullable=False, index=True)
    value         = Column(String(2048), nullable=False)
    name          = Column(String(256))                  # optional display name
    description   = Column(Text)
    criticality   = Column(String(16), nullable=False, default="medium")   # low/medium/high/critical
    attributes    = Column(JSON, nullable=False, default=dict)             # arbitrary key/value
    compromised   = Column(Boolean, nullable=False, default=False)

    added_by_id   = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    added_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("incident_id", "type", "value", name="uq_entity_incident_type_value"),
    )


# ─── Entity event log (per-asset timeline) ───────────────────────────────────
# event_type: "system" = auto-populated (entity add, compromised toggle);
#             "note"   = analyst-entered observation.
# Only "note" events may be deleted. System events are append-only.

class EntityEvent(Base):
    __tablename__ = "entity_events"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_id   = Column(UUID(as_uuid=True),
                         ForeignKey("entities.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    incident_id = Column(UUID(as_uuid=True),
                         ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    event_type  = Column(String(16), nullable=False, default="note")  # system | note
    title       = Column(String(512), nullable=False)
    body        = Column(Text)
    actor_id    = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    occurred_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    created_at  = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ─── Entity relations (asset graph edges) ────────────────────────────────────

class EntityRelation(Base):
    __tablename__ = "entity_relations"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id       = Column(UUID(as_uuid=True),
                               ForeignKey("incidents.id", ondelete="CASCADE"),
                               nullable=False, index=True)
    from_entity_id    = Column(UUID(as_uuid=True),
                               ForeignKey("entities.id", ondelete="CASCADE"),
                               nullable=False)
    to_entity_id      = Column(UUID(as_uuid=True),
                               ForeignKey("entities.id", ondelete="CASCADE"),
                               nullable=False)
    relationship_type = Column(String(64), nullable=False)
    notes             = Column(Text)
    created_by_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at        = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("from_entity_id", "to_entity_id", "relationship_type",
                         name="uq_entity_rel"),
    )


# ─── Entity files (raw collected artefacts: logs, screenshots, etc.) ─────────
# Lighter-weight than Evidence: no chain-of-custody, no CoC timeline.
# AES-256-GCM encrypted at rest in logs_path/entity-files/.

class EntityFile(Base):
    __tablename__ = "entity_files"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # entity_id is optional: a file may live at the incident level (the "Files"
    # store) with no entity, or be linked to one. Deleting the entity unlinks the
    # file (SET NULL) rather than destroying it, since the file is incident-owned.
    entity_id      = Column(UUID(as_uuid=True),
                            ForeignKey("entities.id", ondelete="SET NULL"),
                            nullable=True, index=True)
    incident_id    = Column(UUID(as_uuid=True),
                            ForeignKey("incidents.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    original_name  = Column(String(512), nullable=False)
    file_size      = Column(BigInteger,  nullable=False)
    content_type   = Column(String(128))
    file_path      = Column(String(1024), nullable=False)   # relative under logs_path
    nonce_hex      = Column(String(24),  nullable=False)
    uploaded_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    uploaded_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    # E4: a screenshot picked for the report's Figures section. Only PNG/JPEG/GIF/WebP by
    # content (checked when it is set, files/routes.py); the caption is printed under it.
    include_in_report = Column(Boolean, nullable=False, default=False, server_default="false")
    report_caption    = Column(String(512))
    # E-fix L5: SHA-256 (hex) and sniffed image type of the original, stored when the file is picked
    # (files/routes.py) so report data needn't decrypt it on every call. NULL = not picked, or picked
    # before these columns existed (report data then hashes it on the fly).
    report_sha256     = Column(String(64))
    report_mime       = Column(String(16))


# ─── Evidence (chain of custody) ─────────────────────────────────────────────
# 800-61 R3 / ISO 27037 vocabulary. Two kinds in MVP:
#   - digital_file: uploaded, AES-256-GCM encrypted at rest in /evidence
#   - physical_item: referenced (drive/phone/sealed bag), tracked by id+photos
# Custody actions land in the existing hash-chained audit log with
# `resource_type='evidence'`; this row holds the *current* state (custodian,
# status). Append-only history lives in the audit chain.

class Evidence(Base):
    __tablename__ = "evidence"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id   = Column(UUID(as_uuid=True),
                           ForeignKey("incidents.id", ondelete="CASCADE"),
                           nullable=False, index=True)

    kind          = Column(String(16), nullable=False)            # digital_file / physical_item
    name          = Column(String(256), nullable=False)
    identifier    = Column(String(128), nullable=False)           # NIST template item # / case tag
    description   = Column(Text)
    tlp           = Column(String(16), nullable=False, default="amber")   # TLP 2.0
    status        = Column(String(24), nullable=False, default="active", index=True)
    # status vocabulary: active / verify_failed / destroyed / returned / archived

    # — digital_file fields —
    original_filename = Column(String(512))
    storage_path      = Column(String(1024))   # path under evidence_path, encrypted at rest
    file_size_bytes   = Column(BigInteger)
    mime_type         = Column(String(128))
    sha256            = Column(String(64),  index=True)
    sha1              = Column(String(40))
    md5               = Column(String(32))
    # AES-256-GCM crypto envelope. Its length names the stored format (evidence/crypto.py):
    # 24 hex = v0 whole-file nonce (tag appended to the ciphertext); 14 hex = the FENRGCM v2
    # nonce prefix (G1 stage 3a), checked against the file's header on every read.
    nonce_hex         = Column(String(24))

    # — physical_item fields —
    make              = Column(String(128))
    model             = Column(String(128))
    serial            = Column(String(128))
    physical_location = Column(String(256))
    condition         = Column(Text)
    # Photo references stored as JSON list of objects: {url, caption, taken_at}
    photos            = Column(JSON, nullable=False, default=list)

    # — common —
    entity_id            = Column(UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True, index=True)
    current_custodian_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    # ── External custodian (ISO/IEC 27037 §6.1 — chain accountability covers
    # real-world parties without platform accounts: external counsel, courier,
    # police officer pre-formal-handoff, vendor IR team). Mutually exclusive
    # with current_custodian_id — exactly one is populated at any time.
    current_custodian_external_name    = Column(String(256))
    current_custodian_external_org     = Column(String(256))
    current_custodian_external_contact = Column(String(256))
    # C4 — an internal custody transfer awaiting the recipient's acceptance. Custody changes
    # only when the recipient accepts; all three are NULL when nothing is pending (CHECK and
    # partial indexes in core/database.py).
    pending_custodian_id          = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    pending_transfer_by_id        = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    pending_transfer_requested_at = Column(DateTime(timezone=True))
    collected_by_id      = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    collected_as_role    = Column(String(8))   # GS-12 — defr | des (ISO/IEC 27037 §3.7/§3.8)
    collected_at         = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    collected_location   = Column(String(256))
    disposed_at          = Column(DateTime(timezone=True))
    final_hash_at_disposition = Column(String(64))   # sha256 at the moment of destroy/return
    # GS-10 — second approver for disposal of a legal-hold item (two-person integrity).
    dispose_witness_id   = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Marks evidence flagged for legal hold. Disposal of a held item requires a
    # second approver (GS-10); the LE-package builder can filter to held items.
    legal_hold           = Column(Boolean, nullable=False, default=False, index=True)
    # G5 (R09) — the current hold: since when, set by whom, why (all NULL when not held; cleared on
    # release). Set / released only through PUT …/legal-hold; the history is in the custody log.
    legal_hold_since     = Column(DateTime(timezone=True))
    legal_hold_by_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    legal_hold_reason    = Column(Text)

    # ── Wizard A — Acquisition (ISO/IEC 27037 §5.4.4 + GDPR Art. 5.1(c)) ──────
    # All nullable so legacy rows survive. Populated when the guided wizard is
    # used; the legacy direct-add flow leaves them blank.
    lawful_basis              = Column(String(32))     # ir | consent | warrant | court_order | eio | mla | lia | other
    lawful_basis_note         = Column(Text)            # justification text
    acquisition_tool          = Column(String(128))
    acquisition_tool_version  = Column(String(64))
    acquisition_tool_sha256   = Column(String(64))
    acquisition_params        = Column(Text)
    acquisition_hash_source   = Column(String(64))     # source hash before imaging
    acquisition_hash_target   = Column(String(64))     # destination hash after imaging (must match source)
    # C3 — when the image was taken / item seized (operator-stated; collected_at = registered
    # in FENRIR). No backfill: a legacy row without one stays NULL rather than an invented time.
    acquired_at               = Column(DateTime(timezone=True))
    # C3 — typed target hash vs the server's hash of the uploaded bytes (same algorithm):
    # match | mismatch (legacy rows only; new mismatches are refused) | not_checked |
    # container_media (the hash covers an E01/AFF4 container's media, not the file). CHECK in
    # core/database.py.
    upload_hash_check         = Column(String(16))
    write_blocker_used        = Column(Boolean)        # null = unknown, true/false = recorded
    write_blocker_serial      = Column(String(128))
    system_state              = Column(String(16))     # powered_off | live | live_critical | unknown
    live_justification        = Column(Text)            # required when system_state in ('live','live_critical')
    network_isolated          = Column(Boolean)
    witness_user_id           = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    witness_name              = Column(String(128))    # free-text fallback when not a platform user

    # ── Collection wizard (ISO/IEC 27037 §7 / §7.1.1.3 / §7.1.3.1.1) ─────────
    # All nullable + additive; legacy and non-wizard rows leave them blank.
    device_types              = Column(JSON, default=list)   # non-exclusive §7 type tags: computer/peripheral/storage/mobile/network/cctv
    handling_mode             = Column(String(16))           # collect | acquire (the Fig-1 decision)
    decision_factors          = Column(JSON)                 # §7.1.1.3 factors that drove collect/acquire (soft)
    acquisition_scope         = Column(String(16))           # full_image | logical (§7.1.3.1.1)
    logical_acquisition_rationale = Column(Text)             # required when acquisition_scope='logical'
    system_time_offset        = Column(String(128))          # device clock vs reliable source + offset (§6.6)
    # G4 (R35) — the same offset as a number: device clock minus true UTC, in seconds (positive =
    # the device clock ran ahead). Optional and never parsed from the text above. Imports from the
    # exhibit subtract it from the device's times (the recorded time is kept). CHECK in
    # core/database.py.
    system_time_offset_seconds = Column(BigInteger)
    screen_state              = Column(Text)                 # on-screen programs/docs for powered-on devices (§6.6)
    changes_made              = Column(Text)                 # inevitable change + justification (§6.1 item 5)
    device_details            = Column(JSON, default=dict)   # branch-specific capture (network/mobile/cctv) — see coc-collection-wizard-slice.md

    # ── ISO/IEC 27041 — method/tool validation + competence (Slice B) ───────
    # Soft-scored (lowers provenance, never blocks seal). All additive/nullable.
    acquisition_tool_validated       = Column(Boolean)        # tool/method validated as suitable? (checklist item 7)
    acquisition_tool_validation_ref  = Column(String(256))    # validation report id / URL
    acquisition_tool_validation_date = Column(String(32))     # ISO-8601 date the tool/method was validated
    collected_by_qualifications      = Column(Text)           # snapshot of collector's User.qualifications (item 10)

    # Non-mapped (Slice D / GS-2 / GS-3): set per-instance by the list/provenance
    # endpoints from grouped queries (EvidenceCopy + examination audit rows). Plain
    # class defaults avoid both async lazy-loads and missing-attribute on serialisation.
    has_verified_working_copy = False
    has_examination           = False   # GS-3: ≥1 evidence_examine audit row
    has_examination_findings  = False   # GS-3: an examination recorded findings (27042 item 8)
    has_examination_scope     = False   # GS-3: an examination recorded scope limitations (item 12)
    internal_transfers_acknowledged = 0  # C4: internal custody changes the recipient accepted
    internal_transfers_legacy       = 0  # C4: internal custody changes recorded before acceptance existed

    # Sealing: once set true, the wizard-captured fields are locked. Subsequent
    # changes go through update with separate audit entries flagged "amended-after-seal".
    coc_sealed                = Column(Boolean, nullable=False, default=False, index=True)
    coc_sealed_at             = Column(DateTime(timezone=True))
    coc_sealed_by_id          = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # ── RFC 3161 trusted timestamp on the seal (GS-4) — optional/best-effort ──
    seal_tst        = Column(Text)            # base64 DER Time-Stamp Token over sha256
    seal_tst_time   = Column(String(32))      # TSA-asserted time (ISO-8601 UTC)
    seal_tsa        = Column(String(256))      # TSA URL/name that issued the token

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("incident_id", "identifier", name="uq_evidence_incident_identifier"),
    )


# ─── EvidenceCopy — working-copy ledger (ISO/IEC 27037 §7.1.3.1.1, Slice C) ───
# The master forensic copy IS the Evidence blob (never modified — examination only
# hashes it). Each EvidenceCopy row is a tracked, master-verified derivation handed
# out for analysis: auto-minted on export for each item whose bytes the bundle carries
# (F4: never for a physical or file-less item), or recorded out-of-band. C-ledger
# model — no second blob is stored; the bytes ride the export bundle.
# G5: an analyst download is issued as a working copy (kind=download) whose hashes are of the
# bytes actually sent; a lab copy made outside FENRIR (kind=lab_copy) records the hashes its tool
# reported for the copy, compared with the master's recorded hashes.

class EvidenceCopy(Base):
    __tablename__ = "evidence_copies"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id   = Column(UUID(as_uuid=True),
                           ForeignKey("evidence.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    role          = Column(String(16), nullable=False, default="working")  # 'working' (room for 'master')
    sha256        = Column(String(64))                       # hash of the bytes handed out (== master at mint)
    verified_against_master = Column(Boolean, nullable=False, default=False)
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    created_by_qualifications = Column(Text)                 # snapshot (Slice B linkage)
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    purpose       = Column(Text)                             # why / who it went to
    export_id     = Column(UUID(as_uuid=True),
                           ForeignKey("custody_exports.id", ondelete="SET NULL"),
                           nullable=True, index=True)
    discarded_at  = Column(DateTime(timezone=True))          # working copies are disposable

    # ── G5 (R08) — the copy's own record. NULL on rows made before G5: an export row (export_id
    # set) or a "Record copy" row whose sha256 is a re-hash of the master, not of the copy. ──
    kind          = Column(String(16))       # download | lab_copy (export rows keep NULL; CHECK in core/database.py)
    copy_seq      = Column(Integer)          # n in "<exhibit identifier>-WC-n", per exhibit (partial UNIQUE)
    copy_identifier = Column(String(160))
    # download: issued → downloading → complete | aborted | failed_integrity;
    # lab_copy: verified | mismatch (the tool-reported hash vs the master's recorded hash). CHECK.
    status        = Column(String(20))
    sha1          = Column(String(40))       # the copy's own hashes: of the bytes sent (download) or
    md5           = Column(String(32))       # as the copying tool reported them (lab_copy)
    # download: a one-time link for its issuer (created_by_id) only. SHA-256 of the token, never the token.
    token_hash        = Column(String(64))
    token_expires_at  = Column(DateTime(timezone=True))
    download_started_at = Column(DateTime(timezone=True))
    completed_at      = Column(DateTime(timezone=True))   # the transfer ended (any outcome)
    bytes_sent        = Column(BigInteger)
    end_reason        = Column(String(32))   # aborted / failed: client_disconnected | read_error | integrity | hash_mismatch
    destination_note  = Column(Text)         # where the copy went (workstation, lab media, case folder)
    copy_tool         = Column(String(256))  # lab_copy: the tool + version that made the copy
    # An examination found the copy no longer matches its recorded hash: it can't be examined again.
    altered_at        = Column(DateTime(timezone=True))


# ─── ValidatedTool — registry of validated forensic tools/methods (GS-1) ─────
# ISO/IEC 27041: validation is asserted ONCE by an authority (lab manager) with an
# evidence reference, then acquisitions/examinations reference it — instead of a
# per-action free-text claim. Admin-managed; the wizards pick from it.

class ValidatedTool(Base):
    __tablename__ = "validated_tools"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name           = Column(String(128), nullable=False)
    version        = Column(String(64),  nullable=False)
    validation_ref = Column(String(256))      # validation report id / URL / NIST CFTT entry
    scope          = Column(Text)             # what the tool/method is validated for
    validated_by   = Column(String(128))      # who performed/owns the validation
    validated_at   = Column(String(32))       # ISO-8601 date of validation
    notes          = Column(Text)
    is_active      = Column(Boolean, nullable=False, default=True, index=True)
    created_at     = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_validated_tool_name_version"),
    )


# ─── CustodyExport (Phase 2 legal handoff) ───────────────────────────────────
# An export bundles plaintext copies of selected evidence items into an
# AES-256-GCM-encrypted ZIP. The bundle key is ephemeral (one per export) and
# shown to the requester ONCE in the GUI. The encrypted bundle sits on disk
# at `/evidence/exports/{id}.enc`; the recipient retrieves it via the
# token-gated `/api/exports/{token}` URL (single-use, 24h expiry).
#
# Status semantics:
#   pending   — row exists, bundle still being built (transient)
#   ready     — bundle on disk, token live, awaiting download
#   consumed  — downloaded once; token can never be used again
#   expired   — past expires_at (computed at read time)
#   revoked   — admin invalidated before consumption (phase 3)

class CustodyExport(Base):
    __tablename__ = "custody_exports"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id     = Column(UUID(as_uuid=True),
                             ForeignKey("incidents.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    exported_by_id  = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)

    recipient       = Column(String(256), nullable=False)
    purpose         = Column(Text,        nullable=False)
    acknowledgments = Column(Text)

    # Token is URL-safe random 32 bytes — recipient pastes the URL, no auth.
    token           = Column(String(64),  nullable=False, unique=True, index=True)
    status          = Column(String(16),  nullable=False, default="ready", index=True)

    # On-disk bundle metadata
    file_path       = Column(String(1024))    # relative under evidence_path
    file_size       = Column(BigInteger)
    bundle_sha256   = Column(String(64))      # sha256 of the encrypted bundle bytes
    # First 8 + last 8 chars of the key, for the recipient to sanity-check
    # they pasted the correct key. NOT the full key — that's never stored.
    key_hint        = Column(String(32))

    # Which evidence rows were included. Snapshot at export time; the
    # underlying Evidence rows can later be transferred/disposed without
    # affecting the bundle.
    item_ids        = Column(JSON, nullable=False, default=list)

    created_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    expires_at      = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at     = Column(DateTime(timezone=True))
    consumed_ip     = Column(String(64))


# ─── LePackage (P1 #4 — court-ready handoff bundle) ──────────────────────────
# Wraps a CustodyExport (which owns the encrypted blob on disk, the one-time
# download token, and the bundle lifecycle) with LE-specific metadata. The
# bundle itself contains a full evidentiary record for an incident; see
# `le_package/builder.py`. Generation is admin-only.
#
# Integrity model:
#   • bundle_sha256        — sha256 of the encrypted .enc blob (also on
#                            CustodyExport — denormalised here for queries)
#   • manifest_sha256      — sha256 of MANIFEST.json embedded in the bundle.
#                            Anchored in the audit chain at generation time.
#   • hmac_sha256          — HMAC-SHA-256(MANIFEST.json) under the bundle KEK.
#                            Sender-of-record proof: the receiver can re-derive
#                            the HMAC once they hold the (out-of-band) key.
#   • audit_anchor_row_id  — pointer to the audit row written at generation;
#                            its row_hash is the tamper-evidence anchor.

class LePackage(Base):
    __tablename__ = "le_packages"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id         = Column(UUID(as_uuid=True),
                                 ForeignKey("incidents.id", ondelete="CASCADE"),
                                 nullable=False, index=True)

    # The encrypted blob, token, and download lifecycle live on CustodyExport.
    custody_export_id   = Column(UUID(as_uuid=True),
                                 ForeignKey("custody_exports.id", ondelete="CASCADE"),
                                 nullable=False, unique=True, index=True)

    # Case metadata required by the receiving authority.
    case_reference        = Column(String(128), nullable=False, index=True)
    requesting_authority  = Column(String(256), nullable=False)
    legal_basis           = Column(String(32),  nullable=False)   # warrant | subpoena | court_order | mla | voluntary | other
    retention_until       = Column(DateTime(timezone=True))       # null = indefinite

    # Build options used (snapshot — affects which items + files are bundled).
    legal_hold_only       = Column(Boolean, nullable=False, default=False)
    include_artifacts     = Column(Boolean, nullable=False, default=False)

    # Generator identity (denormalised; CustodyExport already has it).
    prepared_by_id        = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    prepared_at           = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    # Integrity anchors.
    bundle_sha256         = Column(String(64))
    manifest_sha256       = Column(String(64))
    hmac_sha256           = Column(String(64))
    audit_anchor_row_id   = Column(UUID(as_uuid=True), ForeignKey("audit_logs.id"), nullable=True)

    # Inventory summary.
    file_count            = Column(Integer)
    total_bytes           = Column(BigInteger)
    evidence_count        = Column(Integer)
    audit_row_count       = Column(Integer)

    # ── Wizard C — Authority handoff (Directive 2014/41/EU + Budapest Conv) ─
    # Cross-border legal-basis specifics. Free-text alongside the enum so an
    # EIO or MLA reference can be tracked. Populated by the handoff wizard.
    eio_reference         = Column(String(128))    # European Investigation Order reference number
    issuing_state         = Column(String(64))     # ISO 3166-1 alpha-2 country code (issuing party)
    executing_state       = Column(String(64))     # ISO 3166-1 alpha-2 country code (executing party — usually our jurisdiction)
    mla_reference         = Column(String(128))    # MLAT request number when legal_basis='mla'

    recipient_name        = Column(String(256))    # the specific officer / clerk receiving the bundle
    recipient_role        = Column(String(128))
    recipient_id_ref      = Column(String(128))    # badge/warrant card/court ref
    recipient_organisation= Column(String(256))    # usually mirrors requesting_authority but distinct
    recipient_address     = Column(Text)
    delivery_channel      = Column(String(32))     # download_url | sealed_usb | encrypted_email | other
    delivery_notes        = Column(Text)
    sender_declaration    = Column(Text)            # the operator's signed declaration text
    # INTEGRITY.sig is an HMAC-SHA-256 (eidas_qes hook reserved). Rows created before 2026-10-03
    # say "ed25519": a wrong label, kept as recorded (docs/reports.md §3).
    signature_kind        = Column(String(32),  default="hmac-sha256")

    # Receipt loop — recipient hits an ack URL (QR code on the printed handoff
    # form). Single-use token, audit-logged when consumed.
    acknowledgment_token  = Column(String(64),  unique=True, index=True)
    acknowledged_at       = Column(DateTime(timezone=True))
    acknowledged_by_name  = Column(String(256))
    acknowledged_ip       = Column(String(64))
    acknowledged_notes    = Column(Text)


# ─── AuditExport (signed audit-log handoff) ──────────────────────────────────
# Stands alongside CustodyExport / LePackage. A signed extract of the
# tamper-evident audit log slice that matches a caller-supplied filter,
# delivered as an AES-256-GCM ZIP whose payload includes a ReportLab PDF
# plus the canonical JSONL of the same slice with a detached Ed25519
# signature.
#
# Scope:
#   • incident_id IS NULL    → global export (all rows, admin only)
#   • incident_id IS NOT NULL → scoped to one incident
#
# Lifecycle:
#   • ready    — bundle on disk, token live (24h), awaiting download
#   • consumed — single download used; token cannot be reused
#   • expired  — past expires_at (computed at read time)
#   • purged   — bundle file deleted by retention cron (30d); metadata persists

class AuditExport(Base):
    __tablename__ = "audit_exports"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # NULL for global exports.
    incident_id     = Column(UUID(as_uuid=True),
                             ForeignKey("incidents.id", ondelete="SET NULL"),
                             nullable=True, index=True)
    exported_by_id  = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)

    # Caller-supplied filter snapshot (date_from / date_to / action / username /
    # resource_type / outcome). Stored so a verifier can confirm the slice
    # boundaries match what the bundle claims.
    filters         = Column(JSON, nullable=False, default=dict)
    # Free-form purpose; mirrors CustodyExport.purpose for legal handoff context.
    purpose         = Column(Text)

    # Audit chain anchors at the time of export — proves the slice is a
    # contiguous segment of the live chain (first row's prev_hash + last
    # row's row_hash) plus the head row's hash for cross-reference.
    first_row_id    = Column(UUID(as_uuid=True), ForeignKey("audit_logs.id"), nullable=True)
    last_row_id     = Column(UUID(as_uuid=True), ForeignKey("audit_logs.id"), nullable=True)
    first_prev_hash = Column(String(64))
    last_row_hash   = Column(String(64))
    chain_head_hash = Column(String(64))    # row_hash of the latest audit row at export time
    row_count       = Column(Integer,        nullable=False, default=0)

    # JSONL signature material.
    jsonl_sha256    = Column(String(64))     # sha256 of audit.jsonl (pre-encryption)
    signature_b64   = Column(String(128))    # base64 of 64-byte Ed25519 sig
    pubkey_fpr      = Column(String(64))     # sha256 fingerprint of pubkey used

    # On-disk bundle metadata.
    file_path       = Column(String(1024))   # relative under evidence_path
    file_size       = Column(Integer)
    bundle_sha256   = Column(String(64))     # sha256 of the encrypted bundle bytes
    key_hint        = Column(String(32))     # first 8 + last 8 of the bundle key

    # Single-use token, mirroring CustodyExport. Lives at /api/audit-exports/{token}.
    token           = Column(String(64), nullable=False, unique=True, index=True)
    status          = Column(String(16), nullable=False, default="ready", index=True)

    created_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    expires_at      = Column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at     = Column(DateTime(timezone=True))
    consumed_ip     = Column(String(64))
    # 30d retention horizon. Bundle file purged at or after this; row persists.
    retention_until = Column(DateTime(timezone=True), nullable=False, index=True)


# ─── Playbook (templates + per-incident tasks) ───────────────────────────────
# Templates are reusable task lists, stored as a JSON `tasks` array on the
# template row. Seeded templates (CISA Fed IR, CISA Vuln Response, NIST SP
# 800-61 R3) are inserted on startup with `is_system=True` and are not
# editable through the UI. Custom templates land in a later slice.
#
# Per-incident PlaybookTask rows are independent copies of the template's
# task entries — once instantiated, edits to the template don't affect
# already-applied incidents.

class PlaybookTemplate(Base):
    __tablename__ = "playbook_templates"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key         = Column(String(64), nullable=False, unique=True, index=True)
    name        = Column(String(256), nullable=False)
    description = Column(Text)
    category    = Column(String(64), nullable=True, default="")
    is_system   = Column(Boolean, nullable=False, default=False)
    # tasks JSON: [{ "title", "description"?, "phase", "order" }, ...]
    tasks       = Column(JSON, nullable=False, default=list)

    created_at  = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at  = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class PlaybookTask(Base):
    __tablename__ = "playbook_tasks"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True),
                         ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    title       = Column(String(512), nullable=False)
    description = Column(Text)
    # 800-61 R3 phase value (preparation / detection_and_analysis / ... ).
    phase       = Column(String(40),  nullable=False, index=True)
    order_index = Column(Integer,     nullable=False, default=0)

    # open / in_progress / done / skipped
    status      = Column(String(16),  nullable=False, default="open", index=True)
    skip_reason = Column(Text)

    assignee_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    due_at          = Column(DateTime(timezone=True))
    completed_at    = Column(DateTime(timezone=True))
    completed_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # Provenance — null for custom-added tasks.
    source_template_id = Column(UUID(as_uuid=True), ForeignKey("playbook_templates.id"), nullable=True)
    source_task_index  = Column(Integer, nullable=True)

    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ─── Respond — containment / eradication / recovery trackers ─────────────────
# Single table with a `category` discriminator (containment | eradication |
# recovery) per the 800-61 R3 CER phase. Extra category-specific fields live in
# a `details` JSON column to avoid three mostly-identical tables.

class RespondAction(Base):
    __tablename__ = "respond_actions"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True),
                         ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    category    = Column(String(24), nullable=False, index=True)   # containment | eradication | recovery
    title       = Column(String(512), nullable=False)
    description = Column(Text)
    status      = Column(String(16), nullable=False, default="open", index=True)   # open | in_progress | done | deferred | reverted
    assignee_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    notes       = Column(Text)
    details     = Column(JSON, nullable=False, default=dict)   # category-specific free-form fields
    order_index = Column(Integer, nullable=False, default=0)

    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    completed_at  = Column(DateTime(timezone=True))
    occurred_at   = Column(DateTime(timezone=True))   # analyst-supplied time the action was actually performed

    # Revert workflow — status='reverted' means the action was rolled back.
    # The original record stays for audit; reverted_* fields capture who/when/why.
    reverted_at    = Column(DateTime(timezone=True))
    reverted_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    revert_reason  = Column(Text)

    # C1: the entity / IOC the action targets (same incident, checked by the route)
    # and the template it was made from. Deleting the entity/IOC unlinks the action.
    # Partial indexes (WHERE ... IS NOT NULL) are created in core/database.py.
    entity_id   = Column(UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True)
    ioc_id      = Column(UUID(as_uuid=True), ForeignKey("iocs.id", ondelete="SET NULL"), nullable=True)
    template_id = Column(String(64), nullable=True)


# ─── Decisions log (per-incident) ────────────────────────────────────────────
# Records choices made during the response — distinct from tasks (work items).
# Decisions are append-only in spirit; editing is allowed but audited.
# Records choices made during the response — distinct from tasks (work items).
# Decisions are append-only in spirit; editing is allowed but audited.

class Decision(Base):
    __tablename__ = "decisions"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id   = Column(UUID(as_uuid=True),
                           ForeignKey("incidents.id", ondelete="CASCADE"),
                           nullable=False, index=True)

    summary       = Column(Text, nullable=False)
    rationale     = Column(Text)
    outcome       = Column(String(16), nullable=False, default="pending")   # pending | approved | rejected | deferred
    decided_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at    = Column(DateTime(timezone=True))
    tags          = Column(JSON, nullable=False, default=list)

    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ─── Comments (per-incident flat thread) ─────────────────────────────────────

class Comment(Base):
    __tablename__ = "comments"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True),
                         ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    body        = Column(Text, nullable=False)
    author_id   = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at  = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    updated_at  = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    edited_at   = Column(DateTime(timezone=True))   # set on first edit


# ─── Notes (one per analyst per incident; markdown; optionally private) ─────
# A personal markdown scratchpad, GitHub-README style -- one evolving note
# per analyst per incident, not a thread of entries. A note marked private
# is visible only to its author -- not even an admin -- so `is_private` is
# never bypassed in the list query. See notes/routes.py.
# Every actual change snapshots a NoteVersion (version-numbered, its own
# is_private carried forward from save time) so history/diff stay accurate
# even if the note's current privacy later changes.

class Note(Base):
    __tablename__ = "notes"
    __table_args__ = (
        UniqueConstraint("incident_id", "author_id", name="uq_notes_incident_author"),
    )

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True),
                         ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    body        = Column(Text, nullable=False)
    is_private  = Column(Boolean, nullable=False, default=True, server_default="true")
    version     = Column(Integer, nullable=False, default=1, server_default="1")
    author_id   = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    created_at  = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    updated_at  = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    edited_at   = Column(DateTime(timezone=True))   # set on first edit


class NoteVersion(Base):
    __tablename__ = "note_versions"
    __table_args__ = (
        UniqueConstraint("note_id", "version_number", name="uq_note_version"),
    )

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    note_id        = Column(UUID(as_uuid=True), ForeignKey("notes.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)

    body        = Column(Text, nullable=False)
    is_private  = Column(Boolean, nullable=False)   # carried from the note at save time

    created_at  = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


# ─── OOB communications log (per-incident) ───────────────────────────────────
# Records out-of-band contact events. Channel list matches old Fenrir:
# personal_mobile / signal / whatsapp / personal_email / in_person /
# secure_fax / courier / third_party_ir.

class OOBLog(Base):
    __tablename__ = "oob_logs"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id         = Column(UUID(as_uuid=True),
                                 ForeignKey("incidents.id", ondelete="CASCADE"),
                                 nullable=False, index=True)

    stakeholder_name    = Column(String(255), nullable=False)
    channel             = Column(String(32),  nullable=False)
    direction           = Column(String(16),  nullable=False, default="outbound")  # outbound | inbound
    summary             = Column(Text,        nullable=False)
    verified            = Column(Boolean,     nullable=False, default=False)
    verification_method = Column(String(128))

    created_by_id       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at          = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


# ─── Stakeholder contacts (per-incident) ─────────────────────────────────────
# Contact registry for people involved in or notified about an incident.
# contact_methods JSON: [{ "channel", "value", "preferred": bool, "notes" }, ...]
# Channels: email / phone / mobile / signal / whatsapp / telegram /
#           teams / slack / secure_fax / in_person

class IncidentStakeholder(Base):
    __tablename__ = "incident_stakeholders"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id  = Column(UUID(as_uuid=True),
                          ForeignKey("incidents.id", ondelete="CASCADE"),
                          nullable=False, index=True)

    name            = Column(String(255), nullable=False)
    title           = Column(String(128))               # job title / functional role
    organization    = Column(String(256))
    type            = Column(String(32), nullable=False, default="other")
    # internal | legal | regulatory | law_enforcement | media_pr | vendor |
    # ir_firm | customer | insurer | board | other
    contact_methods = Column(JSON, nullable=False, default=list)
    notes           = Column(Text)
    available_hours = Column(String(64))                # e.g. "24/7", "09:00-17:00 CET"

    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ─── Contacts directory (org-wide, E2) ───────────────────────────────────────
# External parties the organisation prepares before an incident: supervisory authority,
# national CSIRT, police cyber unit, insurer, IR retainer, PR. Same columns as
# IncidentStakeholder plus verification. Adding one to an incident COPIES it into
# incident_stakeholders, so later directory edits never rewrite a case record.

class OrgContact(Base):
    __tablename__ = "org_contacts"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name            = Column(String(255), nullable=False)
    title           = Column(String(128))
    organization    = Column(String(256))
    type            = Column(String(32), nullable=False, default="other")   # StakeholderType
    contact_methods = Column(JSON, nullable=False, default=list)
    notes           = Column(Text)
    available_hours = Column(String(64))
    last_verified_at = Column(DateTime(timezone=True), nullable=True)       # server time of the last check
    verified_by_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by_id   = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at      = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ─── Timeline events (per-incident) ─────────────────────────────────────────
# Each row is one observed event placed on the forensic / incident timeline.
# event_time = the forensic timestamp (when it happened in the world).
# created_at = when the analyst added the row.
# origin: "manual" = typed by analyst; "forensic_import" = promoted from the
# artifact parser (Slice 2). Column exists from day one so no ALTER later.

class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True),
                         ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    event_time   = Column(DateTime(timezone=True), nullable=False, index=True)
    hostname     = Column(String(256))
    # The in-scope entity (host, account, …) this event happened on — same incident only.
    entity_id    = Column(UUID(as_uuid=True), ForeignKey("entities.id", ondelete="SET NULL"), nullable=True)
    source       = Column(String(128))    # e.g. "Sysmon", "Windows Security Log"
    event_type   = Column(String(128))    # e.g. "Process Execution", "Logon"
    description  = Column(Text, nullable=False)
    raw_log      = Column(Text)           # full event snippet, ≤ 4 000 chars

    # 800-61 R3 phase when this event occurred (analyst judgement, optional)
    ir_phase     = Column(String(40))

    # MITRE ATT&CK — all optional; analyst may not know the mapping yet
    mitre_tactic_id      = Column(String(16))
    mitre_tactic_name    = Column(String(64))
    mitre_technique_id   = Column(String(16))
    mitre_technique_name = Column(String(128))

    origin        = Column(String(16), nullable=False, default="manual")  # manual | forensic_import | system

    # C5 — provenance of an event promoted from a Timeline Import run (forensic/routes.py promote):
    # the exhibit, the run and the event's index in its stored parse (partial UNIQUE
    # (forensic_import_id, import_event_index) in core/database.py, so re-promoting is a no-op), and
    # how the UTC time was worked out: explicit | assumed_tz | inferred_year (CHECK). NULL on legacy,
    # analyst-entered and /timeline/batch events. An event with forensic_import_id, evidence_id or
    # time_basis keeps its facts (time, host, source, type, description, raw log) immutable —
    # timeline/routes.py.
    evidence_id        = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    # RESTRICT (Wave C fix-up M3): the import is the event's provenance record and keeps its facts
    # immutable; it can't be deleted while events promoted from it exist (SET NULL would unlock them).
    forensic_import_id = Column(UUID(as_uuid=True), ForeignKey("forensic_imports.id", ondelete="RESTRICT"), nullable=True)
    import_event_index = Column(Integer)
    time_basis         = Column(String(16))
    # G4 (R03) — promoted from a Defender PDF import run (server-side promote, index = the candidate's
    # position). RESTRICT like forensic_import_id; at most one of the two is set (CHECK).
    defender_import_id = Column(UUID(as_uuid=True), ForeignKey("defender_pdf_imports.id", ondelete="RESTRICT"), nullable=True)
    # G3 (R02) — promoted from a PCAP analysis run (candidate index in import_event_index) or a browser
    # history upload (the visit / download row in source_record_id). RESTRICT like the others; at most
    # one run per event (CHECK); partial UNIQUE indexes make re-promoting a no-op.
    pcap_analysis_id          = Column(UUID(as_uuid=True), ForeignKey("pcap_analyses.id", ondelete="RESTRICT"), nullable=True)
    browser_history_upload_id = Column(UUID(as_uuid=True), ForeignKey("browser_history_uploads.id", ondelete="RESTRICT"), nullable=True)
    source_record_id          = Column(UUID(as_uuid=True))
    # G-fix B (L26) — a mail relay hop imported from an email analysis that has a run record (G3).
    # RESTRICT like the other runs; at most one run per event (CHECK ck_timeline_events_one_run_gfixb).
    email_analysis_id         = Column(UUID(as_uuid=True), ForeignKey("email_analysis.id", ondelete="RESTRICT"), nullable=True)
    # G4 (R35) — set together (CHECK) when the exhibit's clock offset corrected this event's time:
    # recorded_event_time = the time as the device recorded it (never overwritten), event_time =
    # recorded_event_time − clock_offset_seconds. NULL = no offset applied.
    recorded_event_time  = Column(DateTime(timezone=True))
    clock_offset_seconds = Column(BigInteger)

    # System timeline events — auto-generated by the platform or manually marked as a system note.
    # system_source: respond_action | legal_deadline | decision | manual
    is_system     = Column(Boolean, nullable=False, default=False)
    system_source = Column(String(32))

    # Report visibility: external_safe events appear in Executive Summary reports
    # by default; internal-only events are excluded unless explicitly overridden.
    # Default TRUE for analyst-authored events; system events flip to FALSE on insert.
    external_safe = Column(Boolean, nullable=False, default=True)

    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ─── PCAP analysis results (per-incident) ────────────────────────────────────
# Raw analysis results from the air-gapped analysis worker are stored as JSON
# and scoped to the incident. Analysts can extract IOCs directly into the
# incident's IOC list from a saved result.

class PCAPAnalysis(Base):
    __tablename__ = "pcap_analyses"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id    = Column(UUID(as_uuid=True),
                            ForeignKey("incidents.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    filename       = Column(String(512),  nullable=False)
    file_size      = Column(Integer)
    uploaded_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    uploaded_by    = Column(String(64))       # denormalised username
    result_json    = Column(JSON, nullable=False, default=dict)
    created_at     = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    # G3 (R02) run record: the capture is kept as its exhibit (encrypted at rest, hashed) — registered as
    # a draft by the upload, a unique SHA-256 match, or a picked exhibit (exhibit_link as EmailAnalysis)
    # — with the SHA-256 analysed, the analyser + version the worker reported, the exhibit's clock offset
    # applied to the timeline candidates (snapshot) and those candidates (promote copies them). All NULL
    # on analyses before G3 (the raw capture was not kept).
    evidence_id          = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    input_sha256         = Column(String(64))
    analyser_name        = Column(String(64))
    analyser_version     = Column(String(32))
    exhibit_link         = Column(String(16))
    clock_offset_seconds = Column(BigInteger)
    timeline_candidates  = Column(JSON)


# ─── Quarantine artifacts ─────────────────────────────────────────────────────
# Malware samples and suspicious files collected during an investigation.
# Stored plaintext on the air-gapped /quarantine volume (read-only for the
# analysis worker). Downloads are wrapped in a "infected"-password ZIP per the
# standard malware-analyst convention to prevent AV auto-execution.

class Artifact(Base):
    __tablename__ = "artifacts"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id       = Column(UUID(as_uuid=True),
                               ForeignKey("incidents.id", ondelete="CASCADE"),
                               nullable=False, index=True)

    # Original name supplied by the analyst (display only — not used for storage).
    original_filename = Column(String(512), nullable=False)
    # UUID-prefixed name used on disk — prevents collisions and path traversal.
    stored_filename   = Column(String(512), nullable=False)

    file_size         = Column(Integer,     nullable=False)  # bytes
    mime_type         = Column(String(128))

    # Cryptographic hashes computed on upload in a single streaming pass.
    md5_hash          = Column(String(32))
    sha256_hash       = Column(String(64),  index=True)
    sha512_hash       = Column(String(128))

    description       = Column(Text)

    # Tracks whether static analysis has been run against this artifact.
    # pending → in_progress → completed | failed
    analysis_status   = Column(String(16), nullable=False, default="pending")
    # Last analysis results keyed by tool name (e.g. {"hashes": {...}, "pe": {...}}).
    analysis_results  = Column(JSON, nullable=False, default=dict)

    uploaded_by_id    = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    uploaded_by       = Column(String(64))   # denormalised username
    uploaded_at       = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


# ─── Browser history (Chrome/Edge/Brave "History" or Firefox "places.sqlite") ─
# One upload = one parsed SQLite file. The raw file is quarantined as an
# Artifact (same as email_analyzer) with an optional later "mint as Evidence"
# for chain-of-custody; the parsed visits/search-terms are persisted here so
# the page survives a refresh -- not held in request-scoped memory.

class BrowserHistoryUpload(Base):
    __tablename__ = "browser_history_uploads"

    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id        = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                                nullable=False, index=True)

    browser            = Column(String(16), nullable=False)   # chrome | edge | brave | firefox (analyst-selected)
    schema_family      = Column(String(16), nullable=False)   # chromium | firefox (content-detected)

    source_artifact_id = Column(UUID(as_uuid=True), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True)
    # Firefox only: the separately-uploaded formhistory.sqlite quarantined
    # alongside the main places.sqlite (its search-bar terms are merged into
    # this upload's search_terms; the raw file itself gets its own Artifact
    # row like the main file does, but is not mintable as Evidence separately).
    form_history_artifact_id = Column(UUID(as_uuid=True), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True)
    evidence_id        = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)

    original_filename  = Column(String(512), nullable=False)
    file_size          = Column(Integer, nullable=False)
    sha256_hash        = Column(String(64), nullable=False)

    record_count       = Column(Integer, nullable=False, default=0)
    search_term_count  = Column(Integer, nullable=False, default=0)
    download_count     = Column(Integer, nullable=False, default=0)
    truncated          = Column(Boolean, nullable=False, default=False)  # hit the defensive row cap

    # G3 (R02) run record: evidence_id is the exhibit the history file IS (registered as a draft by the
    # upload, a unique SHA-256 match, or picked; exhibit_link as EmailAnalysis), sha256_hash the bytes
    # parsed, plus Firefox's formhistory.sqlite exhibit, the parser + version and the exhibit's clock
    # offset (snapshot; applied to times promoted to the Timeline). New uploads keep no quarantine copy.
    # All NULL on uploads before G3.
    form_history_evidence_id = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    parser_name          = Column(String(64))
    parser_version       = Column(String(32))
    exhibit_link         = Column(String(16))
    clock_offset_seconds = Column(BigInteger)

    uploaded_by_id      = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    uploaded_by         = Column(String(64))
    uploaded_at         = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class BrowserHistoryVisit(Base):
    __tablename__ = "browser_history_visits"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    upload_id   = Column(UUID(as_uuid=True), ForeignKey("browser_history_uploads.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    # Denormalized for direct incident-scoped search/pagination without a join.
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    url         = Column(Text, nullable=False)
    host        = Column(String(512), index=True)
    title       = Column(Text)
    visit_time  = Column(DateTime(timezone=True), nullable=False, index=True)
    visit_count = Column(Integer)
    transition  = Column(String(32))   # decoded label, e.g. "typed" | "link" | "reload" | "bookmark"


class BrowserHistorySearchTerm(Base):
    __tablename__ = "browser_history_search_terms"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    upload_id   = Column(UUID(as_uuid=True), ForeignKey("browser_history_uploads.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    term        = Column(Text, nullable=False)
    url         = Column(Text)
    # The associated URL's last-visit time (keyword_search_terms itself has no
    # timestamp column) -- approximate, not "when this was typed."
    visit_time  = Column(DateTime(timezone=True), index=True)


class BrowserHistoryDownload(Base):
    __tablename__ = "browser_history_downloads"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    upload_id   = Column(UUID(as_uuid=True), ForeignKey("browser_history_uploads.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)

    url            = Column(Text)              # final URL in the redirect chain (Chromium); best-effort (Firefox)
    target_path    = Column(Text)              # where the file was saved on disk
    start_time     = Column(DateTime(timezone=True), index=True)
    end_time       = Column(DateTime(timezone=True))
    received_bytes = Column(Integer)
    total_bytes    = Column(Integer)
    state          = Column(String(32))        # decoded label: in_progress | complete | cancelled | interrupted
    danger         = Column(String(32))        # decoded label where recognized, else the raw code as a string
    mime_type      = Column(String(128))


# ─── Collection packages (U1 — signed offline collectors) ────────────────────
# An incident-scoped, Ed25519-signed Velociraptor offline-collector package.
# The package ZIP (collector binary + signed manifest + launcher) lives on the
# quarantine volume under _collections/{incident_id}/{id}.zip. A responder runs
# it out-of-band; the output returns via the Artifacts pipeline (U1.2+).
#
# Lifecycle / retention (a repacked collector is ~60 MB — disk hygiene matters):
#   generated  → built, one-time-downloadable
#   consumed   → token used; ZIP deleted on download (single use)
#   expired    → TTL passed before download; ZIP swept
#   superseded → built with an outdated/insecure Velociraptor version; ZIP swept
#   deleted    → analyst removed it; ZIP swept
# Any non-generated status with a lingering ZIP is reclaimed by the sweep.

class CollectionPackage(Base):
    __tablename__ = "collection_packages"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id       = Column(UUID(as_uuid=True),
                               ForeignKey("incidents.id", ondelete="CASCADE"),
                               nullable=False, index=True)

    name              = Column(String(200), nullable=False)
    platform          = Column(String(16),  nullable=False, default="windows")
    profile           = Column(String(32),  nullable=False)          # triage | full | custom
    artifact_selection = Column(JSON, nullable=False, default=list)  # Velociraptor artifact names

    # Stamped at generation — reproducibility + stale/insecure detection.
    velociraptor_version = Column(String(32))

    # X.509 collection encryption (the collector encrypts its output to this
    # package's cert; only FENRIR can decrypt). The RSA private key is wrapped
    # under EVIDENCE_KEK ("{nonce_hex}:{b64 ciphertext}"); the cert fingerprint
    # is provenance. Decryption happens at ingest, in pure Python.
    enc_private_key   = Column(Text)
    cert_fingerprint  = Column(String(64))

    # Provenance / signing. The manifest (incident + artifacts + version +
    # collector hash + generation time) is Ed25519-signed with the platform
    # audit-signing key; the public key/fingerprint are at GET /api/version.
    manifest_sha256     = Column(String(64))
    package_sha256      = Column(String(64))   # sha256 of the package ZIP
    signature_b64       = Column(Text)         # base64 Ed25519 sig over canonical manifest
    signing_fingerprint = Column(String(64))

    # One-time download (mirrors CustodyExport): URL-safe random, single-use.
    token             = Column(String(64), unique=True, index=True)
    token_expires_at  = Column(DateTime(timezone=True), index=True)

    # On-disk bundle, relative under quarantine_path.
    file_path         = Column(String(1024))
    file_size         = Column(Integer)

    status            = Column(String(16), nullable=False, default="generated", index=True)

    created_by_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_by        = Column(String(64))     # denormalised username
    created_at        = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    consumed_at       = Column(DateTime(timezone=True))
    consumed_ip       = Column(String(64))

    # Ingest linkage — populated by U1.2 (verify + register output as Artifact).
    ingested_at        = Column(DateTime(timezone=True))
    ingested_by_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    output_sha256      = Column(String(64))            # the decrypted collection ZIP
    # G4 (R03) — run record of the ingest: SHA-256 + size of the container exactly as received
    # (hashed while streaming, before decryption) and the exhibit whose SHA-256 it uniquely
    # matched at ingest (an active exhibit of the incident; NULL = none / ambiguous).
    container_sha256   = Column(String(64))
    container_size     = Column(BigInteger)
    evidence_id        = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    result_artifact_id = Column(UUID(as_uuid=True),
                                ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True)


# ─── Forensic timeline imports ────────────────────────────────────────────────
# Stores the parsed-event payload from a Timeline Import upload so the analyst
# can leave the page, come back, and resume triaging without re-uploading.
# The raw file is NOT preserved (use the Artifact pipeline if you need it).
# Disposal is a hard DELETE — no soft-delete, no quarantine, no recovery.

class ForensicImport(Base):
    __tablename__ = "forensic_imports"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id       = Column(UUID(as_uuid=True),
                               ForeignKey("incidents.id", ondelete="CASCADE"),
                               nullable=False, index=True)

    filename          = Column(String(512), nullable=False)
    file_size         = Column(Integer,     nullable=False)
    mime_type         = Column(String(128))
    sha256_hash       = Column(String(64))                 # of the uploaded file

    # C5 — the exhibit these bytes are: set by from-evidence (hash re-verified against the stored
    # SHA-256) or by an upload whose SHA-256 equals exactly one exhibit of the incident. The parser
    # version and the IANA source timezone used for zone-less times. NULL on pre-C5 imports.
    evidence_id       = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    parser_version    = Column(String(32))
    source_tz         = Column(String(64))
    # G4 (R35) — the exhibit's clock offset (seconds, device minus true UTC) applied to this import's
    # times when it was parsed: a snapshot, so a later change to the exhibit never rewrites it.
    clock_offset_seconds = Column(BigInteger)

    detected_format   = Column(String(32))                  # evtx / json / syslog / ...
    event_count       = Column(Integer, nullable=False, default=0)
    suspicious_count  = Column(Integer, nullable=False, default=0)
    # M1 — True when a parser cap cut the output; total_seen = source records the parser read
    # (rows / records / matched lines), so the UI can say "N of M". NULL on imports made before.
    truncated         = Column(Boolean)
    total_seen        = Column(Integer)

    # Parsed events keyed to the ParsedEventOut schema. Bounded by parser
    # MAX_EVENTS (2 000) × ~2 KB raw_log ≈ ~4 MiB JSON per row, comfortably
    # within Postgres jsonb limits.
    parsed_events     = Column(JSON, nullable=False, default=list)

    uploaded_by_id    = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    uploaded_by       = Column(String(64))                  # denormalised username
    uploaded_at       = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class DefenderPdfImport(Base):
    __tablename__ = "defender_pdf_imports"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id       = Column(UUID(as_uuid=True),
                               ForeignKey("incidents.id", ondelete="CASCADE"),
                               nullable=False, index=True)

    filename            = Column(String(512), nullable=False)
    file_size           = Column(Integer, nullable=False)
    sha256_hash         = Column(String(64), nullable=False)
    source_artifact_id  = Column(UUID(as_uuid=True), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True)
    # G4 (R03) run record: the exhibit the PDF is (from-evidence with the hash re-verified, or an
    # upload whose SHA-256 equals exactly one active exhibit), the parser and its version, and the
    # exhibit's clock offset applied to the candidates' times (snapshot). NULL on imports before G4.
    evidence_id         = Column(UUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    parser_name         = Column(String(64))
    parser_version      = Column(String(32))
    clock_offset_seconds = Column(BigInteger)

    candidate_count       = Column(Integer, nullable=False, default=0)
    low_confidence_count  = Column(Integer, nullable=False, default=0)

    # {"Severity": ..., "Status": ..., "title": ..., ...} -- display-only
    # incident metadata, and the parsed candidates keyed to DefenderPdfCandidate.
    incident_meta     = Column(JSON, nullable=False, default=dict)
    candidates        = Column(JSON, nullable=False, default=list)

    uploaded_by_id    = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    uploaded_by       = Column(String(64))
    uploaded_at       = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


# ─── Post-Incident: Closure Checklist ────────────────────────────────────────

class ClosureChecklistItem(Base):
    __tablename__ = "closure_checklist_items"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    item_key    = Column(String(64),  nullable=False)   # stable key from the seed list
    label       = Column(String(256), nullable=False)
    checked     = Column(Boolean, nullable=False, default=False)
    checked_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    checked_by  = Column(String(128), nullable=True)    # denormalized display name
    checked_at  = Column(DateTime(timezone=True), nullable=True)
    assigned_to_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_to = Column(String(128), nullable=True)    # denormalized display name
    notes       = Column(Text, nullable=True)
    sort_order  = Column(Integer, nullable=False, default=0)
    # Soft-delete flag — DELETE flips this to FALSE so the idempotent seed
    # loop in post_incident/routes.py doesn't resurrect dismissed defaults.
    is_active   = Column(Boolean, nullable=False, default=True)

    __table_args__ = (UniqueConstraint("incident_id", "item_key", name="uq_closure_item"),)


# ─── Post-Incident: Lessons Learned ──────────────────────────────────────────

class LessonsLearned(Base):
    __tablename__ = "lessons_learned"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, unique=True, index=True)
    status      = Column(String(16), nullable=False, default="draft")   # draft | final

    # ── Review metadata ───────────────────────────────────────────────────────
    conducted_at   = Column(DateTime(timezone=True), nullable=True)
    facilitated_by = Column(String(256), nullable=True)
    participants   = Column(JSON, nullable=False, default=list)         # [str, ...]

    # ── Narrative ─────────────────────────────────────────────────────────────
    incident_narrative = Column(Text, nullable=True)

    # ── Root cause ────────────────────────────────────────────────────────────
    root_cause_category    = Column(String(64),  nullable=True)
    root_cause_description = Column(Text,        nullable=True)
    contributing_factors   = Column(JSON, nullable=False, default=list) # [str, ...]

    # ── Response effectiveness ────────────────────────────────────────────────
    # { dim_id: { "rating": "good"|"acceptable"|"poor", "notes": str }, ... }
    effectiveness  = Column(JSON, nullable=False, default=dict)

    # ── Observations ─────────────────────────────────────────────────────────
    what_went_well  = Column(JSON, nullable=False, default=list)        # [str, ...]
    friction_points = Column(JSON, nullable=False, default=list)        # [str, ...]
    near_misses     = Column(JSON, nullable=False, default=list)        # [str, ...]

    # ── Response timeline (minutes from incident start) ───────────────────────
    timeline_detection_mins   = Column(Integer, nullable=True)
    timeline_escalation_mins  = Column(Integer, nullable=True)
    timeline_containment_mins = Column(Integer, nullable=True)
    timeline_comms_mins       = Column(Integer, nullable=True)
    timeline_remediation_mins = Column(Integer, nullable=True)

    # ── Action items ──────────────────────────────────────────────────────────
    # [{ id, action, owner, due_date (ISO date str), priority, status }]
    action_items         = Column(JSON, nullable=False, default=list)

    # ── Control improvements ──────────────────────────────────────────────────
    # [{ id, recommendation, category, priority }]
    control_improvements = Column(JSON, nullable=False, default=list)

    # ── Report-page narratives ────────────────────────────────────────────────
    # Plain-text fields editable directly from the Reports tab. When set, the
    # report renderer prefers these over the structured lists above for the
    # §09 Lessons Learned and §10 Remediation Plan sections.
    report_what_worked_well         = Column(Text, nullable=True)
    report_what_could_improve       = Column(Text, nullable=True)
    report_security_recommendations = Column(Text, nullable=True)
    report_remediation_short        = Column(Text, nullable=True)
    report_remediation_medium       = Column(Text, nullable=True)
    report_remediation_long         = Column(Text, nullable=True)

    # ── Audit ─────────────────────────────────────────────────────────────────
    updated_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ─── OSINT enrichment cache ───────────────────────────────────────────────────

class EnrichmentCache(Base):
    __tablename__ = "enrichment_cache"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tool        = Column(String(64),  nullable=False, index=True)
    indicator   = Column(String(512), nullable=False, index=True)
    result      = Column(JSON,        nullable=False)
    fetched_at  = Column(DateTime(timezone=True), nullable=False, default=utcnow)
    ttl_seconds = Column(Integer,     nullable=False)

    __table_args__ = (
        UniqueConstraint("tool", "indicator", name="uq_enrichment_tool_indicator"),
    )


# ─── OSINT session (persisted per incident) ────────────────────────────────────

class OSINTSession(Base):
    __tablename__ = "osint_sessions"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id   = Column(UUID(as_uuid=True),
                           ForeignKey("incidents.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    raw_text      = Column(Text)
    indicators    = Column(JSON, nullable=False, default=list)  # [{type, value, id}]
    results       = Column(JSON, nullable=False, default=dict)  # {indicator_id: [EnrichResultItem]}
    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_by    = Column(String(64))   # denormalised username
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ─── YARA rule library (global) ───────────────────────────────────────────────

class YaraRule(Base):
    __tablename__ = "yara_rules"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name            = Column(String(256), nullable=False)
    description     = Column(String(512))
    author          = Column(String(128))
    tags            = Column(JSON, nullable=False, default=list)
    rule_content    = Column(Text, nullable=False)
    is_active       = Column(Boolean, nullable=False, default=True)
    match_count     = Column(Integer, nullable=False, default=0)
    last_matched_at = Column(DateTime(timezone=True), nullable=True)
    created_by_id   = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ─── YARA match results (per-incident) ───────────────────────────────────────

# ─── Legal: regulatory deadline tracking ─────────────────────────────────────

class RegulatoryDeadline(Base):
    __tablename__ = "regulatory_deadlines"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id       = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                               nullable=False, index=True)
    regulation        = Column(String(32),  nullable=False)   # GDPR, NIS2, DORA, PCI_DSS, HIPAA, CCPA
    article           = Column(String(128))
    obligation        = Column(Text,  nullable=False)
    recipient         = Column(String(256))
    deadline_hours    = Column(Integer, nullable=False)
    breach_detected_at = Column(DateTime(timezone=True), nullable=False)
    deadline_at       = Column(DateTime(timezone=True), nullable=False)
    status            = Column(String(32),  nullable=False, default="pending")
    completed_at      = Column(DateTime(timezone=True))
    completed_by_id   = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    completion_notes  = Column(Text)
    is_mandatory      = Column(Boolean, nullable=False, default=True)
    notes             = Column(Text)
    created_by_id     = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at        = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at        = Column(DateTime(timezone=True), onupdate=utcnow)
    # Last in-app reminder sent (legal/reminders.py): 0 none, 1 T-12h, 2 T-2h, 3 overdue.
    # Reset to 0 when the deadline is re-anchored.
    reminder_stage    = Column(SmallInteger, nullable=False, default=0, server_default="0")


# ─── Post-Incident: business impact assessment ────────────────────────────────

class BusinessImpact(Base):
    __tablename__ = "business_impacts"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id   = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                           nullable=False, unique=True)
    financial     = Column(Text)
    operational   = Column(Text)
    data_exposure = Column(Text)
    reputational  = Column(Text)
    regulatory    = Column(Text)
    legal         = Column(Text)
    notes         = Column(Text)
    updated_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    updated_at    = Column(DateTime(timezone=True), onupdate=utcnow)


# ─── Post-Incident: cost tracking ────────────────────────────────────────────

COST_CATEGORIES = (
    "personnel", "tools_licenses", "external_ir", "legal_counsel",
    "regulatory_fines", "downtime_revenue", "remediation_infra",
    "pr_communications", "other",
)
IR_PHASES = ("detection", "containment", "eradication", "recovery", "post_incident")

class IncidentCost(Base):
    __tablename__ = "incident_costs"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id  = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    category     = Column(String(64), nullable=False)
    description  = Column(Text, nullable=False)
    amount       = Column(Numeric(14, 2), nullable=False)
    currency     = Column(String(3), nullable=False, default="USD")
    ir_phase     = Column(String(64))
    is_estimated = Column(Boolean, nullable=False, default=False)
    incurred_at  = Column(Date)
    recorded_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at   = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ─── YARA match results (per-incident) ───────────────────────────────────────

class YaraMatch(Base):
    __tablename__ = "yara_matches"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id         = Column(UUID(as_uuid=True), ForeignKey("yara_rules.id", ondelete="SET NULL"), nullable=True)
    rule_name       = Column(String(256), nullable=False)
    incident_id     = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    artifact_id     = Column(UUID(as_uuid=True), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=True)
    artifact_name   = Column(String(512))
    matched_strings = Column(JSON, nullable=False, default=list)
    created_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    __table_args__ = (
        UniqueConstraint("rule_id", "artifact_id", name="uq_yara_match"),
    )


# ─── Threat Intelligence ─────────────────────────────────────────────────────

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name                = Column(String(128),  nullable=False)
    url                 = Column(String(512),  nullable=False, unique=True)
    feed_type           = Column(String(8),    nullable=False)   # csv | json | txt
    ioc_type            = Column(String(32),   nullable=False)   # ip | domain | url | hash_* | ...
    enabled             = Column(Boolean,      nullable=False, default=True)
    pull_interval_hours = Column(Integer,      nullable=False, default=24)
    last_pulled_at      = Column(DateTime(timezone=True))
    last_ioc_count      = Column(Integer,      nullable=False, default=0)
    total_iocs_ingested = Column(Integer,      nullable=False, default=0)
    parser_config       = Column(JSON,         nullable=False, default=dict)
    created_at          = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ThreatIntelIOC(Base):
    """Global threat-intel IOCs ingested from feeds. Not tied to any incident."""
    __tablename__ = "threat_intel_iocs"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    feed_id       = Column(UUID(as_uuid=True),
                           ForeignKey("threat_feeds.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    feed_name     = Column(String(128),  nullable=False)   # denormalised for display
    type          = Column(String(32),   nullable=False, index=True)
    value         = Column(String(2048), nullable=False, index=True)
    tags          = Column(JSON,         nullable=False, default=list)
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at  = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_ti_ioc_type_value"),
    )


# ─── Platform settings (admin-managed, encrypted at rest) ────────────────────

class PlatformSetting(Base):
    __tablename__ = "platform_settings"

    key             = Column(String(128), primary_key=True)   # e.g. "api_key.virustotal"
    encrypted_value = Column(Text, nullable=False)             # Fernet ciphertext
    updated_at      = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    updated_by_id   = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)


# ─── War Room: per-incident live chat ────────────────────────────────────────

class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username    = Column(String(64), nullable=False)   # denormalised; survives user deletion
    body        = Column(Text, nullable=False)
    created_at  = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


# ─── Notifications ────────────────────────────────────────────────────────────

class Notification(Base):
    __tablename__ = "notifications"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id     = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    type        = Column(String(64), nullable=False)   # warroom_message | incident_created | phase_changed | comment
    title       = Column(String(255), nullable=False)
    body        = Column(Text)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True)
    read        = Column(Boolean, nullable=False, default=False, index=True)
    created_at  = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


# ─── Incident assignments (per-incident IR role roster) ──────────────────────
# Links users to an incident in a specific operational role.
# One user can hold multiple roles; no duplicate (incident, user, role) triples.

class IncidentAssignment(Base):
    __tablename__ = "incident_assignments"

    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id      = Column(UUID(as_uuid=True),
                              ForeignKey("incidents.id", ondelete="CASCADE"),
                              nullable=False, index=True)
    user_id          = Column(UUID(as_uuid=True),
                              ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username         = Column(String(64), nullable=False)     # denormalised
    role_id          = Column(UUID(as_uuid=True),
                              ForeignKey("operational_roles.id", ondelete="SET NULL"), nullable=True)
    role_label       = Column(String(128), nullable=False)    # denormalised
    notes            = Column(Text)
    assigned_by_id   = Column(UUID(as_uuid=True),
                              ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_by_username = Column(String(64))                 # denormalised
    assigned_at      = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("incident_id", "user_id", "role_id", name="uq_assignment_incident_user_role"),
    )


# ─── Responder profiles (org-wide IR roster) ─────────────────────────────────
# One profile per user. Created on first PATCH (upsert); users without a profile
# are still visible in the roster with empty skills + default availability.

class ResponderProfile(Base):
    __tablename__ = "responder_profiles"

    user_id      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
                          primary_key=True)
    skills       = Column(JSON, nullable=False, default=list)
    availability = Column(String(32), nullable=False, default="available")
    # available | on_call | unavailable | out_of_office
    notes        = Column(Text)
    # E2: how to reach this responder when email / chat may be compromised. Same JSON shape as
    # IncidentStakeholder.contact_methods. Personal data: returned to analysts and admins only,
    # never copied into reports or the LE package.
    oob_contact_methods = Column(JSON, nullable=False, default=list, server_default="[]")
    updated_at   = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ─── On-call schedule (org-wide rota) ───────────────────────────────────────
# Single rota for the whole org. An entry marks one user as on-call for a
# contiguous date range (start_date..end_date inclusive, UTC dates).
# Overlapping entries are allowed — the most specific wins at query time.

class OnCallEntry(Base):
    __tablename__ = "on_call_entries"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id             = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username            = Column(String(64),  nullable=False)     # denormalised
    display_name        = Column(String(255))                      # denormalised full_name
    start_date          = Column(Date, nullable=False, index=True)
    end_date            = Column(Date, nullable=False, index=True)  # inclusive
    notes               = Column(Text)
    created_by_id       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by_username = Column(String(64))
    created_at          = Column(DateTime(timezone=True), default=utcnow, nullable=False)


# ─── Incident handoffs (shift-change / per-incident) ─────────────────────────
# Records shift-change handoffs between analysts. The outgoing analyst fills a
# note and picks the incoming analyst; a notification is pushed to the receiver.
# Status: pending → acknowledged.

class IncidentHandoff(Base):
    __tablename__ = "incident_handoffs"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id       = Column(UUID(as_uuid=True),
                               ForeignKey("incidents.id", ondelete="CASCADE"),
                               nullable=False, index=True)

    outgoing_user_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    outgoing_username = Column(String(64), nullable=False)     # denormalised
    incoming_user_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    incoming_username = Column(String(64), nullable=False)     # denormalised

    note              = Column(Text)      # freetext status summary
    status            = Column(String(16), nullable=False, default="pending", index=True)  # pending | acknowledged

    # Structured investigation-state fields (aligned with v1 handoff package)
    current_hypothesis    = Column(Text)
    hypothesis_confidence = Column(Integer, nullable=False, default=50)
    key_findings          = Column(Text)
    warnings              = Column(Text)
    threads               = Column(JSON, nullable=False, default=list)   # [{label, status, confidence, notes}]
    ruled_out             = Column(JSON, nullable=False, default=list)   # [{item, reason}]
    pending               = Column(JSON, nullable=False, default=list)   # [{item, priority, notes}]
    next_steps            = Column(JSON, nullable=False, default=list)   # [{action, priority}]
    open_questions        = Column(JSON, nullable=False, default=list)   # [str]
    snapshot_data         = Column(JSON, nullable=False, default=dict)   # counters captured at handoff time

    created_at        = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    acknowledged_at   = Column(DateTime(timezone=True))
    acknowledged_note = Column(Text)


# ─── Threat actor library (global) ───────────────────────────────────────────
# Seeded from MITRE ATT&CK Groups on startup; admins may add custom actors.
# associated_techniques: JSON list of MITRE technique IDs e.g. ["T1566","T1078"]
# typical_targets:       JSON list of sector strings e.g. ["Government","Energy"]
# aliases:               JSON list of alternate names

class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id                    = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name                  = Column(String(128), unique=True, nullable=False, index=True)
    aliases               = Column(JSON, nullable=False, default=list)
    description           = Column(Text)
    country_of_origin     = Column(String(64))
    motivation            = Column(String(32), nullable=False, default="unknown")
    # financial | espionage | hacktivist | destructive | ransomware | unknown
    associated_techniques = Column(JSON, nullable=False, default=list)
    typical_targets       = Column(JSON, nullable=False, default=list)
    is_system             = Column(Boolean, nullable=False, default=True)
    created_at            = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # MITRE ATT&CK sync metadata — populated by the STIX puller. `software`
    # is a list of {name, type: 'malware'|'tool', mitre_id?} used by the
    # scoring engine's malware_match signal.
    mitre_id              = Column(String(16), unique=True, index=True)
    mitre_url             = Column(String(512))
    software              = Column(JSON, nullable=False, default=list)
    last_synced_at        = Column(DateTime(timezone=True))


# ─── Incident attributions (per-incident) ────────────────────────────────────
# Links an incident to a threat actor (or an unnamed cluster) with analyst-
# supplied confidence level and supporting evidence references.

class IncidentAttribution(Base):
    __tablename__ = "incident_attributions"

    id                   = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id          = Column(UUID(as_uuid=True),
                                  ForeignKey("incidents.id", ondelete="CASCADE"),
                                  nullable=False, index=True)
    threat_actor_id      = Column(UUID(as_uuid=True),
                                  ForeignKey("threat_actors.id", ondelete="SET NULL"),
                                  nullable=True)
    # When threat_actor_id is NULL, actor_label holds a free-text cluster name.
    actor_label          = Column(String(128))   # denormalised name at attribution time
    confidence           = Column(String(16), nullable=False, default="possible")
    # possible | probable | confirmed
    analyst_notes        = Column(Text)
    supporting_ioc_ids   = Column(JSON, nullable=False, default=list)
    supporting_timeline_ids = Column(JSON, nullable=False, default=list)

    # Suggest-engine output captured at accept time. `evidence` is the
    # per-signal breakdown (signal_type, label, points, description, technique_id?)
    # produced by threat_actors.scoring. `score` is the 0–100 numeric result.
    score                = Column(Integer)
    evidence             = Column(JSON, nullable=False, default=list)

    created_by_id        = Column(UUID(as_uuid=True),
                                  ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by_username  = Column(String(64))    # denormalised
    created_at           = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at           = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


# ─── Generated reports + access audit ─────────────────────────────────────────
# Persists every report the analyst saves (preview / download / explicit save)
# so it can be re-downloaded later with SHA-256 integrity proof and per-access
# audit log. Mirrors v1's audit-grade report flow.

class GeneratedReport(Base):
    __tablename__ = "generated_reports"

    id                 = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id        = Column(UUID(as_uuid=True),
                                ForeignKey("incidents.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    report_type        = Column(String(16),  nullable=False)            # exec | full
    template_id        = Column(String(32),  nullable=False)
    classification     = Column(String(64),  nullable=False)            # TLP:* or custom
    audience           = Column(String(256))
    footer_text        = Column(String(512))

    sha256             = Column(String(64),  nullable=False, index=True)
    file_size          = Column(Integer,     nullable=False)
    html_content       = Column(Text,        nullable=False)            # inline; postgres TOAST

    generated_by_id    = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                                nullable=True)
    generated_at       = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)


class ReportAccess(Base):
    """One row per download. The `access_reason` is mandatory so the audit
    trail captures *why* each re-download happened — not just *who*."""
    __tablename__ = "report_accesses"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    report_id       = Column(UUID(as_uuid=True),
                             ForeignKey("generated_reports.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    accessed_by_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                             nullable=True)
    accessed_at     = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    access_reason   = Column(Text, nullable=False)
    ip_address      = Column(String(64))


# ─── Stakeholder Matrix (global notification rules) ──────────────────────────
# Org-wide rules: "for incidents of severity X, role Y must be notified within
# Z minutes; rule is required or advisory; categorised by communication kind".
# Distinct from IncidentStakeholder (per-incident contact registry).

class StakeholderMatrixRule(Base):
    __tablename__ = "stakeholder_matrix_rules"

    id                    = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    severity              = Column(String(16),  nullable=False, index=True)   # low|medium|high|critical
    role                  = Column(String(128), nullable=False)               # e.g. "CISO"
    notify_within_minutes = Column(Integer,     nullable=False)
    category              = Column(String(32),  nullable=False, default="operational")
    required              = Column(Boolean,     nullable=False, default=False)

    created_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"),
                           nullable=True)
    created_at    = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    updated_at    = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow,
                           nullable=False)

    __table_args__ = (
        UniqueConstraint("severity", "role", "category",
                         name="uq_stakeholder_matrix_severity_role_category"),
    )
