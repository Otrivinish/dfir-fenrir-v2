"""All Pydantic request/response schemas."""
from datetime import datetime
from typing import Literal, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, model_validator

from core.config import settings


# ─── Auth ───────────────────────────────────────────────────────────────────

class SetupRequest(BaseModel):
    token:     str = Field(min_length=10)
    username:  str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    email:     EmailStr
    full_name: Optional[str] = Field(default=None, max_length=255)
    password:  str = Field(min_length=settings.password_min_length, max_length=settings.password_max_length)


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    status: Literal["ok", "totp_required"]
    user:   Optional["UserOut"] = None


class TotpVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class TotpEnableRequest(BaseModel):
    code: str


class TotpDisableRequest(BaseModel):
    password: str
    code:     Optional[str] = None    # current TOTP code, sanity-check the user owns the device


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str = Field(min_length=settings.password_min_length, max_length=settings.password_max_length)


# ─── User ───────────────────────────────────────────────────────────────────

class UserOut(BaseModel):
    id:            UUID
    username:      str
    email:         str
    full_name:     Optional[str] = None
    role:          str
    is_active:     bool
    totp_enabled:  bool
    force_totp_enrol: bool = False
    force_password_change: bool = False
    auth_provider: str
    qualifications: Optional[str] = None   # ISO/IEC 27037 Annex A / 27041 competence
    created_at:    datetime
    last_login_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username:  str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    email:     EmailStr
    full_name: Optional[str] = None
    role:      Literal["admin", "analyst", "viewer"] = "analyst"
    password:  str = Field(min_length=settings.password_min_length, max_length=settings.password_max_length)
    qualifications: Optional[str] = Field(default=None, max_length=2048)


class UserUpdate(BaseModel):
    full_name:             Optional[str] = None
    role:                  Optional[Literal["admin", "analyst", "viewer"]] = None
    is_active:             Optional[bool] = None
    disable_totp:          Optional[bool] = None
    force_totp_enrol:      Optional[bool] = None
    force_password_change: Optional[bool] = None
    qualifications:        Optional[str] = Field(default=None, max_length=2048)


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=settings.password_min_length, max_length=settings.password_max_length)
    force_change_on_login: bool = True


# ─── Sessions ───────────────────────────────────────────────────────────────

class SessionOut(BaseModel):
    id:           UUID
    label:        Optional[str] = None
    ip_address:   Optional[str] = None
    user_agent:   Optional[str] = None
    country:      Optional[str] = None
    city:         Optional[str] = None
    created_at:   datetime
    last_seen_at: datetime
    expires_at:   datetime
    is_current:   bool = False

    class Config:
        from_attributes = True


class SessionLabelUpdate(BaseModel):
    label: str = Field(min_length=1, max_length=64)


class AdminSessionOut(BaseModel):
    id:           UUID
    user_id:      UUID
    username:     str = ''
    label:        Optional[str] = None
    ip_address:   Optional[str] = None
    user_agent:   Optional[str] = None
    country:      Optional[str] = None
    city:         Optional[str] = None
    created_at:   datetime
    last_seen_at: datetime
    expires_at:   datetime
    is_current:   bool = False

    class Config:
        from_attributes = True


# ─── Teams ──────────────────────────────────────────────────────────────────

class TeamOut(BaseModel):
    id:           UUID
    name:         str
    description:  Optional[str] = None
    color:        str
    member_count: int = 0
    created_at:   datetime

    class Config:
        from_attributes = True


class TeamCreate(BaseModel):
    name:        str = Field(min_length=1, max_length=128)
    description: Optional[str] = None
    color:       str = Field(default="#22d3ee", pattern=r"^#[0-9a-fA-F]{6}$")


class TeamUpdate(BaseModel):
    name:        Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = None
    color:       Optional[str] = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")


# ─── Operational roles ──────────────────────────────────────────────────────

class OperationalRoleOut(BaseModel):
    id:          UUID
    key:         str
    label:       str
    description: Optional[str] = None
    is_system:   bool
    is_active:   bool
    sort_order:  int

    class Config:
        from_attributes = True


class OperationalRoleCreate(BaseModel):
    key:         str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")
    label:       str = Field(min_length=1, max_length=128)
    description: Optional[str] = None
    sort_order:  int = 100


class OperationalRoleUpdate(BaseModel):
    label:       Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = None
    is_active:   Optional[bool] = None
    sort_order:  Optional[int] = None


# ─── TOTP setup response ────────────────────────────────────────────────────

class TotpSetupResponse(BaseModel):
    secret:          str
    provisioning_uri: str
    qr_code_data_url: str    # base64 PNG


# ─── Incident ───────────────────────────────────────────────────────────────
# Standards-aligned enum vocabularies. Don't invent new values.

class TeamRef(BaseModel):
    """Minimal team reference embedded in incident responses."""
    id:    UUID
    name:  str
    color: str
    class Config: from_attributes = True
#
# Severity is internal Low/Medium/High/Critical (matches CVSS bands, SOC default).
# Mapping to NCISS (for federal/regulator reports) is performed at report time:
#   critical → emergency, high → severe, medium → medium, low → low
# CSF 2.0 function tagging belongs at the report level (which subcategories the
# response programme covered), not on every incident — see CLAUDE.md.

Severity        = Literal["low", "medium", "high", "critical"]
Phase           = Literal["preparation", "detection_and_analysis",                     # 800-61 R3
                          "containment_eradication_recovery", "post_incident"]
Tlp             = Literal["red", "amber_strict", "amber", "green", "clear"]            # TLP 2.0
IncidentState   = Literal["open", "closed"]
# Analyst's investigation-confidence assessment. Distinct from severity (impact)
# and phase (response posture). Suspected is the default for new incidents.
TriageState     = Literal["suspected", "confirmed", "false_positive", "benign_positive"]
IncidentType    = Literal[                                                              # CISA/SOC categories
    "malware", "ransomware", "phishing", "data_breach", "unauthorized_access",
    "insider_threat", "ddos", "bec", "credential_compromise",
    "web_attack", "vulnerability_exploitation", "supply_chain", "physical", "other",
]
DetectionMethod = Literal[
    "siem_alert", "user_report", "threat_hunting",
    "external_notification", "automated_scan", "pen_test", "other",
]
SystemType      = Literal[
    "workstation", "server", "network_device", "cloud_resource",
    "application", "database", "mobile", "other",
]


class IncidentCreate(BaseModel):
    title:            str = Field(min_length=3, max_length=200)
    description:      Optional[str] = None
    severity:         Severity = "medium"
    phase:            Phase    = "detection_and_analysis"
    tlp:              Tlp      = "amber"
    triage_state:     TriageState = "suspected"
    incident_type:    Optional[IncidentType]    = None
    detection_method: Optional[DetectionMethod] = None
    reporter:         Optional[str] = Field(default=None, max_length=128)
    occurred_at:      Optional[datetime] = None
    team_ids:         list[UUID] = []
    tags:             list[str]  = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title:            Optional[str]              = Field(default=None, min_length=3, max_length=200)
    description:      Optional[str]              = None
    severity:         Optional[Severity]         = None
    phase:            Optional[Phase]            = None
    tlp:              Optional[Tlp]              = None
    triage_state:     Optional[TriageState]      = None
    incident_type:    Optional[IncidentType]     = None
    detection_method: Optional[DetectionMethod]  = None
    reporter:         Optional[str]              = Field(default=None, max_length=128)
    occurred_at:      Optional[datetime]         = None
    contained_at:     Optional[datetime]         = None
    team_ids:         Optional[list[UUID]]       = None  # None = no change; [] = remove all teams
    tags:             Optional[list[str]]        = None  # None = no change; [] = clear


class IncidentOut(BaseModel):
    id:               UUID
    incident_number:  Optional[int] = None
    ref:              Optional[str] = None
    title:            str
    description:      Optional[str] = None
    severity:         Severity
    phase:            Phase
    tlp:              Tlp
    triage_state:     TriageState = "suspected"
    incident_type:    Optional[IncidentType]    = None
    detection_method: Optional[DetectionMethod] = None
    status:           IncidentState
    reporter:         Optional[str] = None
    created_by_id:    Optional[UUID] = None
    dark_operation:   bool = False
    created_at:       datetime
    updated_at:       datetime
    closed_at:        Optional[datetime] = None
    occurred_at:      Optional[datetime] = None
    contained_at:     Optional[datetime] = None
    teams:            list[TeamRef] = []
    tags:             list[str]      = Field(default_factory=list)

    class Config:
        from_attributes = True


class IncidentList(BaseModel):
    items:       list[IncidentOut]
    next_cursor: Optional[str] = None


class IncidentSnapshot(BaseModel):
    """At-a-glance per-incident counts for the Details landing tab.

    All values are non-negative integers. Aggregations only — no row data — so
    this endpoint is access-checked but not RBAC-sensitive beyond accessibility.
    """
    iocs:             int
    entities:         int
    evidence:         int
    timeline:         int
    affected_systems: int
    assignments:      int
    playbook_total:   int   # excludes skipped tasks (matches sidebar widget convention)
    playbook_done:    int
    playbook_skipped: int


# ─── IOCs ───────────────────────────────────────────────────────────────────
# 800-61 R3 vocabulary: "indicator of compromise". Per-incident scope.

IocType = Literal[
    "ip", "domain", "url",
    "hash_md5", "hash_sha1", "hash_sha256",
    "email", "registry_key", "file_path", "other",
]


class IOCOut(BaseModel):
    id:          UUID
    incident_id: UUID
    type:        IocType
    value:       str
    notes:       Optional[str]  = None
    source:      Optional[str]  = None
    # Tri-state: True = malicious, False = clean, None = unknown.
    malicious:   Optional[bool] = None
    confidence:  int            = 50
    tags:        list[str]     = Field(default_factory=list)
    entity_id:   Optional[UUID] = None
    added_by_id: Optional[UUID] = None
    added_by_username: Optional[str] = None
    added_at:    datetime
    updated_at:  datetime
    # Populated at query time — not stored on the row.
    ti_matched:      bool          = False
    ti_match_source: Optional[str] = None
    lolbin_hit:      bool          = False
    lolbin_name:     Optional[str] = None

    class Config:
        from_attributes = True


class IOCCreate(BaseModel):
    type:       IocType
    value:      str            = Field(min_length=1, max_length=2048)
    notes:      Optional[str]  = Field(default=None, max_length=4096)
    source:     Optional[str]  = Field(default=None, max_length=256)
    # Tri-state: omit / None = unknown (default for newly-added IOCs).
    malicious:  Optional[bool] = None
    confidence: int            = Field(default=50, ge=0, le=100)
    tags:       list[str]     = Field(default_factory=list, max_length=32)
    entity_id:  Optional[UUID] = None


class IOCUpdate(BaseModel):
    # type/value are editable; the route re-checks the (incident, type, value)
    # uniqueness constraint and rejects a collision with 409.
    type:       Optional[IocType]   = None
    value:      Optional[str]       = Field(default=None, min_length=1, max_length=2048)
    notes:      Optional[str]       = Field(default=None, max_length=4096)
    malicious:  Optional[bool]      = None
    confidence: Optional[int]       = Field(default=None, ge=0, le=100)
    tags:       Optional[list[str]] = Field(default=None, max_length=32)
    entity_id:  Optional[UUID]      = None


class IOCBatchCreate(BaseModel):
    items: list[IOCCreate] = Field(min_length=1, max_length=1000)


class IOCBatchResult(BaseModel):
    created: int
    skipped: int       = 0   # duplicates skipped (already on the incident)
    errors:  list[str] = Field(default_factory=list)


class IocTimelineLinkCreate(BaseModel):
    event_id: UUID


class IocTimelineLinkOut(BaseModel):
    event_id:    UUID
    event_time:  datetime
    description: str


class IocTimelineLinkList(BaseModel):
    items: list[IocTimelineLinkOut]


class IOCList(BaseModel):
    items:       list[IOCOut]
    next_cursor: Optional[str] = None


# ─── Entities ───────────────────────────────────────────────────────────────
# Asset/scope objects attached to an incident. Distinct from IOCs.

EntityType = Literal[
    "host", "user", "ip", "domain",
    "email", "service", "network_range", "group", "other",
]

Criticality = Literal["low", "medium", "high", "critical"]


class EntityOut(BaseModel):
    id:          UUID
    incident_id: UUID
    type:        EntityType
    value:       str
    name:        Optional[str] = None
    description: Optional[str] = None
    criticality: Criticality
    compromised: bool = False
    attributes:  dict = Field(default_factory=dict)
    added_by_id: Optional[UUID] = None
    added_at:    datetime
    updated_at:  datetime
    file_count:  int = 0

    class Config:
        from_attributes = True


class EntityCreate(BaseModel):
    type:        EntityType
    value:       str = Field(min_length=1, max_length=2048)
    name:        Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    criticality: Criticality = "medium"
    attributes:  dict = Field(default_factory=dict)


class EntityUpdate(BaseModel):
    # Changing type or value is delete + recreate so dedup + audit stay clean.
    name:        Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    criticality: Optional[Criticality] = None
    compromised: Optional[bool] = None
    attributes:  Optional[dict] = None


class EntityList(BaseModel):
    items:       list[EntityOut]
    next_cursor: Optional[str] = None


class EntityFileOut(BaseModel):
    id:             UUID
    entity_id:      Optional[UUID] = None
    incident_id:    UUID
    original_name:  str
    file_size:      int
    content_type:   Optional[str] = None
    uploaded_by_id: Optional[UUID] = None
    # Populated at query time for display — not stored on the row.
    uploaded_by_username: Optional[str] = None
    entity_name:          Optional[str] = None
    uploaded_at:    datetime

    class Config:
        from_attributes = True


class IncidentFileUpdate(BaseModel):
    """Rename a stored file and/or (un)link it to an entity. `entity_id` is
    tri-state — an explicit null unlinks; omitting it leaves the link unchanged."""
    original_name: Optional[str]  = Field(default=None, min_length=1, max_length=512)
    entity_id:     Optional[UUID] = None


class EntityFileList(BaseModel):
    items: list[EntityFileOut]


# ─── Entity events (asset log) ──────────────────────────────────────────────

class EntityEventOut(BaseModel):
    id:         UUID
    entity_id:  UUID
    incident_id: UUID
    event_type: str          # system | note
    title:      str
    body:       Optional[str] = None
    actor_id:   Optional[UUID] = None
    occurred_at: datetime
    created_at:  datetime

    class Config:
        from_attributes = True


class EntityEventCreate(BaseModel):
    title:       str           = Field(min_length=1, max_length=512)
    body:        Optional[str] = Field(default=None, max_length=4096)
    occurred_at: Optional[datetime] = None   # defaults to server utcnow if omitted


class EntityEventList(BaseModel):
    items: list[EntityEventOut]


# ─── Entity relations ────────────────────────────────────────────────────────

class EntityRelationOut(BaseModel):
    id:                UUID
    incident_id:       UUID
    from_entity_id:    UUID
    to_entity_id:      UUID
    relationship_type: str
    notes:             Optional[str] = None
    created_by_id:     Optional[UUID] = None
    created_at:        datetime

    class Config:
        from_attributes = True


class EntityRelationCreate(BaseModel):
    from_entity_id:    UUID
    to_entity_id:      UUID
    relationship_type: str = Field(min_length=1, max_length=64)
    notes:             Optional[str] = Field(default=None, max_length=1024)


class EntityRelationList(BaseModel):
    items: list[EntityRelationOut]


# ─── Evidence (chain of custody) ────────────────────────────────────────────
# 800-61 R3 / ISO 27037 vocabulary.

EvidenceKind    = Literal["digital_file", "physical_item"]
EvidenceStatus  = Literal["active", "verify_failed", "destroyed", "returned", "archived"]
CustodyAction   = Literal["collect", "transfer", "examine", "verify", "verify_failed",
                          "export", "return", "destroy", "archive"]
DispositionKind = Literal["destroy", "return", "archive"]
CollectorRole = Literal["defr", "des"]   # GS-12 — ISO/IEC 27037 §3.7 (DEFR) / §3.8 (DES)


class PhotoRef(BaseModel):
    url:       str
    caption:   Optional[str] = None
    taken_at:  Optional[datetime] = None
    id:        Optional[str] = None   # GS-11 — set for uploaded (encrypted-at-rest) photos
    mime_type: Optional[str] = None


class EvidenceOut(BaseModel):
    id:                UUID
    incident_id:       UUID
    kind:              EvidenceKind
    name:              str
    identifier:        str
    description:       Optional[str] = None
    tlp:               Tlp
    status:            EvidenceStatus

    # digital_file
    original_filename: Optional[str] = None
    file_size_bytes:   Optional[int] = None
    mime_type:         Optional[str] = None
    sha256:            Optional[str] = None
    sha1:              Optional[str] = None
    md5:               Optional[str] = None

    # physical_item
    make:              Optional[str] = None
    model:             Optional[str] = None
    serial:            Optional[str] = None
    physical_location: Optional[str] = None
    condition:         Optional[str] = None
    photos:            list[PhotoRef] = Field(default_factory=list)

    # common
    entity_id:            Optional[UUID] = None
    current_custodian_id: Optional[UUID] = None
    current_custodian_external_name:    Optional[str] = None
    current_custodian_external_org:     Optional[str] = None
    current_custodian_external_contact: Optional[str] = None
    collected_by_id:      Optional[UUID] = None
    collected_as_role:    Optional[CollectorRole] = None   # GS-12 (DEFR/DES)
    collected_at:         datetime
    collected_location:   Optional[str] = None
    disposed_at:          Optional[datetime] = None
    dispose_witness_id:   Optional[UUID] = None             # GS-10 (two-person disposal)
    final_hash_at_disposition: Optional[str] = None
    legal_hold:           bool = False

    # Wizard A — acquisition (ISO/IEC 27037 §9.2 + GDPR Art. 5.1(c))
    lawful_basis:              Optional[str] = None
    lawful_basis_note:         Optional[str] = None
    acquisition_tool:          Optional[str] = None
    acquisition_tool_version:  Optional[str] = None
    acquisition_tool_sha256:   Optional[str] = None
    acquisition_params:        Optional[str] = None
    acquisition_hash_source:   Optional[str] = None
    acquisition_hash_target:   Optional[str] = None
    write_blocker_used:        Optional[bool] = None
    write_blocker_serial:      Optional[str]  = None
    system_state:              Optional[str]  = None
    live_justification:        Optional[str]  = None
    network_isolated:          Optional[bool] = None
    witness_user_id:           Optional[UUID] = None
    witness_name:              Optional[str]  = None
    # Collection-wizard (ISO/IEC 27037 §7)
    device_types:              Optional[list[str]] = None
    handling_mode:             Optional[str]  = None
    decision_factors:          Optional[dict] = None
    acquisition_scope:         Optional[str]  = None
    logical_acquisition_rationale: Optional[str] = None
    system_time_offset:        Optional[str]  = None
    screen_state:              Optional[str]  = None
    changes_made:              Optional[str]  = None
    device_details:            Optional[dict] = None
    # ISO/IEC 27041 — method/tool validation + competence (Slice B)
    acquisition_tool_validated:       Optional[bool] = None
    acquisition_tool_validation_ref:  Optional[str]  = None
    acquisition_tool_validation_date: Optional[str]  = None
    collected_by_qualifications:      Optional[str]  = None
    # ISO/IEC 27037 §7.1.3.1.1 — has ≥1 master-verified working copy (Slice D)
    has_verified_working_copy:        bool = False
    # ISO/IEC 27042 — examination documentation flags (GS-3)
    has_examination:                  bool = False
    has_examination_findings:         bool = False
    has_examination_scope:            bool = False
    coc_sealed:                bool = False
    coc_sealed_at:             Optional[datetime] = None
    coc_sealed_by_id:          Optional[UUID] = None
    # GS-4 trusted timestamp on the seal (the TST blob itself is not listed — fetch on demand)
    seal_tst_time:             Optional[str] = None
    seal_tsa:                  Optional[str] = None

    created_at:           datetime
    updated_at:           datetime

    class Config:
        from_attributes = True


# ── Wizard A: acquisition payload (additive to PhysicalEvidenceCreate /
# the digital-file Form fields). Sent by the new /collect-with-wizard
# endpoint and the /seal endpoint.
LawfulBasis  = Literal["ir", "consent", "warrant", "court_order", "eio", "mla", "lia", "other"]
SystemState  = Literal["powered_off", "live", "live_critical", "unknown"]
# Collection-wizard slice (ISO/IEC 27037 §7) — see docs/coc-collection-wizard-slice.md
DeviceType       = Literal["computer", "peripheral", "storage", "mobile", "network", "cctv"]
HandlingMode     = Literal["collect", "acquire"]
AcquisitionScope = Literal["full_image", "logical"]


class AcquisitionMetadata(BaseModel):
    lawful_basis:              Optional[LawfulBasis] = None
    lawful_basis_note:         Optional[str] = Field(default=None, max_length=4096)
    acquisition_tool:          Optional[str] = Field(default=None, max_length=128)
    acquisition_tool_version:  Optional[str] = Field(default=None, max_length=64)
    acquisition_tool_sha256:   Optional[str] = Field(default=None, min_length=64, max_length=64)
    acquisition_params:        Optional[str] = Field(default=None, max_length=4096)
    acquisition_hash_source:   Optional[str] = Field(default=None, min_length=64, max_length=64)
    acquisition_hash_target:   Optional[str] = Field(default=None, min_length=64, max_length=64)
    write_blocker_used:        Optional[bool] = None
    write_blocker_serial:      Optional[str]  = Field(default=None, max_length=128)
    system_state:              Optional[SystemState] = None
    live_justification:        Optional[str]  = Field(default=None, max_length=4096)
    network_isolated:          Optional[bool] = None
    witness_user_id:           Optional[UUID] = None
    witness_name:              Optional[str]  = Field(default=None, max_length=128)
    # Collection-wizard (ISO/IEC 27037 §7)
    device_types:              Optional[list[DeviceType]] = None
    handling_mode:             Optional[HandlingMode] = None
    decision_factors:          Optional[dict] = None
    acquisition_scope:         Optional[AcquisitionScope] = None
    logical_acquisition_rationale: Optional[str] = Field(default=None, max_length=4096)
    system_time_offset:        Optional[str]  = Field(default=None, max_length=128)
    screen_state:              Optional[str]  = Field(default=None, max_length=4096)
    changes_made:              Optional[str]  = Field(default=None, max_length=4096)
    device_details:            Optional[dict] = None
    # ISO/IEC 27041 — method/tool validation (Slice B)
    acquisition_tool_validated:       Optional[bool] = None
    acquisition_tool_validation_ref:  Optional[str]  = Field(default=None, max_length=256)
    acquisition_tool_validation_date: Optional[str]  = Field(default=None, max_length=32)


class EvidenceSealRequest(BaseModel):
    """Marks an evidence row as wizard-A sealed. Auto-validates that the
    minimum ISO 27037 / GDPR fields are present before sealing."""
    confirm: bool = True


# ── Provenance scoring ───────────────────────────────────────────────────
# Returned by GET /evidence/{id}/provenance. Mirrors the SOP autoCheck logic
# server-side so external clients (MCP, scripts) see the same score the UI
# computes. Score letters:
#   green  — all applicable checks pass
#   amber  — one or more advisory checks fail or are unknown
#   red    — at least one mandatory check fails

class ProvenanceCheck(BaseModel):
    code:        str           # iso_27037_9_1_4, iso_27037_9_2_3, …
    label:       str
    status:      str           # pass | fail | manual | n_a
    severity:    str           # mandatory | advisory
    note:        Optional[str] = None


class ProvenanceScore(BaseModel):
    score:        str   # green | amber | red
    checks:       list[ProvenanceCheck]
    summary:      str   # short human-readable summary
    completeness: int = 0   # % of determinable checks passing (ISO 27041 paper rubric; >90% = good)


# Used for creating a `physical_item` (digital_file uses multipart/form-data
# directly — see evidence/routes.py — because file upload doesn't fit JSON).
class PhysicalEvidenceCreate(BaseModel):
    name:               str = Field(min_length=1, max_length=256)
    identifier:         str = Field(min_length=1, max_length=128)
    description:        Optional[str] = Field(default=None, max_length=4096)
    tlp:                Tlp = "amber"
    entity_id:          Optional[UUID] = None
    make:               Optional[str] = Field(default=None, max_length=128)
    model:              Optional[str] = Field(default=None, max_length=128)
    serial:             Optional[str] = Field(default=None, max_length=128)
    physical_location:  Optional[str] = Field(default=None, max_length=256)
    condition:          Optional[str] = Field(default=None, max_length=4096)
    photos:             list[PhotoRef] = Field(default_factory=list)
    collected_location: Optional[str] = Field(default=None, max_length=256)
    collected_as_role:  Optional[CollectorRole] = None   # GS-12 (DEFR/DES)

    # Wizard A — acquisition metadata. Same fields as the digital flow; the
    # write-blocker / acquisition-hash fields don't apply but we accept them
    # so a polymorphic add-evidence form can stay generic.
    lawful_basis:              Optional[str] = None
    lawful_basis_note:         Optional[str] = Field(default=None, max_length=4096)
    acquisition_tool:          Optional[str] = Field(default=None, max_length=128)
    acquisition_tool_version:  Optional[str] = Field(default=None, max_length=64)
    acquisition_tool_sha256:   Optional[str] = Field(default=None, min_length=64, max_length=64)
    acquisition_params:        Optional[str] = Field(default=None, max_length=4096)
    witness_user_id:           Optional[UUID] = None
    witness_name:              Optional[str] = Field(default=None, max_length=128)
    # Collection-wizard (ISO/IEC 27037 §7)
    device_types:              Optional[list[DeviceType]] = None
    handling_mode:             Optional[HandlingMode] = None
    decision_factors:          Optional[dict] = None
    acquisition_scope:         Optional[AcquisitionScope] = None
    logical_acquisition_rationale: Optional[str] = Field(default=None, max_length=4096)
    system_time_offset:        Optional[str] = Field(default=None, max_length=128)
    screen_state:              Optional[str] = Field(default=None, max_length=4096)
    changes_made:              Optional[str] = Field(default=None, max_length=4096)
    device_details:            Optional[dict] = None
    # ISO/IEC 27041 — method/tool validation (Slice B)
    acquisition_tool_validated:       Optional[bool] = None
    acquisition_tool_validation_ref:  Optional[str]  = Field(default=None, max_length=256)
    acquisition_tool_validation_date: Optional[str]  = Field(default=None, max_length=32)


class EvidenceUpdate(BaseModel):
    # MVP allows updating descriptive fields only. Identifier is immutable,
    # custodian changes go through /transfer, status changes through /dispose
    # or /verify.
    name:              Optional[str] = Field(default=None, min_length=1, max_length=256)
    description:       Optional[str] = Field(default=None, max_length=4096)
    tlp:               Optional[Tlp] = None
    physical_location: Optional[str] = Field(default=None, max_length=256)
    condition:         Optional[str] = Field(default=None, max_length=4096)
    photos:            Optional[list[PhotoRef]] = None
    legal_hold:        Optional[bool] = None
    collected_as_role: Optional[CollectorRole] = None   # GS-12 (DEFR/DES)


class ExternalCustodian(BaseModel):
    """A real-world custodian without a Fenrir account — courier, external counsel,
    LE officer pre-formal-handoff, vendor IR team, etc. Captured for ISO 27037 §9.3
    chain-accountability coverage."""
    name:         str = Field(min_length=1, max_length=256)
    organisation: Optional[str] = Field(default=None, max_length=256)
    contact:      Optional[str] = Field(default=None, max_length=256)


class TransferRequest(BaseModel):
    """Exactly one of `to_user_id` or `to_external` must be set."""
    to_user_id:  Optional[UUID] = None
    to_external: Optional[ExternalCustodian] = None
    reason:      str = Field(min_length=1, max_length=2048)
    # Structured tamper-evident transport (ISO/IEC 27037 §6.9.4) — optional.
    transport_method: Optional[str] = Field(default=None, max_length=128)   # courier, hand-carry, encrypted_channel…
    seal_id:          Optional[str] = Field(default=None, max_length=128)   # tamper-evident seal number
    courier_ref:      Optional[str] = Field(default=None, max_length=128)   # tracking / waybill ref

    @model_validator(mode="after")
    def _exactly_one_recipient(self):
        if (self.to_user_id is None) == (self.to_external is None):
            raise ValueError("exactly one of to_user_id or to_external must be provided")
        return self


class ExamineRequest(BaseModel):
    tool:  str = Field(min_length=1, max_length=256)
    notes: Optional[str] = Field(default=None, max_length=4096)


class DisposeRequest(BaseModel):
    kind:      DispositionKind
    reason:    str = Field(min_length=1, max_length=2048)
    witness_id: Optional[UUID] = None   # GS-10 — required (distinct user) when disposing a legal-hold item


class VerifyResult(BaseModel):
    ok:                bool
    sha256_recorded:   Optional[str] = None
    sha256_recomputed: Optional[str] = None
    message:           Optional[str] = None


class EvidenceList(BaseModel):
    items:       list[EvidenceOut]
    next_cursor: Optional[str] = None


# ── Working-copy ledger (ISO/IEC 27037 §7.1.3.1.1, Slice C) ──────────────────
class EvidenceCopyOut(BaseModel):
    id:                       UUID
    evidence_id:              UUID
    role:                     str
    sha256:                   Optional[str] = None
    verified_against_master:  bool = False
    created_by_id:            Optional[UUID] = None
    created_by_qualifications: Optional[str] = None
    created_at:               datetime
    purpose:                  Optional[str] = None
    export_id:                Optional[UUID] = None
    discarded_at:             Optional[datetime] = None

    class Config:
        from_attributes = True


class WorkingCopyCreate(BaseModel):
    purpose: str = Field(min_length=1, max_length=2048)


class EvidenceCopyList(BaseModel):
    items: list[EvidenceCopyOut]


# ── Validated-tools registry (ISO/IEC 27041, GS-1) ──────────────────────────
class ValidatedToolOut(BaseModel):
    id:             UUID
    name:           str
    version:        str
    validation_ref: Optional[str] = None
    scope:          Optional[str] = None
    validated_by:   Optional[str] = None
    validated_at:   Optional[str] = None
    notes:          Optional[str] = None
    is_active:      bool = True
    created_at:     datetime

    class Config:
        from_attributes = True


class ValidatedToolCreate(BaseModel):
    name:           str = Field(min_length=1, max_length=128)
    version:        str = Field(min_length=1, max_length=64)
    validation_ref: Optional[str] = Field(default=None, max_length=256)
    scope:          Optional[str] = Field(default=None, max_length=4096)
    validated_by:   Optional[str] = Field(default=None, max_length=128)
    validated_at:   Optional[str] = Field(default=None, max_length=32)
    notes:          Optional[str] = Field(default=None, max_length=4096)


class ValidatedToolUpdate(BaseModel):
    validation_ref: Optional[str] = Field(default=None, max_length=256)
    scope:          Optional[str] = Field(default=None, max_length=4096)
    validated_by:   Optional[str] = Field(default=None, max_length=128)
    validated_at:   Optional[str] = Field(default=None, max_length=32)
    notes:          Optional[str] = Field(default=None, max_length=4096)
    is_active:      Optional[bool] = None


class ValidatedToolList(BaseModel):
    items: list[ValidatedToolOut]


# ─── Email analyzer (U8.1) ────────────────────────────────────────────────────

class EmailAnalysisOut(BaseModel):
    id:                 UUID
    incident_id:        UUID
    source_artifact_id: Optional[UUID] = None
    evidence_id:        Optional[UUID] = None
    subject:      Optional[str] = None
    from_display: Optional[str] = None
    from_addr:    Optional[str] = None
    reply_to:     Optional[str] = None
    return_path:  Optional[str] = None
    message_id:   Optional[str] = None
    date_hdr:     Optional[str] = None
    verdict:      str
    score:        int
    findings:     list = []
    headers:      dict = {}
    urls:         list = []
    attachments:  list = []
    created_by:   Optional[str] = None
    created_at:   datetime

    class Config:
        from_attributes = True


class EmailAnalysisList(BaseModel):
    items: list[EmailAnalysisOut]


class PromoteIocItem(BaseModel):
    type:  str
    value: str = Field(min_length=1, max_length=2048)
    notes: Optional[str] = None


class PromoteIocsRequest(BaseModel):
    iocs: list[PromoteIocItem] = Field(default_factory=list)


# ─── Audit-chain anchors (GS-8) ───────────────────────────────────────────────

class AuditAnchorOut(BaseModel):
    id:            UUID
    anchored_at:   datetime
    head_row_id:   Optional[UUID] = None
    head_row_hash: str
    row_count:     int
    verify_ok:     bool
    verify_detail: Optional[str] = None
    tst_time:      Optional[str] = None   # asserted TSA time (ISO 8601 Z)
    tsa:           Optional[str] = None
    has_tst:       bool = False           # token present (full token not exposed in lists)

    class Config:
        from_attributes = True


class AuditAnchorList(BaseModel):
    items: list[AuditAnchorOut]


ExportStatus = Literal["pending", "ready", "consumed", "expired", "revoked"]


class ExportCreate(BaseModel):
    item_ids:        list[UUID]  = Field(min_length=1)
    recipient:       str         = Field(min_length=1, max_length=256)
    purpose:         str         = Field(min_length=1, max_length=4096)
    acknowledgments: Optional[str] = Field(default=None, max_length=4096)


class ExportOut(BaseModel):
    id:              UUID
    incident_id:     UUID
    exported_by_id:  Optional[UUID] = None
    recipient:       str
    purpose:         str
    acknowledgments: Optional[str] = None
    status:          ExportStatus
    file_size:       Optional[int] = None
    bundle_sha256:   Optional[str] = None
    key_hint:        Optional[str] = None
    item_ids:        list[UUID] = Field(default_factory=list)
    created_at:      datetime
    expires_at:      datetime
    consumed_at:     Optional[datetime] = None

    class Config:
        from_attributes = True


class ExportCreateResponse(BaseModel):
    """Returned ONCE on export creation — `key` is never retrievable again."""
    export:       ExportOut
    key:          str    # 64-char hex AES-256 key
    download_url: str    # relative path: /api/exports/{token}
    bundle_sha256: str   # convenience — same as export.bundle_sha256


class ExportList(BaseModel):
    items:       list[ExportOut]
    next_cursor: Optional[str] = None


class CustodyEventOut(BaseModel):
    id:           UUID
    event_type:   str
    user_id:      Optional[UUID] = None
    username:     Optional[str] = None
    resource_type: Optional[str] = None
    resource_id:  Optional[str] = None
    outcome:      Optional[str] = None
    details:      dict = Field(default_factory=dict)
    ip_address:   Optional[str] = None
    created_at:   datetime
    hash:         Optional[str] = None
    prev_hash:    Optional[str] = None

    class Config:
        from_attributes = True


class ChainVerifyResult(BaseModel):
    ok:              bool
    checked:         int                    # number of rows examined
    broken_at_id:    Optional[UUID] = None  # first row whose hash failed
    broken_reason:   Optional[str]  = None  # human-readable failure reason
    message:         str


# ─── Playbook ───────────────────────────────────────────────────────────────
# Templates are reusable task lists; per-incident PlaybookTasks are
# independent copies once instantiated.

TaskStatus = Literal["open", "in_progress", "done", "skipped"]


class PlaybookTaskTemplate(BaseModel):
    """A single task inside a template's `tasks` JSON array."""
    title:       str         = Field(min_length=1, max_length=512)
    description: Optional[str] = None
    phase:       Phase
    order:       int         = 0


class PlaybookTemplateOut(BaseModel):
    id:          UUID
    key:         str
    name:        str
    description: Optional[str] = None
    category:    Optional[str] = None
    is_system:   bool
    tasks:       list[PlaybookTaskTemplate] = Field(default_factory=list)
    created_at:  datetime
    updated_at:  datetime

    class Config:
        from_attributes = True


class PlaybookTemplateSummary(BaseModel):
    """List view — omits the tasks array."""
    id:           UUID
    key:          str
    name:         str
    description:  Optional[str] = None
    category:     Optional[str] = None
    is_system:    bool
    task_count:   int = 0
    run_count:    int = 0
    last_run_at:  Optional[datetime] = None

    class Config:
        from_attributes = True


class PlaybookTemplateCreate(BaseModel):
    name:        str              = Field(min_length=1, max_length=256)
    description: Optional[str]   = Field(default=None, max_length=4096)
    category:    Optional[str]   = Field(default=None, max_length=64)
    tasks:       list[PlaybookTaskTemplate] = Field(default_factory=list)


class PlaybookTemplateUpdate(BaseModel):
    name:        Optional[str]   = Field(default=None, min_length=1, max_length=256)
    description: Optional[str]   = Field(default=None, max_length=4096)
    category:    Optional[str]   = Field(default=None, max_length=64)
    tasks:       Optional[list[PlaybookTaskTemplate]] = None


class PlaybookTaskOut(BaseModel):
    id:                 UUID
    incident_id:        UUID
    title:              str
    description:        Optional[str] = None
    phase:              Phase
    order_index:        int
    status:             TaskStatus
    skip_reason:        Optional[str] = None
    assignee_id:        Optional[UUID] = None
    due_at:             Optional[datetime] = None
    completed_at:       Optional[datetime] = None
    completed_by_id:    Optional[UUID] = None
    source_template_id: Optional[UUID] = None
    source_task_index:  Optional[int] = None
    created_by_id:      Optional[UUID] = None
    created_at:         datetime
    updated_at:         datetime

    class Config:
        from_attributes = True


class PlaybookTaskCreate(BaseModel):
    title:       str         = Field(min_length=1, max_length=512)
    description: Optional[str] = Field(default=None, max_length=4096)
    phase:       Phase
    order_index: int         = 0
    assignee_id: Optional[UUID] = None
    due_at:      Optional[datetime] = None


class PlaybookTaskUpdate(BaseModel):
    title:       Optional[str] = Field(default=None, min_length=1, max_length=512)
    description: Optional[str] = Field(default=None, max_length=4096)
    phase:       Optional[Phase] = None
    order_index: Optional[int] = None
    status:      Optional[TaskStatus] = None
    skip_reason: Optional[str] = Field(default=None, max_length=2048)
    assignee_id: Optional[UUID] = None
    due_at:      Optional[datetime] = None


class PlaybookInstantiateRequest(BaseModel):
    template_id: UUID
    # If False (default), tasks from the template are appended to the
    # existing list. If True, the incident's current task list is cleared
    # first (admin-only on the route).
    replace:     bool = False


# ─── Comms — comments + OOB ─────────────────────────────────────────────────

OOBChannel  = Literal["personal_mobile", "signal", "whatsapp", "personal_email",
                       "in_person", "secure_fax", "courier", "third_party_ir"]
OOBDirection = Literal["outbound", "inbound"]


class CommentOut(BaseModel):
    id:          UUID
    incident_id: UUID
    body:        str
    author_id:       Optional[UUID] = None
    author_username: Optional[str]  = None
    created_at:      datetime
    updated_at:      datetime
    edited_at:       Optional[datetime] = None

    class Config:
        from_attributes = True


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=8192)


class CommentUpdate(BaseModel):
    body: str = Field(min_length=1, max_length=8192)


class CommentList(BaseModel):
    items:       list[CommentOut]
    next_cursor: Optional[str] = None


class PassphraseOut(BaseModel):
    passphrase: str


class DarkOperationUpdate(BaseModel):
    enabled: bool


class OOBLogOut(BaseModel):
    id:                  UUID
    incident_id:         UUID
    stakeholder_name:    str
    channel:             OOBChannel
    direction:           OOBDirection
    summary:             str
    verified:            bool
    verification_method: Optional[str] = None
    created_by_id:       Optional[UUID] = None
    created_by_username: Optional[str]  = None
    created_at:          datetime

    class Config:
        from_attributes = True


class OOBLogCreate(BaseModel):
    stakeholder_name:    str          = Field(min_length=1, max_length=255)
    channel:             OOBChannel
    direction:           OOBDirection = "outbound"
    summary:             str          = Field(min_length=1, max_length=4096)
    verified:            bool         = False
    verification_method: Optional[str] = Field(default=None, max_length=128)


class OOBLogList(BaseModel):
    items: list[OOBLogOut]


# ─── Stakeholder contacts ────────────────────────────────────────────────────

StakeholderChannel = Literal[
    "email", "phone", "mobile", "signal", "whatsapp",
    "telegram", "teams", "slack", "secure_fax", "in_person",
]
StakeholderType = Literal[
    "internal", "legal", "regulatory", "law_enforcement",
    "media_pr", "vendor", "ir_firm", "customer", "insurer", "board", "other",
]


class ContactMethod(BaseModel):
    channel:   StakeholderChannel
    value:     str  = Field(min_length=1, max_length=512)
    preferred: bool = False
    notes:     Optional[str] = Field(default=None, max_length=512)


class IncidentStakeholderOut(BaseModel):
    id:              UUID
    incident_id:     UUID
    name:            str
    title:           Optional[str] = None
    organization:    Optional[str] = None
    type:            str
    contact_methods: list[ContactMethod] = Field(default_factory=list)
    notes:           Optional[str] = None
    available_hours: Optional[str] = None
    created_by_id:   Optional[UUID] = None
    created_at:      datetime
    updated_at:      datetime

    class Config:
        from_attributes = True


class IncidentStakeholderCreate(BaseModel):
    name:            str              = Field(min_length=1, max_length=255)
    title:           Optional[str]    = Field(default=None, max_length=128)
    organization:    Optional[str]    = Field(default=None, max_length=256)
    type:            StakeholderType  = "other"
    contact_methods: list[ContactMethod] = Field(default_factory=list)
    notes:           Optional[str]    = Field(default=None, max_length=4096)
    available_hours: Optional[str]    = Field(default=None, max_length=64)


class IncidentStakeholderUpdate(BaseModel):
    name:            Optional[str]    = Field(default=None, min_length=1, max_length=255)
    title:           Optional[str]    = Field(default=None, max_length=128)
    organization:    Optional[str]    = Field(default=None, max_length=256)
    type:            Optional[StakeholderType] = None
    contact_methods: Optional[list[ContactMethod]] = None
    notes:           Optional[str]    = Field(default=None, max_length=4096)
    available_hours: Optional[str]    = Field(default=None, max_length=64)


class IncidentStakeholderBulkCreate(BaseModel):
    rows: list[IncidentStakeholderCreate] = Field(min_length=1, max_length=500)


class IncidentStakeholderBulkResult(BaseModel):
    created: int
    errors:  list[str] = Field(default_factory=list)


class IncidentStakeholderList(BaseModel):
    items: list[IncidentStakeholderOut]


# ─── Respond — actions + decisions ──────────────────────────────────────────

RespondActionCategory = Literal["containment", "eradication", "recovery"]
RespondActionStatus   = Literal["open", "in_progress", "done", "deferred", "reverted"]
DecisionOutcome       = Literal["pending", "approved", "rejected", "deferred"]


class RespondActionOut(BaseModel):
    id:            UUID
    incident_id:   UUID
    category:      RespondActionCategory
    title:         str
    description:   Optional[str] = None
    status:        RespondActionStatus
    assignee_id:   Optional[UUID] = None
    notes:         Optional[str] = None
    details:       dict = Field(default_factory=dict)
    order_index:   int
    created_by_id: Optional[UUID] = None
    created_at:    datetime
    updated_at:    datetime
    completed_at:  Optional[datetime] = None
    occurred_at:   Optional[datetime] = None
    reverted_at:    Optional[datetime] = None
    reverted_by_id: Optional[UUID] = None
    revert_reason:  Optional[str] = None

    class Config:
        from_attributes = True


class RespondActionRevert(BaseModel):
    revert_reason: str = Field(min_length=1, max_length=4096)


class RespondActionCreate(BaseModel):
    category:    RespondActionCategory
    title:       str = Field(min_length=1, max_length=512)
    description: Optional[str] = Field(default=None, max_length=4096)
    status:      RespondActionStatus = "open"
    assignee_id: Optional[UUID] = None
    notes:       Optional[str] = Field(default=None, max_length=4096)
    details:     dict = Field(default_factory=dict)
    order_index: int = 0
    occurred_at: Optional[datetime] = None


class RespondActionUpdate(BaseModel):
    title:       Optional[str] = Field(default=None, min_length=1, max_length=512)
    description: Optional[str] = Field(default=None, max_length=4096)
    status:      Optional[RespondActionStatus] = None
    assignee_id: Optional[UUID] = None
    notes:       Optional[str] = Field(default=None, max_length=4096)
    details:     Optional[dict] = None
    order_index: Optional[int] = None
    occurred_at: Optional[datetime] = None


class RespondActionList(BaseModel):
    items:       list[RespondActionOut]
    next_cursor: Optional[str] = None


class DecisionOut(BaseModel):
    id:            UUID
    incident_id:   UUID
    summary:       str
    rationale:     Optional[str] = None
    outcome:       DecisionOutcome
    decided_by_id: Optional[UUID] = None
    decided_at:    Optional[datetime] = None
    tags:          list[str] = Field(default_factory=list)
    created_by_id: Optional[UUID] = None
    created_at:    datetime
    updated_at:    datetime

    class Config:
        from_attributes = True


class DecisionCreate(BaseModel):
    summary:       str = Field(min_length=1, max_length=4096)
    rationale:     Optional[str] = Field(default=None, max_length=4096)
    outcome:       DecisionOutcome = "pending"
    decided_by_id: Optional[UUID] = None
    decided_at:    Optional[datetime] = None
    tags:          list[str] = Field(default_factory=list)


class DecisionUpdate(BaseModel):
    summary:       Optional[str] = Field(default=None, min_length=1, max_length=4096)
    rationale:     Optional[str] = Field(default=None, max_length=4096)
    outcome:       Optional[DecisionOutcome] = None
    decided_by_id: Optional[UUID] = None
    decided_at:    Optional[datetime] = None
    tags:          Optional[list[str]] = None


class DecisionList(BaseModel):
    items:       list[DecisionOut]
    next_cursor: Optional[str] = None


# ─── Timeline events ─────────────────────────────────────────────────────────

TimelineOrigin = Literal["manual", "forensic_import", "system"]


class TimelineEventOut(BaseModel):
    id:                   UUID
    incident_id:          UUID
    event_time:           datetime
    hostname:             Optional[str] = None
    source:               Optional[str] = None
    event_type:           Optional[str] = None
    description:          str
    raw_log:              Optional[str] = None
    ir_phase:             Optional[Phase] = None
    mitre_tactic_id:      Optional[str] = None
    mitre_tactic_name:    Optional[str] = None
    mitre_technique_id:   Optional[str] = None
    mitre_technique_name: Optional[str] = None
    origin:               TimelineOrigin
    is_system:            bool            = False
    system_source:        Optional[str]   = None
    external_safe:        bool            = True
    created_by_id:        Optional[UUID] = None
    created_by_username:  Optional[str]  = None
    created_at:           datetime
    updated_at:           datetime

    class Config:
        from_attributes = True


class TimelineEventCreate(BaseModel):
    event_time:           datetime
    hostname:             Optional[str]   = Field(default=None, max_length=256)
    source:               Optional[str]   = Field(default=None, max_length=128)
    event_type:           Optional[str]   = Field(default=None, max_length=128)
    description:          str             = Field(min_length=1, max_length=4096)
    raw_log:              Optional[str]   = Field(default=None, max_length=4000)
    ir_phase:             Optional[Phase] = None
    mitre_tactic_id:      Optional[str]   = Field(default=None, max_length=16)
    mitre_tactic_name:    Optional[str]   = Field(default=None, max_length=64)
    mitre_technique_id:   Optional[str]   = Field(default=None, max_length=16)
    mitre_technique_name: Optional[str]   = Field(default=None, max_length=128)
    is_system:            bool            = False
    system_source:        Optional[str]   = Field(default=None, max_length=32)


class TimelineEventUpdate(BaseModel):
    event_time:           Optional[datetime] = None
    hostname:             Optional[str]   = Field(default=None, max_length=256)
    source:               Optional[str]   = Field(default=None, max_length=128)
    event_type:           Optional[str]   = Field(default=None, max_length=128)
    description:          Optional[str]   = Field(default=None, min_length=1, max_length=4096)
    raw_log:              Optional[str]   = Field(default=None, max_length=4000)
    ir_phase:             Optional[Phase] = None
    mitre_tactic_id:      Optional[str]   = Field(default=None, max_length=16)
    mitre_tactic_name:    Optional[str]   = Field(default=None, max_length=64)
    mitre_technique_id:   Optional[str]   = Field(default=None, max_length=16)
    mitre_technique_name: Optional[str]   = Field(default=None, max_length=128)


class TimelineEventList(BaseModel):
    items:              list[TimelineEventOut]
    next_cursor:        Optional[str] = None
    system_event_count: int           = 0   # total system events in this incident (set when include_system=False)


class TimelineEventBatchCreate(BaseModel):
    events: list[TimelineEventCreate] = Field(min_length=1, max_length=500)


class TimelineEventBatchResult(BaseModel):
    created: int
    errors:  list[str] = Field(default_factory=list)


# ─── Post-Incident ────────────────────────────────────────────────────────────

class ClosureChecklistItemOut(BaseModel):
    id:               UUID
    incident_id:      UUID
    item_key:         str
    label:            str
    checked:          bool
    checked_by_id:    Optional[UUID]   = None
    checked_by:       Optional[str]    = None
    checked_at:       Optional[datetime] = None
    assigned_to_id:   Optional[UUID]   = None
    assigned_to:      Optional[str]    = None
    notes:            Optional[str]    = None
    sort_order:       int
    class Config: from_attributes = True

class ClosureChecklistToggle(BaseModel):
    checked: bool

class ClosureChecklistMeta(BaseModel):
    assigned_to_id: Optional[UUID] = None
    notes:          Optional[str]  = Field(default=None, max_length=4096)

class ClosureChecklistCreate(BaseModel):
    label: str = Field(min_length=1, max_length=256)

class ClosureChecklistList(BaseModel):
    items: list[ClosureChecklistItemOut]

class UserAssignable(BaseModel):
    id:        UUID
    username:  str
    full_name: Optional[str] = None
    class Config: from_attributes = True

class LessonsLearnedOut(BaseModel):
    id:           UUID
    incident_id:  UUID
    status:       str

    conducted_at:   Optional[datetime] = None
    facilitated_by: Optional[str]      = None
    participants:   list[str]          = []

    incident_narrative:    Optional[str] = None
    root_cause_category:   Optional[str] = None
    root_cause_description:Optional[str] = None
    contributing_factors:  list[str]     = []

    effectiveness:  dict = {}

    what_went_well:  list[str] = []
    friction_points: list[str] = []
    near_misses:     list[str] = []

    timeline_detection_mins:   Optional[int] = None
    timeline_escalation_mins:  Optional[int] = None
    timeline_containment_mins: Optional[int] = None
    timeline_comms_mins:       Optional[int] = None
    timeline_remediation_mins: Optional[int] = None

    action_items:         list = []
    control_improvements: list = []

    report_what_worked_well:         Optional[str] = None
    report_what_could_improve:       Optional[str] = None
    report_security_recommendations: Optional[str] = None
    report_remediation_short:        Optional[str] = None
    report_remediation_medium:       Optional[str] = None
    report_remediation_long:         Optional[str] = None

    updated_by_id: Optional[UUID] = None
    updated_at:    datetime
    class Config: from_attributes = True


class LessonsLearnedUpdate(BaseModel):
    status:         Optional[str] = None

    conducted_at:   Optional[datetime] = None
    facilitated_by: Optional[str]      = Field(default=None, max_length=256)
    participants:   Optional[list[str]] = None

    incident_narrative:    Optional[str] = Field(default=None, max_length=32768)
    root_cause_category:   Optional[str] = Field(default=None, max_length=64)
    root_cause_description:Optional[str] = Field(default=None, max_length=16384)
    contributing_factors:  Optional[list[str]] = None

    effectiveness: Optional[dict] = None

    what_went_well:  Optional[list[str]] = None
    friction_points: Optional[list[str]] = None
    near_misses:     Optional[list[str]] = None

    timeline_detection_mins:   Optional[int] = None
    timeline_escalation_mins:  Optional[int] = None
    timeline_containment_mins: Optional[int] = None
    timeline_comms_mins:       Optional[int] = None
    timeline_remediation_mins: Optional[int] = None

    action_items:         Optional[list] = None
    control_improvements: Optional[list] = None

    report_what_worked_well:         Optional[str] = Field(default=None, max_length=16384)
    report_what_could_improve:       Optional[str] = Field(default=None, max_length=16384)
    report_security_recommendations: Optional[str] = Field(default=None, max_length=16384)
    report_remediation_short:        Optional[str] = Field(default=None, max_length=16384)
    report_remediation_medium:       Optional[str] = Field(default=None, max_length=16384)
    report_remediation_long:         Optional[str] = Field(default=None, max_length=16384)

class MitreTechniqueCount(BaseModel):
    technique_id:   str
    technique_name: str
    count:          int
    origins:        dict[str, int]

class MitreTacticSummary(BaseModel):
    tactic_id:   str
    tactic_name: str
    total:       int
    techniques:  list[MitreTechniqueCount]

class MitreSummaryOut(BaseModel):
    total_events:  int
    mapped_events: int
    tactics:       list[MitreTacticSummary]


# ─── Forensic artifact parse (stateless — not persisted) ─────────────────────
# Parsed events are returned in the response body; the frontend holds them in
# React state. The analyst promotes selected events to the timeline / IOCs via
# the existing CRUD endpoints. Nothing is stored by the parse endpoint itself.

class ParsedEventOut(BaseModel):
    idx:                  int           # 0-based index within this parse response
    event_time:           Optional[str] = None   # ISO 8601 UTC; None = parse failed
    hostname:             Optional[str] = None
    source:               Optional[str] = None
    event_type:           Optional[str] = None
    description:          str
    raw_log:              Optional[str] = None
    mitre_tactic_id:      Optional[str] = None
    mitre_tactic_name:    Optional[str] = None
    mitre_technique_id:   Optional[str] = None
    mitre_technique_name: Optional[str] = None
    suspicious:           bool = False
    suspicious_reasons:   list[str] = Field(default_factory=list)


class ForensicParseResponse(BaseModel):
    source_file:    str
    detected_format: str   # evtx | xml | sqlite | csv | json
    count:          int    # total events returned (capped at MAX_EVENTS)
    suspicious_count: int
    events:         list[ParsedEventOut]


# ── Persisted forensic imports ───────────────────────────────────────────
# Same payload as ForensicParseResponse, plus row metadata for re-load.

class ForensicImportSummary(BaseModel):
    id:              UUID
    filename:        str
    file_size:       int
    mime_type:       Optional[str] = None
    sha256_hash:     Optional[str] = None
    detected_format: Optional[str] = None
    event_count:     int
    suspicious_count: int
    uploaded_by:     Optional[str] = None
    uploaded_at:     datetime
    class Config: from_attributes = True


class ForensicImportList(BaseModel):
    items: list[ForensicImportSummary]


class ForensicImportDetail(ForensicImportSummary):
    events: list[ParsedEventOut]


# ─── OSINT enrichment ────────────────────────────────────────────────────────

class OsintSourceOut(BaseModel):
    id:              str
    label:           str
    description:     str
    available:       bool        # key configured, or no key required
    public:          bool        # OPSEC: queries visible to third parties
    supported_types: list[str]


class OsintSourcesResponse(BaseModel):
    sources: list[OsintSourceOut]


class EnrichRequest(BaseModel):
    indicator: str       = Field(min_length=1, max_length=512)
    ioc_type:  str       = Field(min_length=1, max_length=64)
    sources:   list[str] = Field(min_length=1, max_length=10)


class EnrichResultItem(BaseModel):
    source:     str
    available:  bool
    from_cache: bool
    data:       Optional[dict] = None
    error:      Optional[str]  = None


class EnrichResponse(BaseModel):
    indicator: str
    ioc_type:  str
    results:   list[EnrichResultItem]


# ─── OSINT sessions (per-incident persistence) ───────────────────────────────

class OSINTSessionCreate(BaseModel):
    raw_text:   Optional[str]   = None
    indicators: list[dict]      = Field(default_factory=list)


class OSINTSessionUpdate(BaseModel):
    raw_text:   Optional[str]        = None
    indicators: Optional[list[dict]] = None
    results:    Optional[dict]       = None


class OSINTSessionOut(BaseModel):
    id:           UUID
    incident_id:  UUID
    raw_text:     Optional[str] = None
    indicators:   list[dict]
    results:      dict
    created_by:   Optional[str] = None
    created_at:   datetime
    updated_at:   datetime

    class Config:
        from_attributes = True


class OSINTSessionList(BaseModel):
    sessions: list[OSINTSessionOut]


# ─── YARA ─────────────────────────────────────────────────────────────────────

class YaraRuleOut(BaseModel):
    id:              UUID
    name:            str
    description:     Optional[str] = None
    author:          Optional[str] = None
    tags:            list[str] = []
    rule_content:    str
    is_active:       bool
    match_count:     int
    last_matched_at: Optional[datetime] = None
    created_by_id:   Optional[UUID] = None
    created_at:      datetime
    class Config: from_attributes = True

class YaraRuleCreate(BaseModel):
    name:         str            = Field(min_length=1, max_length=256)
    description:  Optional[str] = Field(default=None, max_length=512)
    author:       Optional[str] = Field(default=None, max_length=128)
    tags:         list[str]     = []
    rule_content: str           = Field(min_length=1)

class YaraRuleUpdate(BaseModel):
    name:      Optional[str]  = Field(default=None, min_length=1, max_length=256)
    is_active: Optional[bool] = None

class YaraRuleList(BaseModel):
    items: list[YaraRuleOut]

class YaraMatchOut(BaseModel):
    id:              UUID
    rule_id:         Optional[UUID] = None
    rule_name:       str
    incident_id:     UUID
    artifact_id:     Optional[UUID] = None
    artifact_name:   Optional[str]  = None
    matched_strings: list[dict]     = []
    created_at:      datetime
    class Config: from_attributes = True

class YaraMatchList(BaseModel):
    items: list[YaraMatchOut]

class YaraScanResult(BaseModel):
    artifacts_scanned: int
    matches_found:     int
    errors:            list[str] = []


# ─── Detection queries (SIEM/XDR) ────────────────────────────────────────────

class DetectionQuery(BaseModel):
    label:      str
    query:      str
    confidence: str   # HIGH | MEDIUM | LOW
    category:   str   # Indicator | Behavioral | Hunt

class DetectionPlatform(BaseModel):
    platform: str
    label:    str
    queries:  list[DetectionQuery]

class DetectionBundle(BaseModel):
    incident_id: UUID
    platforms:   list[DetectionPlatform]
    total:       int


# ─── Audit log (per-incident view) ──────────────────────────────────────────

class AuditLogEntryOut(BaseModel):
    id:             UUID
    timestamp:      datetime
    user_id:        Optional[UUID] = None
    username:       Optional[str]  = None
    role_at_time:   Optional[str]  = None
    action:         str
    outcome:        Optional[str]  = None
    resource_type:  Optional[str]  = None
    resource_id:    Optional[str]  = None
    resource_label: Optional[str]  = None
    details:        dict = Field(default_factory=dict)
    ip_address:     Optional[str]  = None
    request_method: Optional[str]  = None
    request_path:   Optional[str]  = None
    request_id:     Optional[str]  = None
    row_hash:       str
    prev_hash:      str

    class Config:
        from_attributes = True


class AuditLogList(BaseModel):
    items:       list[AuditLogEntryOut]
    next_cursor: Optional[str] = None


# ─── Platform settings — API keys ────────────────────────────────────────────

ENRICHMENT_SERVICES = ["virustotal", "abuseipdb", "shodan", "greynoise", "urlscan"]


class ApiKeyServiceOut(BaseModel):
    service:    str
    label:      str
    configured: bool        # True if key available from DB or env fallback
    source:     Optional[str] = None   # "db" | "env" | None


class ApiKeySet(BaseModel):
    value: str = Field(min_length=1, max_length=512)


class ApiKeysResponse(BaseModel):
    services: list[ApiKeyServiceOut]


# ─── IOC batch enrichment ────────────────────────────────────────────────────

class IocEnrichAllRequest(BaseModel):
    sources: Optional[list[str]] = None  # None = all available


class IocEnrichAllResponse(BaseModel):
    ioc_count:     int
    enriched_count: int
    results:       dict[str, list[EnrichResultItem]]  # ioc_id → results


LoginResponse.model_rebuild()


# ─── Threat Intel Feeds ──────────────────────────────────────────────────────

class ThreatFeedCreate(BaseModel):
    name:                str     = Field(min_length=1, max_length=128)
    url:                 str     = Field(min_length=8, max_length=512)
    feed_type:           Literal["csv", "json", "txt"]
    ioc_type:            IocType
    pull_interval_hours: int     = Field(default=24, ge=1, le=168)
    parser_config:       dict    = Field(default_factory=dict)


class ThreatFeedUpdate(BaseModel):
    enabled:             Optional[bool] = None
    pull_interval_hours: Optional[int]  = Field(default=None, ge=1, le=168)
    parser_config:       Optional[dict] = None


class ThreatFeedOut(BaseModel):
    id:                  UUID
    name:                str
    url:                 str
    feed_type:           str
    ioc_type:            str
    enabled:             bool
    pull_interval_hours: int
    last_pulled_at:      Optional[datetime] = None
    last_ioc_count:      int
    total_iocs_ingested: int
    created_at:          datetime

    class Config:
        from_attributes = True


class ThreatIntelIOCOut(BaseModel):
    id:           UUID
    feed_name:    str
    type:         str
    value:        str
    tags:         list
    first_seen_at: datetime
    last_seen_at:  datetime

    class Config:
        from_attributes = True


class ThreatIntelIOCList(BaseModel):
    items:       list[ThreatIntelIOCOut]
    total:       int
    next_cursor: Optional[str] = None


class TiScanResult(BaseModel):
    scanned:  int
    hits:     int
    matches:  list[dict]   # [{ioc_id, type, value, feed_name}]


# ─── Incident assignments ────────────────────────────────────────────────────

class IncidentAssignmentOut(BaseModel):
    id:                   UUID
    incident_id:          UUID
    user_id:              Optional[UUID]  = None
    username:             str
    role_id:              Optional[UUID]  = None
    role_label:           str
    notes:                Optional[str]   = None
    assigned_by_id:       Optional[UUID]  = None
    assigned_by_username: Optional[str]   = None
    assigned_at:          datetime

    class Config:
        from_attributes = True


class IncidentAssignmentCreate(BaseModel):
    user_id:   UUID
    role_id:   UUID
    notes:     Optional[str] = Field(default=None, max_length=1024)


class IncidentAssignmentList(BaseModel):
    items: list[IncidentAssignmentOut]


# ─── Threat actors ───────────────────────────────────────────────────────────

class ThreatActorOut(BaseModel):
    id:                    UUID
    name:                  str
    aliases:               list[str]
    description:           Optional[str]   = None
    country_of_origin:     Optional[str]   = None
    motivation:            str
    associated_techniques: list[str]
    typical_targets:       list[str]
    is_system:             bool
    created_at:            datetime
    mitre_id:              Optional[str]      = None
    mitre_url:             Optional[str]      = None
    software:              list[dict]         = Field(default_factory=list)
    last_synced_at:        Optional[datetime] = None

    class Config:
        from_attributes = True


class ThreatActorCreate(BaseModel):
    name:                  str              = Field(min_length=1, max_length=128)
    aliases:               list[str]        = Field(default_factory=list)
    description:           Optional[str]    = None
    country_of_origin:     Optional[str]    = Field(default=None, max_length=64)
    motivation:            Literal["financial", "espionage", "hacktivist",
                                   "destructive", "ransomware", "unknown"] = "unknown"
    associated_techniques: list[str]        = Field(default_factory=list)
    typical_targets:       list[str]        = Field(default_factory=list)


class ThreatActorUpdate(BaseModel):
    name:                  Optional[str]    = Field(default=None, min_length=1, max_length=128)
    aliases:               Optional[list[str]] = None
    description:           Optional[str]    = None
    country_of_origin:     Optional[str]    = Field(default=None, max_length=64)
    motivation:            Optional[Literal["financial", "espionage", "hacktivist",
                                            "destructive", "ransomware", "unknown"]] = None
    associated_techniques: Optional[list[str]] = None
    typical_targets:       Optional[list[str]] = None


class ThreatActorList(BaseModel):
    items: list[ThreatActorOut]


class ActorIncidentLink(BaseModel):
    """One row of the per-actor incident cross-reference. Filtered server-side
    by the caller's incident access scope."""
    attribution_id:  UUID
    incident_id:     UUID
    incident_ref:    Optional[str]    = None
    incident_title:  str
    incident_status: str
    severity:        str
    confidence:      str
    score:           Optional[int]    = None
    attributed_at:   datetime
    attributed_by:   Optional[str]    = None


class ActorIncidentLinkList(BaseModel):
    items: list[ActorIncidentLink]


# ─── Incident attributions ────────────────────────────────────────────────────

class IncidentAttributionOut(BaseModel):
    id:                      UUID
    incident_id:             UUID
    threat_actor_id:         Optional[UUID]  = None
    actor_label:             Optional[str]   = None
    confidence:              str
    score:                   Optional[int]   = None
    evidence:                list[dict]      = Field(default_factory=list)
    analyst_notes:           Optional[str]   = None
    supporting_ioc_ids:      list[str]
    supporting_timeline_ids: list[str]
    created_by_id:           Optional[UUID]  = None
    created_by_username:     Optional[str]   = None
    created_at:              datetime
    updated_at:              datetime

    class Config:
        from_attributes = True


class IncidentAttributionCreate(BaseModel):
    threat_actor_id:         Optional[UUID]  = None
    actor_label:             Optional[str]   = Field(default=None, max_length=128)
    confidence:              Literal["possible", "probable", "confirmed"] = "possible"
    score:                   Optional[int]   = Field(default=None, ge=0, le=100)
    evidence:                list[dict]      = Field(default_factory=list)
    analyst_notes:           Optional[str]   = None
    supporting_ioc_ids:      list[str]       = Field(default_factory=list)
    supporting_timeline_ids: list[str]       = Field(default_factory=list)


class IncidentAttributionUpdate(BaseModel):
    confidence:              Optional[Literal["possible", "probable", "confirmed"]] = None
    analyst_notes:           Optional[str]   = None
    supporting_ioc_ids:      Optional[list[str]] = None
    supporting_timeline_ids: Optional[list[str]] = None


class IncidentAttributionList(BaseModel):
    items: list[IncidentAttributionOut]


class AttributionSuggestion(BaseModel):
    actor:              ThreatActorOut
    score:              int                  # 0–100 from threat_actors.scoring
    confidence:         str                  # possible | probable | confirmed
    evidence:           list[dict]           # per-signal breakdown
    matched_techniques: list[str]            # convenience subset for the table


class AttributionSuggestList(BaseModel):
    incident_technique_count: int
    incident_ioc_count:       int
    cache_warming:            bool = False   # true on first call before MITRE sync completes
    suggestions:              list[AttributionSuggestion]


# ─── On-call schedule ───────────────────────────────────────────────────────

from datetime import date as DateType  # noqa: E402  (local import to avoid top-level Date clash)


class OnCallEntryOut(BaseModel):
    id:                  UUID
    user_id:             Optional[UUID]
    username:            str
    display_name:        Optional[str] = None
    start_date:          DateType
    end_date:            DateType
    notes:               Optional[str] = None
    created_by_username: Optional[str] = None
    created_at:          datetime

    class Config:
        from_attributes = True


class OnCallEntryCreate(BaseModel):
    user_id:    UUID
    start_date: DateType
    end_date:   DateType
    notes:      Optional[str] = None


class OnCallEntryUpdate(BaseModel):
    user_id:    Optional[UUID]     = None
    start_date: Optional[DateType] = None
    end_date:   Optional[DateType] = None
    notes:      Optional[str]      = None


class OnCallEntryList(BaseModel):
    items:   list[OnCallEntryOut]
    current: Optional[OnCallEntryOut] = None   # who is on-call right now (may overlap with items)


# ─── Incident handoffs ──────────────────────────────────────────────────────

class IncidentHandoffOut(BaseModel):
    id:                UUID
    incident_id:       UUID
    outgoing_user_id:  Optional[UUID]
    outgoing_username: str
    incoming_user_id:  Optional[UUID]
    incoming_username: str
    note:                   Optional[str] = None
    status:                 str            # pending | acknowledged
    current_hypothesis:     Optional[str] = None
    hypothesis_confidence:  int = 50
    key_findings:           Optional[str] = None
    warnings:               Optional[str] = None
    threads:                list = Field(default_factory=list)
    ruled_out:              list = Field(default_factory=list)
    pending:                list = Field(default_factory=list)
    next_steps:             list = Field(default_factory=list)
    open_questions:         list = Field(default_factory=list)
    snapshot_data:          dict = Field(default_factory=dict)
    created_at:             datetime
    acknowledged_at:        Optional[datetime] = None
    acknowledged_note:      Optional[str]      = None

    class Config:
        from_attributes = True


class IncidentHandoffCreate(BaseModel):
    incoming_user_id:       UUID
    note:                   Optional[str] = None
    current_hypothesis:     Optional[str] = None
    hypothesis_confidence:  int = Field(default=50, ge=0, le=100)
    key_findings:           Optional[str] = None
    warnings:               Optional[str] = None
    threads:                list = Field(default_factory=list)
    ruled_out:              list = Field(default_factory=list)
    pending:                list = Field(default_factory=list)
    next_steps:             list = Field(default_factory=list)
    open_questions:         list = Field(default_factory=list)


class IncidentHandoffAcknowledge(BaseModel):
    acknowledged_note: Optional[str] = None


class IncidentHandoffList(BaseModel):
    items: list[IncidentHandoffOut]


# ─── Affected systems ─────────────────────────────────────────────────────────

class AffectedSystemOut(BaseModel):
    id:                  UUID
    incident_id:         UUID
    name:                str
    system_type:         Optional[SystemType] = None
    notes:               Optional[str] = None
    created_at:          datetime
    created_by_username: Optional[str] = None

    class Config:
        from_attributes = True


class AffectedSystemCreate(BaseModel):
    name:        str = Field(min_length=1, max_length=255)
    system_type: Optional[SystemType] = None
    notes:       Optional[str] = None


class AffectedSystemUpdate(BaseModel):
    name:        Optional[str] = Field(default=None, min_length=1, max_length=255)
    system_type: Optional[SystemType] = None
    notes:       Optional[str] = None


class AffectedSystemList(BaseModel):
    items: list[AffectedSystemOut]


# ─── IR Roster ────────────────────────────────────────────────────────────────

class ResponderProfileUpdate(BaseModel):
    skills:       Optional[list[str]] = None
    availability: Optional[Literal["available", "on_call", "unavailable", "out_of_office"]] = None
    notes:        Optional[str] = None


class RosterEntry(BaseModel):
    user_id:              UUID
    username:             str
    full_name:            Optional[str] = None
    role:                 str
    skills:               list[str] = []
    availability:         str = "available"
    notes:                Optional[str] = None
    active_incident_count: int = 0

    class Config:
        from_attributes = True


class RosterList(BaseModel):
    items: list[RosterEntry]


class CoverageAssignment(BaseModel):
    assignment_id: UUID
    user_id:       Optional[UUID] = None
    username:      str


class CoverageSlot(BaseModel):
    role_id:    UUID
    role_key:   str
    role_label: str
    sort_order: int
    assignments: list[CoverageAssignment] = []


class CoverageList(BaseModel):
    slots: list[CoverageSlot]


# ─── API tokens (Bearer auth) ───────────────────────────────────────────────

class ApiTokenCreate(BaseModel):
    name:        str = Field(min_length=1, max_length=128)
    role:        Literal["admin", "analyst", "viewer"] = "analyst"
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=3650)


class ApiTokenOut(BaseModel):
    id:           UUID
    name:         str
    token_prefix: str
    role:         str
    created_at:   datetime
    last_used_at: Optional[datetime] = None
    expires_at:   Optional[datetime] = None
    revoked_at:   Optional[datetime] = None
    revoke_reason: Optional[str] = None

    class Config:
        from_attributes = True


class ApiTokenIssued(ApiTokenOut):
    """Returned exactly once at issue. Includes the plain token."""
    token: str


class ApiTokenList(BaseModel):
    items: list[ApiTokenOut]


class AdminApiTokenOut(ApiTokenOut):
    user_id:      UUID
    username:     Optional[str] = None


class AdminApiTokenList(BaseModel):
    items: list[AdminApiTokenOut]


# ─── LE package (court-ready handoff bundle) ────────────────────────────────

LegalBasis = Literal["warrant", "subpoena", "court_order", "eio", "mla", "voluntary", "other"]
DeliveryChannel = Literal["download_url", "sealed_usb", "encrypted_email", "courier", "other"]


class LePackagePrepare(BaseModel):
    case_reference:       str = Field(min_length=1, max_length=128)
    requesting_authority: str = Field(min_length=1, max_length=256)
    legal_basis:          LegalBasis
    retention_until:      Optional[datetime] = None
    legal_hold_only:      bool = False
    include_artifacts:    bool = False
    # The recipient label written into the underlying CustodyExport row (mirrors
    # evidence/exports). If empty, we default to requesting_authority.
    recipient:            Optional[str] = Field(default=None, max_length=256)

    # Wizard C — cross-border + recipient + delivery + signature fields.
    # All optional so the legacy 6-field prepare keeps working.
    eio_reference:           Optional[str] = Field(default=None, max_length=128)
    issuing_state:           Optional[str] = Field(default=None, max_length=64)
    executing_state:         Optional[str] = Field(default=None, max_length=64)
    mla_reference:           Optional[str] = Field(default=None, max_length=128)
    recipient_name:          Optional[str] = Field(default=None, max_length=256)
    recipient_role:          Optional[str] = Field(default=None, max_length=128)
    recipient_id_ref:        Optional[str] = Field(default=None, max_length=128)
    recipient_organisation:  Optional[str] = Field(default=None, max_length=256)
    recipient_address:       Optional[str] = Field(default=None, max_length=4096)
    delivery_channel:        Optional[DeliveryChannel] = None
    delivery_notes:          Optional[str] = Field(default=None, max_length=4096)
    sender_declaration:      Optional[str] = Field(default=None, max_length=4096)
    # When True, the server mints an acknowledgment_token + URL so the recipient
    # can close the loop. The URL is returned on the prepared response.
    enable_acknowledgment:   bool = False


class LePackageOut(BaseModel):
    id:                    UUID
    incident_id:           UUID
    case_reference:        str
    requesting_authority:  str
    legal_basis:           str
    retention_until:       Optional[datetime] = None
    legal_hold_only:       bool
    include_artifacts:     bool
    prepared_by_id:        Optional[UUID] = None
    prepared_at:           datetime
    bundle_sha256:         Optional[str] = None
    manifest_sha256:       Optional[str] = None
    hmac_sha256:           Optional[str] = None
    file_count:            Optional[int] = None
    total_bytes:           Optional[int] = None
    evidence_count:        Optional[int] = None
    audit_row_count:       Optional[int] = None
    # Tamper-evident anchor written AFTER bundle build. Surfaced here so the
    # operator can pass it to the recipient out-of-band alongside the bundle KEK.
    audit_anchor_row_id:   Optional[UUID] = None
    audit_anchor_row_hash: Optional[str]  = None

    # Surface the underlying CustodyExport lifecycle so the UI can render status.
    custody_export_id:     UUID
    status:                Optional[str] = None         # ready | consumed | revoked | expired
    expires_at:            Optional[datetime] = None
    consumed_at:           Optional[datetime] = None
    key_hint:              Optional[str] = None

    # Wizard C surface
    eio_reference:           Optional[str] = None
    issuing_state:           Optional[str] = None
    executing_state:         Optional[str] = None
    mla_reference:           Optional[str] = None
    recipient_name:          Optional[str] = None
    recipient_role:          Optional[str] = None
    recipient_id_ref:        Optional[str] = None
    recipient_organisation:  Optional[str] = None
    recipient_address:       Optional[str] = None
    delivery_channel:        Optional[str] = None
    delivery_notes:          Optional[str] = None
    sender_declaration:      Optional[str] = None
    signature_kind:          Optional[str] = None
    acknowledged_at:         Optional[datetime] = None
    acknowledged_by_name:    Optional[str] = None

    class Config:
        from_attributes = True


class LePackagePrepared(LePackageOut):
    """Returned once at generation. Includes the plaintext bundle password
    (for the AES-256 ZIP) + download URL. The password is the only copy —
    not persisted server-side."""
    bundle_password:    str
    download_url:       str
    # When enable_acknowledgment was True, the recipient-facing ack URL.
    acknowledgment_url: Optional[str] = None


# Acknowledgment loop — recipient hits the URL emitted on creation.
class LePackageAckRequest(BaseModel):
    name:   str  = Field(min_length=1, max_length=256)
    notes:  Optional[str] = Field(default=None, max_length=4096)


# Sender-mediated ("manual") acknowledgment — for external recipients who
# cannot reach the URL-based ack page (offline LE agencies, paper-only
# handoffs). The platform admin attests receipt on the recipient's behalf
# and the audit row records `details.method = "manual:..."` to distinguish.
LePackageAckMethod = Literal[
    "paper", "email", "phone", "in_person", "secure_portal", "other",
]


class LePackageManualAckRequest(BaseModel):
    recipient_name:    str = Field(min_length=1, max_length=256)
    recipient_title:   Optional[str] = Field(default=None, max_length=256)
    recipient_agency:  Optional[str] = Field(default=None, max_length=256)
    received_at:       datetime
    method:            LePackageAckMethod
    attestation_text:  str = Field(min_length=10, max_length=4096)
    # Optional pointer to the scanned signed receipt uploaded as Evidence
    # for this incident — inherits the Evidence module's AES-256 at-rest
    # encryption + chain-of-custody log automatically.
    evidence_id:       Optional[UUID] = None


class LePackageAckResponse(BaseModel):
    case_reference:       str
    requesting_authority: str
    acknowledged_at:      datetime
    acknowledged_by_name: str


class LePackageList(BaseModel):
    items: list[LePackageOut]


# ─── Audit-log export (signed PDF + JSONL + Ed25519 sig) ─────────────────────

AuditExportOutcome = Literal["success", "failure", "denied"]


class AuditExportFilters(BaseModel):
    """Caller-supplied filter snapshot. All fields optional; empty = no slice limit."""
    date_from:     Optional[datetime] = None
    date_to:       Optional[datetime] = None
    action:        Optional[str]      = Field(default=None, max_length=128, description="substring match")
    username:      Optional[str]      = Field(default=None, max_length=64,  description="exact match")
    resource_type: Optional[str]      = Field(default=None, max_length=64)
    outcome:       Optional[AuditExportOutcome] = None


class AuditExportPrepare(BaseModel):
    purpose: Optional[str] = Field(default=None, max_length=2048)
    filters: AuditExportFilters = Field(default_factory=AuditExportFilters)


class AuditExportOut(BaseModel):
    id:              UUID
    incident_id:     Optional[UUID] = None
    exported_by_id:  Optional[UUID] = None
    filters:         dict
    purpose:         Optional[str] = None

    # Chain anchors recorded at export time.
    first_prev_hash: Optional[str] = None
    last_row_hash:   Optional[str] = None
    chain_head_hash: Optional[str] = None
    row_count:       int = 0

    # Signature material.
    jsonl_sha256:    Optional[str] = None
    pubkey_fpr:      Optional[str] = None

    # Bundle metadata.
    file_size:       Optional[int] = None
    bundle_sha256:   Optional[str] = None
    key_hint:        Optional[str] = None

    status:          str
    created_at:      datetime
    expires_at:      datetime
    consumed_at:     Optional[datetime] = None
    retention_until: datetime

    class Config:
        from_attributes = True


class AuditExportPrepared(AuditExportOut):
    """Returned once at generation. Includes the plaintext bundle password +
    download URL. The password is the only copy — not persisted server-side."""
    bundle_password: str
    download_url:    str


class AuditExportList(BaseModel):
    items: list[AuditExportOut]


# ─── Stakeholder Matrix (global notification rules) ──────────────────────────

StakeholderMatrixSeverity = Literal["low", "medium", "high", "critical"]
StakeholderMatrixCategory = Literal[
    "operational", "regulatory", "legal", "executive",
    "media", "technical", "other",
]


class StakeholderMatrixRuleOut(BaseModel):
    id:                    UUID
    severity:              str
    role:                  str
    notify_within_minutes: int
    category:              str
    required:              bool
    created_at:            datetime
    updated_at:            datetime
    class Config:
        from_attributes = True


class StakeholderMatrixRuleCreate(BaseModel):
    severity:              StakeholderMatrixSeverity
    role:                  str = Field(min_length=1, max_length=128)
    notify_within_minutes: int = Field(ge=1, le=10080)   # ≤ 1 week
    category:              StakeholderMatrixCategory = "operational"
    required:              bool = False


class StakeholderMatrixRuleUpdate(BaseModel):
    severity:              Optional[StakeholderMatrixSeverity] = None
    role:                  Optional[str] = Field(default=None, min_length=1, max_length=128)
    notify_within_minutes: Optional[int] = Field(default=None, ge=1, le=10080)
    category:              Optional[StakeholderMatrixCategory] = None
    required:              Optional[bool] = None


class StakeholderMatrixRuleList(BaseModel):
    items: list[StakeholderMatrixRuleOut]
