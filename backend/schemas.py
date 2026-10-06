"""All Pydantic request/response schemas."""
from datetime import datetime, timezone
from typing import Annotated, Literal, Optional, Union
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, computed_field, field_validator, model_validator

from core.config import settings
from core.outbound_policy import outbound_block_reasons


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

NCISS_BY_SEVERITY = {"critical": "emergency", "high": "severe", "medium": "medium", "low": "low"}


def nciss_severity(severity: Optional[str]) -> Optional[str]:
    """NCISS value for an internal severity (the fixed mapping above); None for anything else."""
    return NCISS_BY_SEVERITY.get((severity or "").lower())


Severity        = Literal["low", "medium", "high", "critical"]
Phase           = Literal["preparation", "detection_and_analysis",                     # 800-61 R3
                          "containment_eradication_recovery", "post_incident"]
# Phases an incident can be created in: it exists because something was detected.
StartPhase      = Literal["detection_and_analysis", "containment_eradication_recovery"]
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


# I4: NIST SP 800-61 impact categories (Rev. 2 §3.2.6, carried by Rev. 3 practice), all optional.
FunctionalImpact  = Literal["none", "low", "medium", "high"]
InformationImpact = Literal["none", "privacy", "proprietary", "integrity"]
Recoverability    = Literal["regular", "supplemented", "extended", "not_recoverable"]
DetectedAtSource  = Literal["reported", "alert", "received"]
# I4: the fields POST /api/incidents requires (owner decision 2026-10-06).
INCIDENT_CREATE_REQUIRED = ("title", "severity", "incident_type", "detection_method", "detected_at")
_IMPACT_DOC = ("NIST SP 800-61 impact category. functional_impact: none|low|medium|high; information_impact: "
               "none|privacy (personal data)|proprietary|integrity; recoverability: regular|supplemented|extended|"
               "not_recoverable.")


class IncidentCreate(BaseModel):
    """New incident. Required (owner decision 2026-10-06): title, severity, incident_type, detection_method,
    detected_at; any of them missing or null is one 422 code required_fields_missing whose `fields` lists them
    all. Everything else is optional."""
    title:            Optional[str] = Field(default=None, min_length=3, max_length=200, description="Required.")
    description:      Optional[str] = None
    severity:         Optional[Severity] = Field(default=None, description="Required.")
    phase:            StartPhase = Field(default="detection_and_analysis",
                                         description="Starting phase: detection_and_analysis or containment_eradication_recovery only.")
    tlp:              Tlp      = "amber"
    triage_state:     TriageState = "suspected"
    triage_reason:    Optional[str] = Field(default=None, max_length=2000,
                                            description="Why the incident starts as this triage state. Required (at least 10 "
                                                        "characters; 422 triage_reason_required otherwise) to create a "
                                                        "false_positive or benign_positive outside detection_and_analysis, "
                                                        "since it can then be closed without Gate 2. When given, it is "
                                                        "audited and added to the Timeline.")
    incident_type:    Optional[IncidentType]    = Field(default=None, description="Required.")
    detection_method: Optional[DetectionMethod] = Field(default=None, description="Required.")
    reporter:         Optional[str] = Field(default=None, max_length=128)
    occurred_at:      Optional[datetime] = None
    detected_at:      Optional[datetime] = Field(default=None,
                                                 description="Required. When the incident was detected (UTC). Not before occurred_at, not in the future; never set by the server.")
    # I4 optional intake.
    ic_user_id:       Optional[UUID] = Field(default=None, description=(
        "Assign this user as Incident Commander in the same transaction. Unknown id 404 user_not_found; a "
        "deactivated user, or one who can't see the incident (its team_ids), 422 assignee_no_access."))
    functional_impact:  Optional[FunctionalImpact]  = Field(default=None, description=_IMPACT_DOC)
    information_impact: Optional[InformationImpact] = Field(default=None, description=_IMPACT_DOC)
    recoverability:     Optional[Recoverability]    = Field(default=None, description=_IMPACT_DOC)
    severity_rationale: Optional[str] = Field(default=None, max_length=2000, description="Why this severity.")
    alert_reference:    Optional[str] = Field(default=None, max_length=256,
                                          description="The alert this came from: source system and alert id, e.g. 'Sentinel 4f2a91'.")
    first_host:       Optional[str] = Field(default=None, min_length=1, max_length=255, description=(
        "First affected host: added to Entities as a compromised host (in scope)."))
    first_ioc:        Optional["IntakeIoc"] = Field(default=None, description="First indicator of compromise: added to IOCs (source 'intake').")
    team_ids:         list[UUID] = Field(default_factory=list,
                                         description="Restrict the new incident to these teams ([] = visible to everyone). "
                                                     "An admin may pick any team; an analyst only teams they belong to (409 "
                                                     "would_lock_out). An unknown team is 422 team_not_found.")
    tags:             list[str]  = Field(default_factory=list)
    dark_operation:   bool       = Field(default=False, description=(
        "Open dark: no Teams/Slack/email alert from the start. Sent explicitly (true or false), it records the "
        "Dark Operation decision (dark_operation_decided_at, audited with the creation); omitted, no decision "
        "is recorded."))

    class Config:
        json_schema_extra = {"required": list(INCIDENT_CREATE_REQUIRED)}


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
    detected_at:      Optional[datetime]         = Field(default=None, description=(
        "Sets detected_at_source to reported (null clears both)."))
    functional_impact:  Optional[FunctionalImpact]  = Field(default=None, description=_IMPACT_DOC + " null clears.")
    information_impact: Optional[InformationImpact] = Field(default=None, description=_IMPACT_DOC + " null clears.")
    recoverability:     Optional[Recoverability]    = Field(default=None, description=_IMPACT_DOC + " null clears.")
    severity_rationale: Optional[str]               = Field(default=None, max_length=2000, description="null or blank clears.")
    alert_reference:    Optional[str]               = Field(default=None, max_length=256, description="null or blank clears.")
    contained_at:     Optional[datetime]         = Field(default=None,
                                                         description="When the incident was contained (UTC). Declared, never set by the server. Not in the future.")
    eradicated_at:    Optional[datetime]         = Field(default=None,
                                                         description="When eradication was complete (UTC). Not in the future, not before contained_at.")
    recovered_at:     Optional[datetime]         = Field(default=None,
                                                         description="When normal operations were restored (UTC). Not in the future, not before contained_at or eradicated_at.")
    team_ids:         Optional[list[UUID]]       = Field(default=None,
                                                         description="Replace the incident's teams (omit = no change; [] = no teams, "
                                                                     "visible to everyone). Incident lead only: an admin, or an analyst "
                                                                     "assigned as Incident Commander or Deputy (403 not_incident_lead). "
                                                                     "Only an admin can clear the list of a restricted incident (409 "
                                                                     "would_unrestrict). An unknown team is 422 team_not_found.")
    tags:             Optional[list[str]]        = None  # None = no change; [] = clear
    # Phase-change controls (B5 phase gates); they apply only when `phase` changes.
    phase_reason:     Optional[str]              = Field(default=None, max_length=2000,
                                                         description="Why the phase changes, at least 10 characters after trimming. "
                                                                     "Required to move backwards (to an earlier phase) and with "
                                                                     "override_gate; missing or shorter is 422 code phase_reason_required. "
                                                                     "Audited with the change.")
    override_gate:    bool                       = Field(default=False,
                                                         description="Proceed into post_incident although Gate 1 is unmet "
                                                                     "(409 gate_unmet otherwise). Needs phase_reason; writes an "
                                                                     "incident_gate_override audit row and a system timeline event. "
                                                                     "A reason without this flag never overrides. Incident lead only "
                                                                     "(admin, or an analyst assigned as Incident Commander or Deputy): "
                                                                     "with a phase change, true from anyone else is 403 not_incident_lead.")
    triage_reason:    Optional[str]              = Field(default=None, max_length=2000,
                                                         description="Why triage_state changes, at least 10 characters after trimming. "
                                                                     "Required when triage_state becomes false_positive or benign_positive "
                                                                     "and the incident is (or, with phase in the same request, ends up) "
                                                                     "outside detection_and_analysis, and when a phase change moves a false "
                                                                     "or benign positive out of detection_and_analysis, because such an "
                                                                     "incident can then be closed without Gate 2; missing or shorter is 422 "
                                                                     "code triage_reason_required. When given with a triage change it is "
                                                                     "audited and posted as a system timeline event (\"Triage changed\"); "
                                                                     "with such a phase change, as \"Triage set\".")
    dark_operation:   Optional[bool]             = Field(default=None,
                                                         description="Not settable here: sending it (any value) is 422 code "
                                                                     "use_dark_operation_endpoint. Toggle Dark Operation with "
                                                                     "PATCH /api/incidents/{id}/oob/dark-operation {\"enabled\": bool}, "
                                                                     "which audits the change.")


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
    closed_by_id:     Optional[UUID] = None
    occurred_at:      Optional[datetime] = None
    detected_at:      Optional[datetime] = None
    detected_at_source: Optional[DetectedAtSource] = Field(default=None, description=(
        "Where detected_at came from: reported (entered by a person or API client), alert (the SIEM alert's own "
        "time) or received (the SIEM alert carried no usable time, so this is when FENRIR received it). Null for "
        "incidents recorded before this field existed."))
    contained_at:     Optional[datetime] = None
    eradicated_at:    Optional[datetime] = None
    recovered_at:     Optional[datetime] = None
    functional_impact:  Optional[FunctionalImpact]  = None
    information_impact: Optional[InformationImpact] = None
    recoverability:     Optional[Recoverability]    = None
    severity_rationale: Optional[str] = None
    alert_reference:    Optional[str] = None
    dark_operation_decided_at: Optional[datetime] = Field(default=None, description=(
        "When Dark Operation was last explicitly decided (on or off); null = never decided."))
    teams:            list[TeamRef] = []
    tags:             list[str]      = Field(default_factory=list)

    @computed_field(description="Why automatic outbound (Teams/Slack webhooks, alert email, automatic DNS "
                                "lookups) is suppressed for this incident; [] = it is not. Manual OSINT / "
                                "enrichment lookups then need confirm_outbound=true (H3).")
    @property
    def outbound_suppressed_by(self) -> list[Literal["dark_operation", "tlp_red"]]:
        return outbound_block_reasons(self)

    class Config:
        from_attributes = True


class IncidentList(BaseModel):
    items:       list[IncidentOut]
    next_cursor: Optional[str] = None


# Phases a closed incident can be re-opened into (never Preparation).
ReopenPhase = Literal["detection_and_analysis", "containment_eradication_recovery", "post_incident"]
_REASON_DOC = "at least 10 characters after trimming; missing or shorter is 422 code reason_required."


class IncidentClose(BaseModel):
    # reason is checked in the route, not here, so a missing one gets the flat
    # {detail, code} body; the schema still marks it required.
    reason: Optional[str] = Field(default=None, max_length=2000,
                                  description="Closing sign-off statement, " + _REASON_DOC)
    override_gate: bool = Field(default=False,
                                description="Close although Gate 2 is unmet (409 gate_unmet otherwise); the "
                                            "reason doubles as the override justification. Writes an "
                                            "incident_gate_override audit row and a system timeline event. "
                                            "Incident lead only (admin, or an analyst assigned as Incident "
                                            "Commander or Deputy): true from anyone else is 403 not_incident_lead.")

    class Config:
        json_schema_extra = {"required": ["reason"]}


class IncidentReopen(BaseModel):
    reason: Optional[str]         = Field(default=None, max_length=2000,
                                          description="Why the incident is re-opened, " + _REASON_DOC)
    phase:  Optional[ReopenPhase] = Field(default=None,
                                          description="Phase to re-open into: detection_and_analysis, "
                                                      "containment_eradication_recovery or post_incident; "
                                                      "missing is 422 code phase_required. Re-opening into "
                                                      "post_incident an incident closed in another phase runs "
                                                      "Gate 1 (409 gate_unmet when unmet).")
    override_gate: bool = Field(default=False,
                                description="Re-open into post_incident although Gate 1 is unmet; the reason "
                                            "doubles as the override justification. Writes an "
                                            "incident_gate_override audit row and a system timeline event. "
                                            "Incident lead only (admin, or an analyst assigned as Incident "
                                            "Commander or Deputy): true from anyone else is 403 not_incident_lead.")

    class Config:
        json_schema_extra = {"required": ["reason", "phase"]}


# ─── Phase gates (incidents/gates.py) ────────────────────────────────────────
# Gate 1 "post_incident": entering Post-Incident (NIST SP 800-61 R3 RS.MI / RC.RP).
# Gate 2 "close":         closing the incident (800-61 R3 ID.IM).
GateName = Literal["post_incident", "close"]


GateLevel = Literal["block", "warn"]
GateCheckStatus = Literal["met", "unmet"]
SignOffRole = Literal["ic", "dpo"]


class GateItem(BaseModel):
    """One gate check (in checks[], unmet[], warnings[]) or a carried-forward obligation (not a check)."""
    key:      str = Field(description="Stable machine-readable check key, e.g. recovered_at_missing.")
    label:    str = Field(description="The message: what is missing when unmet, what is satisfied when met.")
    level:    Optional[GateLevel] = Field(default=None, description=(
        "block: an unmet check stops the transition (409 gate_unmet) unless the incident lead overrides with a "
        "reason; warn: shown and recorded in the transition audit, never stops it. Null on carried_forward items."))
    status:   Optional[GateCheckStatus] = Field(default=None, description="met | unmet. Null on carried_forward items.")
    detail:   Optional[str] = Field(default=None, description="Specifics, e.g. the open actions' titles.")
    fix_hint: Optional[str] = Field(default=None, description="Where and how to fix it.")
    route:    Optional[str] = Field(default=None,
                                    description="Incident sub-page where it is fixed, relative to "
                                                "/incidents/{id}/ (e.g. respond, legal, post-incident).")
    due_at:   Optional[datetime] = Field(default=None, description="Deadline (UTC), for legal items.")


class GateSignOffCreate(BaseModel):
    role:      Optional[SignOffRole] = Field(default=None, description=(
        "ic: the Incident Commander's sign-off (the incident's IC / Deputy IC, or an admin); dpo: the Data "
        "Protection Officer's (an analyst assigned the data_protection_officer role on the incident, or an "
        "admin). Missing is 422 code role_required."))
    statement: Optional[str] = Field(default=None, max_length=2000, description=(
        "The sign-off statement, at least 10 characters after trimming (422 code statement_required)."))

    class Config:
        json_schema_extra = {"required": ["role", "statement"]}


class GateSignOffOut(BaseModel):
    """One recorded sign-off (append-only)."""
    id:           UUID
    gate:         GateName
    role:         SignOffRole
    user_id:      UUID
    username:     str
    signed_as:    str = Field(description="The basis: the operational role key(s) the signer held on the incident "
                                          "(incident_commander, deputy_commander, data_protection_officer), or admin.")
    signed_at:    datetime
    statement:    str
    state_sha256: str = Field(description="SHA-256 of the gate's blocking checks as the signer saw them "
                                          "(sign-off checks excluded).")
    current:      bool = Field(description="Made since the incident was last re-opened: only these count for the gate.")
    matches_current_state: bool = Field(description="state_sha256 equals the gate's state_sha256 now. False means "
                                                    "the blocking checks changed since the sign-off (informational).")


class GateResult(BaseModel):
    gate:            GateName
    label:           str
    met:             bool = Field(description="True when no block-level check is unmet (or the gate is exempt). "
                                              "Warn-level checks never affect it.")
    exempt:          bool = Field(default=False,
                                  description="The gate does not apply: close for a false or benign positive.")
    unmet:           list[GateItem] = Field(default_factory=list,
                                            description="The unmet block-level checks: what stops the transition.")
    warnings:        list[GateItem] = Field(default_factory=list,
                                            description="The unmet warn-level checks: shown, recorded, never blocking.")
    checks:          list[GateItem] = Field(default_factory=list,
                                            description="Every check that applies to this incident, met or unmet, "
                                                        "with its level, in display order.")
    carried_forward: list[GateItem] = Field(default_factory=list,
                                            description="Open obligations that do not block this gate.")
    sign_offs_required: list[SignOffRole] = Field(default_factory=list, description=(
        "Sign-offs this gate needs: close always ic; dpo on close for a personal-data breach, and on "
        "post_incident when a breach's GDPR / NIS2 obligation was waived as not required."))
    sign_offs:       list[GateSignOffOut] = Field(default_factory=list,
                                                  description="Sign-offs on this gate since the last re-open, newest first.")
    state_sha256:    Optional[str] = Field(default=None, description="SHA-256 of the blocking checks now "
                                                                     "(sign-off checks excluded): what a sign-off records.")
    open_preparation_tasks: Optional[int] = Field(default=None, description=(
        "Gate 2 (close) only: how many open or in-progress playbook tasks are in the 800-61 Preparation phase "
        "(organisation readiness work copied in by a template). They warn (preparation_tasks_open) and never "
        "block the close (I5)."))


class IncidentGates(BaseModel):
    """Both gates' status, evaluated now by the same code that enforces them."""
    incident_id: UUID
    items:       list[GateResult]


IncidentCapability = Literal["read_audit_log", "manage_le_package", "set_teams", "override_gate",
                             "remove_any_assignment", "assign_lead_roles", "remove_own_assignment",
                             "replace_playbook", "sign_off_ic", "sign_off_dpo"]


class IncidentAccess(BaseModel):
    """What the caller may do on one incident beyond their platform role (E3), evaluated now."""
    is_lead: bool = Field(description="True for an admin, or an analyst (effective role: an API token's "
                                      "role cap applies) assigned as Incident Commander or Deputy "
                                      "Incident Commander on this incident.")
    capabilities: list[IncidentCapability] = Field(
        description="read_audit_log, manage_le_package (build/list/acknowledge LE packages), set_teams, "
                    "override_gate, remove_any_assignment: the incident lead. assign_lead_roles (create or "
                    "remove IC / Deputy assignments): the lead, or, while no active analyst or admin holds "
                    "IC / Deputy, the incident's creator or today's on-call analyst. "
                    "remove_own_assignment: analysts and admins. sign_off_ic: the incident lead. sign_off_dpo: an "
                    "admin, or an analyst assigned the data_protection_officer role on the incident.")


class GateUnmetBody(BaseModel):
    """409 body when a gate blocks a phase change or close (flat, like every API error)."""
    detail: str
    code:   Literal["gate_unmet"]
    gate:   GateName
    unmet:  list[GateItem]
    warnings: list[GateItem] = Field(default_factory=list, description="Warn-level checks also unmet (not blocking).")


# ─── Recovery tracker (I1, R21) ─────────────────────────────────────────────
# One record per in-scope system: a compromised entity of type host, service or network_range.
# Rules (state machine, required fields, time checks) live in recovery/service.py.

RecoveryState = Literal["not_started", "restoring", "restored", "validated", "not_required"]


class RecoveryChecklistItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    item: str  = Field(min_length=1, max_length=200)
    done: bool = False


class RecoveryUpdate(BaseModel):
    """Change one system's recovery record. Every field is optional; send only what changes
    (`null` clears an optional field). `state` moves the state machine one step:
    not_started → restoring | not_required; restoring → restored; restored → validated.
    Going back (restoring → not_started, restored → restoring, validated → restoring,
    not_required → not_started) needs `reason` and clears the later sign-offs.
    restored needs a restore point (`restore_point_ref`); validated needs `validation_method`;
    not_required needs `not_required_reason`. `restored_at` / `validated_at` default to now and
    are recorded with the caller as restored_by / validated_by."""
    model_config = ConfigDict(extra="forbid")

    state:                Optional[RecoveryState] = None
    reason:               Optional[str] = Field(default=None, max_length=2000,
                                                description="Why the system goes back a step (required then); audited.")
    not_required_reason:  Optional[str] = Field(default=None, max_length=2000,
                                                description="Why this system needs no restore (required for not_required).")
    restore_point_ref:    Optional[str] = Field(default=None, max_length=512,
                                                description="Backup id, snapshot or image the system is restored from.")
    restore_point_at:     Optional[datetime] = Field(default=None, description="The point in time the restore returns to (UTC); not in the future, not after restored_at.")
    restored_at:          Optional[datetime] = Field(default=None, description="When the restore finished (UTC); with state=restored, or to correct it while restored/validated.")
    validation_method:    Optional[str] = Field(default=None, max_length=4000,
                                                description="How the system was checked clean (scans, EDR sweep, hash comparison …).")
    validation_checklist: Optional[list[RecoveryChecklistItem]] = Field(default=None, max_length=30)
    validated_at:         Optional[datetime] = Field(default=None, description="When validation finished (UTC); with state=validated, or to correct it while validated. Not before restored_at.")
    monitoring_start:     Optional[datetime] = Field(default=None, description="Start of the heightened-monitoring window (UTC).")
    monitoring_end:       Optional[datetime] = Field(default=None, description="End of the monitoring window (UTC); not before monitoring_start.")
    notes:                Optional[str] = Field(default=None, max_length=8000)


class RecoverySystemOut(BaseModel):
    """One in-scope system and its recovery record. `record_id` is null until the first write
    (state not_started)."""
    entity_id:             UUID
    entity_type:           str
    entity_value:          str
    entity_name:           Optional[str] = None
    criticality:           str
    record_id:             Optional[UUID] = None
    state:                 RecoveryState
    allowed_transitions:   list[RecoveryState] = Field(description="States `state` may move to next (going back needs `reason`).")
    not_required_reason:   Optional[str] = None
    restore_point_ref:     Optional[str] = None
    restore_point_at:      Optional[datetime] = None
    restored_at:           Optional[datetime] = None
    restored_by_id:        Optional[UUID] = None
    restored_by_username:  Optional[str] = None
    validation_method:     Optional[str] = None
    validation_checklist:  list[RecoveryChecklistItem] = Field(default_factory=list)
    validated_at:          Optional[datetime] = None
    validated_by_id:       Optional[UUID] = None
    validated_by_username: Optional[str] = None
    same_person_validation: bool = Field(default=False, description="Warning: the person who validated the system "
                                                                    "also restored it (not blocked).")
    monitoring_start:      Optional[datetime] = None
    monitoring_end:        Optional[datetime] = None
    notes:                 Optional[str] = None
    updated_at:            Optional[datetime] = None
    updated_by_username:   Optional[str] = None


class RecoverySummary(BaseModel):
    """Roll-up over the incident's in-scope systems (compromised host / service / network_range entities)."""
    total:        int
    not_started:  int
    restoring:    int
    restored:     int
    validated:    int
    not_required: int
    complete: bool = Field(description="At least one in-scope system, and every one is validated or not_required.")
    same_person_validations: int = Field(description="Validated systems whose validator also restored them (warning).")
    monitoring_started: int = Field(description="Systems whose monitoring window has started (monitoring_start ≤ now).")
    can_declare_recovered: bool = Field(description="complete, the incident has no recovered_at and is not closed: "
                                                    "the UI offers Declare recovered (PATCH /api/incidents/{id} recovered_at). "
                                                    "Nothing is set automatically.")


class RecoveryList(BaseModel):
    items:       list[RecoverySystemOut]
    next_cursor: Optional[str] = None
    summary:     RecoverySummary


# ─── Stakeholder notification tracker (I2, R22) ────────────────────────────
# One obligation per stakeholder-matrix rule that matches the incident's severity (and type).
# Rules (recompute, transitions, required fields, time checks): stakeholder_notifications/service.py.

NotificationStatus  = Literal["pending", "notified", "not_required"]
NotificationChannel = Literal["phone", "email", "in_person", "oob", "other"]


class StakeholderNotificationUpdate(BaseModel):
    """Record or change one obligation; send only what changes. `status`:
    pending → notified | not_required; notified / not_required → pending needs `reason` (clears
    the recorded notification or the not-required reason). notified needs `channel`;
    `notified_at` defaults to now and may not be in the future; the caller is recorded as
    notified_by. not_required needs `not_required_reason`. Correcting a recorded notification
    (notified_at, channel, oob_log_id, stakeholder_id) needs `reason`."""
    model_config = ConfigDict(extra="forbid")

    status:              Optional[NotificationStatus] = None
    notified_at:         Optional[datetime] = Field(default=None, description="When the stakeholder was told (UTC); default now; not in the future.")
    channel:             Optional[NotificationChannel] = Field(default=None, description="How: phone, email, in_person, oob (out-of-band) or other.")
    oob_log_id:          Optional[UUID] = Field(default=None, description="Optional link to this incident's out-of-band log entry.")
    stakeholder_id:      Optional[UUID] = Field(default=None, description="Optional link to this incident's stakeholder record (who was told).")
    note:                Optional[str] = Field(default=None, max_length=4000)
    not_required_reason: Optional[str] = Field(default=None, max_length=2000, description="Why this notification is not needed (required for not_required).")
    reason:              Optional[str] = Field(default=None, max_length=2000,
                                           description="Why a recorded status is undone or a recorded notification corrected; audited.")


class StakeholderNotificationOut(BaseModel):
    """One notification obligation. `rule_id` is null once its matrix rule was deleted. Role,
    category, required and the SLA are a snapshot of the rule when the obligation arose."""
    id:                    UUID
    rule_id:               Optional[UUID] = None
    severity:              Severity
    role:                  str
    category:              str
    required:              bool = Field(description="False = an advisory rule: listed, not counted in the roll-up, no reminder.")
    notify_within_minutes: int
    clock_start_at:        datetime = Field(description="When the incident first reached `severity` (the countdown start).")
    due_at:                datetime
    status:                NotificationStatus
    allowed_transitions:   list[NotificationStatus]
    overdue:               bool = Field(description="pending, not superseded, and past due_at.")
    superseded:            bool = Field(description="The rule no longer matches the incident (kept, not counted).")
    superseded_at:         Optional[datetime] = None
    superseded_reason:     Optional[str] = Field(default=None, description="severity_changed, incident_type, rule_changed or rule_removed.")
    notified_at:           Optional[datetime] = None
    notified_by_id:        Optional[UUID] = None
    notified_by_username:  Optional[str] = None
    channel:               Optional[NotificationChannel] = None
    oob_log_id:            Optional[UUID] = None
    stakeholder_id:        Optional[UUID] = None
    stakeholder_name:      Optional[str] = None
    note:                  Optional[str] = None
    not_required_reason:   Optional[str] = None
    created_at:            datetime
    updated_at:            datetime
    updated_by_username:   Optional[str] = None


class StakeholderNotificationSummary(BaseModel):
    """Roll-up over the incident's ACTIVE (not superseded) obligations from REQUIRED rules."""
    required_total: int = Field(description="Required obligations that apply (not_required ones excluded): the y of 'x of y'.")
    notified:       int = Field(description="Of those, notified: the x of 'x of y'.")
    overdue:        int = Field(description="Of those, pending past due_at.")
    not_required:   int = Field(description="Required obligations recorded as not required (with a reason).")
    next_due_at:    Optional[datetime] = Field(default=None, description="Earliest due_at among the pending ones.")


class SeverityLevelOut(BaseModel):
    severity:   Severity
    reached_at: datetime = Field(description="When the incident first reached this severity (UTC).")
    source:     Literal["initial", "change", "backfill"]


class StakeholderNotificationList(BaseModel):
    items:           list[StakeholderNotificationOut]
    next_cursor:     Optional[str] = None
    summary:         StakeholderNotificationSummary
    severity_levels: list[SeverityLevelOut] = Field(description="Each severity the incident has reached, first time, oldest first.")


StartCheckKey = Literal["ic_assigned", "comms_lead_assigned", "legal_liaison_assigned", "detected_at_set",
                        "playbook_applied", "legal_initialised", "dark_operation_decided", "notifications_on_time"]


class StartCheck(BaseModel):
    key:    StartCheckKey
    label:  str
    status: Literal["ok", "warning", "overdue"] = Field(description=(
        "ok; warning while missing; overdue once missing longer than overdue_after_minutes after the incident was "
        "created. notifications_on_time is overdue as soon as a stakeholder notification is overdue."))
    detail: Optional[str] = None
    route:  str = Field(description="Incident sub-page where it is fixed, relative to /incidents/{id}/.")


class IncidentStartChecks(BaseModel):
    """I4: what should be in place soon after an incident is opened. Warnings only: nothing blocks."""
    total:    int
    ok:       int
    warning:  int
    overdue:  int
    overdue_after_minutes: int
    overdue_at: datetime = Field(description="created_at + overdue_after_minutes: when a missing check turns overdue.")
    items:    list[StartCheck] = Field(description="Only the checks that apply to this incident.")


class IncidentSnapshot(BaseModel):
    """At-a-glance per-incident counts for the Details landing tab and the
    incident rail's live counts.

    All values are non-negative integers. Aggregations only — no row data — so
    this endpoint is access-checked but not RBAC-sensitive beyond accessibility.
    """
    iocs:             int
    entities:         int
    evidence:         int
    timeline:         int
    affected_systems: int   # compromised entities (C2)
    assignments:      int
    playbook_total:   int   # excludes skipped tasks (matches sidebar widget convention)
    playbook_done:    int
    playbook_skipped: int
    files:            int = Field(description="Supporting documents (the incident's Files store, "
                                              "including files linked to an entity).")
    respond_open:     int = Field(description="Respond actions (containment / eradication / recovery) "
                                              "with status open or in_progress.")
    respond_total:    int = Field(description="All Respond actions, any status (done, deferred and "
                                              "reverted included).")
    handoffs_pending: int = Field(description="Shift handoffs not yet acknowledged (status pending).")
    recovery:         RecoverySummary = Field(description="Recovery tracker roll-up (I1): per-state counts over "
                                                          "the in-scope systems; see GET …/recovery.")
    notifications:    StakeholderNotificationSummary = Field(description="Stakeholder notification tracker roll-up (I2); "
                                                                         "see GET …/stakeholder-notifications.")
    start_checks:     IncidentStartChecks = Field(description="Incident-start checks (I4); see GET …/start-checks.")


# ─── Containment state (C1) ─────────────────────────────────────────────────
# Derived from the Respond board (respond/containment.py) and returned on the
# entity and IOC lists.

ContainmentEffect = Literal["isolated", "disabled", "blocked"]


class ContainmentOut(BaseModel):
    """Containment state of an entity or IOC, from its latest non-reverted
    containment action that has a containment template.

    `state` is the effect once that action is done, or `pending` while it is
    open or in progress; `effect` always names what the action does.
    """
    state:      Literal["isolated", "disabled", "blocked", "pending"]
    effect:     ContainmentEffect
    action_id:  UUID
    updated_at: datetime


# ─── IOCs ───────────────────────────────────────────────────────────────────
# 800-61 R3 vocabulary: "indicator of compromise". Per-incident scope.

IocType = Literal[
    "ip", "domain", "url",
    "hash_md5", "hash_sha1", "hash_sha256",
    "email", "registry_key", "file_path", "crypto_wallet", "other",
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
    evidence_id: Optional[UUID] = None   # C5 — the exhibit the indicator was found in
    added_by_id: Optional[UUID] = None
    added_by_username: Optional[str] = None
    added_at:    datetime
    updated_at:  datetime
    # Populated at query time — not stored on the row.
    ti_matched:      bool          = False
    ti_match_source: Optional[str] = None
    lolbin_hit:      bool          = False
    lolbin_name:     Optional[str] = None
    # Set on the list endpoint only; null when no containment action applies.
    containment:     Optional[ContainmentOut] = None

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
    # C5 — an exhibit (evidence item) of THIS incident the indicator was found in
    # (404 evidence_not_found / 422 evidence_other_incident).
    evidence_id: Optional[UUID] = None


class IntakeIoc(BaseModel):
    """I4: the first indicator, given with POST /api/incidents."""
    type:  IocType
    value: str = Field(min_length=1, max_length=2048)


IncidentCreate.model_rebuild()


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
    # Set on the list endpoint only; null when no containment action applies.
    containment: Optional[ContainmentOut] = None

    class Config:
        from_attributes = True


class EntityCreate(BaseModel):
    type:        EntityType
    value:       str = Field(min_length=1, max_length=2048)
    name:        Optional[str] = Field(default=None, max_length=256)
    description: Optional[str] = Field(default=None, max_length=4096)
    criticality: Criticality = "medium"
    # True = in scope as compromised (it then appears under Affected systems / ?compromised=true).
    compromised: bool = False
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
    # E4: picked as a figure for generated reports, and the caption printed under it.
    include_in_report: bool          = False
    report_caption:    Optional[str] = None
    # H4: the server's hashes of the original (lower-case hex; null = not hashed yet, see
    # `python -m files.backfill_hashes`), and the exhibit it was registered as (null = none).
    sha256:            Optional[str]  = None
    sha1:              Optional[str]  = None
    md5:               Optional[str]  = None
    evidence_id:       Optional[UUID] = None
    evidence_identifier: Optional[str]  = None   # filled at query time
    evidence_sealed:     Optional[bool] = None   # false = still an unsealed draft

    class Config:
        from_attributes = True


class IncidentFileUpdate(BaseModel):
    """Rename a stored file, (un)link it to an entity, or pick it as a report figure.
    `entity_id` is tri-state — an explicit null unlinks; omitting it leaves the link
    unchanged. `include_in_report=true` is accepted only for a PNG, JPEG, GIF or WebP
    image, checked by content (422 code unsupported_report_image; SVG is refused, as is
    an image whose dimensions can't be read from its header), at most 16384 px per side
    and 50 megapixels (422 code image_too_large), whose stored bytes pass their integrity
    check (409 code file_integrity_failed).
    `report_caption` (max 512) is printed under the figure; null or "" clears it."""
    original_name:     Optional[str]  = Field(default=None, min_length=1, max_length=512)
    entity_id:         Optional[UUID] = None
    include_in_report: Optional[bool] = None
    report_caption:    Optional[str]  = Field(default=None, max_length=512)
    reason:            Optional[str]  = Field(default=None, max_length=2000,
                                              description="H4: required with a rename (original_name that changes the "
                                                          "name): " + _REASON_DOC + " Audited with the old and new "
                                                          "name; ignored otherwise.")


class FileDelete(BaseModel):
    """H4: the JSON body of a supporting-document delete."""
    reason: Optional[str] = Field(default=None, max_length=2000,
                                  description="Why the file is deleted, " + _REASON_DOC)


class FileReference(BaseModel):
    type:  str            = Field(description="report_figure | generated_report | case_note | exhibit | entity")
    id:    Optional[str]  = None
    label: Optional[str]  = None


class FileRegisterExhibitOut(BaseModel):
    """H4: the exhibit a supporting document is registered as."""
    evidence_id:         UUID
    evidence_identifier: str
    evidence_sealed:     bool
    exhibit_link:        str = Field(description="registered (a new unsealed draft exhibit) | sha256_match (the "
                                                 "incident's active exhibit with the same SHA-256, linked) | "
                                                 "already_registered (an earlier call registered or linked it)")
    file:                EntityFileOut


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
# C3 — typed target hash vs the server's hash of the uploaded bytes (see models.Evidence).
UploadHashCheck = Literal["match", "mismatch", "not_checked", "container_media"]


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
    # C4 — an internal transfer awaiting the recipient's acceptance (all null when none).
    # Custody (current_custodian_id) changes only when the recipient accepts.
    pending_custodian_id:          Optional[UUID] = None
    pending_transfer_by_id:        Optional[UUID] = None
    pending_transfer_requested_at: Optional[datetime] = None
    collected_by_id:      Optional[UUID] = None
    collected_as_role:    Optional[CollectorRole] = None   # GS-12 (DEFR/DES)
    collected_at:         datetime
    collected_location:   Optional[str] = None
    disposed_at:          Optional[datetime] = None
    dispose_witness_id:   Optional[UUID] = None             # GS-10 (two-person disposal)
    final_hash_at_disposition: Optional[str] = None
    legal_hold:           bool = False
    # G5 (R09) — the current hold (all null when not held). Set / release: PUT …/legal-hold; the
    # history is in the custody log (evidence_legal_hold_set / evidence_legal_hold_released).
    legal_hold_since:     Optional[datetime] = None
    legal_hold_by_id:     Optional[UUID] = None
    legal_hold_reason:    Optional[str] = None

    # Wizard A — acquisition (ISO/IEC 27037 §5.4.4 + GDPR Art. 5.1(c))
    lawful_basis:              Optional[str] = None
    lawful_basis_note:         Optional[str] = None
    acquisition_tool:          Optional[str] = None
    acquisition_tool_version:  Optional[str] = None
    acquisition_tool_sha256:   Optional[str] = None
    acquisition_params:        Optional[str] = None
    acquisition_hash_source:   Optional[str] = None
    acquisition_hash_target:   Optional[str] = None
    acquired_at:               Optional[datetime] = None          # C3 — when the image was taken / item seized
    upload_hash_check:         Optional[UploadHashCheck] = None   # C3 — null on legacy rows without a target hash
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
    # G4 (R35) — device clock minus true UTC, in seconds (positive = the device clock ran ahead);
    # null = not recorded as a number. Imports from the exhibit subtract it from the device's times.
    system_time_offset_seconds: Optional[int] = None
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
    # C4 — internal custody changes in the audit chain (set by the list endpoint, 0 elsewhere):
    # accepted by the recipient / recorded before recipient acceptance existed (legacy).
    internal_transfers_acknowledged:  int = 0
    internal_transfers_legacy:        int = 0
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


# G4 (R35) — the structured device-clock offset. Bound: 100 years either way (a clock reset to 1970
# is about -56 years); the database CHECK uses the same bound.
TIME_OFFSET_MAX_SECONDS = 3_155_760_000
TIME_OFFSET_DESCRIPTION = (
    "Device clock minus true UTC, in whole seconds, after allowing for the device's timezone: "
    "+120 = the device clock was 2 minutes ahead, -30 = 30 s behind. Optional; the free-text "
    "system_time_offset is kept as it is and never parsed. When set, imports from this exhibit "
    "(Logs & triage from-evidence, Defender from-evidence, an upload or collection linked to it) "
    "subtract it from the device's times and keep the time as recorded.")


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
    system_time_offset_seconds: Optional[int] = Field(
        default=None, ge=-TIME_OFFSET_MAX_SECONDS, le=TIME_OFFSET_MAX_SECONDS,
        description=TIME_OFFSET_DESCRIPTION)
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
    # C3 — when the item was seized (UTC; at most a couple of minutes ahead of the server
    # clock, else 422 acquired_in_future). collected_at stays "registered in FENRIR".
    acquired_at:        Optional[datetime] = None

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
    system_time_offset_seconds: Optional[int] = Field(
        default=None, ge=-TIME_OFFSET_MAX_SECONDS, le=TIME_OFFSET_MAX_SECONDS,
        description=TIME_OFFSET_DESCRIPTION)
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
    photos:            Optional[list[PhotoRef]] = Field(
        default=None, description="Replaces the photo list. Not on a sealed item: 409 code sealed_field_immutable "
                                  "(add a photo with POST …/photos instead).")
    legal_hold:        Optional[bool] = Field(
        default=None, description="Not settable here: sending it (any value) is 422 code use_legal_hold_endpoint. "
                                  "Set or release a legal hold with PUT …/evidence/{id}/legal-hold "
                                  "{\"legal_hold\": bool, \"reason\": …}, which is audited.")
    collected_as_role: Optional[CollectorRole] = Field(
        default=None, description="GS-12 (DEFR/DES). A fact of the collection: not on a sealed item (409 code "
                                  "sealed_field_immutable).")
    # G4 (R35) — set or correct the structured clock offset; an explicit null clears it. Audited
    # {from, to} (plus evidence_amend_after_seal on a sealed item). Imports already made keep the
    # offset they were parsed with: re-import from the exhibit to apply a new value.
    system_time_offset_seconds: Optional[int] = Field(
        default=None, ge=-TIME_OFFSET_MAX_SECONDS, le=TIME_OFFSET_MAX_SECONDS,
        description=TIME_OFFSET_DESCRIPTION + " Send null to clear it.")


# G-fix B (L12): what each code of the acquisition-record enums means, in the OpenAPI field descriptions
# (the values themselves come from the Literal types).
_LAWFUL_BASIS_DOC = ("Lawful basis for the acquisition: ir = incident response (legitimate interest), consent = "
                     "the data subject authorised it, warrant = judicial authorisation, court_order, eio = European "
                     "Investigation Order (Dir. 2014/41/EU), mla = mutual legal assistance (Budapest Convention "
                     "Art. 31), lia = another legitimate-interest assessment, other = justify in lawful_basis_note")
_SYSTEM_STATE_DOC = ("State of the system when acquired: powered_off (forensic image), live (justify in "
                     "live_justification), live_critical (live, could not be powered off; justify), unknown")
_DEVICE_TYPES_DOC = ("ISO/IEC 27037 §7 device types (a list): computer, peripheral, storage (media), mobile, "
                     "network (device), cctv (CCTV / video surveillance)")
_HANDLING_MODE_DOC = "ISO/IEC 27037 §7 handling: collect (seize the device) or acquire (copy the data)"
_ACQUISITION_SCOPE_DOC = ("full_image (a complete image) or logical (selected data; give "
                          "logical_acquisition_rationale)")
_COLLECTOR_ROLE_DOC = ("Who collected it (GS-12): defr = digital evidence first responder (ISO/IEC 27037 §3.7), "
                       "des = digital evidence specialist (§3.8)")
_TARGET_HASH_SCOPE_DOC = ("What acquisition_hash_target is the hash of: uploaded_file (the default; compared with "
                          "the stored file, a mismatch is 422 hash_mismatch) or container_media (an E01 / AFF4 "
                          "media hash; recorded, advisory)")


class EvidenceAcquisitionRecord(BaseModel):
    """G3 — complete the acquisition record of an UNSEALED item (e.g. a draft exhibit registered by an
    Email / PCAP / Browser history upload, or a Quick add) so it can be sealed. Only the fields sent
    change (an explicit null clears one); the stored file and its hashes never change. Same rules as
    the collect routes: hashes are MD5 / SHA-1 / SHA-256 hex (422 invalid_hash_format), a target hash
    with target_hash_scope=uploaded_file is compared with the stored file's hash of the same
    algorithm (422 hash_mismatch, nothing changed), acquired_at not in the future, the witness an
    active user who can see the incident."""
    lawful_basis:              Optional[LawfulBasis] = Field(default=None, description=_LAWFUL_BASIS_DOC)
    lawful_basis_note:         Optional[str] = Field(default=None, max_length=4096)
    acquisition_tool:          Optional[str] = Field(default=None, max_length=128)
    acquisition_tool_version:  Optional[str] = Field(default=None, max_length=64)
    acquisition_tool_sha256:   Optional[str] = Field(default=None, max_length=64)
    acquisition_params:        Optional[str] = Field(default=None, max_length=4096)
    acquisition_hash_source:   Optional[str] = Field(default=None, max_length=64)
    acquisition_hash_target:   Optional[str] = Field(default=None, max_length=64)
    target_hash_scope:         Literal["uploaded_file", "container_media"] = Field(
        default="uploaded_file", description=_TARGET_HASH_SCOPE_DOC)
    acquired_at:               Optional[datetime] = None
    write_blocker_used:        Optional[bool] = None
    write_blocker_serial:      Optional[str]  = Field(default=None, max_length=128)
    system_state:              Optional[SystemState] = Field(default=None, description=_SYSTEM_STATE_DOC)
    live_justification:        Optional[str]  = Field(default=None, max_length=4096)
    network_isolated:          Optional[bool] = None
    witness_user_id:           Optional[UUID] = None
    witness_name:              Optional[str]  = Field(default=None, max_length=128)
    collected_location:        Optional[str]  = Field(default=None, max_length=256)
    collected_as_role:         Optional[CollectorRole] = Field(default=None, description=_COLLECTOR_ROLE_DOC)
    device_types:              Optional[list[DeviceType]] = Field(default=None, description=_DEVICE_TYPES_DOC)
    handling_mode:             Optional[HandlingMode] = Field(default=None, description=_HANDLING_MODE_DOC)
    decision_factors:          Optional[dict] = None
    acquisition_scope:         Optional[AcquisitionScope] = Field(default=None, description=_ACQUISITION_SCOPE_DOC)
    logical_acquisition_rationale: Optional[str] = Field(default=None, max_length=4096)
    system_time_offset:        Optional[str]  = Field(default=None, max_length=128)
    system_time_offset_seconds: Optional[int] = Field(
        default=None, ge=-TIME_OFFSET_MAX_SECONDS, le=TIME_OFFSET_MAX_SECONDS,
        description=TIME_OFFSET_DESCRIPTION)
    screen_state:              Optional[str]  = Field(default=None, max_length=4096)
    changes_made:              Optional[str]  = Field(default=None, max_length=4096)
    device_details:            Optional[dict] = None
    acquisition_tool_validated:       Optional[bool] = None
    acquisition_tool_validation_ref:  Optional[str]  = Field(default=None, max_length=256)
    acquisition_tool_validation_date: Optional[str]  = Field(default=None, max_length=32)


class ExternalCustodian(BaseModel):
    """A real-world custodian without a Fenrir account — courier, external counsel,
    LE officer pre-formal-handoff, vendor IR team, etc. Captured for ISO 27037 §6.1
    chain-accountability coverage."""
    name:         str = Field(min_length=1, max_length=256)
    organisation: Optional[str] = Field(default=None, max_length=256)
    contact:      Optional[str] = Field(default=None, max_length=256)


class TransferRequest(BaseModel):
    """Exactly one of `to_user_id` or `to_external` must be set.

    C4: `to_user_id` (internal) is a REQUEST — custody changes only when that user accepts
    via `…/transfer/accept`. The one exception is taking an item back from external custody:
    the receiving user (`to_user_id` = yourself) records it in one step and must give
    `condition_on_receipt` + `seals_intact`."""
    to_user_id:  Optional[UUID] = None
    to_external: Optional[ExternalCustodian] = None
    reason:      str = Field(min_length=1, max_length=2048)
    # Structured tamper-evident transport (ISO/IEC 27037 §6.9.4) — optional.
    transport_method: Optional[str] = Field(default=None, max_length=128)   # courier, hand-carry, encrypted_channel…
    seal_id:          Optional[str] = Field(default=None, max_length=128)   # tamper-evident seal number
    courier_ref:      Optional[str] = Field(default=None, max_length=128)   # tracking / waybill ref
    # C4 — only for a return from external custody (ignored otherwise).
    condition_on_receipt: Optional[str] = Field(default=None, max_length=4096)
    seals_intact:         Optional[bool] = None

    @model_validator(mode="after")
    def _exactly_one_recipient(self):
        if (self.to_user_id is None) == (self.to_external is None):
            raise ValueError("exactly one of to_user_id or to_external must be provided")
        return self


class TransferAcceptRequest(BaseModel):
    """C4 — the recipient confirms receipt after inspecting the item (ISO/IEC 27037 §6.1, §6.9.4;
    SWGDE §6.2/§6.3)."""
    condition_on_receipt: str = Field(min_length=1, max_length=4096)   # what the recipient found
    seals_intact:         bool                                         # tamper-evident seals / packaging intact


class TransferDeclineRequest(BaseModel):
    """C4 — decline (recipient) or cancel (requester / admin) a pending transfer."""
    reason: str = Field(min_length=1, max_length=2048)


_EXAM_TARGET_DOC = (
    "G5 (R08): a digital exhibit is examined on a working copy — `working_copy_id` names a verified one "
    "(a complete analyst download whose hash matches the master, a lab copy recorded as verified, or an "
    "export copy) — or, explicitly, in place: `examined_in_place: true` with an `in_place_reason` (audited). "
    "Exactly one of the two (422 working_copy_required / working_copy_or_in_place / in_place_reason_required; "
    "an unknown copy is 404 working_copy_not_found, an unverified or altered one 409 working_copy_not_verified). "
    "A physical item is exempt (it has no working copies: working_copy_id is 422 working_copy_not_applicable).")


class ExamineRequest(BaseModel):
    __doc__ = "Record an examination action. " + _EXAM_TARGET_DOC
    tool:  str = Field(min_length=1, max_length=256)
    notes: Optional[str] = Field(default=None, max_length=4096)
    working_copy_id:   Optional[UUID] = None
    examined_in_place: bool = False
    in_place_reason:   Optional[str] = Field(default=None, max_length=2048)


class LegalHoldChange(BaseModel):
    """G5 (R09/R75) — set (`legal_hold: true`) or release (`false`) a legal hold, with a reason (audited).
    Setting: any analyst who can see the incident. Releasing: the incident's lead (IC / Deputy IC) or an
    admin. While held, the item can't be destroyed; returning or archiving it needs a second approver."""
    legal_hold: bool
    reason:     str = Field(min_length=1, max_length=2048)


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
WorkingCopyKind   = Literal["download", "lab_copy", "export", "legacy_record"]
WorkingCopyStatus = Literal["issued", "downloading", "complete", "aborted", "failed_integrity", "expired",
                            "verified", "mismatch", "exported", "legacy_unverified"]


class EvidenceCopyOut(BaseModel):
    """One working copy (ISO/IEC 27037 §7.1.3.1.1). G5: `kind` = download (an analyst download, hashed by
    the server over the bytes it sent) | lab_copy (made outside FENRIR; hashes as the copying tool
    reported them) | export (an export bundle carried the bytes) | legacy_record (recorded before G5: its
    sha256 is a re-hash of the master, not of the copy, so it never counts as verified). `status`:
    download issued → downloading → complete | aborted | failed_integrity, or expired (the link was never
    used); lab_copy verified | mismatch; export exported; legacy_record legacy_unverified.
    `verified_against_master` = the copy's hash equals the master's recorded hash.
    `usable_for_examination` = it can be named as the working copy of an examination."""
    id:                       UUID
    evidence_id:              UUID
    role:                     str
    kind:                     WorkingCopyKind = "legacy_record"
    copy_identifier:          Optional[str] = None
    status:                   WorkingCopyStatus = "legacy_unverified"
    sha256:                   Optional[str] = None
    sha1:                     Optional[str] = None
    md5:                      Optional[str] = None
    hash_source:              Literal["server_stream", "tool_reported", "master"] = "master"
    verified_against_master:  bool = False
    usable_for_examination:   bool = False
    created_by_id:            Optional[UUID] = None
    created_by_qualifications: Optional[str] = None
    created_at:               datetime
    issued_to_id:             Optional[UUID] = None   # download: the only user the link works for
    token_expires_at:         Optional[datetime] = None
    download_started_at:      Optional[datetime] = None
    completed_at:             Optional[datetime] = None
    bytes_sent:               Optional[int] = None
    end_reason:               Optional[str] = None
    purpose:                  Optional[str] = None
    destination_note:         Optional[str] = None
    copy_tool:                Optional[str] = None
    export_id:                Optional[UUID] = None
    discarded_at:             Optional[datetime] = None
    altered_at:               Optional[datetime] = None


class WorkingCopyCreate(BaseModel):
    """G5 (R08) — record a copy made OUTSIDE FENRIR (e.g. imaged to a lab workstation) with the hash(es)
    the copying tool reported for THAT copy: at least one of copy_sha256 / copy_sha1 / copy_md5 (422
    copy_hash_required; hex of the right length, else 422 invalid_hash_format). Each is compared with the
    master's recorded hash of the same algorithm: all equal → status verified; any differs → mismatch
    (flagged, audited, never counted as verified). The master is not re-hashed (use Verify for that)."""
    purpose:          str = Field(min_length=1, max_length=2048)
    copy_sha256:      Optional[str] = Field(default=None, max_length=64)
    copy_sha1:        Optional[str] = Field(default=None, max_length=40)
    copy_md5:         Optional[str] = Field(default=None, max_length=32)
    copy_tool:        Optional[str] = Field(default=None, max_length=256,
                                            description="Tool + version that made the copy, e.g. FTK Imager 4.7.1")
    destination_note: Optional[str] = Field(default=None, max_length=1024,
                                            description="Where the copy is, e.g. lab WS-04 D:\\cases\\…")


class WorkingCopyIssue(BaseModel):
    """G5 (R08) — issue a working copy to download (you, the caller, only)."""
    purpose:          str = Field(min_length=1, max_length=2048)
    destination_note: Optional[str] = Field(default=None, max_length=1024,
                                            description="Where the copy will go, e.g. analysis VM AN-07")


class WorkingCopyIssued(BaseModel):
    """The issued copy and its one-time link. `download_url` works once, for you only (your session or
    API token must also be sent), until `token_expires_at`; it is not stored in clear and is never shown
    again. The response body is the copy's bytes; FENRIR hashes exactly what it sends and records it on
    the copy (GET …/working-copies to read it)."""
    copy:             EvidenceCopyOut
    download_url:     str
    token_expires_at: datetime


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


# G3 (R02) — how an Email / PCAP / Browser history analysis got its exhibit:
#   registered     the upload was registered as a new unsealed draft exhibit, then analysed
#   sha256_match   the upload's SHA-256 equals exactly one active exhibit of the incident: no new exhibit
#   from_evidence  a registered exhibit was picked, decrypted and re-hashed, then analysed
ExhibitLink = Literal["registered", "sha256_match", "from_evidence"]



class PcapAnalysisOut(BaseModel):
    """L17 (G-fix B): a PCAP analysis as POST …/pcap, POST …/pcap/from-evidence/{evidence_id} and
    GET …/pcap/{result_id} return it — the analysis worker's result (its own keys: capture,
    conversations, dns_queries, http_requests, tls_info, findings, iocs, timeline, analyser, …, passed
    through as stored) plus the fields below. Run-record fields are null on an analysis made before
    G3."""
    model_config = ConfigDict(extra="allow")
    result_id:           str = Field(description="The analysis id (use it for promote / import-iocs / delete)")
    filename:            str
    saved_at:            str = Field(description="When the analysis was stored (ISO 8601, UTC offset)")
    evidence_id:         Optional[str] = Field(default=None, description="The exhibit analysed")
    evidence_identifier: Optional[str] = None
    evidence_sealed:     Optional[bool] = Field(default=None, description="false = still an unsealed draft")
    input_sha256:        Optional[str] = Field(default=None, description="SHA-256 of the bytes analysed")
    analyser_name:       Optional[str] = None
    analyser_version:    Optional[str] = None
    exhibit_link:        Optional[ExhibitLink] = Field(
        default=None, description="How the run got its exhibit: registered (a new draft exhibit made by the "
                                  "upload), sha256_match (the upload matched an existing exhibit), from_evidence "
                                  "(a registered exhibit was picked). From-evidence with `upload_id` (a chunked "
                                  "upload of this caller that registered / matched this exhibit) records the "
                                  "upload's link (R93); the custody log still says the master was re-verified.")
    clock_offset_seconds:        Optional[int] = None
    clock_offset_status:         Optional[str] = None
    exhibit_time_offset:         Optional[str] = None
    exhibit_time_offset_seconds: Optional[int] = None
    timeline_candidates: Optional[list[dict]] = Field(
        default=None, description="Each with idx, event_time, time_basis, kind, event_type, description, "
                                  "hostname, source, raw_log, recorded_time and promoted; null before G3")


# ─── Email analyzer (U8.1) ────────────────────────────────────────────────────

class HopImportStatus(BaseModel):
    importable:       int = Field(description="Hops the Timeline import takes (timestamp parses)")
    already_imported: int = Field(description="Importable hops whose Timeline event still exists")


class EmailAnalysisOut(BaseModel):
    id:                 UUID
    incident_id:        UUID
    source_artifact_id: Optional[UUID] = None
    evidence_id:        Optional[UUID] = None
    batch_id:           Optional[UUID] = None
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
    raw_headers:  Optional[str] = None
    auth_verified: Optional[dict] = None
    body_text:    Optional[str] = None
    body_html:    Optional[str] = None
    urls:         list = []
    attachments:  list = []
    created_by:   Optional[str] = None
    created_at:   datetime
    hop_import:   Optional[HopImportStatus] = None   # null in the history list
    # G3 (R02) run record: the exhibit analysed (evidence_id; its identifier and whether it is still an
    # unsealed draft resolved on read), the SHA-256 of the bytes analysed, the analyser + version and
    # how the exhibit was linked. All null on analyses made before G3 (no quarantine copy is made now:
    # source_artifact_id stays null on new analyses).
    input_sha256:       Optional[str] = Field(default=None, description="SHA-256 of the exhibit bytes analysed")
    analyser_name:      Optional[str] = None
    analyser_version:   Optional[str] = None
    exhibit_link:       Optional[ExhibitLink] = None
    evidence_identifier: Optional[str] = None
    evidence_sealed:    Optional[bool] = None

    class Config:
        from_attributes = True


class EmailAnalysisList(BaseModel):
    items: list[EmailAnalysisOut]


class EmailBulkAnalyzeOut(BaseModel):
    batch_id: str
    analyzed: list[EmailAnalysisOut] = []
    skipped:  list[str] = []
    errors:   list[str] = []


class PromoteIocItem(BaseModel):
    type:  str
    value: str = Field(min_length=1, max_length=2048)
    notes: Optional[str] = None


class PromoteIocsRequest(BaseModel):
    iocs: list[PromoteIocItem] = Field(default_factory=list)


class DomainCheckOut(BaseModel):
    domain: str
    spf:    dict
    dmarc:  dict
    dkim:   Optional[dict] = None


# ─── Browser history ─────────────────────────────────────────────────────────

BrowserName = Literal["chrome", "edge", "brave", "firefox"]


class BrowserHistoryUploadOut(BaseModel):
    id:                 UUID
    incident_id:        UUID
    browser:            str
    schema_family:      str
    source_artifact_id: Optional[UUID] = None
    form_history_artifact_id: Optional[UUID] = None
    evidence_id:        Optional[UUID] = None
    original_filename:  str
    file_size:          int
    sha256_hash:        str
    record_count:       int
    search_term_count:  int
    download_count:     int
    truncated:          bool
    uploaded_by:        Optional[str] = None
    uploaded_at:        datetime
    # G3 (R02) run record: evidence_id is the exhibit the history file IS (sha256_hash = the bytes
    # parsed); Firefox's formhistory.sqlite is its own exhibit; the parser + version; how the exhibit
    # was linked; the exhibit's clock offset applied to times promoted to the Timeline (snapshot) and
    # how it compares with the exhibit now (ClockOffsetStatus). Identifiers / draft state resolved on
    # read. Run-record fields are null on uploads made before G3.
    form_history_evidence_id: Optional[UUID] = None
    parser_name:        Optional[str] = None
    parser_version:     Optional[str] = None
    exhibit_link:       Optional[ExhibitLink] = None
    evidence_identifier: Optional[str] = None
    evidence_sealed:    Optional[bool] = None
    form_history_evidence_identifier: Optional[str] = None
    clock_offset_seconds: Optional[int] = None
    clock_offset_status:  Optional["ClockOffsetStatus"] = None
    exhibit_time_offset:  Optional[str] = None
    exhibit_time_offset_seconds: Optional[int] = None

    class Config:
        from_attributes = True


class BrowserHistoryUploadList(BaseModel):
    items: list[BrowserHistoryUploadOut]


class BrowserHistoryFromEvidence(BaseModel):
    """G3 — parse a registered exhibit as browser history (no re-upload)."""
    browser: BrowserName
    form_history_evidence_id: Optional[UUID] = Field(
        default=None, description="Firefox only: a second exhibit, formhistory.sqlite, whose search-bar "
                                  "terms are merged into this upload's search terms")


# ── G1 stage 3b (R80): chunked upload sessions (evidence/uploads.py) ─────────────────────────────
UploadPurpose = Literal["evidence", "email", "pcap", "webhistory"]
UploadExhibitLink = Literal["collected", "registered", "sha256_match"]


class UploadSessionCreate(BaseModel):
    """Open a chunked upload session for one file. The file then goes up as raw
    `application/octet-stream` chunks (PUT …/chunks/{index}); each chunk is hashed and encrypted
    as it arrives, so the plaintext never reaches the server's disk, and nothing is stored until
    `complete` succeeds."""
    model_config = ConfigDict(extra="forbid")
    purpose:  UploadPurpose = Field(description="What `complete` makes of the file: evidence = a digital "
                                    "exhibit (as POST …/evidence/digital); email / pcap / webhistory = a draft "
                                    "exhibit for that analyser (as its G3 upload: register, or link the one "
                                    "active exhibit with the same SHA-256), analysed afterwards through its "
                                    "…/from-evidence/{evidence_id} route")
    filename: str = Field(min_length=1, max_length=255, description="The original file name (basename kept)")
    size:     int = Field(ge=0, description="The exact size in bytes. At most the purpose's cap: evidence 10 GiB "
                          "by default (the server's EVIDENCE_MAX_UPLOAD_BYTES), email 25 MiB, pcap 500 MiB, "
                          "webhistory 500 MiB; email / pcap / webhistory files cannot be empty. The evidence "
                          "volume must have room for it (507 insufficient_storage)")
    mime_type: Optional[str] = Field(default=None, max_length=128,
                                     description="purpose=evidence only: recorded as the exhibit's mime_type")
    expected_hash: Optional[str] = Field(
        default=None, max_length=64,
        description="Optional: the MD5, SHA-1 or SHA-256 (hex; the length decides) of the whole file as the "
                    "client sees it. `complete` compares it with the server's hash of the bytes received, "
                    "before anything is stored: a mismatch is 422 upload_hash_mismatch and nothing is stored")
    metadata: Optional[dict] = Field(
        default=None,
        description="Optional (G-fix B, L12): a preview of the body `complete` will take, without `purpose`. It "
                    "is validated now with the same schema as `complete` (UploadCompleteEvidence / "
                    "UploadCompleteEmail / UploadCompletePcap / UploadCompleteWebHistory), so a wrong field or "
                    "enum value is a 422 BEFORE any byte is sent (the standard request-validation shape, "
                    "loc [\"body\", \"metadata\", …]); it is not stored, and `complete` validates its own "
                    "body again (authoritative). Enum values: tlp red | amber_strict | amber | green | clear; "
                    "lawful_basis ir | consent | warrant | court_order | eio | mla | lia | other; system_state "
                    "powered_off | live | live_critical | unknown; device_types [computer | peripheral | storage | "
                    "mobile | network | cctv]; handling_mode collect | acquire; acquisition_scope full_image | "
                    "logical; target_hash_scope uploaded_file | container_media; collected_as_role defr | des; "
                    "browser (webhistory) chrome | edge | brave | firefox. Only the schema is checked here: "
                    "the witness, entity, identifier and hash checks run at `complete`.")


class UploadSessionOut(BaseModel):
    """An open upload session (in this backend process only: a restart ends it, then 404
    upload_not_found — start again)."""
    upload_id:      UUID
    incident_id:    UUID
    purpose:        UploadPurpose
    filename:       str
    size:           int
    chunk_size:     int = Field(description="Every chunk is exactly this long except the last, which is the "
                                "remainder (size - index * chunk_size)")
    chunk_count:    int
    next_index:     int = Field(description="The only index the next PUT …/chunks/{index} accepts; "
                                "= chunk_count when every byte has arrived")
    received_bytes: int
    created_at:     datetime
    expires_at:     datetime = Field(description="The session is aborted (its staged file deleted) when no "
                                     "chunk arrives before this time; every accepted chunk extends it")


class UploadSessionList(BaseModel):
    """M7 (G-fix B): the caller's own open upload sessions (at most 3, so one page: next_cursor is
    always null)."""
    items:       list[UploadSessionOut]
    next_cursor: Optional[str] = None


class UploadCompleteEvidence(EvidenceAcquisitionRecord):
    """purpose=evidence: the same fields POST …/evidence/digital takes (as JSON; device_types a list,
    decision_factors / device_details objects). The C3 rules are the same: a target hash with
    target_hash_scope=uploaded_file is compared with the server's hash of the uploaded bytes (same
    algorithm) before anything is stored — 422 hash_mismatch, audited evidence_collect_rejected,
    nothing stored. A null field is simply not recorded."""
    model_config = ConfigDict(extra="forbid")
    purpose:     Literal["evidence"]
    name:        str = Field(min_length=1, max_length=256)
    identifier:  str = Field(min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=4096)
    tlp:         Tlp = "amber"
    entity_id:   Optional[UUID] = None


class UploadCompleteEmail(BaseModel):
    """purpose=email: as POST …/email/analyze with a file."""
    model_config = ConfigDict(extra="forbid")
    purpose:     Literal["email"]
    acquired_at: Optional[datetime] = Field(default=None, description="When the message was acquired (UTC; "
                                            "optional, unknown if omitted). Not in the future.")


class UploadCompletePcap(BaseModel):
    """purpose=pcap: as POST …/pcap. Anything but pcap / pcapng is 422 not_a_capture (nothing stored)."""
    model_config = ConfigDict(extra="forbid")
    purpose:     Literal["pcap"]
    acquired_at: Optional[datetime] = Field(default=None, description="When the capture was acquired (UTC; "
                                            "optional, unknown if omitted). Not in the future.")


class UploadCompleteWebHistory(BaseModel):
    """purpose=webhistory: as POST …/webhistory. A file that is not SQLite is 422 not_sqlite (nothing
    stored). Firefox formhistory.sqlite: upload it as its own session with `companion_of` = the
    places.sqlite exhibit, then parse both with …/webhistory/from-evidence/{id}
    {browser, form_history_evidence_id}."""
    model_config = ConfigDict(extra="forbid")
    purpose:      Literal["webhistory"]
    browser:      BrowserName
    acquired_at:  Optional[datetime] = Field(default=None, description="When the file was acquired (UTC; "
                                             "optional, unknown if omitted). Not in the future.")
    companion_of: Optional[UUID] = Field(
        default=None, description="Firefox only: this file is formhistory.sqlite, the companion of this "
                                  "places.sqlite exhibit of the incident (recorded in its evidence_collect audit)")


UploadComplete = Annotated[Union[UploadCompleteEvidence, UploadCompleteEmail, UploadCompletePcap,
                                 UploadCompleteWebHistory], Field(discriminator="purpose")]


class UploadCompleteOut(BaseModel):
    """The exhibit the upload became (201: a new one) or was linked to (200: sha256_match, the
    upload's own copy was discarded)."""
    upload_id:     UUID
    purpose:       UploadPurpose
    exhibit_link:  UploadExhibitLink = Field(description="collected = a new exhibit (purpose evidence); "
                                             "registered = a new unsealed draft exhibit; sha256_match = the one "
                                             "active exhibit with the same SHA-256 (nothing new stored)")
    evidence_id:   UUID
    evidence:      EvidenceOut


class BrowserHistoryPromote(BaseModel):
    """G3 — put visits / downloads on the Timeline. The server copies each record from its upload
    (the caller sends only ids); a record's upload must carry a run record (G3)."""
    visit_ids:    list[UUID] = Field(default_factory=list, max_length=5_000)
    download_ids: list[UUID] = Field(default_factory=list, max_length=5_000)
    ir_phase:     Optional[Phase] = Field(default=None, description="IR phase for the timeline events created")

    @model_validator(mode="after")
    def _one_record(self):
        if not self.visit_ids and not self.download_ids:
            raise ValueError("send at least one visit_id or download_id")
        return self


class BrowserHistoryPromoteResult(BaseModel):
    created:               int
    created_ids:           list[UUID] = Field(default_factory=list)
    # A download without a start time is never placed on the timeline (never at "now").
    skipped_untimestamped: list[UUID] = Field(default_factory=list)
    # Already on the timeline from its upload (re-promoting is a no-op).
    already_promoted:      list[UUID] = Field(default_factory=list)
    # Not a visit / download of this incident.
    not_found:             list[UUID] = Field(default_factory=list)
    # From an upload made before run records (G3): upload it again, or parse its exhibit.
    reparse_required:      list[UUID] = Field(default_factory=list)


class BrowserHistoryVisitOut(BaseModel):
    id:          UUID
    upload_id:   UUID
    url:         str
    host:        Optional[str] = None
    title:       Optional[str] = None
    visit_time:  datetime
    visit_count: Optional[int] = None
    transition:  Optional[str] = None
    browser:     Optional[str] = None   # joined in from the parent upload, for a mixed-upload view
    # G3 — the Timeline event promoted from this visit, if any (read-only).
    timeline_event_id: Optional[UUID] = None

    class Config:
        from_attributes = True


class BrowserHistoryVisitList(BaseModel):
    items:       list[BrowserHistoryVisitOut]
    next_cursor: Optional[str] = None


class BrowserHistorySearchTermOut(BaseModel):
    id:         UUID
    upload_id:  UUID
    term:       str
    url:        Optional[str] = None
    visit_time: Optional[datetime] = None
    browser:    Optional[str] = None

    class Config:
        from_attributes = True


class BrowserHistorySearchTermList(BaseModel):
    items:       list[BrowserHistorySearchTermOut]
    next_cursor: Optional[str] = None


class BrowserHistoryDownloadOut(BaseModel):
    id:             UUID
    upload_id:      UUID
    url:            Optional[str] = None
    target_path:    Optional[str] = None
    start_time:     Optional[datetime] = None
    end_time:       Optional[datetime] = None
    received_bytes: Optional[int] = None
    total_bytes:    Optional[int] = None
    state:          Optional[str] = None
    danger:         Optional[str] = None
    mime_type:      Optional[str] = None
    browser:        Optional[str] = None
    # G3 — the Timeline event promoted from this download, if any (read-only).
    timeline_event_id: Optional[UUID] = None

    class Config:
        from_attributes = True


class BrowserHistoryDownloadList(BaseModel):
    items:       list[BrowserHistoryDownloadOut]
    next_cursor: Optional[str] = None


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
    # M11 (owner, 2026-10-04): unsealed drafts are left out (listed "excluded: unsealed draft") unless this is
    # set; the choice is audited.
    include_unsealed_drafts: bool = Field(
        default=False, description="Include items whose chain of custody is not sealed (drafts). Default: they "
                                   "are listed in the manifest as \"excluded: unsealed draft\" with no records "
                                   "or bytes. Audited.")


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


_TPL_TYPES_DOC = "Incident types this template is suggested for (I3); [] = not suggested for any type."
_TPL_REVIEWED_DOC = ("When someone last marked the template reviewed (POST …/review); null = never. Editing the "
                     "template doesn't change it. Readiness's 12-month playbook check uses this date.")


class _TemplateTypesOut(BaseModel):
    @field_validator("incident_types", mode="before", check_fields=False)
    @classmethod
    def _none_is_empty(cls, v):
        return v or []


class PlaybookTemplateOut(_TemplateTypesOut):
    id:          UUID
    key:         str
    name:        str
    description: Optional[str] = None
    category:    Optional[str] = None
    is_system:   bool
    tasks:       list[PlaybookTaskTemplate] = Field(default_factory=list)
    incident_types:      list[str] = Field(default_factory=list, description=_TPL_TYPES_DOC)
    last_reviewed_at:    Optional[datetime] = Field(default=None, description=_TPL_REVIEWED_DOC)
    last_reviewed_by_id: Optional[UUID] = None
    last_reviewed_by:    Optional[str] = Field(default=None, description="Username of the last reviewer.")
    created_at:  datetime
    updated_at:  datetime

    class Config:
        from_attributes = True


class PlaybookTemplateSummary(_TemplateTypesOut):
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
    incident_types:      list[str] = Field(default_factory=list, description=_TPL_TYPES_DOC)
    last_reviewed_at:    Optional[datetime] = Field(default=None, description=_TPL_REVIEWED_DOC)
    last_reviewed_by_id: Optional[UUID] = None
    last_reviewed_by:    Optional[str] = Field(default=None, description="Username of the last reviewer.")

    class Config:
        from_attributes = True


class PlaybookTemplateCreate(BaseModel):
    name:        str              = Field(min_length=1, max_length=256)
    description: Optional[str]   = Field(default=None, max_length=4096)
    category:    Optional[str]   = Field(default=None, max_length=64)
    tasks:       list[PlaybookTaskTemplate] = Field(default_factory=list)
    incident_types: list[IncidentType] = Field(default_factory=list, max_length=20, description=_TPL_TYPES_DOC)


class PlaybookTemplateUpdate(BaseModel):
    name:        Optional[str]   = Field(default=None, min_length=1, max_length=256)
    description: Optional[str]   = Field(default=None, max_length=4096)
    category:    Optional[str]   = Field(default=None, max_length=64)
    tasks:       Optional[list[PlaybookTaskTemplate]] = None
    incident_types: Optional[list[IncidentType]] = Field(default=None, max_length=20,
                                                         description="Replace the suggested-for types; [] = none.")


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
    archived_at:        Optional[datetime] = Field(default=None, description=(
        "Set when the plan was replaced and this Done/Skipped task was kept as read-only history (I3). "
        "Archived tasks are listed only with include_archived=true and can't be changed."))
    archived_by_id:     Optional[UUID] = None
    archive_reason:     Optional[str] = Field(default=None, description="The replace reason.")

    @computed_field(description="Open or in progress, in the current plan, and past due_at (UTC, evaluated now).")
    @property
    def overdue(self) -> bool:
        if self.archived_at is not None or self.due_at is None or self.status not in ("open", "in_progress"):
            return False
        due = self.due_at if self.due_at.tzinfo else self.due_at.replace(tzinfo=timezone.utc)
        return due <= datetime.now(timezone.utc)

    class Config:
        from_attributes = True


class PlaybookTaskCreate(BaseModel):
    title:       str         = Field(min_length=1, max_length=512)
    description: Optional[str] = Field(default=None, max_length=4096)
    phase:       Phase
    order_index: int         = 0
    assignee_id: Optional[UUID] = None
    due_at:      Optional[datetime] = None


_ASSIGNEE_DOC = ("An active user who can see the incident (404 user_not_found, 422 assignee_no_access). "
                 "Null unassigns; omit to keep.")


class PlaybookTaskUpdate(BaseModel):
    title:       Optional[str] = Field(default=None, min_length=1, max_length=512)
    description: Optional[str] = Field(default=None, max_length=4096)
    phase:       Optional[Phase] = None
    order_index: Optional[int] = None
    status:      Optional[TaskStatus] = None
    skip_reason: Optional[str] = Field(default=None, max_length=2048, description=(
        "Why the task is skipped. Required (non-blank, sent now or already stored) whenever the task ends up "
        "skipped: 422 skip_reason_required. Cleared when a skipped task moves to another status."))
    assignee_id: Optional[UUID] = Field(default=None, description=_ASSIGNEE_DOC)
    due_at:      Optional[datetime] = Field(default=None, description="Due time (UTC). Null clears; omit to keep.")


PlaybookApplyMode = Literal["append", "replace"]


class PlaybookInstantiateRequest(BaseModel):
    template_id: UUID
    mode:        Optional[PlaybookApplyMode] = Field(default=None, description=(
        "append (default): add the template's tasks to the current plan, skipping any task of the same "
        "template with the same title and phase that the current plan already has. replace: the incident "
        "lead (IC/Deputy) or an admin only (403 not_incident_lead), with a reason (422 reason_required); "
        "Done and Skipped tasks are kept as read-only history (archived), Open and In-progress tasks are "
        "removed, then the template's tasks are added."))
    reason:      Optional[str] = Field(default=None, max_length=2048,
                                       description="Why the plan is replaced (required for mode=replace; audited).")
    replace:     Optional[bool] = Field(default=None, deprecated=True, description=(
        "Deprecated: use mode. true = mode replace, false = mode append; contradicting mode is 422 mode_conflict."))


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


# ─── Notes (one per analyst per incident) ───────────────────────────────────

class NoteOut(BaseModel):
    id:          UUID
    incident_id: UUID
    body:        str
    is_private:      bool
    version:         int
    author_id:       Optional[UUID] = None
    author_username: Optional[str]  = None
    created_at:      datetime
    updated_at:      datetime
    edited_at:       Optional[datetime] = None

    class Config:
        from_attributes = True


class NoteList(BaseModel):
    items: list[NoteOut]


class NoteVersionOut(BaseModel):
    version_number: int
    body:           str
    is_private:     bool
    created_at:     datetime

    class Config:
        from_attributes = True


class NoteVersionList(BaseModel):
    items: list[NoteVersionOut]


# ─── Case notes (H2, R05: shared, append-only) ─────────────────────────────

CASE_NOTE_MAX_CHARS = 16384
CASE_NOTE_MAX_LINKS = 50    # per link kind


class CaseNoteCreate(BaseModel):
    """A new case-note entry. Give `body`, or `source_scratchpad_id` (your own legacy scratchpad,
    whose current text becomes the body) -- exactly one. Links must belong to the same incident.
    `corrects_id` names an earlier entry this one corrects (the original is never changed)."""
    model_config = ConfigDict(extra="forbid")

    body:                 Optional[str] = Field(default=None, min_length=1, max_length=CASE_NOTE_MAX_CHARS)
    source_scratchpad_id: Optional[UUID] = None
    corrects_id:          Optional[UUID] = None
    evidence_ids:         list[UUID] = Field(default_factory=list, max_length=CASE_NOTE_MAX_LINKS)
    entity_ids:           list[UUID] = Field(default_factory=list, max_length=CASE_NOTE_MAX_LINKS)
    ioc_ids:              list[UUID] = Field(default_factory=list, max_length=CASE_NOTE_MAX_LINKS)
    timeline_event_ids:   list[UUID] = Field(default_factory=list, max_length=CASE_NOTE_MAX_LINKS)

    @model_validator(mode="after")
    def _one_source(self):
        if (self.body is None) == (self.source_scratchpad_id is None):
            raise ValueError("give exactly one of body or source_scratchpad_id")
        if self.body is not None and not self.body.strip():
            raise ValueError("body must not be blank")
        return self


class CaseNoteOut(BaseModel):
    id:                   UUID
    incident_id:          UUID
    author_id:            UUID
    author_username:      Optional[str] = None
    created_at:           datetime
    body:                 str
    corrects_id:          Optional[UUID] = None
    corrected_by_id:      Optional[UUID] = None   # the entry that corrects this one, if any
    source_scratchpad_id: Optional[UUID] = None
    evidence_ids:         list[UUID]
    entity_ids:           list[UUID]
    ioc_ids:              list[UUID]
    timeline_event_ids:   list[UUID]
    content_sha256:       str

    model_config = ConfigDict(from_attributes=True)


class CaseNoteList(BaseModel):
    items:       list[CaseNoteOut]
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
    "media_pr", "vendor", "ir_firm", "customer", "insurer", "board",
    "supervisory_authority", "csirt", "other",
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


class IncidentStakeholderRow(BaseModel):
    """One stakeholder typed in full (a bulk-import row)."""
    name:            str              = Field(min_length=1, max_length=255)
    title:           Optional[str]    = Field(default=None, max_length=128)
    organization:    Optional[str]    = Field(default=None, max_length=256)
    type:            StakeholderType  = "other"
    contact_methods: list[ContactMethod] = Field(default_factory=list)
    notes:           Optional[str]    = Field(default=None, max_length=4096)
    available_hours: Optional[str]    = Field(default=None, max_length=64)


class IncidentStakeholderCreate(BaseModel):
    contact_id:      Optional[UUID]   = Field(
        default=None,
        description="Copy this Contacts-directory entry (GET /api/contacts) into the incident. Any other "
                    "field you also send (non-null) overrides the copied value. The incident keeps its own "
                    "copy: later directory edits don't change it. Unknown id: 422 contact_not_found.")
    name:            Optional[str]    = Field(default=None, min_length=1, max_length=255,
                                              description="Required unless contact_id is given.")
    title:           Optional[str]    = Field(default=None, max_length=128)
    organization:    Optional[str]    = Field(default=None, max_length=256)
    type:            StakeholderType  = "other"
    contact_methods: list[ContactMethod] = Field(default_factory=list)
    notes:           Optional[str]    = Field(default=None, max_length=4096)
    available_hours: Optional[str]    = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _name_or_contact(self):
        if self.contact_id is None and not self.name:
            raise ValueError("name is required unless contact_id is given")
        return self


class IncidentStakeholderUpdate(BaseModel):
    name:            Optional[str]    = Field(default=None, min_length=1, max_length=255)
    title:           Optional[str]    = Field(default=None, max_length=128)
    organization:    Optional[str]    = Field(default=None, max_length=256)
    type:            Optional[StakeholderType] = None
    contact_methods: Optional[list[ContactMethod]] = None
    notes:           Optional[str]    = Field(default=None, max_length=4096)
    available_hours: Optional[str]    = Field(default=None, max_length=64)


class IncidentStakeholderBulkCreate(BaseModel):
    rows: list[IncidentStakeholderRow] = Field(min_length=1, max_length=500)


class IncidentStakeholderBulkResult(BaseModel):
    created: int
    errors:  list[str] = Field(default_factory=list)


class IncidentStakeholderList(BaseModel):
    items: list[IncidentStakeholderOut]


# ─── Contacts directory (org-wide, E2) ───────────────────────────────────────

class OrgContactOut(BaseModel):
    id:                   UUID
    name:                 str
    title:                Optional[str] = None
    organization:         Optional[str] = None
    type:                 str
    contact_methods:      list[ContactMethod] = Field(default_factory=list)
    notes:                Optional[str] = None
    available_hours:      Optional[str] = None
    last_verified_at:     Optional[datetime] = Field(
        default=None, description="Server time (UTC) of the last verification; null = never verified.")
    verified_by_id:       Optional[UUID] = None
    verified_by_username: Optional[str] = None
    created_at:           datetime
    updated_at:           datetime


class OrgContactCreate(BaseModel):
    name:            str              = Field(min_length=1, max_length=255)
    title:           Optional[str]    = Field(default=None, max_length=128)
    organization:    Optional[str]    = Field(default=None, max_length=256)
    type:            StakeholderType  = "other"
    contact_methods: list[ContactMethod] = Field(default_factory=list, max_length=20)
    notes:           Optional[str]    = Field(default=None, max_length=4096)
    available_hours: Optional[str]    = Field(default=None, max_length=64)


class OrgContactUpdate(BaseModel):
    name:            Optional[str]    = Field(default=None, min_length=1, max_length=255)
    title:           Optional[str]    = Field(default=None, max_length=128)
    organization:    Optional[str]    = Field(default=None, max_length=256)
    type:            Optional[StakeholderType] = None
    contact_methods: Optional[list[ContactMethod]] = Field(default=None, max_length=20)
    notes:           Optional[str]    = Field(default=None, max_length=4096)
    available_hours: Optional[str]    = Field(default=None, max_length=64)
    verified:        Optional[Literal[True]] = Field(
        default=None,
        description="true = you checked this entry is still right: stamps last_verified_at with the "
                    "server time and verified_by with you. The time can't be supplied.")


class OrgContactList(BaseModel):
    items:       list[OrgContactOut]
    next_cursor: Optional[str] = None


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
    defer_reason:   Optional[str] = None
    # The entity / IOC the action targets (null = unlinked free-text target) and
    # the template it was made from.
    entity_id:      Optional[UUID] = None
    ioc_id:         Optional[UUID] = None
    template_id:    Optional[str] = None

    class Config:
        from_attributes = True


class RespondActionRevert(BaseModel):
    revert_reason: str = Field(min_length=1, max_length=4096)


_ENTITY_LINK_DOC = ("Entity this action targets; it must belong to this incident (422 otherwise, "
                    "404 if unknown). An empty details.target is filled from its value.")
_IOC_LINK_DOC = ("IOC this action targets; it must belong to this incident (422 otherwise, "
                 "404 if unknown). An empty details.target is filled from its value.")
_TEMPLATE_DOC = ("Action template id, e.g. isolate_host, block_ip, disable_account. Containment "
                 "templates set the linked entity's / IOC's containment state and accept only a "
                 "matching target type (422 target_type_mismatch, e.g. isolate_host on a hash IOC).")


_DEFER_DOC = ("Why the action is deferred (I5). Optional, kept when the status changes; Gate 1 warns "
              "(respond_deferred_reason_missing) about a deferred containment / eradication / recovery "
              "action without one. Blank clears.")


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
    defer_reason: Optional[str] = Field(default=None, max_length=4096, description=_DEFER_DOC)
    entity_id:   Optional[UUID] = Field(default=None, description=_ENTITY_LINK_DOC)
    ioc_id:      Optional[UUID] = Field(default=None, description=_IOC_LINK_DOC)
    template_id: Optional[str] = Field(default=None, max_length=64, pattern=r"^[a-z][a-z0-9_]*$",
                                       description=_TEMPLATE_DOC)


class RespondActionUpdate(BaseModel):
    title:       Optional[str] = Field(default=None, min_length=1, max_length=512)
    description: Optional[str] = Field(default=None, max_length=4096)
    status:      Optional[RespondActionStatus] = None
    assignee_id: Optional[UUID] = Field(default=None, description=_ASSIGNEE_DOC)
    notes:       Optional[str] = Field(default=None, max_length=4096)
    details:     Optional[dict] = None
    order_index: Optional[int] = None
    occurred_at: Optional[datetime] = None
    defer_reason: Optional[str] = Field(default=None, max_length=4096, description=_DEFER_DOC)
    # For these three, an explicit null clears the value; omit a field to keep it.
    entity_id:   Optional[UUID] = Field(default=None, description=_ENTITY_LINK_DOC + " Null unlinks.")
    ioc_id:      Optional[UUID] = Field(default=None, description=_IOC_LINK_DOC + " Null unlinks.")
    template_id: Optional[str] = Field(default=None, max_length=64, pattern=r"^[a-z][a-z0-9_]*$",
                                       description=_TEMPLATE_DOC + " Null clears it.")


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
    decided_by_id: Optional[UUID] = Field(default=None, description=_ASSIGNEE_DOC.replace("unassigns", "clears the decider"))
    decided_at:    Optional[datetime] = None
    tags:          Optional[list[str]] = None


class DecisionList(BaseModel):
    items:       list[DecisionOut]
    next_cursor: Optional[str] = None


# ─── Timeline events ─────────────────────────────────────────────────────────

TimelineOrigin = Literal["manual", "forensic_import", "system"]
# C5 — how an imported event's UTC time was worked out (forensic/parser.py): explicit (the record
# states UTC/an offset), assumed_tz (naive, read in the import's source_tz), inferred_year (BSD
# syslog, year from the exhibit's acquisition time). 'missing' = no time: never promoted.
TimeBasis = Literal["explicit", "assumed_tz", "inferred_year", "missing"]
# G4 (R35) — an import of an exhibit vs the exhibit's clock offset:
#   applied    the exhibit's structured offset was applied, and it is still the exhibit's value
#   changed    the exhibit's structured offset changed after this import (the import keeps the
#              offset it was parsed with, or none); re-import from the exhibit to apply the new one
#   text_only  the offset is recorded only as text: NOT applied (it is never parsed)
#   none       the exhibit records no offset
#   not_applicable  the analyser's times don't come from the device clock (Defender: Microsoft cloud times,
#              R78), so no offset is applied whatever the exhibit records
# null = the import isn't linked to an exhibit.
ClockOffsetStatus = Literal["applied", "changed", "text_only", "none", "not_applicable"]


class TimelineEventOut(BaseModel):
    id:                   UUID
    incident_id:          UUID
    event_time:           datetime
    hostname:             Optional[str] = None
    entity_id:            Optional[UUID] = None
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
    server_generated:     bool            = Field(
        default=False,
        description="Read-only. True for an event the server recorded itself (is_system with a reserved "
                    "system_source: closure, gate_override, milestone, triage, respond_action, "
                    "respond_action_revert, decision, legal_deadline). PATCH and DELETE of such an event are "
                    "409 system_event_immutable.")
    external_safe:        bool            = True
    # C5 provenance. forensic_import_id set = promoted from a Timeline Import run: its facts
    # (event_time, hostname, source, event_type, description, raw_log) are immutable (409
    # imported_fact_immutable); ir_phase, ATT&CK and entity_id stay editable. time_basis NULL =
    # legacy or analyst-entered. evidence_identifier / parser_version are resolved on read.
    evidence_id:          Optional[UUID] = None
    evidence_identifier:  Optional[str]  = None
    forensic_import_id:   Optional[UUID] = None
    # G4 — promoted from a Defender PDF import run instead (same immutability rules).
    defender_import_id:   Optional[UUID] = None
    # G3 — promoted from a PCAP analysis run (candidate index in import_event_index) or a browser
    # history upload (the visit / download in source_record_id). Same immutability rules.
    pcap_analysis_id:          Optional[UUID] = None
    browser_history_upload_id: Optional[UUID] = None
    source_record_id:          Optional[UUID] = None
    # G-fix B (L26) — a mail relay hop imported from an email analysis with a run record. Same rules.
    email_analysis_id:         Optional[UUID] = None
    import_event_index:   Optional[int]  = None
    parser_name:          Optional[str]  = None
    parser_version:       Optional[str]  = None
    time_basis:           Optional[TimeBasis] = None
    # G4 (R35) — the exhibit's clock offset corrected event_time: recorded_event_time is the time
    # as the device recorded it, event_time = recorded_event_time − clock_offset_seconds. Both
    # null when no offset was applied.
    recorded_event_time:  Optional[datetime] = None
    clock_offset_seconds: Optional[int]  = None
    created_by_id:        Optional[UUID] = None
    created_by_username:  Optional[str]  = None
    created_at:           datetime
    updated_at:           datetime

    class Config:
        from_attributes = True


class TimelineEventCreate(BaseModel):
    event_time:           datetime
    hostname:             Optional[str]   = Field(default=None, max_length=256)
    # An entity of THIS incident (404 unknown / 422 another incident's). An empty hostname
    # defaults to the entity's value.
    entity_id:            Optional[UUID]  = None
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
    system_source:        Optional[str]   = Field(
        default=None, max_length=32,
        description="Label of an analyst annotation (is_system=true), e.g. \"manual\". The sources the server "
                    "writes itself (closure, gate_override, milestone, triage, respond_action, "
                    "respond_action_revert, decision, legal_deadline) are refused: 422 reserved_system_source. "
                    "Ignored by the batch import.")


class TimelineEventUpdate(BaseModel):
    # None = unchanged, except entity_id and ir_phase: sent as null they unlink / clear.
    event_time:           Optional[datetime] = None
    hostname:             Optional[str]   = Field(default=None, max_length=256)
    entity_id:            Optional[UUID]  = None
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


# ─── Defender incident PDF import (stateless preview + review) ──────────────
# The analyst reviews and reclassifies every candidate in the frontend, then
# commits accepted ones via the existing IOC/Entity/Timeline create endpoints
# -- same "parse returns candidates, promotion is a frontend concern" pattern
# already used by ForensicImport and EmailAnalysis. Nothing is persisted here.

DefenderCandidateDestination = Literal["ioc", "entity", "timeline_event"]


class DefenderPdfCandidate(BaseModel):
    # G4 — the candidate's position in the import (what promote takes); set on read.
    idx:                  Optional[int] = None
    kind:                 str
    suggested_destination: DefenderCandidateDestination
    value:                Optional[str] = None
    description:          str
    verdict:              Optional[str] = None
    event_time:           Optional[datetime] = None
    hostname:             Optional[str] = None
    source:               Optional[str] = None
    event_type:           Optional[str] = None
    ioc_type:             Optional[IocType] = None
    entity_type_hint:     Optional[EntityType] = None
    criticality:          Optional[Criticality] = None
    raw_log:              Optional[str] = None
    low_confidence:       bool = False
    # G4 — how event_time was worked out: explicit (the PDF states its UTC offset), assumed_tz (no
    # offset note: read as UTC) or missing. recorded_time = the time as printed (converted to UTC)
    # when the exhibit's clock offset corrected event_time. Both null on imports made before G4.
    time_basis:           Optional[TimeBasis] = None
    recorded_time:        Optional[datetime] = None


class DefenderPdfParseResponse(BaseModel):
    incident:    dict[str, str]
    candidates:  list[DefenderPdfCandidate]


class DefenderPdfImportSummary(BaseModel):
    id:                    UUID
    filename:              str
    file_size:             int
    sha256_hash:           str = Field(description="SHA-256 of the PDF that was parsed (the run's input)")
    candidate_count:       int
    low_confidence_count:  int
    uploaded_by:           Optional[str] = None
    uploaded_at:           datetime
    # G4 (R03) run record: the exhibit the PDF is (from-evidence, or an upload whose SHA-256 equals
    # exactly one active exhibit), the parser and its version (null on imports made before G4), the
    # quarantined copy of an uploaded PDF, and the clock offset applied (see ClockOffsetStatus).
    evidence_id:           Optional[UUID] = None
    evidence_identifier:   Optional[str]  = None
    source_artifact_id:    Optional[UUID] = None
    parser_name:           Optional[str]  = None
    parser_version:        Optional[str]  = None
    clock_offset_seconds:  Optional[int]  = None
    clock_offset_status:   Optional[ClockOffsetStatus] = None
    exhibit_time_offset:   Optional[str]  = None
    exhibit_time_offset_seconds: Optional[int] = None

    class Config:
        from_attributes = True


class DefenderPdfImportDetail(DefenderPdfImportSummary):
    incident:    dict[str, str]
    candidates:  list[DefenderPdfCandidate]


class DefenderPdfImportList(BaseModel):
    items: list[DefenderPdfImportSummary]


class DefenderPdfPromoteItem(BaseModel):
    idx:         int = Field(ge=0, description="The candidate's idx in the import")
    destination: DefenderCandidateDestination


class DefenderPdfPromote(BaseModel):
    """G4 — commit candidates of a stored Defender import; the server copies them."""
    items:    list[DefenderPdfPromoteItem] = Field(min_length=1, max_length=5_000)
    ir_phase: Optional[Phase] = Field(default=None, description="IR phase for the timeline events created")


class DefenderPdfPromoteResult(BaseModel):
    created:               int = Field(description="IOCs + entities + timeline events created")
    created_iocs:          int = 0
    created_entities:      int = 0
    created_events:        int = 0
    created_indices:       list[int] = Field(default_factory=list)
    # A timeline event needs a time: candidates without one are skipped (never placed at "now").
    skipped_untimestamped: list[int] = Field(default_factory=list)
    # A timeline event already promoted from this import at this idx (re-promoting is a no-op).
    already_promoted:      list[int] = Field(default_factory=list)
    # The IOC / entity (same type + value) is already on the incident: left as it is.
    already_exists:        list[int] = Field(default_factory=list)


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
    not_applicable:   bool = False
    na_reason:        Optional[str]    = None
    class Config: from_attributes = True

class ClosureChecklistToggle(BaseModel):
    """Send `checked`, or `not_applicable` (+ optional `na_reason`); at least one (422 code
    nothing_to_change). Checking clears N/A; marking N/A unchecks the item. Gate 2 counts an N/A item
    as done, and warns (checklist_na_reason_missing) when it has no reason."""
    checked:        Optional[bool] = None
    not_applicable: Optional[bool] = Field(default=None, description="Mark (true) or unmark (false) the item "
                                                                      "not applicable (I5).")
    na_reason:      Optional[str]  = Field(default=None, max_length=2000,
                                           description="Why it is not applicable; only with not_applicable=true. "
                                                       "Blank is stored as none.")

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
    # C5 — how event_time was worked out; None on imports parsed before parser versioning.
    time_basis:           Optional[TimeBasis] = None
    # G4 (R35) — the time as the source recorded it, when the exhibit's clock offset corrected
    # event_time (event_time = recorded_time − the import's clock_offset_seconds); else None.
    recorded_time:        Optional[str] = None


class ForensicParseResponse(BaseModel):
    source_file:    str
    detected_format: str   # evtx | xml | sqlite | csv | json
    count:          int    # total events returned (capped at MAX_EVENTS)
    suspicious_count: int
    # True when a parser cap cut the output; total_seen = source records the parser read.
    truncated:      bool = False
    total_seen:     Optional[int] = None
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
    # C5 — the exhibit the parsed bytes are (from-evidence, or an upload whose SHA-256 equals
    # exactly one exhibit of the incident), the parser version and the source timezone used.
    # All NULL on imports made before C5.
    evidence_id:         Optional[UUID] = None
    evidence_identifier: Optional[str]  = None
    parser_version:      Optional[str]  = None
    source_tz:           Optional[str]  = None
    # True when a parser cap cut the output: event_count of total_seen source records (rows /
    # records / matched lines) were converted. Both NULL on imports made before this was recorded.
    truncated:           Optional[bool] = None
    total_seen:          Optional[int]  = None
    # G4 (R35) — the exhibit's clock offset applied to this import's times (seconds, device minus
    # true UTC; null = none applied), how that compares with the exhibit now, and the exhibit's
    # recorded offset (text and number) for display.
    clock_offset_seconds: Optional[int] = None
    clock_offset_status:  Optional[ClockOffsetStatus] = None
    exhibit_time_offset:  Optional[str] = None
    exhibit_time_offset_seconds: Optional[int] = None
    class Config: from_attributes = True


class ForensicImportList(BaseModel):
    items: list[ForensicImportSummary]


class ForensicImportDetail(ForensicImportSummary):
    events: list[ParsedEventOut]


TimelineImportParser = Literal["auto", "evtx", "xml", "sqlite", "csv", "tsv", "syslog", "json"]


class ForensicImportFromEvidence(BaseModel):
    """C5 — parse a registered exhibit (no re-upload)."""
    source_tz: str = Field(min_length=1, max_length=64,
                           description="IANA timezone the exhibit's zone-less times are in, e.g. "
                                       "'Europe/Oslo' or 'UTC'. Times that state UTC or an offset "
                                       "are not affected.")
    parser:    TimelineImportParser = Field(
        default="auto",
        description="Format override for a file whose name/extension doesn't say what it is. "
                    "'auto' detects from the content and the exhibit's original filename.")


class ForensicImportPromote(BaseModel):
    """C5 — promote events of a stored import to the timeline by their index (`idx`)."""
    indices:  list[int] = Field(min_length=1, max_length=10_000)
    ir_phase: Optional[Phase] = None


class ForensicImportPromoteResult(BaseModel):
    created:               int
    created_indices:       list[int] = Field(default_factory=list)
    # Never placed on the timeline: no parseable time (time_basis 'missing').
    skipped_untimestamped: list[int] = Field(default_factory=list)
    # Already on the timeline from this import (re-promoting is a no-op).
    already_promoted:      list[int] = Field(default_factory=list)


class PcapPromote(BaseModel):
    """G3 — put timeline candidates of a stored PCAP analysis on the Timeline by `idx`. The server
    copies them from the run (the caller sends only indices)."""
    indices:  list[int] = Field(min_length=1, max_length=10_000)
    ir_phase: Optional[Phase] = None


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
    incident_id: Optional[UUID] = Field(default=None, description="The incident this lookup is for "
                                             "(access-checked; its outbound policy applies).")
    confirm_outbound: bool = Field(default=False, description="Required (true) when the incident -- given, or "
                                   "one you can see holding this indicator as an IOC -- is Dark Operation or "
                                   "TLP:RED: the lookup leaves the platform. Audited.")


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


class IncidentRefSettings(BaseModel):
    """Incident-reference settings. New incidents get PREFIX-YYYY-NNNNN; existing
    references never change (incidents.ref is immutable)."""
    prefix:           str = Field(description="Prefix for new incident references, e.g. INC or ACME")
    format:           str = Field(default="{PREFIX}-{YYYY}-{NNNNN}", description="YYYY = UTC creation year; NNNNN = global sequence, zero-padded to 5, never resets")
    next_ref_preview: str = Field(description="Reference the next incident would get (does not reserve it)")


class IncidentRefSettingsUpdate(BaseModel):
    prefix: str = Field(pattern=r"^[A-Z][A-Z0-9]{1,9}$", description="2–10 characters: A–Z then A–Z/0–9")


class ApiKeySet(BaseModel):
    value: str = Field(min_length=1, max_length=512)


class ApiKeysResponse(BaseModel):
    services: list[ApiKeyServiceOut]


# ─── IOC batch enrichment ────────────────────────────────────────────────────

class IocEnrichAllRequest(BaseModel):
    sources: Optional[list[str]] = None  # None = all available
    confirm_outbound: bool = Field(default=False, description="Required (true) on a Dark Operation or TLP:RED "
                                   "incident: the lookups leave the platform. Audited.")


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

    @field_validator("aliases", "associated_techniques", "typical_targets", mode="before")
    @classmethod
    def _null_list(cls, v):
        """L9: a stored JSON null (an old PATCH with null) reads as an empty list, not a 500."""
        return [] if v is None else v


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

    @field_validator("name", "motivation")
    @classmethod
    def _not_null(cls, v):
        """R70: both columns are NOT NULL — an explicit null is a 422, not a 500 at commit.
        Leave the field out to keep its value."""
        if v is None:
            raise ValueError("may not be null; leave the field out to keep the current value")
        return v


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
    oob_contact_methods: Optional[list[ContactMethod]] = Field(
        default=None,
        description="The responder's out-of-band contact methods (their roster profile). Returned to "
                    "analysts and admins; the key is omitted for viewers.")

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
    """DEPRECATED shape (C2): one compromised entity of the incident, in the old
    affected-system layout. `id` and `entity_id` are both the entity's id; `name` is the
    entity's display name, else its value; `notes` its description; `system_type` the
    original system type kept in `attributes.system_type` (null when the entity never had
    one); `entity_type` the entity's type."""
    id:                  UUID
    incident_id:         UUID
    name:                str
    system_type:         Optional[SystemType] = None
    notes:               Optional[str] = None
    created_at:          datetime
    created_by_username: Optional[str] = None
    entity_id:           UUID
    entity_type:         EntityType


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
    oob_contact_methods: Optional[list[ContactMethod]] = Field(
        default=None, max_length=10,
        description="How to reach this responder when email or chat may be compromised (e.g. a mobile "
                    "number or Signal). Replaces the whole list; [] clears it.")


class RosterEntry(BaseModel):
    user_id:              UUID
    username:             str
    full_name:            Optional[str] = None
    role:                 str
    skills:               list[str] = []
    availability:         str = "available"
    notes:                Optional[str] = None
    active_incident_count: int = 0
    oob_contact_methods:  Optional[list[ContactMethod]] = Field(
        default=None,
        description="Out-of-band contact methods. Personal data: returned to analysts and admins; the key "
                    "is omitted for viewers.")

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
    # M11 (owner, 2026-10-04): unsealed drafts are left out unless the lead opts in (audited).
    include_unsealed_drafts: bool = Field(
        default=False, description="Include exhibits whose chain of custody is not sealed (drafts). Default: "
                                   "they are listed in Evidence_Inventory.csv as \"excluded: unsealed draft\" "
                                   "with no custody log or file. Audited.")


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
    signature_kind:          Optional[str] = Field(
        default=None,
        description="How MANIFEST.json is protected: hmac-sha256 (INTEGRITY.sig, keyed with "
                    "SHA-256 of the bundle password). Packages built before 2026-10-03 say ed25519, "
                    "a wrong label: they are HMAC-SHA-256 too.")
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
    incident_types:        list[str] = Field(default_factory=list, description="Incident types the rule applies to; empty = every type.")
    created_at:            datetime
    updated_at:            datetime
    class Config:
        from_attributes = True

    @field_validator("incident_types", mode="before")
    @classmethod
    def _none_is_empty(cls, v):
        return v or []


class StakeholderMatrixRuleCreate(BaseModel):
    severity:              StakeholderMatrixSeverity
    role:                  str = Field(min_length=1, max_length=128)
    notify_within_minutes: int = Field(ge=1, le=10080)   # ≤ 1 week
    category:              StakeholderMatrixCategory = "operational"
    required:              bool = False
    incident_types:        list[IncidentType] = Field(default_factory=list, max_length=20,
                                                      description="Only incidents of these types (I2); empty = every type.")


class StakeholderMatrixRuleUpdate(BaseModel):
    severity:              Optional[StakeholderMatrixSeverity] = None
    role:                  Optional[str] = Field(default=None, min_length=1, max_length=128)
    notify_within_minutes: Optional[int] = Field(default=None, ge=1, le=10080)
    category:              Optional[StakeholderMatrixCategory] = None
    required:              Optional[bool] = None
    incident_types:        Optional[list[IncidentType]] = Field(default=None, max_length=20,
                                                                description="Replace the type filter; [] = every type.")


class StakeholderMatrixRuleList(BaseModel):
    items: list[StakeholderMatrixRuleOut]
