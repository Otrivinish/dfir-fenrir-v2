"""DFIR-FENRIR v2 — backend entrypoint."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles

from api_tokens.routes import router as api_tokens_router, admin_router as api_tokens_admin_router
from audit.middleware import AuditContextMiddleware
from audit_export.routes import (
    global_router as audit_export_global_router,
    incident_router as audit_export_incident_router,
)
from audit_export.download import router as audit_export_download_router
from audit_export.signing import (
    assert_signing_key_configured,
    public_key_fingerprint,
    public_key_pem,
)
from le_package.routes import router as le_package_router, ack_router as le_package_ack_router
from rate_limit.middleware import RateLimitMiddleware
from auth.bootstrap import bootstrap_on_startup
from auth.routes import router as auth_router
from core.config import settings
from core.database import SessionLocal, init_db
from entities.routes import router as entities_router
from files.routes import router as files_router
from evidence.crypto import assert_kek_configured
from evidence.download import router as exports_download_router
from evidence.routes import router as evidence_router
from incidents.routes import router as incidents_router
from iocs.exports import router as iocs_exports_router
from iocs.routes import router as iocs_router
from playbook.seeds import seed_playbook_templates
from threat_intel.seeds import fix_bad_feeds
from playbook.tasks import router as playbook_tasks_router
from playbook.templates import router as playbook_templates_router
from artifacts.routes import router as artifacts_router
from collectors.routes import (
    router as collectors_router,
    download_router as collectors_download_router,
    admin_router as collectors_admin_router,
)
from comms.routes import router as comms_router
from mitre.routes import router as mitre_router, global_router as mitre_global_router
from respond.routes import router as respond_router
from forensic.routes import router as forensic_router
from osint.routes import router as osint_router
from osint.session_routes import router as osint_session_router
from reports.routes import router as reports_router
from timeline.routes import router as timeline_router
from lolbins.routes import router as lolbins_router
from pcap.routes import router as pcap_router
from email_analyzer.routes import router as email_analyzer_router
from post_incident.routes import router as post_incident_router
from yara_rules.routes import global_router as yara_global_router
from yara_rules.routes import incident_router as yara_incident_router
from dashboard.routes import router as dashboard_router
from detections.routes import router as detections_router
from legal.routes import router as legal_router
from costs.routes import router as costs_router
from roles.routes import router as roles_router
from audit.routes import router as audit_log_router, global_router as audit_global_router
from stakeholders.routes import router as stakeholders_router
from stakeholder_matrix.routes import router as stakeholder_matrix_router
from correlations.routes import incident_router as correlations_incident_router
from correlations.routes import router as correlations_router
from threat_intel.routes import router as threat_intel_router
from sessions_api.routes import router as sessions_router, global_router as sessions_global_router
from settings_api.routes import router as settings_router
from teams.routes import router as teams_router
from users.routes import router as users_router
from validated_tools.routes import router as validated_tools_router
from audit_monitor.routes import router as audit_anchors_router
from warroom.routes import router as warroom_router
from notifications.routes import router as notifications_router
from assignments.routes import router as assignments_router
from backup.routes import router as backup_router
from storage.routes import router as storage_router
from presence.routes import router as presence_router
from threat_actors.routes import global_router as threat_actors_global_router
from threat_actors.routes import incident_router as threat_actors_incident_router
from threat_actors.seeds import seed_threat_actors
from tags.routes import router as tags_router
from on_call.routes import router as on_call_router
from handoffs.routes import router as handoffs_router, pending_router as handoffs_pending_router
from search.routes import router as search_router
from affected_systems.routes import router as affected_systems_router
from roster.routes import router as roster_router, incident_router as roster_incident_router
from integrations.routes import router as integrations_router
from inbound_webhooks.routes import router as inbound_webhooks_router
from metrics.routes import router as metrics_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail-fast on a weak SECRET_KEY — it derives the Fernet key that encrypts
    # TOTP secrets at rest (core/security.py). Unlike the KEK/signing keys it
    # ships with a *working* insecure default, so the app would otherwise boot
    # silently with a publicly-known key and every TOTP seed would be trivially
    # decryptable from a DB/backup leak (MFA defeat).
    if settings.secret_key in ("", "change_me_to_a_long_random_value") or len(settings.secret_key) < 32:
        raise RuntimeError(
            "SECRET_KEY must be set to a unique value of at least 32 chars "
            "(generate: python3 -c \"import secrets; print(secrets.token_hex(64))\")."
        )
    # Fail-fast on evidence misconfig — refuse to serve if AES-256 KEK is bad.
    assert_kek_configured()
    # Fail-fast on audit-export misconfig — refuse to serve without Ed25519 key.
    assert_signing_key_configured()
    await init_db()
    async with SessionLocal() as db:
        await bootstrap_on_startup(db)
        await seed_playbook_templates(db)
        await fix_bad_feeds(db)
        await seed_threat_actors(db)
    # Background syslog forwarder — idles when disabled, picks up config changes
    # via /api/integrations/syslog PUT calling forwarder.reload().
    from syslog_forwarder import start_forwarder, stop_forwarder
    await start_forwarder()
    try:
        yield
    finally:
        await stop_forwarder()


def _operation_id(route: "APIRoute") -> str:
    """operationId = handler function name → clean, stable tool names for MCP
    generators that consume /api/openapi.json. Names are unique across the API
    (the few collisions carry an explicit operation_id= on the decorator)."""
    return route.name


app = FastAPI(
    title="DFIR-FENRIR v2",
    version="2.0.0",
    # Default unauthenticated docs are disabled — auth-gated routes are mounted below.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
    generate_unique_id_function=_operation_id,
)

_allowed_hosts = [h.strip() for h in settings.allowed_hosts.split(",") if h.strip()]
if not _allowed_hosts:
    raise RuntimeError("ALLOWED_HOSTS must be a non-empty comma-separated list (e.g. 'localhost,127.0.0.1')")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Audit context — runs before routes so write_audit can read request_id / path / ip.
app.add_middleware(AuditContextMiddleware)
# Rate limit — outermost so excluded paths are decided before any auth resolution.
# Starlette runs middleware bottom-up at request time, so adding last = runs first.
app.add_middleware(RateLimitMiddleware)


# ─── Health ──────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "service": "fenrir-v2-backend"}


@app.get("/api/version")
async def version() -> dict:
    return {
        "version": app.version,
        "title":   app.title,
        # Audit-export verifiers pin this. Public, no auth — by design.
        "audit_signing": {
            "algorithm":   "ed25519",
            "public_key":  public_key_pem(),
            "fingerprint": public_key_fingerprint(),
        },
    }


# ─── OpenAPI + Swagger / ReDoc — auth-gated ─────────────────────────────────
# Default FastAPI exposes these unauthenticated. We disabled the defaults
# (FastAPI(docs_url=None, …)) and re-mount them with auth so the API surface
# isn't leaked to unauthenticated callers.
#
# Visibility model:
#   • /api/openapi.json — any authenticated user (cookie OR Bearer). MCP
#     clients need this to generate tools, so we don't lock it to admin.
#   • /api/docs, /api/redoc — admin only. Surfaced inside the SPA under
#     /admin/api-docs via an iframe (Caddy's CSP allows frame-ancestors 'self').

from fastapi import Depends
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from starlette.responses import JSONResponse
from auth.deps import current_user, require_admin
from models import User


@app.get("/api/openapi.json", include_in_schema=False)
async def openapi_spec(_: User = Depends(current_user)) -> JSONResponse:
    spec = get_openapi(
        title=app.title, version=app.version, routes=app.routes,
        description=app.description, terms_of_service=app.terms_of_service,
        contact=app.contact, license_info=app.license_info,
    )
    return JSONResponse(spec)


# Self-hosted Swagger UI + ReDoc bundles (see backend/Dockerfile). Served under
# /api/_static/ so the Caddy CSP doesn't need cdn.jsdelivr.net or Google Fonts.
app.mount("/api/_static", StaticFiles(directory="/app/static"), name="api-static")


@app.get("/api/docs", include_in_schema=False)
async def swagger_ui(_: User = Depends(require_admin)):
    return get_swagger_ui_html(
        openapi_url="/api/openapi.json",
        title=f"{app.title} — API docs",
        swagger_js_url="/api/_static/swagger-ui-bundle.js",
        swagger_css_url="/api/_static/swagger-ui.css",
        swagger_favicon_url="/favicon.ico",
    )


@app.get("/api/redoc", include_in_schema=False)
async def redoc_ui(_: User = Depends(require_admin)):
    return get_redoc_html(
        openapi_url="/api/openapi.json",
        title=f"{app.title} — API reference",
        redoc_js_url="/api/_static/redoc.standalone.js",
        redoc_favicon_url="/favicon.ico",
        with_google_fonts=False,
    )


# ─── Auth + identity routers ────────────────────────────────────────────────

app.include_router(auth_router,      prefix="/api/auth",               tags=["Auth"])
app.include_router(api_tokens_router,        prefix="/api/tokens",       tags=["API Tokens"])
app.include_router(api_tokens_admin_router,  prefix="/api/admin",        tags=["Admin"])
app.include_router(users_router,     prefix="/api/users",              tags=["Users"])
app.include_router(validated_tools_router, prefix="/api/validated-tools", tags=["Validated Tools"])
app.include_router(audit_anchors_router,   prefix="/api/admin",            tags=["Audit"])
app.include_router(sessions_router,  prefix="/api/sessions",           tags=["Sessions"])
app.include_router(settings_router,  prefix="/api/settings",           tags=["Settings"])
app.include_router(teams_router,     prefix="/api/teams",              tags=["Teams"])
app.include_router(roles_router,     prefix="/api/operational-roles",  tags=["Operational Roles"])
app.include_router(incidents_router, prefix="/api/incidents",          tags=["Incidents"])
app.include_router(iocs_exports_router,          prefix="/api/incidents", tags=["IOC Exports"])
# correlations per-incident: literal /iocs/correlations must precede parametric /iocs/{ioc_id}
app.include_router(correlations_incident_router, prefix="/api/incidents", tags=["Correlations"])
app.include_router(iocs_router,                  prefix="/api/incidents", tags=["IOCs"])
app.include_router(entities_router,  prefix="/api/incidents",          tags=["Entities"])
app.include_router(files_router,     prefix="/api/incidents",          tags=["Files"])
app.include_router(evidence_router,  prefix="/api/incidents",          tags=["Evidence"])
app.include_router(playbook_tasks_router,     prefix="/api/incidents",          tags=["Playbook"])
app.include_router(playbook_templates_router, prefix="/api/playbook-templates", tags=["Playbook templates"])
app.include_router(respond_router,            prefix="/api/incidents",          tags=["Respond"])
app.include_router(comms_router,             prefix="/api/incidents",          tags=["Comms"])
app.include_router(timeline_router,          prefix="/api/incidents",          tags=["Timeline"])
app.include_router(forensic_router,          prefix="/api/incidents",          tags=["Forensic"])
app.include_router(mitre_router,             prefix="/api/incidents",          tags=["MITRE ATT&CK"])
app.include_router(mitre_global_router,      prefix="/api/mitre",              tags=["MITRE ATT&CK"])
app.include_router(lolbins_router,           prefix="/api/lolbins",            tags=["LOLBins"])
app.include_router(osint_router,             prefix="/api/osint",              tags=["OSINT"])
app.include_router(osint_session_router,     prefix="/api/incidents",           tags=["OSINT"])
app.include_router(pcap_router,              prefix="/api/incidents",           tags=["PCAP"])
app.include_router(email_analyzer_router,    prefix="/api/incidents",           tags=["Email"])
app.include_router(artifacts_router,         prefix="/api/incidents",           tags=["Artifacts"])
app.include_router(collectors_router,        prefix="/api/incidents",           tags=["Collections"])
app.include_router(collectors_download_router, prefix="/api/collections",       tags=["Collections"])
app.include_router(collectors_admin_router,  prefix="/api/admin",               tags=["Collections"])
app.include_router(post_incident_router,     prefix="/api/incidents",           tags=["Post-Incident"])
app.include_router(reports_router,           prefix="/api/incidents",           tags=["Reports"])
app.include_router(yara_global_router,       prefix="/api/yara",                tags=["YARA"])
app.include_router(yara_incident_router,     prefix="/api/incidents",           tags=["YARA"])
app.include_router(detections_router,        prefix="/api/incidents",           tags=["Detections"])
app.include_router(legal_router,             prefix="/api/incidents",           tags=["Legal"])
app.include_router(le_package_router,        prefix="/api/incidents",           tags=["LE Package"])
# Public LE-package ack — no /api/incidents prefix because recipients hit it
# directly from a printed handoff form / QR code (no platform account).
app.include_router(le_package_ack_router, tags=["LE Package"])
app.include_router(costs_router,             prefix="/api/incidents",           tags=["Costs"])
app.include_router(audit_log_router,         prefix="/api/incidents",           tags=["Audit Log"])
app.include_router(audit_export_incident_router, prefix="/api/incidents",        tags=["Audit Export"])
app.include_router(stakeholders_router,      prefix="/api/incidents",           tags=["Stakeholders"])
app.include_router(stakeholder_matrix_router, prefix="/api/stakeholder-matrix",  tags=["Stakeholder Matrix"])
app.include_router(assignments_router,       prefix="/api/incidents",           tags=["Assignments"])
app.include_router(presence_router,          prefix="/api/incidents",           tags=["Presence"])
# threat actor attribution: literal /attributions/suggest must precede /{attribution_id}
app.include_router(threat_actors_incident_router, prefix="/api/incidents",      tags=["Attribution"])
# warroom: literal /warroom/messages + /warroom/online + /warroom/ws under /{incident_id}
app.include_router(warroom_router,           prefix="/api/incidents",           tags=["War Room"])
app.include_router(dashboard_router,       prefix="/api/dashboard",      tags=["Dashboard"])
app.include_router(metrics_router,         prefix="/api/metrics",         tags=["Metrics"])
app.include_router(correlations_router,    prefix="/api/correlations",   tags=["Correlations"])
app.include_router(threat_intel_router,    prefix="/api/threat-intel",   tags=["Threat Intel"])
# Notifications: REST under /api, WebSocket at /api/notifications/ws
app.include_router(notifications_router,   prefix="/api",                tags=["Notifications"])
# Token-gated, auth-free. Recipient pastes /api/exports/{token} to download.
app.include_router(exports_download_router, prefix="/api/exports",     tags=["Exports"])
# Token-gated audit-log export download. Sibling endpoint with the same shape.
app.include_router(audit_export_download_router, prefix="/api/audit-exports", tags=["Audit Export"])
app.include_router(threat_actors_global_router, prefix="/api",               tags=["Threat Actors"])
app.include_router(tags_router,             prefix="/api/tags",          tags=["Tags"])
app.include_router(backup_router,           tags=["Admin"])
app.include_router(storage_router,          tags=["Admin"])
app.include_router(audit_global_router,    prefix="/api/admin",  tags=["Admin"])
app.include_router(audit_export_global_router, prefix="/api/admin", tags=["Audit Export"])
app.include_router(sessions_global_router, prefix="/api/admin",  tags=["Admin"])
app.include_router(on_call_router,         prefix="/api/on-call",    tags=["On-Call"])
app.include_router(handoffs_router,        prefix="/api/incidents",  tags=["Handoffs"])
app.include_router(handoffs_pending_router, prefix="/api",           tags=["Handoffs"])
app.include_router(search_router,                                    tags=["Search"])
app.include_router(affected_systems_router,  prefix="/api/incidents", tags=["Affected Systems"])
app.include_router(roster_router,            prefix="/api/roster",    tags=["Roster"])
app.include_router(roster_incident_router,   prefix="/api/incidents", tags=["Roster"])
app.include_router(integrations_router,      prefix="/api/integrations", tags=["Integrations"])
app.include_router(inbound_webhooks_router,  prefix="/api/webhooks",    tags=["Inbound Webhooks"])
