"""Application settings loaded from env."""
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, case_sensitive=False)

    # Database
    database_url: str = "postgresql+asyncpg://fenrir:fenrir@postgres:5432/fenrir"

    # Redis
    redis_url: str = "redis://redis:6379"
    redis_password: str | None = None

    # App
    secret_key: str = "change_me_to_a_long_random_value"
    session_ttl_seconds: int = 8 * 60 * 60       # 8h (hard cap)
    # Rolling idle window — sessions are revoked after this many minutes
    # without a request, even if session_ttl_seconds hasn't elapsed. Closes
    # the stolen-cookie window when a browser session is left open unattended.
    inactivity_timeout_minutes: int = 30
    max_sessions_per_user: int = 10

    # Auth
    password_min_length: int = 12
    password_max_length: int = 128
    totp_max_failures: int = 5
    totp_lockout_seconds: int = 15 * 60          # 15 min
    login_max_failures: int = 10
    login_lockout_seconds: int = 15 * 60
    # Org-wide TOTP policy. When True (default), the first-run admin and any
    # admin-created users are flagged `force_totp_enrol=True` and gated through
    # /totp/enrol before they can use the app. When False, TOTP is opt-in:
    # users can enrol from Settings on their own schedule.
    totp_required: bool = True

    # CORS / hosts
    cors_origins: str = "https://localhost"
    allowed_hosts: str = "localhost,127.0.0.1"

    # Rate limit — generic per-credential / per-IP token bucket. Per-username
    # login lockouts (above) are orthogonal: they protect a single account from
    # credential stuffing; this caps total request volume per caller.
    rate_limit_enabled: bool = True
    rate_limit_anon_per_min: int = 60      # unauth: 1/sec sustained
    rate_limit_anon_burst:   int = 30      # bucket capacity
    rate_limit_auth_per_min: int = 600     # auth:  10/sec sustained
    rate_limit_auth_burst:   int = 120     # bucket capacity

    # Bootstrap
    bootstrap_token_file: str = "/app/data/bootstrap_token.txt"

    # Quarantine — malware artifacts
    quarantine_path: str = "/quarantine"
    artifact_max_upload_bytes: int = 500 * 1024 * 1024   # 500 MiB

    # U1 — signed offline collectors (Velociraptor-wrapped). Packages are
    # generated offline in the backend container and stored under
    # {quarantine_path}/_collections/. Generation degrades gracefully to a 503
    # until both binaries are bundled in the image (see docs/u1-collector-spike.md).
    velociraptor_linux_bin:   str = "/opt/velociraptor/velociraptor-linux-amd64"     # the builder
    velociraptor_windows_bin: str = "/opt/velociraptor/velociraptor-windows-amd64.exe"  # informational
    # macOS (Apple Silicon). Velociraptor can't repack Mach-O, so macOS packages
    # ship a "generic collector" (embedded config) PLUS this darwin binary +
    # a launcher; the responder runs them together. Bundled in the image.
    velociraptor_darwin_arm_bin: str = "/opt/velociraptor/velociraptor-darwin-arm64"
    # Pre-warmed Velociraptor datastore — baked at image build (which has
    # internet) with the Windows binary tool cached in public/. Runtime
    # generation points `collector --datastore` here so it repacks the Windows
    # collector fully OFFLINE (no download), the way air-gapped VR servers work.
    velociraptor_datastore:   str = "/opt/velociraptor/datastore"
    # Bundled Velociraptor version, stamped on every package for court
    # reproducibility AND used for stale/insecure detection: a package built
    # with a version != this is superseded and its (~60 MB) binary swept. Empty
    # disables stale-superseding (dev only).
    velociraptor_version: str = ""
    # Retention — a repacked collector is ~60 MB, so unbounded generation fills
    # the quarantine volume. TTL expires the one-time download; the cap bounds
    # un-downloaded packages per incident; the sweep reclaims both.
    collection_package_ttl_hours: int = 24
    collection_max_active_per_incident: int = 10
    # Ingest (U1.2) — responder uploads the collector's output ZIP. Full
    # collections are larger than malware samples, so a bigger cap than artifacts.
    collection_output_max_bytes: int = 2 * 1024 * 1024 * 1024   # 2 GiB

    # Evidence — chain of custody
    # 64 hex chars = 32 bytes = AES-256. Generate with `openssl rand -hex 32`.
    # Required at startup — backend refuses to boot without it (Evidence
    # routes encrypt files at rest with this key).
    evidence_kek: str | None = None

    # Audit log export signing — Ed25519 seed (32 bytes, base64).
    # Required at startup — backend refuses to boot without it (signed PDF
    # audit exports use this key to sign the canonical JSONL slice).
    # Generate: scripts/generate-audit-key.sh
    audit_signing_key: str | None = None
    # Local directory for encrypted evidence files. In Docker this is the
    # mounted /evidence volume (separate, non-root, encrypted at rest). The
    # env var is `EVIDENCE_PATH` to match the rest of the *_PATH env naming.
    evidence_path: str = "/evidence"
    # Hard cap on per-file upload size (bytes). Larger files = phase-2.
    evidence_max_upload_bytes: int = 1024 * 1024 * 1024   # 1 GiB

    # RFC 3161 trusted timestamping (GS-4) — optional + best-effort. When unset,
    # seals/manifests/exports fall back to the server clock (recorded as such) and
    # nothing blocks. Only the hash is sent to the TSA.
    tsa_url: Optional[str] = None
    tsa_timeout_seconds: int = 5

    # OSINT enrichment API keys (all optional — feature degrades gracefully).
    # DB-stored keys (admin Settings page) take precedence; these serve as
    # env-var fallbacks for deployments that pre-configure keys via compose.
    greynoise_api_key:  Optional[str] = None
    abuseipdb_api_key:  Optional[str] = None
    virustotal_api_key: Optional[str] = None
    shodan_api_key:     Optional[str] = None
    urlscan_api_key:    Optional[str] = None

    # Additional volume paths
    branding_path: str = "/branding"
    reports_path:  str = "/generated_reports"
    logs_path:     str = "/asset_logs"

    # Backup
    backup_path: str = "/backups"

    # Postgres password for pg_dump in the backup endpoint.
    # In Docker this is POSTGRES_PASSWORD; fallback: parse from database_url.
    postgres_password: Optional[str] = None

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def pg_password(self) -> str:
        """Resolved Postgres password for subprocess tools (pg_dump)."""
        if self.postgres_password:
            return self.postgres_password
        # Parse from database_url: postgresql+asyncpg://user:password@host/db
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.database_url)
            return parsed.password or ""
        except Exception:
            return ""


settings = Settings()
