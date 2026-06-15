"""Build a signed Velociraptor offline-collector package.

Air-gap-safe + offline: shells out to the *bundled* Velociraptor binaries (no
download), builds a Windows collector from the Linux backend via cross-platform
repack (validated in docs/u1-collector-spike.md), wraps it with an Ed25519-signed
manifest, and writes a one-file package ZIP onto the quarantine volume.

We own the provenance layer only — Velociraptor does the forensically-sound
collection. The manifest binds the package to the incident at generation time;
the public key/fingerprint are served at GET /api/version for external verifiers.

Degrades cleanly: if the binaries are not bundled, `build_package` raises
CollectorBuildError and the route returns 503 — nothing fake is ever produced.

Scope note (U1.1): the *collection output* X.509 encryption recommended by the
spike is a U1.2 concern (it pairs with ingest/decrypt). U1.1 ships generation +
signed-manifest provenance + one-time download.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import secrets
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from audit_export.signing import (
    public_key_fingerprint,
    public_key_pem,
    sign_bytes,
)
from collectors.crypto import generate_keypair_and_cert
from core.config import settings

MANIFEST_VERSION = "1.0"
_BUILD_TIMEOUT_S = 600   # collector repack is fast, but bound it


class CollectorBuildError(RuntimeError):
    """Raised when the bundled Velociraptor binaries are missing or the build fails."""


# ─── Paths (all under the quarantine volume, traversal-guarded) ──────────────

def collections_root() -> Path:
    # Leading underscore keeps these out of the per-incident artifact dirs
    # (which are named by bare incident UUID).
    return Path(settings.quarantine_path) / "_collections"


def package_dir(incident_id: uuid.UUID) -> Path:
    return collections_root() / str(incident_id)


def package_path(incident_id: uuid.UUID, package_id: uuid.UUID) -> Path:
    p = (package_dir(incident_id) / f"{package_id}.zip").resolve()
    root = collections_root().resolve()
    if not str(p).startswith(str(root)):
        raise CollectorBuildError("Invalid package path")
    return p


def binaries_present(platform: str | None = None) -> bool:
    # The Linux builder + the pre-warmed datastore (cached Windows tool) are what
    # generation needs for any platform. macOS additionally ships the darwin
    # binary inside the package, so its presence is required for that platform.
    if not (
        Path(settings.velociraptor_linux_bin).is_file()
        and Path(settings.velociraptor_datastore).is_dir()
    ):
        return False
    if platform == "macos_arm":
        return Path(settings.velociraptor_darwin_arm_bin).is_file()
    return True


# ─── Velociraptor invocation ─────────────────────────────────────────────────
# Validated against v0.76.6 (docs/u1-collector-spike.md): the `collector`
# command takes a spec FILE (no --binary/--output flags); the spec carries the
# target OS, the artifact dict, and the output name; the collector binary lands
# at {datastore}/{OptCollectorTemplate}. The Windows binary is sourced from the
# datastore's cached tool (pre-warmed at image build) → fully offline.

_OS_TOKEN = {"windows": "Windows", "macos_arm": "MacOSArm"}


def _spec_yaml(platform: str, artifacts: list[str], collector_name: str, cert_pem: str) -> str:
    """Collector spec. `Artifacts` is a DICT (name → params); empty params = {}.
    Output is X.509-encrypted to `cert_pem` (the responder's media never holds
    plaintext). All values are strings (Velociraptor requirement)."""
    os_token = _OS_TOKEN.get(platform, "Windows")
    lines = [f"OS: {os_token}", "Artifacts:"]
    lines += [f"  {name}: {{}}" for name in artifacts]
    lines += ["Target: ZIP", "EncryptionScheme: X509", "EncryptionArgs:", "  public_key: |"]
    lines += [f"    {line}" for line in cert_pem.strip().splitlines()]
    lines += [f'OptCollectorTemplate: "{collector_name}"']
    return "\n".join(lines) + "\n"


def _build_collector_exe(
    platform: str, artifacts: list[str], collector_name: str, out_path: Path, cert_pem: str
) -> None:
    if not binaries_present():
        raise CollectorBuildError(
            "Velociraptor is not bundled. The backend image must carry "
            f"{settings.velociraptor_linux_bin} and a pre-warmed datastore at "
            f"{settings.velociraptor_datastore} — see docs/u1-collector-spike.md."
        )
    with tempfile.TemporaryDirectory() as td:
        spec_path = Path(td) / "collector_spec.yaml"
        spec_path.write_text(_spec_yaml(platform, artifacts, collector_name, cert_pem))
        try:
            proc = subprocess.run(
                [
                    settings.velociraptor_linux_bin, "--nobanner",
                    "collector", str(spec_path),
                    "--datastore", settings.velociraptor_datastore,
                ],
                capture_output=True, text=True, timeout=_BUILD_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise CollectorBuildError(f"Velociraptor build failed to launch: {e}") from e
    if proc.returncode != 0:
        raise CollectorBuildError(
            f"Velociraptor collector build failed (exit {proc.returncode}): "
            f"{(proc.stderr or proc.stdout or '').strip()[:500]}"
        )
    # The collector lands in the datastore under the requested name; move it out.
    produced = Path(settings.velociraptor_datastore) / collector_name
    if not produced.is_file():
        raise CollectorBuildError("Velociraptor reported success but produced no collector")
    shutil.move(str(produced), str(out_path))


# ─── Package assembly (sync — run in a thread via run_in_executor) ───────────

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


_RUN_ME = """\
DFIR-FENRIR v2 — Offline Collection Package
===========================================

Incident : {ref} — {title}
Package   : {name} ({profile})
Built     : {created_at}
Velociraptor version: {vr_version}
Collector SHA-256: {collector_sha256}

WHAT THIS IS
------------
A self-contained Velociraptor forensic collector, scoped to the incident above
and signed by your FENRIR instance (see MANIFEST.json / MANIFEST.sig).

HOW TO RUN (on the target host, as Administrator)
-------------------------------------------------
1. Copy this whole folder to the target (responder media — do NOT download it
   from the internet on the target).
2. Your AV/EDR will likely flag the collector. This is expected for any IR
   collector. Pre-clear it by allow-listing the SHA-256 above.
3. Run the collector executable as Administrator. It writes a
   Collection_<host>_<timestamp>.zip beside itself.
4. Carry that Collection ZIP back and upload it in FENRIR under
   Incident → Forensic → Collections → Ingest results.

The signed MANIFEST proves this package was issued by your FENRIR instance for
this incident. Do not modify the files in this package.
"""


_RUN_ME_MACOS = """\
DFIR-FENRIR v2 — Offline Collection Package (macOS / Apple Silicon)
==================================================================

Incident : {ref} — {title}
Package   : {name} ({profile})
Built     : {created_at}
Velociraptor version: {vr_version}
Collector SHA-256: {collector_sha256}

WHAT THIS IS
------------
A Velociraptor "generic collector" scoped to the incident above, signed by your
FENRIR instance (see MANIFEST.json / MANIFEST.sig). macOS binaries can't be
repacked, so this package ships the collection definition PLUS the collector
engine; they run together.

Files:
  - {collector_filename}        the collection definition (embedded config)
  - velociraptor-darwin-arm64   the collector engine (Apple Silicon)

HOW TO RUN (on the target Mac, as root)
---------------------------------------
1. Copy this whole folder to the target (responder media — do NOT download
   anything from the internet on the target).
2. Gatekeeper + AV/EDR will flag the binary. This is expected. Clear quarantine
   and make it executable:
       xattr -dr com.apple.quarantine velociraptor-darwin-arm64
       chmod +x velociraptor-darwin-arm64
3. Run the collection:
       sudo ./velociraptor-darwin-arm64 -- --embedded_config {collector_filename}
   It writes a Collection-<host>-<timestamp>.zip beside itself
   (X.509-encrypted to your FENRIR instance).
4. Carry that Collection ZIP back and upload it in FENRIR under
   Incident → Forensic → Collections → Ingest results.

The signed MANIFEST proves this package was issued by your FENRIR instance for
this incident. Do not modify the files in this package.
"""


def build_package(
    *,
    incident_id: uuid.UUID,
    incident_ref: str,
    incident_title: str,
    package_id: uuid.UUID,
    name: str,
    platform: str,
    profile: str,
    artifacts: list[str],
    created_by: str,
) -> dict:
    """Build the collector, sign a manifest, assemble the package ZIP on disk.

    Returns a metadata dict for the CollectionPackage row. Synchronous — call
    via loop.run_in_executor. Raises CollectorBuildError on any failure.
    """
    created_at = datetime.now(timezone.utc)
    out_dir = package_dir(incident_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Per-package X.509 keypair — the collector encrypts its output to this cert;
    # the private key is wrapped under EVIDENCE_KEK and stored on the row.
    cert_pem, cert_fingerprint, wrapped_private_key = generate_keypair_and_cert(
        f"fenrir-collection-{package_id}"
    )

    with tempfile.TemporaryDirectory() as td:
        built = Path(td) / "collector.out"
        # Datastore output name is the package id (unique — no cross-build
        # collision). For Windows this is a repacked .exe; for macOS it's a
        # generic-collector script (Velociraptor can't repack Mach-O).
        _build_collector_exe(platform, artifacts, str(package_id), built, cert_pem)
        collector_sha256 = _sha256_file(built)

        # Per-platform package layout: macOS ships the generic collector + the
        # darwin engine + a launcher; Windows ships the self-contained exe.
        extra_files: list[tuple[Path, str]] = []
        binary_sha256 = None
        if platform == "macos_arm":
            in_zip_name = f"collector_{incident_ref}_macos"
            run_me_tpl  = _RUN_ME_MACOS
            darwin_bin  = Path(settings.velociraptor_darwin_arm_bin)
            if not darwin_bin.is_file():
                raise CollectorBuildError(
                    f"macOS binary not bundled at {darwin_bin} — see docs/u1-collector-spike.md."
                )
            extra_files.append((darwin_bin, "velociraptor-darwin-arm64"))
            binary_sha256 = _sha256_file(darwin_bin)
        else:
            in_zip_name = f"Collector_{incident_ref}_windows.exe"
            run_me_tpl  = _RUN_ME

        manifest = {
            "version": MANIFEST_VERSION,
            "incident": {
                "id":    str(incident_id),
                "ref":   incident_ref,
                "title": incident_title,
            },
            "package": {
                "id":                   str(package_id),
                "name":                 name,
                "platform":             platform,
                "profile":              profile,
                "artifacts":            artifacts,
                "velociraptor_version": settings.velociraptor_version or "unknown",
                "collector_filename":   in_zip_name,
                "collector_sha256":     collector_sha256,
                "engine_binary_sha256": binary_sha256,   # macOS only
                "encryption":           "X509",
                "cert_fingerprint":     cert_fingerprint,
                "created_at":           created_at.isoformat(),
                "created_by":           created_by,
            },
            "signing": {
                "algorithm":      "Ed25519",
                "fingerprint":    public_key_fingerprint(),
                "public_key_pem": public_key_pem(),
            },
        }
        # Canonical bytes are what we sign + hash. The pretty MANIFEST.json in
        # the ZIP is for humans; verification re-derives the canonical form.
        canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest_sha256 = hashlib.sha256(canonical).hexdigest()
        signature_b64 = base64.b64encode(sign_bytes(canonical)).decode("ascii")

        # Assemble the package ZIP in memory, then write once.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(built, in_zip_name)
            for src, arcname in extra_files:
                zf.write(src, arcname)
            zf.writestr("MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True))
            zf.writestr("MANIFEST.canonical.json", canonical.decode())
            zf.writestr("MANIFEST.sig", signature_b64 + "\n")
            zf.writestr("RUN_ME.txt", run_me_tpl.format(
                ref=incident_ref, title=incident_title, name=name, profile=profile,
                created_at=created_at.isoformat(), vr_version=settings.velociraptor_version or "unknown",
                collector_sha256=collector_sha256, collector_filename=in_zip_name,
            ))
        package_bytes = buf.getvalue()

    final_path = package_path(incident_id, package_id)
    final_path.write_bytes(package_bytes)
    package_sha256 = hashlib.sha256(package_bytes).hexdigest()

    token = secrets.token_urlsafe(32)
    expires_at = created_at + timedelta(hours=settings.collection_package_ttl_hours)

    return {
        "velociraptor_version": settings.velociraptor_version or None,
        "manifest_sha256":      manifest_sha256,
        "package_sha256":       package_sha256,
        "signature_b64":        signature_b64,
        "signing_fingerprint":  public_key_fingerprint(),
        "token":                token,
        "token_expires_at":     expires_at,
        # X.509 — wrapped private key (decrypts the ingested collection) + cert fp.
        "enc_private_key":      wrapped_private_key,
        "cert_fingerprint":     cert_fingerprint,
        # Path relative to quarantine_path, for storage parity with artifacts.
        "file_path":            str(final_path.relative_to(Path(settings.quarantine_path))),
        "file_size":            len(package_bytes),
        "created_at":           created_at,
    }
