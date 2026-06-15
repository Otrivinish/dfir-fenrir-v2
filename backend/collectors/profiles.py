"""Bundled collection profiles — Velociraptor artifact selections per platform.

Single source of truth for what each profile collects; exposed read-only via
the API so the frontend shows exactly what a package will run. Windows-first
(U1.1); Linux/macOS profiles land in U1.5. Artifact names are Velociraptor's
built-in catalog — validate against the pinned binary in the bundling step
(see docs/u1-collector-spike.md).
"""
from __future__ import annotations

PROFILES: dict[str, dict[str, dict]] = {
    "windows": {
        "triage": {
            "label": "Windows Triage",
            "description": (
                "Fast forensic triage — event logs, registry, execution + "
                "persistence artefacts. Minutes to run, low footprint."
            ),
            # Validated against Velociraptor v0.76.6's built-in artifact set
            # (docs/u1-collector-spike.md). KapeFiles.Targets is not built in.
            "artifacts": [
                "Windows.EventLogs.Evtx",
                "Windows.Forensics.Prefetch",
                "Windows.Registry.NTUser",
                "Windows.Forensics.Amcache",
                "Windows.System.Pslist",
            ],
        },
        "full": {
            "label": "Windows Full",
            "description": (
                "Comprehensive collection — adds MFT, USN journal, scheduled "
                "tasks, services and network state. Larger + slower."
            ),
            "artifacts": [
                "Windows.EventLogs.Evtx",
                "Windows.Forensics.Prefetch",
                "Windows.Registry.NTUser",
                "Windows.Forensics.Amcache",
                "Windows.System.Pslist",
                "Windows.NTFS.MFT",
                "Windows.Forensics.Usn",
                "Windows.System.TaskScheduler",
                "Windows.System.Services",
                "Windows.Network.Netstat",
            ],
        },
    },
    # Apple Silicon (arm64). Velociraptor can't repack Mach-O — these packages
    # ship a generic collector + the bundled darwin-arm64 binary + a launcher.
    "macos_arm": {
        "triage": {
            "label": "macOS Triage (Apple Silicon)",
            "description": (
                "Fast macOS triage — processes, users, login items, install "
                "history and quarantined-download records."
            ),
            # Validated against Velociraptor v0.76.6's built-in artifact set.
            "artifacts": [
                "MacOS.Sys.Pslist",
                "MacOS.System.Users",
                "MacOS.Detection.Autoruns",
                "MacOS.Detection.InstallHistory",
                "MacOS.System.QuarantineEvents",
            ],
        },
        "full": {
            "label": "macOS Full (Apple Silicon)",
            "description": (
                "Comprehensive macOS collection — adds packages, plists, TCC, "
                "FSEvents, network state, dock and browser history."
            ),
            "artifacts": [
                "MacOS.Sys.Pslist",
                "MacOS.System.Users",
                "MacOS.Detection.Autoruns",
                "MacOS.Detection.InstallHistory",
                "MacOS.System.QuarantineEvents",
                "MacOS.System.Packages",
                "MacOS.System.Plist",
                "MacOS.System.TCC",
                "MacOS.Forensics.FSEvents",
                "MacOS.Network.Netstat",
                "MacOS.System.Dock",
                "MacOS.Applications.Chrome.History",
            ],
        },
    },
}

PLATFORMS = tuple(PROFILES.keys())


def get_profile(platform: str, profile: str) -> dict | None:
    return PROFILES.get(platform, {}).get(profile)


def list_profiles() -> list[dict]:
    out = []
    for platform, profs in PROFILES.items():
        for key, p in profs.items():
            out.append({
                "platform":    platform,
                "profile":     key,
                "label":       p["label"],
                "description": p["description"],
                "artifacts":   p["artifacts"],
            })
    return out
