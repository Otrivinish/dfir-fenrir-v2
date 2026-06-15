#!/usr/bin/env bash
# Generate the Ed25519 signing key used by signed audit-log exports and
# print it in the form expected by the backend env.
#
# Idempotent: if AUDIT_SIGNING_KEY is already set in ./.env (looked at from
# the repo root), this script bails without touching anything. Pass --force
# to override (use with care — rotating the key invalidates every previously
# issued audit-export signature).
#
# Output: the public key fingerprint + base64 seed line to copy into .env.
set -euo pipefail

force=0
for arg in "$@"; do
  case "$arg" in
    --force) force=1 ;;
    -h|--help)
      cat <<'EOF'
generate-audit-key.sh — Ed25519 audit-export signing key generator

Usage:
  ./scripts/generate-audit-key.sh          # generate, print, refuse if already set
  ./scripts/generate-audit-key.sh --force  # generate even if .env already has one
EOF
      exit 0 ;;
    *)
      echo "Unknown arg: $arg" >&2
      exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
env_file="$repo_root/.env"

if [ -f "$env_file" ] && grep -qE '^AUDIT_SIGNING_KEY=' "$env_file" 2>/dev/null; then
  existing=$(grep -E '^AUDIT_SIGNING_KEY=' "$env_file" | head -n1 | cut -d= -f2-)
  if [ -n "$existing" ] && [ "$existing" != "change_me_generate_with_scripts_generate_audit_key_sh" ]; then
    if [ "$force" -ne 1 ]; then
      echo "AUDIT_SIGNING_KEY is already set in $env_file." >&2
      echo "Pass --force to rotate (this invalidates existing audit-export signatures)." >&2
      exit 1
    fi
    echo "# --force: rotating existing AUDIT_SIGNING_KEY in $env_file" >&2
  fi
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found on PATH" >&2
  exit 2
fi

python3 - <<'PY'
import base64
import hashlib
import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    sys.stderr.write(
        "The `cryptography` package is required.\n"
        "Install with: pip install cryptography\n"
    )
    sys.exit(2)

seed = os.urandom(32)
priv = Ed25519PrivateKey.from_private_bytes(seed)
pub_raw = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
pub_pem = priv.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("ascii")

seed_b64 = base64.b64encode(seed).decode("ascii")
fingerprint = hashlib.sha256(pub_raw).hexdigest()

sys.stderr.write(
    "# Public key fingerprint (SHA-256 of raw pubkey, hex):\n"
    f"#   {fingerprint}\n\n"
    "# Public key (PEM — share with verifiers, also exposed at /api/version):\n"
)
sys.stderr.write("".join(f"# {line}\n" for line in pub_pem.strip().splitlines()))
sys.stderr.write("\n# Add the following line to your .env (NEVER commit this):\n")
sys.stdout.write(f"AUDIT_SIGNING_KEY={seed_b64}\n")
PY
