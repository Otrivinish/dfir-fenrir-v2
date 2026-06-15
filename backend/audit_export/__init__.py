"""Signed audit log export — per-incident and global admin.

Bundle layout (inside AES-256-GCM envelope):

    audit.pdf            — ReportLab, classification banner, cover page with chain anchors
    audit.jsonl          — canonical v2 audit payloads, lex-sorted keys, one row per line
    audit.jsonl.sig      — 64-byte raw Ed25519 signature over audit.jsonl
    public_key.pem       — Ed25519 public key (PEM)
    manifest.json        — export metadata (filters, row counts, anchors, hashes)
    README.txt           — verification recipe

See `fenrir_audit_export_design.md` in user memory for the locked design.
"""
