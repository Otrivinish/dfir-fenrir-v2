"""Chain-of-custody SOP — embedded verbatim into 09_Legal/ in every LE package.

The platform claims to operate to NIST SP 800-86, ISO/IEC 27037, ACPO, and
SWGDE practices. Receiving authorities must be able to see, in writing, what
those claims mean concretely for *this* platform. This file is the answer.
"""

CHAIN_OF_CUSTODY_SOP = """\
# DFIR-FENRIR — Chain-of-Custody SOP

This is the standard operating procedure that the DFIR-FENRIR platform
implements when handling digital evidence. It is included verbatim with every
Law-Enforcement Package so receiving authorities can audit the integrity
claims made on the cover document (README.md).

## Standards alignment

This SOP is derived from, and operates in alignment with:

  • NIST SP 800-86   — Guide to Integrating Forensic Techniques into Incident Response
  • ISO/IEC 27037    — Guidelines for identification, collection, acquisition, and
                        preservation of digital evidence
  • ACPO Good Practice Guide for Digital Evidence (UK, 2012)
  • SWGDE Best Practices for Computer Forensic Acquisitions (2018)

When a control in one standard is stricter than another, the strictest wins.

## ACPO principles (operative — every action against evidence respects these)

  1. No action taken should change data held on a digital device or media that
     may subsequently be relied upon in court.
  2. Where access to original data is necessary, the person doing so must be
     competent and able to give evidence explaining their actions.
  3. An audit trail of all processes applied to the evidence must be created
     and preserved. An independent third party should be able to examine
     those processes and achieve the same result.
  4. The person in charge of the investigation has overall responsibility for
     ensuring the law and these principles are followed.

## Collection (ISO 27037 §6.7 / NIST 800-86 §4.1)

  • Every Evidence item is recorded with: who collected it, when (UTC),
    where (logical or physical location), the collection method used, the
    custodial role of the collector, and the device/source identifiers.
  • Digital-file evidence is hashed (SHA-256, SHA-1, MD5) at the moment of
    upload, before any processing. Hashes are persisted on the Evidence row
    and re-checked at every transfer / examination / disposition.
  • Physical evidence is photographed and described before any movement.

## At-rest protection (ISO 27037 §6.9)

  • Every uploaded evidence file is encrypted at rest with AES-256-GCM,
    using a per-file 96-bit nonce, under a master Key Encryption Key (KEK)
    that lives only in process memory (env var `EVIDENCE_KEK`).
  • Plaintext is never persisted outside the encrypted volume.
  • The /evidence volume is dedicated, runs non-root (uid 1001), and has no
    network access from the analysis worker (air-gapped Docker network).

## Custody actions (ACPO Principle 3)

Every action that touches an Evidence row writes a row to the platform's
tamper-evident audit log. Actions tracked include:

    evidence_collect        Initial upload / registration
    evidence_transfer       Custody handover between users
    evidence_examine        Read or analyse the evidence
    evidence_verify         Hash recomputation against the recorded SHA-256
    evidence_dispose        Destruction / return / archival
    evidence_legal_hold     Set / clear legal hold flag

Each audit row carries: timestamp (UTC), actor user-id + username, actor role
at the moment of action, source IP (from the trusted reverse proxy), the
HTTP request_id (UUID — groups multi-row actions), outcome (success / failure
/ denied), and a JSON `details` payload.

## Tamper evidence (the hash chain)

The audit log is structured as a SHA-256 hash chain:

    row_hash = sha256( prev_hash || canonical_json(payload) )

Each new row anchors the previous row's hash. The chain begins at a fixed
genesis row (prev_hash = "0" * 64). Any modification, insertion, or deletion
in the chain breaks the hash relation downstream and is detected by the
platform's verifier.

Concurrent inserts serialise on a Postgres advisory lock so prev_hash always
points at the immediately-preceding row's row_hash — there are no races.

## Package generation (this document is in the package; the act of generation
is itself logged)

When this LE Package was generated, the platform:

  1. Opened a single read-only database transaction.
  2. Queried the source-of-truth tables for the incident.
  3. Decrypted each `digital_file` Evidence row from its at-rest AES-256-GCM
     ciphertext using the in-memory master KEK.
  4. Built every file in the bundle in memory, hashing each (SHA-256 + SHA-512)
     immediately and recording the hash in MANIFEST.json.
  5. Hashed MANIFEST.json (SHA-256) and recorded the fingerprint in a new
     audit row with `action = 'le_package_generate'`. That row's `row_hash`
     is exposed as `audit_anchor.row_hash` in MANIFEST.json — the package's
     existence is now anchored in the tamper-evident chain.
  6. Sealed the entire bundle as an AES-256 password-protected ZIP (WinZip
     AE-2, written via pyzipper) under a freshly generated 24-character
     URL-safe random password. The password is shown to the generator ONCE
     and is never persisted by the platform. The same password is also used
     to derive the HMAC key in step 5b below.
     5b. The HMAC key over MANIFEST.json (written to `INTEGRITY.sig`) is
         derived deterministically as `SHA-256(bundle_password)`. A recipient
         who can open the ZIP can therefore re-derive the HMAC key and
         independently verify that the manifest was assembled by the holder
         of the bundle secret.
  7. Wrote the password-protected ZIP to `/evidence/exports/{id}.zip` and
     issued a single-use 24-hour download token for the recipient. The
     recipient opens the bundle with any standard archive tool (macOS
     Finder, 7-Zip, WinRAR, `unzip -P`) — no Python or `cryptography`
     library required.

## Integrity verification at the receiving end

The recipient can verify integrity at three independent layers:

  1. Per-file: `sha256sum --check INTEGRITY.sha256` (must report `OK` for every line).
  2. Manifest: `sha256(MANIFEST.json)` must match the value recorded in the
     audit row included in the package (`08_Audit/Audit_Trail.csv`, action
     `le_package_generate`, `details.manifest_sha256`).
  3. Sender-of-record: HMAC-SHA-256 over MANIFEST.json under
     `SHA-256(bundle_password)` matches `INTEGRITY.sig`. The bundle
     password is delivered out-of-band; deriving the HMAC key from it
     deterministically keeps integrity verification single-secret.
     Proves the package was assembled by a holder of that password — by
     construction, the platform at generation time.

## Out of scope

  • Cryptographic signing under a public PKI (GPG / X.509) is not part of
    this SOP. It can be layered on top by the operator if required; in that
    case `INTEGRITY.sig` is replaced with a detached PGP/GPG signature and
    the receiver verifies with the operator's published key.
  • Time-stamping authority (TSA / RFC 3161) integration is not part of this
    SOP. The platform's UTC timestamps are taken from the container clock,
    which is NTP-disciplined by the host.

— END OF SOP —
"""
