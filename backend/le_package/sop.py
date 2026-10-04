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

## Collection (ISO 27037 §5.4.3–§5.4.4, §6.1 / NIST 800-86 §3.1.2)

  • Every Evidence item is recorded with: who collected it, when (UTC),
    where (logical or physical location), the collection method used, the
    custodial role of the collector, and the device/source identifiers.
  • Digital-file evidence is hashed (SHA-256, SHA-1, MD5) at the moment of
    upload, before any processing. Hashes are persisted on the Evidence row
    and re-checked at every transfer / examination / disposition.
  • The target hash reported by the imaging tool (MD5, SHA-1 or SHA-256) is
    compared with the hash of the uploaded bytes before anything is stored;
    a mismatch is refused and logged (evidence_collect_rejected). A hash that
    covers an E01/AFF4 container's media is recorded as advisory, not compared.
  • The acquisition time (when the image was taken or the item seized) is
    recorded separately from the time the item was registered.
  • Physical evidence is photographed and described before any movement.

## At-rest protection (ISO 27037 §6.9)

  • Every uploaded evidence file is encrypted at rest with AES-256-GCM.
    Files stored since 2026-10-04 (format FENRGCM v2) are encrypted in 1 MiB
    chunks under a random 256-bit data key of their own; that key is wrapped
    with AES-KW (RFC 3394) under a key derived from the master Key Encryption
    Key (K_wrap = HKDF-SHA256(KEK)) and kept in the file's header. Each chunk's
    nonce is a random 56-bit per-file prefix, the 32-bit chunk index and a
    final-chunk flag, so truncation, reordering and splicing are detected.
    Files stored earlier (format v0) are one AES-256-GCM message under the KEK
    with a random 96-bit nonce. The KEK is supplied to the backend as a
    container secret file (never an environment variable) and held in process
    memory; it never leaves the platform.
  • Since 2026-10-04 an evidence file's plaintext is not written to disk:
    uploads are encrypted as they arrive, or held only in a memory-only
    scratch area (tmpfs, never swapped) until they are encrypted; analysers
    decrypt into memory or into that memory-only area and delete it after
    each parse. Files in the artifact quarantine (05_Artifacts) are the
    exception: they are stored unencrypted on their own volume.
  • The /evidence volume is dedicated, runs non-root (uid 1001), and has no
    network access from the analysis worker (air-gapped Docker network).

## Custody actions (ACPO Principle 3)

Every action that touches an Evidence row writes a row to the platform's
tamper-evident audit log. Actions tracked include:

    evidence_collect        Initial upload / registration (incl. items minted
                            from the Email or Browser-history tools; older
                            mints are logged as email_mint_evidence /
                            webhistory_mint_evidence)
    evidence_collect_rejected  Upload refused: target hash ≠ uploaded bytes
                            (nothing stored)
    evidence_transfer_request  Custody transfer requested (internal: custody does
                            not change until the recipient accepts)
    evidence_transfer       Custody changed hands: the recipient accepted and
                            recorded the condition on receipt and the seals, or
                            a handover to / return from an external party
    evidence_transfer_declined  Pending transfer declined by the recipient or
                            cancelled by the requester or an admin
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

  1. Queried the source-of-truth tables for the incident with ordinary
     database queries in one session (PostgreSQL READ COMMITTED: not a
     single snapshot and not a read-only transaction).
  2. Decrypted each included `digital_file` Evidence row from its at-rest
     AES-256-GCM ciphertext: a v2 file with its own data key, unwrapped (AES-KW)
     with a key the platform derives from its in-memory master KEK by
     HKDF-SHA256; a legacy v0 file directly with the KEK. No at-rest key is
     placed in the package. Each file is authenticated in full before it is
     written; one that fails is left out and recorded in its `.meta.json`.
  3. Streamed every file into the bundle (bounded memory, built in a staging
     file and published only when complete), hashing each (SHA-256 + SHA-512)
     over the exact bytes written and recording the hash in MANIFEST.json.
  4. Hashed MANIFEST.json (SHA-256). When a time-stamping authority is
     configured, it also requested an RFC 3161 time-stamp token over that
     hash and wrote it as `MANIFEST.tst` (README.md says whether this package
     has one).
  5. Generated a fresh 24-character URL-safe random password and derived the
     HMAC key from it as `SHA-256(bundle_password)`; the HMAC-SHA-256 over
     MANIFEST.json is `INTEGRITY.sig`. A recipient who can open the ZIP can
     therefore re-derive the key and check that the manifest was assembled
     by a holder of the bundle password.
  6. Sealed the inner ZIP (`le_package.zip`, itself not encrypted) inside an
     AES-256 password-protected ZIP (WinZip AE-2, written via pyzipper) under
     that password. The password is shown to the generator ONCE and is never
     persisted by the platform.
  7. Wrote the password-protected ZIP to `/evidence/exports/{id}.zip` and
     issued a single-use 24-hour download token for the recipient. The
     recipient opens the bundle with any standard archive tool (macOS
     Finder, 7-Zip, WinRAR, `unzip -P`) — no Python or `cryptography`
     library required.
  8. Only then recorded the manifest SHA-256, bundle SHA-256 and HMAC in a
     new audit row with `action = 'le_package_generate'`. Because it is
     written after the build, that row is not in the package's `08_Audit/`
     and MANIFEST.json carries no anchor; its id and `row_hash` are kept on
     the platform's record of the package.

## Integrity verification at the receiving end

The recipient can verify integrity at three independent layers:

  1. Per-file: `sha256sum --check INTEGRITY.sha256` (must report `OK` for every line).
  2. Manifest: `sha256(MANIFEST.json)` must match the Manifest SHA-256 on
     README.md. The platform recorded the same value in its
     `le_package_generate` audit row (`details.manifest_sha256`) after the
     build; that row is not in the package, so ask the sender for it.
  3. Sender-of-record: HMAC-SHA-256 over MANIFEST.json under
     `SHA-256(bundle_password)` matches `INTEGRITY.sig`. The bundle
     password is delivered out-of-band; deriving the HMAC key from it
     deterministically keeps integrity verification single-secret.
     Proves the package was assembled by a holder of that password — by
     construction, the platform at generation time.

## Out of scope, and optional

  • Cryptographic signing under a public PKI (GPG / X.509) is not part of
    this SOP. It can be layered on top by the operator if required; in that
    case `INTEGRITY.sig` is replaced with a detached PGP/GPG signature and
    the receiver verifies with the operator's published key.
  • Trusted time-stamping (RFC 3161) is optional: only when the platform has a
    time-stamping authority configured (and it answered) does the package
    carry `MANIFEST.tst`; verify it with
    `openssl ts -verify -data MANIFEST.json -in MANIFEST.tst -CAfile <TSA CA>`.
    Otherwise the platform's UTC timestamps come from the container clock
    only, which is NTP-disciplined by the host.

— END OF SOP —
"""
