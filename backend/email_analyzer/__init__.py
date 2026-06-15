"""U8.1 — Email analyzer (phishing triage). Offline, parse-only.

Extracts headers/hops/auth, body URLs, and attachments from a raw email and routes them
into existing subsystems (IOCs, quarantine Artifacts, Timeline, Evidence). Never renders
HTML, fetches a URL, or executes an attachment. See docs/u8-email-analyzer-slice.md.
"""
