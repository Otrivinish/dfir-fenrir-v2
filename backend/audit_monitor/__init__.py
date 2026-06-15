"""GS-8 — continuous, court-provable tamper monitoring.

A sidecar runs `python -m audit_monitor` on an interval. Each tick verifies the audit
chain segment since the previous anchor, RFC-3161 timestamps the current chain head
(best-effort, reuses GS-4), and records an `AuditAnchor`. Consecutive anchors cover the
whole log; the external timestamps make a re-forged chain unprovable.
See docs/coc-gs8-tamper-monitoring-slice.md + docs/audit-integrity.md.
"""
