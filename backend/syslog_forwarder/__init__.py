"""Forward platform logs to an external syslog endpoint (RFC 5424).

Two scopes:
  - audit_only — only audit-log rows
  - all        — audit rows + Python `logging` records (warnings, errors, etc.)

Three transports:
  - udp     — fire-and-forget, no delivery guarantees
  - tcp     — octet-counted framing (RFC 6587)
  - tls     — TCP wrapped in TLS 1.3 (RFC 5425), optional mTLS
"""
from syslog_forwarder.service import (
    forwarder, forward_audit_row, start_forwarder, stop_forwarder,
)

__all__ = ["forwarder", "forward_audit_row", "start_forwarder", "stop_forwarder"]
