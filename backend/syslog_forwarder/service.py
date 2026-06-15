"""RFC 5424 syslog forwarder.

A single in-process forwarder owns a bounded asyncio queue + a background worker
task. Producers (audit log, Python `logging`) push pre-built messages; the worker
drains them onto a socket, reconnecting with exponential backoff when needed.

Backpressure: the queue is bounded. On overflow we drop the message and bump
`dropped_count` — we never block the request path. This matches what every
production syslog client does (rsyslog, syslog-ng, fluentbit) when the upstream
is slow or unreachable.

TLS: when protocol == 'tls' we use `ssl.SSLContext(PROTOCOL_TLS_CLIENT)` with
`minimum_version=TLSv1_3`, optional custom CA bundle, optional mTLS client cert.
Matches the project's TLS-1.3-everywhere posture.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import tempfile
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import decrypt_secret
from models import PlatformSetting

log = logging.getLogger(__name__)

# Bounded queue — dropping on overflow is the documented backpressure policy.
_QUEUE_MAX = 10_000

# Backoff bounds for the reconnect loop.
_BACKOFF_MIN_S = 1.0
_BACKOFF_MAX_S = 60.0

# Conservative single-message cap; RFC 5424 §6.1 says receivers MUST support 480
# bytes and SHOULD support 2048+. 64 KiB matches what rsyslog/syslog-ng default to.
_MAX_MSG_BYTES = 65_536

VALID_PROTOCOLS = {"udp", "tcp", "tls"}
VALID_SCOPES    = {"audit_only", "all"}


# ─── Config (key/value rows in PlatformSetting) ──────────────────────────────

class SyslogConfig:
    """Parsed, validated config snapshot. Immutable for a worker generation."""

    __slots__ = (
        "enabled", "host", "port", "protocol", "facility", "app_name", "scope",
        "ca_bundle_pem", "client_cert_pem", "client_key_pem", "verify_tls",
    )

    def __init__(self):
        self.enabled:         bool = False
        self.host:            str = ""
        self.port:            int = 514
        self.protocol:        str = "udp"
        self.facility:        int = 13   # log audit
        self.app_name:        str = "dfir-fenrir"
        self.scope:           str = "audit_only"
        self.ca_bundle_pem:   Optional[str] = None
        self.client_cert_pem: Optional[str] = None
        self.client_key_pem:  Optional[str] = None
        self.verify_tls:      bool = True

    def is_runnable(self) -> bool:
        return self.enabled and bool(self.host) and self.protocol in VALID_PROTOCOLS

    def fingerprint(self) -> tuple:
        # Used to detect config changes that require a reconnect.
        return (
            self.enabled, self.host, self.port, self.protocol, self.facility,
            self.app_name, self.scope, self.verify_tls,
            bool(self.ca_bundle_pem), bool(self.client_cert_pem),
            bool(self.client_key_pem),
        )


async def load_config(db: AsyncSession) -> SyslogConfig:
    rows = (await db.execute(
        select(PlatformSetting).where(PlatformSetting.key.like("syslog.%"))
    )).scalars().all()
    raw: dict[str, str] = {}
    for r in rows:
        try:
            raw[r.key] = decrypt_secret(r.encrypted_value)
        except Exception:
            log.warning("syslog config: could not decrypt key %s", r.key)
    cfg = SyslogConfig()
    cfg.enabled   = (raw.get("syslog.enabled") or "").lower() == "true"
    cfg.host      = (raw.get("syslog.host") or "").strip()
    try:    cfg.port = int(raw.get("syslog.port") or "514")
    except ValueError: cfg.port = 514
    proto = (raw.get("syslog.protocol") or "udp").lower()
    cfg.protocol = proto if proto in VALID_PROTOCOLS else "udp"
    try:    cfg.facility = max(0, min(23, int(raw.get("syslog.facility") or "13")))
    except ValueError: cfg.facility = 13
    cfg.app_name  = (raw.get("syslog.app_name") or "dfir-fenrir").strip() or "dfir-fenrir"
    scope = (raw.get("syslog.scope") or "audit_only").lower()
    cfg.scope = scope if scope in VALID_SCOPES else "audit_only"
    cfg.ca_bundle_pem   = raw.get("syslog.ca_bundle")   or None
    cfg.client_cert_pem = raw.get("syslog.client_cert") or None
    cfg.client_key_pem  = raw.get("syslog.client_key")  or None
    cfg.verify_tls = (raw.get("syslog.verify_tls") or "true").lower() != "false"
    return cfg


# ─── RFC 5424 framing ────────────────────────────────────────────────────────

# Severity (RFC 5424 §6.2.1):
#   0 emerg, 1 alert, 2 crit, 3 err, 4 warn, 5 notice, 6 info, 7 debug
_SEVERITY_FROM_PYTHON = {
    logging.CRITICAL: 2,
    logging.ERROR:    3,
    logging.WARNING:  4,
    logging.INFO:     6,
    logging.DEBUG:    7,
}


def _hostname() -> str:
    return socket.gethostname() or "-"


def _nilify(s: Optional[str]) -> str:
    """RFC 5424 NILVALUE convention for empty optional fields."""
    s = (s or "").strip()
    return s if s else "-"


def _strip_control(s: str) -> str:
    # Neutralise CR/LF (and other C0 control chars) so attacker-controlled content
    # — e.g. a logged OSINT indicator — can't inject a forged syslog line or
    # desync octet-counted framing on the receiver. Collectors split on newlines.
    return "".join(" " if ord(c) < 0x20 or c == "\x7f" else c for c in s)


def _sd_escape(s: str) -> str:
    # Inside SD-PARAM values: backslash, double-quote, right-bracket are escaped.
    # Strip control chars first so newlines can't break out of the value.
    s = _strip_control(s)
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def build_rfc5424(
    *,
    facility:  int,
    severity:  int,
    app_name:  str,
    hostname:  str,
    procid:    str,
    msgid:     str,
    timestamp: datetime,
    sd_id:     Optional[str] = None,
    sd_params: Optional[dict[str, str]] = None,
    message:   str,
) -> bytes:
    """Build one RFC 5424 syslog frame (without transport framing)."""
    pri = facility * 8 + severity
    ts  = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    sd  = "-"
    if sd_id and sd_params:
        parts = " ".join(f'{k}="{_sd_escape(v)}"' for k, v in sd_params.items() if v is not None)
        sd = f"[{sd_id} {parts}]" if parts else f"[{sd_id}]"
    # Header: <PRI>1 TS HOST APP PROCID MSGID SD MSG
    # Strip control chars from the free-text MSG too (it carries logged content).
    line = f"<{pri}>1 {ts} {_nilify(hostname)} {_nilify(app_name)} {_nilify(procid)} {_nilify(msgid)} {sd} {_strip_control(message)}"
    data = line.encode("utf-8", errors="replace")
    if len(data) > _MAX_MSG_BYTES:
        data = data[:_MAX_MSG_BYTES]
    return data


# ─── Forwarder singleton ─────────────────────────────────────────────────────

class _ConnectionDead(Exception):
    pass


class SyslogForwarder:
    """Process-wide singleton — start_forwarder()/stop_forwarder() drive its lifecycle."""

    def __init__(self):
        self._queue:    asyncio.Queue[bytes] = asyncio.Queue(maxsize=_QUEUE_MAX)
        self._task:     Optional[asyncio.Task] = None
        self._cfg:      SyslogConfig = SyslogConfig()
        self._cfg_fp:   tuple = self._cfg.fingerprint()
        self._stop_evt: Optional[asyncio.Event] = None
        self._log_handler: Optional[logging.Handler] = None

        # Observability (read by the GET endpoint)
        self.dropped_count:  int = 0
        self.sent_count:     int = 0
        self.last_error:     Optional[str] = None
        self.last_success_at: Optional[datetime] = None
        self.connected:      bool = False

    # ── public API ──────────────────────────────────────────────────────────

    def is_enabled(self) -> bool:
        return self._cfg.is_runnable()

    def scope(self) -> str:
        return self._cfg.scope

    def submit(self, frame: bytes) -> None:
        """Non-blocking enqueue. Drops on overflow (bumps dropped_count)."""
        if not self._cfg.is_runnable():
            return
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            self.dropped_count += 1

    async def reload(self, db: AsyncSession) -> None:
        """Re-read config from DB; reconnects if the fingerprint changed."""
        new_cfg = await load_config(db)
        if new_cfg.fingerprint() == self._cfg_fp:
            self._cfg = new_cfg
            return
        self._cfg = new_cfg
        self._cfg_fp = new_cfg.fingerprint()
        self._install_log_handler()
        # Drop the current connection — the worker will rebuild it.
        if self._stop_evt:
            self._stop_evt.set()
            self._stop_evt = asyncio.Event()

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop_evt = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="syslog-forwarder")
        self._install_log_handler()

    async def stop(self) -> None:
        if not self._task:
            return
        self._task.cancel()
        try:
            await self._task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        self._task = None
        self._uninstall_log_handler()

    # ── one-shot send (used by /test endpoint) ──────────────────────────────

    async def send_test(self, db: AsyncSession) -> tuple[bool, str]:
        cfg = await load_config(db)
        if not cfg.host:
            return False, "Host is not configured."
        frame = build_rfc5424(
            facility=cfg.facility,
            severity=6,  # info
            app_name=cfg.app_name,
            hostname=_hostname(),
            procid="test",
            msgid="FENRIR-TEST",
            timestamp=datetime.now(timezone.utc),
            sd_id="origin@32473",
            sd_params={"app": cfg.app_name, "kind": "self-test"},
            message="DFIR-FENRIR syslog forwarding test message.",
        )
        try:
            await self._send_one_shot(cfg, frame)
            return True, "Test message delivered."
        except Exception as e:  # noqa: BLE001
            return False, f"{type(e).__name__}: {e}"

    # ── internals ───────────────────────────────────────────────────────────

    def _install_log_handler(self):
        """Tap into Python logging when scope == 'all'. Idempotent."""
        want = self._cfg.is_runnable() and self._cfg.scope == "all"
        if want and not self._log_handler:
            h = _PythonLoggingHandler(self)
            h.setLevel(logging.WARNING)
            # Suppress our own logger to avoid feedback loops.
            class _NoOwnLogs(logging.Filter):
                def filter(self, record):
                    return not record.name.startswith("syslog_forwarder")
            h.addFilter(_NoOwnLogs())
            logging.getLogger().addHandler(h)
            self._log_handler = h
        elif not want and self._log_handler:
            self._uninstall_log_handler()

    def _uninstall_log_handler(self):
        if self._log_handler:
            logging.getLogger().removeHandler(self._log_handler)
            self._log_handler = None

    async def _run(self):
        backoff = _BACKOFF_MIN_S
        while True:
            try:
                if not self._cfg.is_runnable():
                    # Drain & wait for config-change ping.
                    self.connected = False
                    await asyncio.sleep(2.0)
                    continue

                await self._connect_and_pump(self._cfg)
                backoff = _BACKOFF_MIN_S
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                self.connected = False
                self.last_error = f"{type(e).__name__}: {e}"
                log.warning("syslog forwarder error (%s) — retrying in %.1fs", self.last_error, backoff)
                try:
                    await asyncio.sleep(backoff)
                except asyncio.CancelledError:
                    raise
                backoff = min(backoff * 2, _BACKOFF_MAX_S)

    async def _connect_and_pump(self, cfg: SyslogConfig):
        if cfg.protocol == "udp":
            await self._pump_udp(cfg)
        else:
            await self._pump_stream(cfg)

    async def _pump_udp(self, cfg: SyslogConfig):
        loop = asyncio.get_running_loop()
        # AF_UNSPEC + getaddrinfo so v4 + v6 both work.
        addrinfo = await loop.getaddrinfo(cfg.host, cfg.port, type=socket.SOCK_DGRAM)
        if not addrinfo:
            raise OSError(f"DNS lookup failed for {cfg.host}")
        fam, _stype, _proto, _, sockaddr = addrinfo[0]
        sock = socket.socket(fam, socket.SOCK_DGRAM)
        sock.setblocking(False)
        self.connected = True
        try:
            while True:
                if self._stop_evt and self._stop_evt.is_set():
                    return
                frame = await self._queue.get()
                try:
                    await loop.sock_sendto(sock, frame, sockaddr)
                    self.sent_count += 1
                    self.last_success_at = datetime.now(timezone.utc)
                except (OSError, asyncio.CancelledError):
                    self._requeue_front(frame)
                    raise
        finally:
            sock.close()
            self.connected = False

    async def _pump_stream(self, cfg: SyslogConfig):
        reader, writer = await self._open_stream(cfg)
        self.connected = True
        try:
            while True:
                if self._stop_evt and self._stop_evt.is_set():
                    return
                frame = await self._queue.get()
                # RFC 6587 octet-counted framing: <len> SP <frame>
                octets = f"{len(frame)} ".encode("ascii") + frame
                try:
                    writer.write(octets)
                    await writer.drain()
                    self.sent_count += 1
                    self.last_success_at = datetime.now(timezone.utc)
                except (OSError, ConnectionError, asyncio.CancelledError):
                    self._requeue_front(frame)
                    raise
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            self.connected = False

    async def _open_stream(self, cfg: SyslogConfig):
        if cfg.protocol == "tls":
            ctx = _build_ssl_context(cfg)
            return await asyncio.open_connection(
                cfg.host, cfg.port, ssl=ctx,
                server_hostname=cfg.host if cfg.verify_tls else None,
            )
        return await asyncio.open_connection(cfg.host, cfg.port)

    async def _send_one_shot(self, cfg: SyslogConfig, frame: bytes):
        """Used by the /test endpoint — bypasses the queue, returns errors."""
        if cfg.protocol == "udp":
            loop = asyncio.get_running_loop()
            addrinfo = await loop.getaddrinfo(cfg.host, cfg.port, type=socket.SOCK_DGRAM)
            fam, _, _, _, sockaddr = addrinfo[0]
            sock = socket.socket(fam, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, frame, sockaddr)
            finally:
                sock.close()
            return
        if cfg.protocol == "tls":
            ctx = _build_ssl_context(cfg)
            reader, writer = await asyncio.open_connection(
                cfg.host, cfg.port, ssl=ctx,
                server_hostname=cfg.host if cfg.verify_tls else None,
            )
        else:
            reader, writer = await asyncio.open_connection(cfg.host, cfg.port)
        try:
            octets = f"{len(frame)} ".encode("ascii") + frame
            writer.write(octets)
            await writer.drain()
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    def _requeue_front(self, frame: bytes):
        """On send failure, put the frame back so reconnect can retry it."""
        try:
            # Best-effort: if full, the frame is dropped. dropped_count bumps.
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            self.dropped_count += 1


def _build_ssl_context(cfg: SyslogConfig) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cfg.ca_bundle_pem:
        # cafile= API takes a path; use a temp file (clean up on close).
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".pem") as f:
            f.write(cfg.ca_bundle_pem)
            ca_path = f.name
        ctx.load_verify_locations(cafile=ca_path)
    else:
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    if cfg.client_cert_pem and cfg.client_key_pem:
        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".pem") as cf, \
             tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".pem") as kf:
            cf.write(cfg.client_cert_pem); cert_path = cf.name
            kf.write(cfg.client_key_pem);  key_path  = kf.name
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx.check_hostname = cfg.verify_tls
    ctx.verify_mode = ssl.CERT_REQUIRED if cfg.verify_tls else ssl.CERT_NONE
    return ctx


# ─── Python logging.Handler bridge ───────────────────────────────────────────

class _PythonLoggingHandler(logging.Handler):
    """Ships `logging` records through the forwarder when scope == 'all'."""

    def __init__(self, fwd: "SyslogForwarder"):
        super().__init__()
        self._fwd = fwd

    def emit(self, record: logging.LogRecord) -> None:
        try:
            severity = _SEVERITY_FROM_PYTHON.get(record.levelno, 6)
            ts = datetime.fromtimestamp(record.created, tz=timezone.utc)
            msg = self.format(record) if self.formatter else record.getMessage()
            frame = build_rfc5424(
                facility=self._fwd._cfg.facility,
                severity=severity,
                app_name=self._fwd._cfg.app_name,
                hostname=_hostname(),
                procid=str(record.process or "-"),
                msgid=record.name or "py",
                timestamp=ts,
                sd_id="app@32473",
                sd_params={"level": record.levelname, "logger": record.name},
                message=msg,
            )
            self._fwd.submit(frame)
        except Exception:  # noqa: BLE001
            # logging.Handler.handleError protocol — must never raise.
            self.handleError(record)


# ─── Module-level singleton + helpers ────────────────────────────────────────

forwarder = SyslogForwarder()


def forward_audit_row(*, action: str, username: Optional[str], resource_type: Optional[str],
                      resource_id: Optional[str], outcome: Optional[str], ip_address: Optional[str],
                      timestamp: datetime) -> None:
    """Push an audit-log row onto the forwarder queue (non-blocking)."""
    if not forwarder.is_enabled():
        return
    cfg = forwarder._cfg
    severity = 4 if (outcome or "").lower() in ("failure", "denied") else 6
    frame = build_rfc5424(
        facility=cfg.facility,
        severity=severity,
        app_name=cfg.app_name,
        hostname=_hostname(),
        procid="audit",
        msgid="FENRIR-AUDIT",
        timestamp=timestamp,
        sd_id="audit@32473",
        sd_params={
            "action":   action or "-",
            "user":     username or "-",
            "rtype":    resource_type or "-",
            "rid":      resource_id or "-",
            "outcome":  outcome or "-",
            "ip":       ip_address or "-",
        },
        message=f"{action} user={username or '-'} resource={resource_type or '-'}:{resource_id or '-'} outcome={outcome or '-'}",
    )
    forwarder.submit(frame)


async def start_forwarder() -> None:
    # Load config once at startup; pumps will idle if not enabled.
    from core.database import SessionLocal  # local import — avoid cycle at module load
    async with SessionLocal() as db:
        await forwarder.reload(db)
    await forwarder.start()


async def stop_forwarder() -> None:
    await forwarder.stop()
