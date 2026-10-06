"""SIEM alert normalisation for the inbound webhooks (J1, R26). Pure functions, no I/O.

`parse_body` turns the raw request body into a JSON object, or raises a flat 422 ApiError
(`invalid_json`, `payload_not_object`). `normalise(source, payload)` reads one alert:
- the fields an incident is built from (title, description, severity) must have the right type when
  present, else 422 `invalid_field` naming the field (`field`): a container that is not an object,
  a title that is not text. Never a 500.
- the alert time, alert id, rule, category, indicators and entities are optional enrichment: a value
  of the wrong type or shape is skipped, never fatal (a SIEM alert must not be lost over it).

Field lookup (`get_path`) accepts nested objects and flattened dotted keys alike
(`{"event": {"created": …}}` and `{"event.created": …}`), as Splunk, Elastic (ECS) and Sentinel send both.

Category -> incident type: the payload's category, lower-cased with spaces and hyphens as
underscores, must equal one of FENRIR's types or a fixed synonym (`TYPE_SYNONYMS`). No match = no type
(never guessed from the title); the incident's start checks then warn "Incident type set".

Indicators: IPs (public = IOC, private/reserved = in-scope `ip` entity), domains, URLs, MD5/SHA-1/SHA-256
hashes (typed by length) and email addresses become IOCs; hosts and user accounts become entities.
Each value is validated by shape; at most MAX_IOCS / MAX_ENTITIES per alert.

Dedup content key: sha256 of source, rule and the sorted extracted values, only when the alert has a
rule AND at least one value (a rule alone would merge unrelated firings).
"""
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import status

from core.errors import ApiError

SIEM_MAX_BODY_BYTES = 1024 * 1024          # 1 MiB; Caddy caps JSON bodies at 10 MiB before this
MAX_IOCS = 25
MAX_ENTITIES = 25
MAX_ELASTIC_ALERTS = 10                     # context.alerts[] read for times / ids / indicators

LABEL = {"splunk": "Splunk", "sentinel": "Microsoft Sentinel", "elastic": "Elastic SIEM"}

INCIDENT_TYPES = ("malware", "ransomware", "phishing", "data_breach", "unauthorized_access", "insider_threat",
                  "ddos", "bec", "credential_compromise", "web_attack", "vulnerability_exploitation",
                  "supply_chain", "physical", "other")
TYPE_SYNONYMS = {
    "virus": "malware", "trojan": "malware", "worm": "malware", "spyware": "malware",
    "phish": "phishing",
    "data_exfiltration": "data_breach", "exfiltration": "data_breach", "data_leak": "data_breach",
    "unauthorised_access": "unauthorized_access", "intrusion": "unauthorized_access",
    "insider": "insider_threat",
    "denial_of_service": "ddos", "dos": "ddos",
    "business_email_compromise": "bec",
    "credential_access": "credential_compromise", "account_compromise": "credential_compromise",
    "credential_theft": "credential_compromise",
    "web_application_attack": "web_attack",
    "exploit": "vulnerability_exploitation", "exploitation": "vulnerability_exploitation",
}

# Known fields, as Splunk CIM names and Elastic ECS paths (they don't collide: ECS `host`/`url`/`user`
# are objects, so the CIM scalar lookups skip them).
_IP_FIELDS = ("src_ip", "dest_ip", "ip", "remote_ip", "source.ip", "destination.ip", "client.ip", "server.ip")
_IP_OR_HOST_FIELDS = ("src", "dest")
_DOMAIN_FIELDS = ("domain", "dest_domain", "query", "dns.question.name", "destination.domain", "url.domain")
_URL_FIELDS = ("url", "url.full", "url.original")
_HASH_FIELDS = ("file_hash", "hash", "md5", "sha1", "sha256", "file.hash.md5", "file.hash.sha1",
                "file.hash.sha256", "process.hash.md5", "process.hash.sha1", "process.hash.sha256")
_EMAIL_FIELDS = ("sender", "recipient", "email.from.address", "email.to.address", "email.sender.address")
_HOST_FIELDS = ("host", "dest_host", "src_host", "dest_nt_host", "host.name", "host.hostname")
_USER_FIELDS = ("user", "src_user", "dest_user", "user.name", "user.target.name")

_TIME_PATHS = {"splunk": ("_time",), "sentinel": ("TimeGenerated", "properties.timeGenerated"),
               "elastic": ("@timestamp", "event.created")}
_ID_PATHS = {"splunk": ("sid",), "sentinel": ("SystemAlertId", "properties.systemAlertId"),
             "elastic": ("kibana.alert.uuid", "alert.uuid", "alert.id", "alertId", "alert_id")}
_RULE_PATHS = {"splunk": ("search_name",), "sentinel": ("AlertType", "AlertName", "title"),
               "elastic": ("rule.id", "rule.uuid", "kibana.alert.rule.uuid", "rule.name")}
_CATEGORY_PATHS = ("incident_type", "category", "event.category")

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_HASH_TYPE = {32: "hash_md5", 40: "hash_sha1", 64: "hash_sha256"}
_JUNK = {"-", "unknown", "n/a", "na", "none", "null"}


@dataclass
class Alert:
    source: str
    title: str
    description: Optional[str]
    severity_raw: Any
    time_candidates: list = field(default_factory=list)
    alert_id: Optional[str] = None
    rule: Optional[str] = None
    category: Optional[str] = None
    incident_type: Optional[str] = None
    iocs: list = field(default_factory=list)          # [(ioc_type, value)]
    entities: list = field(default_factory=list)      # [(entity_type, value)]
    content_key: Optional[str] = None

    @property
    def reference(self) -> str:
        """`alert_reference` / IOC source: the system and the alert id (else the rule), ≤ 256 chars."""
        return f"{self.source}:{self.alert_id or self.rule or 'alert'}"[:256]


def _bad(code: str, detail: str, **extra) -> ApiError:
    return ApiError(status.HTTP_422_UNPROCESSABLE_CONTENT, code, detail, extra=extra or None)


def parse_body(raw: bytes) -> dict:
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        raise _bad("invalid_json", "The request body is not valid JSON (UTF-8).")
    if not isinstance(payload, dict):
        raise _bad("payload_not_object", f"The alert must be a JSON object, not {type(payload).__name__}.")
    return payload


def get_path(obj: Any, path: str) -> Any:
    """`a.b.c` in nested objects or as a flattened dotted key; None when absent."""
    if not isinstance(obj, dict):
        return None
    if path in obj:
        return obj[path]
    parts = path.split(".")
    for i in range(1, len(parts)):
        head = ".".join(parts[:i])
        if isinstance(obj.get(head), dict):
            v = get_path(obj[head], ".".join(parts[i:]))
            if v is not None:
                return v
    return None


def _obj(container: Any, path: str, shown: str) -> dict:
    v = get_path(container, path)
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise _bad("invalid_field", f"`{shown}` must be a JSON object.", field=shown)
    return v


def _text(container: Any, path: str, shown: str) -> Optional[str]:
    v = get_path(container, path)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (str, int, float)):
        raise _bad("invalid_field", f"`{shown}` must be a string.", field=shown)
    return str(v).strip() or None


def _scalar(v: Any) -> Optional[str]:
    """Lenient: a string/number as stripped text, else None (enrichment never fails intake)."""
    if isinstance(v, bool) or not isinstance(v, (str, int, float)):
        return None
    return str(v).strip()[:256] or None


def _first(objs: list, paths) -> Optional[str]:
    for o in objs:
        for p in paths:
            if (v := _scalar(get_path(o, p))) is not None:
                return v
    return None


def map_type(raw: Any) -> Optional[str]:
    vals = raw if isinstance(raw, list) else [raw]
    for v in vals[:10]:
        if isinstance(v, str):
            k = re.sub(r"[\s-]+", "_", v.strip().lower())
            if k in INCIDENT_TYPES:
                return k
            if k in TYPE_SYNONYMS:
                return TYPE_SYNONYMS[k]
    return None


def _values(v: Any) -> list[str]:
    vals = v if isinstance(v, list) else [v]
    return [s for s in (_scalar(x) for x in vals[:20]) if s and s.lower() not in _JUNK]


class _Collector:
    def __init__(self):
        self.iocs: dict = {}
        self.entities: dict = {}

    def ioc(self, t: str, v: str):
        if len(self.iocs) < MAX_IOCS:
            self.iocs.setdefault((t, v), None)

    def entity(self, t: str, v: str):
        if len(self.entities) < MAX_ENTITIES:
            self.entities.setdefault((t, v), None)

    def ip(self, s: str) -> bool:
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            return False
        (self.ioc if ip.is_global else self.entity)("ip", ip.compressed)
        return True

    def host(self, s: str):
        # a host name has a letter: "999.1.1.1" is a broken IP, not a host
        if _HOST_RE.match(s) and not self.ip(s) and any(c.isalpha() for c in s):
            self.entity("host", s)

    def domain(self, s: str):
        s = s.lower().rstrip(".")
        if _DOMAIN_RE.match(s):
            self.ioc("domain", s)

    def url(self, s: str):
        try:
            ok = s[:8].lower().startswith(("http://", "https://")) and bool(urlsplit(s).netloc) and len(s) <= 2048
        except ValueError:
            ok = False
        if ok and not any(c.isspace() for c in s):
            self.ioc("url", s)

    def hash(self, s: str):
        s = s.lower()
        if len(s) in _HASH_TYPE and _HEX_RE.match(s):
            self.ioc(_HASH_TYPE[len(s)], s)

    def email(self, s: str):
        s = s.lower()
        if _EMAIL_RE.match(s):
            self.ioc("email", s)

    def user(self, s: str):
        if len(s) <= 256 and s.isprintable():
            self.entity("user", s)

    def fields(self, o: Any):
        for paths, fn in ((_IP_FIELDS, self.ip), (_IP_OR_HOST_FIELDS, self.host), (_DOMAIN_FIELDS, self.domain),
                          (_URL_FIELDS, self.url), (_HASH_FIELDS, self.hash), (_EMAIL_FIELDS, self.email),
                          (_HOST_FIELDS, self.host), (_USER_FIELDS, self.user)):
            for p in paths:
                for s in _values(get_path(o, p)):
                    fn(s)

    def sentinel_entities(self, raw: Any):
        if isinstance(raw, str) and len(raw) <= 262144:
            try:
                raw = json.loads(raw)
            except (ValueError, RecursionError):
                return
        if not isinstance(raw, list):
            return
        for e in raw[:100]:
            if not isinstance(e, dict):
                continue
            kind = str(e.get("Type") or e.get("type") or "").lower()
            pick = lambda *ks: next((s for k in ks if (s := _scalar(e.get(k)))), None)  # noqa: E731
            if kind == "ip" and (s := pick("Address")):
                self.ip(s)
            elif kind == "host" and (s := pick("HostName", "FQDN")):
                self.host(s)
            elif kind == "account" and (s := pick("Name")):
                self.user(s)
            elif kind == "url" and (s := pick("Url")):
                self.url(s)
            elif kind == "filehash" and (s := pick("Value")):
                self.hash(s)
            elif kind == "dns" and (s := pick("DomainName")):
                self.domain(s)
            elif kind == "mailbox" and (s := pick("MailboxPrimaryAddress")):
                self.email(s)


def normalise(source: str, p: dict) -> Alert:
    """One SIEM payload -> Alert. 422 invalid_field on a wrongly typed core field."""
    if source == "splunk":
        result = _obj(p, "result", "result")
        title = _text(p, "search_name", "search_name") or _text(result, "alert_name", "result.alert_name") or "Splunk Alert"
        desc = "\n".join(filter(None, [
            f"Splunk search: {_text(p, 'search_name', 'search_name') or ''}",
            f"Host: {_text(result, 'host', 'result.host') or ''}",
            f"Source: {_text(result, 'source', 'result.source') or ''}",
            f"Results link: {_text(p, 'results_link', 'results_link') or ''}",
        ]))
        sev = _text(result, "severity", "result.severity") or _text(p, "severity", "severity")
        objs = [result, p]
    elif source == "sentinel":
        title = _text(p, "title", "title") or _text(p, "name", "name") or "Sentinel Alert"
        desc = _text(p, "description", "description") or ""
        sev = _text(p, "severity", "severity")
        _obj(p, "properties", "properties")
        objs = [p]
    else:   # elastic
        rule = _obj(p, "rule", "rule")
        context = _obj(p, "context", "context")
        ctx_rule = _obj(context, "rule", "context.rule")
        title = _text(rule, "name", "rule.name") or _text(p, "alertName", "alertName") or "Elastic Alert"
        desc = _text(rule, "description", "rule.description") or _text(context, "reason", "context.reason") or ""
        sev = _text(rule, "severity", "rule.severity") or _text(ctx_rule, "severity", "context.rule.severity")
        alerts = context.get("alerts")
        objs = [p, context] + [a for a in (alerts if isinstance(alerts, list) else [])[:MAX_ELASTIC_ALERTS]
                               if isinstance(a, dict)]

    a = Alert(source=source, title=title[:200], description=desc or None, severity_raw=sev or "medium")
    for o in objs:
        for path in _TIME_PATHS[source]:
            v = get_path(o, path)
            if v is not None:
                a.time_candidates.append(v)
    a.alert_id = _first(objs, _ID_PATHS[source] + (("_id",) if source == "elastic" else ()))
    a.rule = _first(objs, _RULE_PATHS[source])
    for o in objs:
        for path in _CATEGORY_PATHS:
            if (t := map_type(get_path(o, path))) is not None:
                a.incident_type, a.category = t, str(get_path(o, path))[:64]
                break
        if a.incident_type:
            break

    c = _Collector()
    for o in objs:
        c.fields(o)
    if source == "sentinel":
        c.sentinel_entities(p.get("Entities"))
    a.iocs, a.entities = list(c.iocs), list(c.entities)
    values = sorted(f"{t}:{v}" for t, v in a.iocs + a.entities)
    if a.rule and values:
        a.content_key = hashlib.sha256("\x1f".join([source, a.rule.lower(), *values]).encode()).hexdigest()
    return a
