"""DFIR-FENRIR v2 — analysis worker.

Runs on the air-gapped fenrir-analysis network with no internet access,
read-only mount of /quarantine, dropped capabilities, and noexec /tmp.
"""
import hashlib
import io
import math
import os
import re
import socket
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

import magic as libmagic
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from pydantic import BaseModel

app = FastAPI(title="DFIR-FENRIR v2 Analysis Worker", version="2.0.0")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "fenrir-v2-analysis-worker"}


# ── PCAP Analysis ─────────────────────────────────────────────────────────────

@app.post("/analyze/pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    """Analyze a PCAP/PCAPNG file — extract conversations, DNS, HTTP, TLS,
    top talkers, and suspicious patterns. Requires tshark for full analysis;
    falls back to a basic raw parser if tshark is absent."""
    content = await file.read()
    if len(content) < 24:
        return {"error": "File too small to be a valid PCAP"}

    magic = content[:4]
    pcap_magic  = {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                   b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'}
    pcapng_magic = b'\x0a\x0d\x0d\x0a'
    if magic not in pcap_magic and magic[:4] != pcapng_magic:
        return {"error": "Not a valid PCAP or PCAPNG file"}

    result = {
        "file_size":        len(content),
        "format":           "pcapng" if magic[:4] == pcapng_magic else "pcap",
        "conversations":    {"tcp": [], "udp": []},
        "dns_queries":      [],
        "http_requests":    [],
        "tls_info":         [],
        "suspicious":       [],
        "top_talkers":      [],
        "port_summary":     {},
        "protocol_summary": {},
        "errors":           [],
    }

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(content)
        tmppath = tmp.name

    try:
        has_tshark = subprocess.run(["which", "tshark"], capture_output=True).returncode == 0
        if has_tshark:
            result.update(_analyze_with_tshark(tmppath, result))
        else:
            result.update(_analyze_raw_pcap(content, result))
            result["errors"].append(
                "tshark not available — using basic parser. "
                "Rebuild the analysis-worker image to enable full analysis."
            )
    finally:
        os.unlink(tmppath)

    return result


def _run_tshark(args: list, timeout: int = 30) -> tuple[str, str]:
    try:
        r = subprocess.run(["tshark"] + args, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return "", "timeout"
    except Exception as e:
        return "", str(e)


def _analyze_with_tshark(tmppath: str, result: dict) -> dict:
    # Protocol summary
    out, _ = _run_tshark(["-r", tmppath, "-q", "-z", "io,phs"])
    for line in out.splitlines()[2:20]:
        parts = line.split()
        if len(parts) >= 2:
            try:
                result["protocol_summary"][parts[0].lower()] = int(parts[1])
            except ValueError:
                pass

    # TCP conversations
    out, _ = _run_tshark(["-r", tmppath, "-q", "-z", "conv,tcp"])
    for line in out.splitlines():
        if "<->" in line:
            parts = line.split()
            if len(parts) >= 9:
                try:
                    result["conversations"]["tcp"].append({
                        "src": parts[0], "dst": parts[2],
                        "frames_ab": int(parts[3]), "bytes_ab": int(parts[4]),
                        "frames_ba": int(parts[5]), "bytes_ba": int(parts[6]),
                        "total_frames": int(parts[7]), "total_bytes": int(parts[8]),
                    })
                except (ValueError, IndexError):
                    pass
    result["conversations"]["tcp"] = sorted(
        result["conversations"]["tcp"], key=lambda x: x.get("total_bytes", 0), reverse=True
    )[:50]

    # UDP conversations
    out, _ = _run_tshark(["-r", tmppath, "-q", "-z", "conv,udp"])
    for line in out.splitlines():
        if "<->" in line:
            parts = line.split()
            if len(parts) >= 9:
                try:
                    result["conversations"]["udp"].append({
                        "src": parts[0], "dst": parts[2],
                        "frames_ab": int(parts[3]), "bytes_ab": int(parts[4]),
                        "total_frames": int(parts[7]), "total_bytes": int(parts[8]),
                    })
                except (ValueError, IndexError):
                    pass
    result["conversations"]["udp"] = sorted(
        result["conversations"]["udp"], key=lambda x: x.get("total_bytes", 0), reverse=True
    )[:30]

    # DNS queries
    out, _ = _run_tshark([
        "-r", tmppath, "-Y", "dns", "-T", "fields",
        "-e", "frame.time_relative", "-e", "ip.src", "-e", "dns.qry.name",
        "-e", "dns.resp.name", "-e", "dns.a", "-e", "dns.cname",
        "-e", "dns.qry.type",  "-e", "dns.flags.response",
    ])
    dns_seen: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            name = parts[2] or parts[3]
            if name and name not in dns_seen:
                dns_seen.add(name)
                result["dns_queries"].append({
                    "time":        parts[0],
                    "src":         parts[1],
                    "query":       parts[2],
                    "response":    parts[3],
                    "resolved_ip": parts[4] if len(parts) > 4 else "",
                    "cname":       parts[5] if len(parts) > 5 else "",
                    "type":        parts[6] if len(parts) > 6 else "",
                    "is_response": parts[7].strip() == "1" if len(parts) > 7 else False,
                    "suspicious":  _suspicious_domain(name),
                })
    result["dns_queries"] = result["dns_queries"][:200]

    # HTTP requests
    out, _ = _run_tshark([
        "-r", tmppath, "-Y", "http.request or http.response", "-T", "fields",
        "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst",
        "-e", "http.request.method", "-e", "http.request.uri",
        "-e", "http.host", "-e", "http.response.code", "-e", "http.user_agent",
    ])
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 6:
            method = parts[3]
            uri    = parts[4][:500] if len(parts) > 4 else ""
            ua     = parts[7][:200] if len(parts) > 7 else ""
            entry = {
                "time":          parts[0],
                "src":           parts[1],
                "dst":           parts[2],
                "method":        method,
                "uri":           uri,
                "host":          parts[5] if len(parts) > 5 else "",
                "response_code": parts[6] if len(parts) > 6 else "",
                "user_agent":    ua,
                "suspicious":    _suspicious_http(method, uri, ua),
            }
            if entry["method"] or entry["response_code"]:
                result["http_requests"].append(entry)
    result["http_requests"] = result["http_requests"][:200]

    # TLS/SSL — Client Hello SNI
    out, _ = _run_tshark([
        "-r", tmppath, "-Y", "tls.handshake.type == 1", "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "tls.handshake.version",
    ])
    tls_seen: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            sni = parts[2] if len(parts) > 2 else ""
            key = f"{parts[0]}-{parts[1]}-{sni}"
            if key not in tls_seen:
                tls_seen.add(key)
                result["tls_info"].append({
                    "src":        parts[0],
                    "dst":        parts[1],
                    "sni":        sni,
                    "version":    parts[3] if len(parts) > 3 else "",
                    "suspicious": _suspicious_domain(sni),
                })
    result["tls_info"] = result["tls_info"][:100]

    # Top talkers by bytes
    out, _ = _run_tshark(["-r", tmppath, "-q", "-z", "endpoints,ip"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and "." in parts[0]:
            try:
                result["top_talkers"].append({
                    "ip":      parts[0],
                    "packets": int(parts[1]),
                    "bytes":   int(parts[2]),
                })
            except (ValueError, IndexError):
                pass
    result["top_talkers"] = sorted(
        result["top_talkers"], key=lambda x: x.get("bytes", 0), reverse=True
    )[:20]

    # Port summary from TCP endpoints
    out, _ = _run_tshark(["-r", tmppath, "-q", "-z", "endpoints,tcp"])
    for line in out.splitlines():
        parts = line.split()
        if parts and ":" in parts[0]:
            port = parts[0].split(":")[-1]
            try:
                int(port)
                result["port_summary"][port] = result["port_summary"].get(port, 0) + 1
            except ValueError:
                pass

    _find_suspicious(result)
    return result


def _analyze_raw_pcap(content: bytes, result: dict) -> dict:
    """Minimal PCAP parser — extracts IPs and packet counts without tshark."""
    result["errors"].append(
        "Basic parser only (no tshark). Install tshark for full analysis."
    )
    magic = content[:4]
    if magic not in {b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'}:
        return result
    endian = "<" if magic == b'\xd4\xc3\xb2\xa1' else ">"
    offset, packets_seen, ip_counts = 24, 0, {}
    while offset + 16 <= len(content) and packets_seen < 5000:
        try:
            _, _, incl_len, _ = struct.unpack_from(f"{endian}IIII", content, offset)
        except struct.error:
            break
        offset += 16
        if offset + incl_len > len(content):
            break
        pkt = content[offset:offset + incl_len]
        offset += incl_len
        packets_seen += 1
        if len(pkt) > 34 and pkt[12:14] == b'\x08\x00':
            src = socket.inet_ntoa(pkt[26:30])
            dst = socket.inet_ntoa(pkt[30:34])
            ip_counts[src] = ip_counts.get(src, 0) + 1
            ip_counts[dst] = ip_counts.get(dst, 0) + 1
    result["top_talkers"] = [
        {"ip": ip, "packets": cnt}
        for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:20]
    ]
    result["protocol_summary"]["packets_parsed"] = packets_seen
    return result


def _suspicious_domain(domain: str) -> dict:
    if not domain:
        return {}
    d = domain.lower().strip(".")
    s: dict = {}
    if len(d) > 50:
        s["long_domain"] = True
    parts = d.split(".")
    if parts and len(parts[0]) > 12:
        vowels = sum(1 for c in parts[0] if c in "aeiou")
        if vowels / max(len(parts[0]), 1) < 0.2:
            s["low_vowel_ratio"] = True
    if re.match(r"\d+\.\d+\.\d+\.\d+", d):
        s["ip_in_dns"] = True
    for tld in [".tk", ".pw", ".cf", ".ga", ".gq", ".ml", ".top", ".xyz", ".click", ".download"]:
        if d.endswith(tld):
            s["suspicious_tld"] = tld
    for pat in ["bit.ly", "tinyurl", "pastebin", "ngrok.io", ".onion", "dyndns", "no-ip.", "ddns."]:
        if pat in d:
            s["known_pattern"] = pat
    return s


def _suspicious_http(method: str, uri: str, ua: str) -> dict:
    s: dict = {}
    uri_l = uri.lower()
    ua_l  = ua.lower()
    for pat in ["/shell", "/cmd", "/exec", "/eval", "base64", "/upload", ".php?",
                "passwd", "/etc/", "cmd.exe", "powershell"]:
        if pat in uri_l:
            s["suspicious_uri"] = pat
    for pat in ["python-requests", "curl/", "wget/", "go-http", "nmap",
                "masscan", "nikto", "sqlmap", "metasploit"]:
        if pat in ua_l:
            s["suspicious_ua"] = pat
    if method in ("CONNECT", "TRACE", "TRACK"):
        s["suspicious_method"] = method
    return s


def _find_suspicious(result: dict) -> None:
    seen: set[str] = set()

    def add(category: str, description: str, detail: str = "", severity: str = "medium") -> None:
        key = f"{category}:{description[:50]}"
        if key not in seen:
            seen.add(key)
            result["suspicious"].append({
                "category": category, "description": description,
                "detail": detail, "severity": severity,
            })

    for dns in result.get("dns_queries", []):
        for k, v in (dns.get("suspicious") or {}).items():
            sev = "high" if k == "low_vowel_ratio" else "medium"
            add("DNS", f"{k.replace('_', ' ').title()}: {dns['query']}", str(v), sev)

    for req in result.get("http_requests", []):
        for k, v in (req.get("suspicious") or {}).items():
            add("HTTP", f"{k.replace('_', ' ').title()}",
                f"{req.get('method', '')} {req.get('host', '')}{req.get('uri', '')[:80]}", "high")

    for tls in result.get("tls_info", []):
        for k, v in (tls.get("suspicious") or {}).items():
            add("TLS", f"Suspicious SNI — {k.replace('_', ' ').title()}: {tls['sni']}", str(v), "medium")

    for conv in result.get("conversations", {}).get("tcp", []):
        if conv.get("total_bytes", 0) > 10_000_000:
            mb = conv["total_bytes"] // 1_048_576
            add("Network", f"Large TCP transfer ({mb} MB)", f"{conv['src']} ↔ {conv['dst']}", "medium")

    if len(result.get("dns_queries", [])) > 100:
        add("DNS", f"High DNS query volume ({len(result['dns_queries'])}+ unique queries)",
            "May indicate DGA activity or C2 beaconing", "medium")

    result["suspicious"] = sorted(
        result["suspicious"],
        key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x["severity"], 2),
    )


# ── Artifact Analysis ─────────────────────────────────────────────────────────
# All artifact endpoints accept {"path": "/quarantine/..."}
# The quarantine volume is mounted read-only at /quarantine.

YARA_RULES_DIR = os.environ.get("YARA_RULES_DIR", "/yara-rules")

# Regex patterns for IOC extraction
_RE_IP     = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_RE_URL    = re.compile(r"https?://[^\s\"'<>\]]{8,256}", re.IGNORECASE)
_RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|info|biz|onion|xyz|top|pw|tk|cc|me|tv|us|app)\b", re.IGNORECASE)
_RE_EMAIL  = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_RE_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_CVE    = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_RE_REGKEY = re.compile(r"(?:HKEY_LOCAL_MACHINE|HKLM|HKCU|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU)\\[\w\\]+", re.IGNORECASE)
_RE_UNC    = re.compile(r"\\\\[a-z0-9_.\-]+\\[a-z0-9_.\-]+(?:\\[^\s\"']*)?", re.IGNORECASE)
_RE_B64    = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

_SUSPICIOUS_APIS = {
    "process_injection":   ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtMapViewOfSection", "RtlCreateUserThread"],
    "process_hollowing":   ["ZwUnmapViewOfSection", "NtUnmapViewOfSection", "SetThreadContext", "ResumeThread"],
    "persistence":         ["RegCreateKeyEx", "RegSetValueEx", "CreateService", "StartService", "SHAddToRecentDocs"],
    "network":             ["WSAStartup", "connect", "InternetOpen", "HttpOpenRequest", "URLDownloadToFile", "WinHttpOpen"],
    "evasion":             ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "GetTickCount", "GetSystemTime"],
    "cryptography":        ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext", "BCryptEncrypt"],
    "file_system":         ["CreateFileMapping", "MapViewOfFile", "DeleteFile", "MoveFile", "CopyFile"],
    "keylogging":          ["SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow", "RegisterHotKey"],
    "privilege_escalation": ["AdjustTokenPrivileges", "LookupPrivilegeValue", "DuplicateTokenEx", "ImpersonateLoggedOnUser"],
}


class ArtifactPathRequest(BaseModel):
    path: str
    offset: Optional[int] = 0
    length: Optional[int] = 512


def _read_artifact(path: str) -> bytes:
    p = Path(path).resolve()
    root = Path("/quarantine").resolve()
    if not str(p).startswith(str(root)):
        raise HTTPException(400, "Path outside quarantine")
    if not p.exists():
        raise HTTPException(404, "File not found")
    return p.read_bytes()


# ── 1. File type ─────────────────────────────────────────────────────────────

@app.post("/analyze/file-type")
async def analyze_file_type(req: ArtifactPathRequest):
    raw = _read_artifact(req.path)
    p   = Path(req.path)
    detected_mime = libmagic.from_buffer(raw[:2048], mime=True)
    detected_desc = libmagic.from_buffer(raw[:2048])
    declared_ext  = p.suffix.lower()

    # Common safe mime → extension mapping
    _ext_map = {
        "application/pdf": ".pdf",
        "application/zip": ".zip",
        "application/x-rar": ".rar",
        "application/x-7z-compressed": ".7z",
        "application/x-executable": ".elf",
        "application/x-dosexec": ".exe",
        "application/msword": ".doc",
        "application/vnd.ms-excel": ".xls",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
        "text/html": ".html",
        "text/javascript": ".js",
        "application/javascript": ".js",
        "application/x-sh": ".sh",
        "application/x-python-code": ".py",
        "application/java-archive": ".jar",
    }
    expected_ext = _ext_map.get(detected_mime)
    mismatch     = bool(expected_ext and declared_ext and expected_ext != declared_ext)

    return {
        "mime_type":      detected_mime,
        "description":    detected_desc,
        "declared_ext":   declared_ext or None,
        "expected_ext":   expected_ext,
        "ext_mismatch":   mismatch,
        "file_size":      len(raw),
    }


# ── 2. Hashes ────────────────────────────────────────────────────────────────

@app.post("/analyze/hashes")
async def analyze_hashes(req: ArtifactPathRequest):
    raw  = _read_artifact(req.path)
    h1   = hashlib.sha1(raw).hexdigest()
    h256 = hashlib.sha256(raw).hexdigest()
    h512 = hashlib.sha512(raw).hexdigest()
    hmd5 = hashlib.md5(raw).hexdigest()

    # Byte-distribution entropy (0–8 scale)
    counts  = [0] * 256
    for b in raw:
        counts[b] += 1
    n = len(raw)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts if c) if n else 0.0

    return {
        "md5":     hmd5,
        "sha1":    h1,
        "sha256":  h256,
        "sha512":  h512,
        "size":    n,
        "entropy": round(entropy, 4),
        "entropy_flag": "packed_or_encrypted" if entropy > 7.0 else ("normal" if entropy < 5.0 else "moderate"),
    }


# ── 3. Entropy ───────────────────────────────────────────────────────────────

@app.post("/analyze/entropy")
async def analyze_entropy(req: ArtifactPathRequest):
    raw       = _read_artifact(req.path)
    n         = len(raw)
    CHUNK     = 256

    def _chunk_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        c = [0] * 256
        for b in data:
            c[b] += 1
        ln = len(data)
        return -sum((v / ln) * math.log2(v / ln) for v in c if v)

    # Overall
    overall = _chunk_entropy(raw)

    # Per-chunk
    chunks = []
    for i in range(0, min(n, 64 * CHUNK), CHUNK):
        segment = raw[i:i + CHUNK]
        chunks.append({"offset": i, "entropy": round(_chunk_entropy(segment), 3)})

    high_entropy_chunks = sum(1 for c in chunks if c["entropy"] > 7.0)

    return {
        "overall_entropy":     round(overall, 4),
        "high_entropy_chunks": high_entropy_chunks,
        "total_chunks":        len(chunks),
        "chunks":              chunks,
        "interpretation":      (
            "likely_packed_or_encrypted" if overall > 7.2 else
            "high_entropy" if overall > 6.5 else
            "normal"
        ),
    }


# ── 4. Strings ───────────────────────────────────────────────────────────────

@app.post("/analyze/strings")
async def analyze_strings(req: ArtifactPathRequest):
    raw = _read_artifact(req.path)
    result: dict[str, Any] = {
        "ascii": [], "unicode": [], "iocs": {}, "suspicious_apis": {}, "b64_candidates": [],
    }

    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(raw)
            tmppath = tmp.name
        r_ascii = subprocess.run(
            ["strings", "-n", "6", tmppath], capture_output=True, text=True, timeout=30
        )
        r_unicode = subprocess.run(
            ["strings", "-n", "6", "-e", "l", tmppath], capture_output=True, text=True, timeout=30
        )
        result["ascii"]   = r_ascii.stdout.splitlines()[:2000]
        result["unicode"] = r_unicode.stdout.splitlines()[:500]
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        result["error"] = f"strings tool unavailable: {e}"
    finally:
        try:
            os.unlink(tmppath)
        except Exception:
            pass

    all_strings = "\n".join(result["ascii"] + result["unicode"])

    # IOC patterns in strings
    result["iocs"] = {
        "ips":     list(set(_RE_IP.findall(all_strings)))[:100],
        "urls":    list(set(_RE_URL.findall(all_strings)))[:100],
        "domains": list(set(_RE_DOMAIN.findall(all_strings)))[:100],
        "emails":  list(set(_RE_EMAIL.findall(all_strings)))[:50],
    }

    # Suspicious API names
    found_apis: dict[str, list[str]] = {}
    for category, apis in _SUSPICIOUS_APIS.items():
        hits = [a for a in apis if a in all_strings]
        if hits:
            found_apis[category] = hits
    result["suspicious_apis"] = found_apis

    # Base64 candidates (long enough to be interesting)
    b64 = [m for m in set(_RE_B64.findall(all_strings)) if len(m) > 20][:50]
    result["b64_candidates"] = b64

    return result


# ── 5. IOC Extract ───────────────────────────────────────────────────────────

@app.post("/analyze/ioc-extract")
async def analyze_ioc_extract(req: ArtifactPathRequest):
    raw  = _read_artifact(req.path)
    text = raw.decode("utf-8", errors="replace")

    def dedupe(items: list) -> list:
        seen: set = set()
        out: list = []
        for i in items:
            if i not in seen:
                seen.add(i)
                out.append(i)
        return out

    ips      = dedupe(_RE_IP.findall(text))[:200]
    urls     = dedupe(_RE_URL.findall(text))[:200]
    domains  = dedupe(_RE_DOMAIN.findall(text))[:200]
    emails   = dedupe(_RE_EMAIL.findall(text))[:100]
    md5s     = dedupe(_RE_MD5.findall(text))[:100]
    sha1s    = dedupe(_RE_SHA1.findall(text))[:100]
    sha256s  = dedupe(_RE_SHA256.findall(text))[:100]
    cves     = dedupe(_RE_CVE.findall(text))[:100]
    regkeys  = dedupe(_RE_REGKEY.findall(text))[:100]
    unc      = dedupe(_RE_UNC.findall(text))[:50]

    total = sum(len(x) for x in [ips, urls, domains, emails, md5s, sha1s, sha256s, cves, regkeys, unc])
    return {
        "ips": ips, "urls": urls, "domains": domains, "emails": emails,
        "md5s": md5s, "sha1s": sha1s, "sha256s": sha256s,
        "cves": cves, "registry_keys": regkeys, "unc_paths": unc,
        "total": total,
    }


# ── 6. PE Analysis ───────────────────────────────────────────────────────────

@app.post("/analyze/pe")
async def analyze_pe(req: ArtifactPathRequest):
    raw = _read_artifact(req.path)
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed"}

    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except pefile.PEFormatError as e:
        return {"error": f"Not a valid PE file: {e}"}

    # Sections
    sections = []
    for s in getattr(pe, "sections", []):
        raw_data = s.get_data()
        n        = len(raw_data)
        counts   = [0] * 256
        for b in raw_data:
            counts[b] += 1
        ent = -sum((c / n) * math.log2(c / n) for c in counts if c) if n else 0.0
        sections.append({
            "name":     s.Name.decode("utf-8", errors="replace").rstrip("\x00"),
            "vaddr":    hex(s.VirtualAddress),
            "vsize":    s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy":  round(ent, 3),
        })

    # Imports
    imports: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            imports[dll] = [
                imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                for imp in entry.imports
            ]

    # Exports
    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(sym.name.decode("utf-8", errors="replace") if sym.name else f"ord_{sym.ordinal}")

    # Version info
    version_info: dict = {}
    if hasattr(pe, "VS_FIXEDFILEINFO"):
        vi = pe.VS_FIXEDFILEINFO[0]
        version_info["file_version"]    = f"{vi.FileVersionMS >> 16}.{vi.FileVersionMS & 0xFFFF}.{vi.FileVersionLS >> 16}.{vi.FileVersionLS & 0xFFFF}"
        version_info["product_version"] = f"{vi.ProductVersionMS >> 16}.{vi.ProductVersionMS & 0xFFFF}.{vi.ProductVersionLS >> 16}.{vi.ProductVersionLS & 0xFFFF}"

    # Suspicion score
    all_imports = [i for dll_imports in imports.values() for i in dll_imports]
    import_str  = " ".join(all_imports)
    score = 0
    flags: list[str] = []
    overall_entropy = -sum((c / len(raw)) * math.log2(c / len(raw)) for c in [raw.count(bytes([b])) for b in range(256)] if c) if raw else 0.0
    if overall_entropy > 7.0:
        score += 30; flags.append("high_overall_entropy")
    for cat, apis in _SUSPICIOUS_APIS.items():
        if any(a in import_str for a in apis):
            score += 10; flags.append(f"suspicious_imports_{cat}")
    for sec in sections:
        if sec["entropy"] > 7.0:
            score += 20; flags.append(f"high_entropy_section_{sec['name']}")
    if not version_info:
        score += 10; flags.append("no_version_info")

    pe.close()
    return {
        "machine":      hex(pe.FILE_HEADER.Machine),
        "timestamp":    pe.FILE_HEADER.TimeDateStamp,
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "entry_point":  hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base":   hex(pe.OPTIONAL_HEADER.ImageBase),
        "sections":     sections,
        "imports":      imports,
        "exports":      exports[:100],
        "version_info": version_info,
        "suspicion_score": min(score, 100),
        "suspicion_flags": flags,
    }


# ── 7. Office / Macro Analysis ───────────────────────────────────────────────

@app.post("/analyze/office")
async def analyze_office(req: ArtifactPathRequest):
    raw = _read_artifact(req.path)
    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    except ImportError:
        return {"error": "oletools not installed"}

    try:
        vba = VBA_Parser(req.path, data=raw)
    except Exception as e:
        return {"error": f"oletools error: {e}"}

    macros = []
    indicators: list[str] = []
    risk = "low"

    _risky = ["AutoOpen", "AutoClose", "AutoExec", "Document_Open", "Workbook_Open",
              "Shell", "CreateObject", "WScript.Shell", "PowerShell",
              "URLDownloadToFile", "XMLHTTP", "WinHttpRequest",
              "Chr(", "Asc(", "Base64", "Execute", "Eval"]

    if vba.detect_vba_macros():
        for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
            code_str = vba_code if isinstance(vba_code, str) else vba_code.decode("utf-8", errors="replace")
            hits = [kw for kw in _risky if kw.lower() in code_str.lower()]
            macros.append({
                "filename":   filename,
                "stream":     stream_path,
                "vba_file":   vba_filename,
                "code":       code_str[:8000],
                "indicators": hits,
            })
            indicators.extend(hits)

        if any(kw in indicators for kw in ["Shell", "CreateObject", "URLDownloadToFile", "PowerShell"]):
            risk = "high"
        elif indicators:
            risk = "medium"

    vba.close()
    return {
        "has_macros":  vba.detect_vba_macros(),
        "macro_count": len(macros),
        "macros":      macros,
        "all_indicators": list(set(indicators)),
        "risk":        risk,
    }


# ── 8. PDF Analysis ──────────────────────────────────────────────────────────

@app.post("/analyze/pdf")
async def analyze_pdf(req: ArtifactPathRequest):
    raw = _read_artifact(req.path)
    if not raw.startswith(b"%PDF"):
        return {"error": "Not a PDF file"}

    result: dict[str, Any] = {
        "suspicious_keywords": {},
        "text_preview":        "",
        "metadata":            {},
        "risk":                "low",
    }

    _pdf_keywords = [
        "/JavaScript", "/JS", "/Launch", "/Action", "/OpenAction",
        "/EmbeddedFile", "/URI", "/SubmitForm", "/ImportData",
        "/RichMedia", "/XFA", "/AcroForm",
    ]

    text_body = raw.decode("latin-1", errors="replace")
    kw_counts: dict[str, int] = {}
    for kw in _pdf_keywords:
        count = text_body.count(kw)
        if count:
            kw_counts[kw] = count
    result["suspicious_keywords"] = kw_counts

    risk_kws = ["/JavaScript", "/JS", "/Launch", "/OpenAction", "/EmbeddedFile"]
    if any(k in kw_counts for k in risk_kws[:2]):
        result["risk"] = "high"
    elif any(k in kw_counts for k in risk_kws):
        result["risk"] = "medium"

    # Extract text via pdfminer
    try:
        from pdfminer.high_level import extract_text
        text = extract_text(io.BytesIO(raw))
        result["text_preview"] = text[:2000] if text else ""
    except Exception as e:
        result["text_error"] = str(e)[:128]

    return result


# ── 9. EXIF / Metadata ───────────────────────────────────────────────────────

@app.post("/analyze/exif")
async def analyze_exif(req: ArtifactPathRequest):
    raw = _read_artifact(req.path)
    result: dict[str, Any] = {"fields": {}, "sensitive_fields": [], "tool": None}

    # Try exiftool (most comprehensive)
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(req.path).suffix) as tmp:
            tmp.write(raw)
            tmppath = tmp.name
        r = subprocess.run(
            ["exiftool", "-json", tmppath],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0 and r.stdout:
            import json
            data = json.loads(r.stdout)
            fields = data[0] if data else {}
            result["fields"] = fields
            result["tool"]   = "exiftool"
            _SENSITIVE = ["Author", "Creator", "LastSavedBy", "Company", "UserName",
                          "GPSLatitude", "GPSLongitude", "MakeModel", "SerialNumber",
                          "OwnerName", "Software"]
            result["sensitive_fields"] = [k for k in fields if any(s.lower() in k.lower() for s in _SENSITIVE)]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    finally:
        try:
            os.unlink(tmppath)
        except Exception:
            pass

    # Fallback: exifread for image files
    if not result["fields"]:
        try:
            import exifread
            tags = exifread.process_file(io.BytesIO(raw), details=False)
            result["fields"] = {str(k): str(v) for k, v in tags.items()}
            result["tool"]   = "exifread"
        except Exception:
            result["tool"] = "none"

    return result


# ── 10. Hex Dump ─────────────────────────────────────────────────────────────

@app.post("/analyze/hexdump")
async def analyze_hexdump(req: ArtifactPathRequest):
    raw    = _read_artifact(req.path)
    offset = min(req.offset or 0, len(raw))
    length = min(req.length or 512, 65536, len(raw) - offset)
    chunk  = raw[offset:offset + length]

    lines = []
    for i in range(0, len(chunk), 16):
        row   = chunk[i:i + 16]
        hex_  = " ".join(f"{b:02x}" for b in row)
        ascii_= "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in row)
        lines.append({
            "offset": f"{offset + i:08x}",
            "hex":    hex_,
            "ascii":  ascii_,
        })
    return {
        "offset":    offset,
        "length":    length,
        "file_size": len(raw),
        "lines":     lines,
    }


# ── 11. YARA ─────────────────────────────────────────────────────────────────

@app.post("/analyze/yara")
async def analyze_yara(req: ArtifactPathRequest):
    raw = _read_artifact(req.path)
    try:
        import yara
    except ImportError:
        return {"error": "yara-python not installed", "matches": []}

    rules_dir = Path(YARA_RULES_DIR)
    if not rules_dir.exists():
        return {"error": f"YARA rules directory not found: {rules_dir}", "matches": []}

    rule_files = list(rules_dir.glob("**/*.yar")) + \
                 list(rules_dir.glob("**/*.yara")) + \
                 list(rules_dir.glob("**/*.rules"))

    if not rule_files:
        return {"matches": [], "rules_loaded": 0, "note": "No .yar/.yara/.rules files in YARA rules directory"}

    matches: list[dict] = []
    loaded = 0
    for rf in rule_files[:100]:  # cap at 100 rule files
        try:
            compiled = yara.compile(str(rf))
            loaded  += 1
            for m in compiled.match(data=raw):
                matches.append({
                    "rule":      m.rule,
                    "namespace": m.namespace,
                    "tags":      list(m.tags),
                    "meta":      dict(m.meta),
                    "strings":   [
                        {"offset": s.instances[0].offset, "identifier": s.identifier, "data": repr(bytes(s.instances[0])[:64])}
                        for s in m.strings
                    ][:20],
                })
        except yara.SyntaxError:
            pass  # Skip malformed rule files

    return {"matches": matches, "rules_loaded": loaded, "rule_files_scanned": len(rule_files)}


class YaraInlineRule(BaseModel):
    name: str
    content: str

class YaraInlineRequest(BaseModel):
    path: str
    rules: list[YaraInlineRule]

@app.post("/analyze/yara-inline")
async def analyze_yara_inline(req: YaraInlineRequest):
    """Run caller-supplied YARA rules (as text) against a quarantine artifact."""
    raw = _read_artifact(req.path)
    try:
        import yara
    except ImportError:
        return {"error": "yara-python not installed", "matches": []}

    matches: list[dict] = []
    errors:  list[str]  = []

    for rule in req.rules:
        try:
            compiled = yara.compile(source=rule.content)
            for m in compiled.match(data=raw):
                strings = []
                for s in m.strings:
                    for inst in s.instances:
                        try:
                            data_repr = inst.matched_data.decode("utf-8", errors="replace")[:200]
                        except Exception:
                            data_repr = repr(inst.matched_data[:50])
                        strings.append({
                            "identifier": s.identifier,
                            "offset":     inst.offset,
                            "data":       data_repr,
                        })
                matches.append({
                    "rule_name": rule.name,
                    "yara_rule": m.rule,
                    "tags":      list(m.tags),
                    "meta":      dict(m.meta),
                    "strings":   strings[:20],
                })
        except Exception as e:
            errors.append(f"{rule.name}: {e}")

    return {"matches": matches, "errors": errors}
