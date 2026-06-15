"""U8.1 — phishing risk scoring. Pure functions over the parsed dict (see parser.py).

Fused weighted signals across header / URL / attachment layers → a 0–100 score and a
green/amber/red verdict. Each fired signal yields a plain-English finding.
"""
from __future__ import annotations

import re

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}
DANGER_EXT  = (".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
               ".lnk", ".iso", ".img", ".bat", ".cmd", ".ps1", ".jar", ".msi", ".com", ".pif")
MACRO_EXT   = (".docm", ".xlsm", ".pptm", ".dotm", ".xlam")
ARCHIVE_EXT = (".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".ace", ".iso", ".img")


def _domain(addr):
    return addr.rsplit("@", 1)[-1].lower() if addr and "@" in addr else (addr or "").lower()


def _reg(host):
    """Naive registrable domain (last two labels) — good enough for alignment + lookalike."""
    if not host:
        return ""
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _famtype(mime):
    mime = (mime or "").lower()
    if any(x in mime for x in ("dosexec", "x-executable", "x-msdownload", "x-elf", "mach-o")):
        return "executable"
    if any(x in mime for x in ("zip", "x-rar", "x-7z", "gzip", "x-tar", "x-iso9660")):
        return "archive"
    if "pdf" in mime:                                            return "pdf"
    if any(x in mime for x in ("msword", "officedocument", "ms-excel", "ms-powerpoint", "opendocument")):
        return "office"
    if mime.startswith("image/"):                               return "image"
    if mime.startswith("text/"):                                return "text"
    if "octet-stream" in mime:                                  return "unknown"
    return mime


def score(parsed: dict) -> dict:
    findings: list[dict] = []
    force_red = False

    def add(code, sev, title, detail, layer, pts):
        findings.append({"code": code, "severity": sev, "title": title,
                         "detail": detail, "layer": layer, "points": pts})

    auth = parsed.get("auth") or {}
    from_addr = parsed.get("from_addr")
    from_dom = _domain(from_addr)
    from_reg = _reg(from_dom)

    # ── header / identity ──
    dmarc = auth.get("dmarc")
    if dmarc == "fail":
        add("dmarc_fail", "high", "DMARC failed",
            "The receiver reported dmarc=fail — the message is not authorised by the From domain.", "header", 30)
    elif dmarc in (None, "none"):
        add("dmarc_none", "medium", "No DMARC pass",
            "No enforced DMARC result recorded — the From domain is spoofable.", "header", 15)

    spf = auth.get("spf")
    spf_reg = _reg(_domain(auth.get("spf_domain")))
    if spf == "pass" and spf_reg and from_reg and spf_reg != from_reg:
        add("spf_unaligned", "high", "SPF not aligned",
            f"SPF passed for {spf_reg}, not the From domain {from_reg} — alignment failure.", "header", 20)
    elif spf == "fail":
        add("spf_fail", "medium", "SPF failed",
            "The sending IP is not authorised by the From domain's SPF record.", "header", 15)

    dkim = auth.get("dkim")
    dkim_reg = _reg(auth.get("dkim_domain"))
    if dkim == "pass" and dkim_reg and from_reg and dkim_reg != from_reg:
        add("dkim_unaligned", "medium", "DKIM not aligned",
            f"DKIM was signed by {dkim_reg}, not the From domain {from_reg}.", "header", 15)

    reply_to = parsed.get("reply_to")
    if reply_to and from_addr and reply_to.lower() != from_addr.lower() and _reg(_domain(reply_to)) != from_reg:
        add("replyto_mismatch", "high", "Reply-To differs from From",
            f"Replies go to {reply_to}, not {from_addr} — classic BEC reply-redirect.", "header", 25)

    rpath = parsed.get("return_path")
    if rpath and from_addr and _reg(_domain(rpath)) != from_reg:
        add("returnpath_mismatch", "low", "Return-Path differs from From",
            f"Envelope sender {rpath} ≠ From {from_addr}.", "header", 10)

    disp = parsed.get("from_display") or ""
    m = re.search(r'[\w.+-]+@[\w.-]+\.\w+', disp)
    if m and from_addr and _reg(_domain(m.group(0))) != from_reg:
        add("displayname_spoof", "medium", "Display name contains a different address",
            f"The display name shows {m.group(0)} but the real sender is {from_addr}.", "header", 15)

    if "xn--" in from_dom:
        add("punycode_from", "high", "Punycode sender domain",
            f"From domain {from_dom} uses punycode — possible homoglyph spoof.", "header", 25)

    for h in parsed.get("hops") or []:
        if h.get("delay_seconds") is not None and h["delay_seconds"] < -60:
            add("forged_hop", "high", "Forged Received hop",
                f"A Received hop has a negative delay ({int(h['delay_seconds'])}s) — timestamps run backwards, "
                "a sign the routing header was forged.", "header", 20)
            break

    # ── URLs ──
    for u in parsed.get("urls") or []:
        host = (u.get("host") or "").lower()
        dh = u.get("display_host")
        if dh and host and _reg(dh) != _reg(host):
            add("url_display_mismatch", "high", "Link text hides its true destination",
                f"The link shows {dh} but points to {host}.", "url", 25)
        if _reg(host) in SHORTENERS:
            add("url_shortener", "low", "URL shortener",
                f"{host} hides the final destination.", "url", 10)
        if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host or ""):
            add("url_raw_ip", "medium", "Raw-IP URL",
                f"{u.get('url')} uses a bare IP address instead of a hostname.", "url", 15)
        authority = u.get("url", "").split("//", 1)[-1].split("/", 1)[0]
        if "@" in authority:
            add("url_userinfo", "medium", "Userinfo trick in URL",
                "The URL authority contains '@' — the visible host may be fake.", "url", 15)
        if "xn--" in host:
            add("url_punycode", "medium", "Punycode URL host",
                f"{host} uses punycode — possible homoglyph.", "url", 15)

    # ── attachments ──
    for a in parsed.get("attachments") or []:
        name = (a.get("filename") or "").lower()
        dfam = _famtype(a.get("declared_type"))
        tfam = _famtype(a.get("true_type"))
        if dfam != tfam and tfam in ("executable", "archive") and dfam not in ("executable", "archive", "unknown", ""):
            add("att_type_mismatch", "high", "Attachment type mismatch",
                f"{a['filename']} claims {a.get('declared_type')} but is actually {a.get('true_type')}.", "attachment", 30)
        if name.endswith(DANGER_EXT):
            add("att_executable", "high", "Executable / script attachment",
                f"{a['filename']} is an executable or script type.", "attachment", 25)
        if name.count(".") >= 2 and name.endswith(DANGER_EXT):
            add("att_double_ext", "high", "Double extension",
                f"{a['filename']} hides its real extension behind a benign-looking one.", "attachment", 20)
        if name.endswith(MACRO_EXT):
            add("att_macro", "medium", "Macro-enabled Office attachment",
                f"{a['filename']} can carry macros.", "attachment", 20)
        if "‮" in (a.get("filename") or ""):
            add("att_rtlo", "high", "Right-to-left override in filename",
                "The filename uses U+202E to disguise its true extension.", "attachment", 20)
        if name.endswith(ARCHIVE_EXT):
            add("att_archive", "low", "Archive attachment",
                f"{a['filename']} is a container — contents aren't visible until extracted in the sandbox.", "attachment", 8)

    pts = sum(x["points"] for x in findings)
    score_val = min(100, pts)
    verdict = "red" if (force_red or score_val >= 50) else ("amber" if score_val >= 20 else "green")
    return {"score": score_val, "verdict": verdict, "findings": findings}
