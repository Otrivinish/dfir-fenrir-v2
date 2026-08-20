"""Live SPF/DMARC/DKIM checks for the email analyzer's manual "check this
domain" mode.

SPF and DMARC are evaluated from live DNS (Google DoH, same no-key pattern
`osint/service.py`'s `dns` source already uses) -- this is genuinely new
capability, not just fetching raw records: the mechanism chain and policy
are actually parsed and given a plain-language verdict.

DKIM cannot be checked from a bare domain -- the selector (`s=` in a real
DKIM-Signature header) isn't guessable, there is no selector registry to
enumerate. Manual mode takes an optional selector instead of pretending to
guess one; the caller (frontend) auto-fills it from an already-parsed
email's `dkim_selector` when one is available.
"""
import httpx

_TIMEOUT = httpx.Timeout(10.0)


async def _fetch_txt(name: str) -> list[str]:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        r = await c.get(
            "https://dns.google/resolve",
            params={"name": name, "type": "TXT"},
            headers={"Accept": "application/dns-json"},
        )
        r.raise_for_status()
        j = r.json() or {}
        out = []
        for a in (j.get("Answer") or []):
            data = (a.get("data") or "").strip()
            if data.startswith('"') and data.endswith('"'):
                data = data[1:-1]
            out.append(data.replace('" "', ""))  # DoH splits long TXT strings into quoted chunks
        return out


def _kv_fields(record: str) -> dict:
    fields = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.strip().lower()] = v.strip()
    return fields


def _parse_spf(txt_records: list[str]) -> dict:
    spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]
    if not spf_records:
        return {"found": False, "verdict": "No SPF record found — any server can send as this domain, unchecked."}

    record = spf_records[0]
    mechanisms = record.split()[1:]
    all_mech = next((m for m in mechanisms if m.lstrip("+-~?") == "all"), None)

    if all_mech is None:
        verdict = "No 'all' mechanism — SPF result for unmatched senders is undefined."
    elif all_mech.startswith("-"):
        verdict = "Hard fail (-all) — unauthorized senders should be rejected."
    elif all_mech.startswith("~"):
        verdict = "Soft fail (~all) — unauthorized senders flagged, not rejected outright."
    elif all_mech.startswith("?"):
        verdict = "Neutral (?all) — no policy stance on unauthorized senders."
    else:  # '+all' or bare 'all'
        verdict = "Pass-all (+all) — misconfiguration: this authorizes ANY sender."

    return {
        "found": True,
        "record": record,
        "mechanisms": mechanisms,
        "multiple_records": len(spf_records) > 1,  # itself an RFC 7208 violation
        "verdict": verdict,
    }


async def _expand_includes(spf: dict) -> list[dict]:
    """One level of include: expansion, so the summary doesn't dead-end at
    'include:_spf.example.com'. Capped at 10 -- SPF's own RFC 7208 lookup
    ceiling -- not arbitrarily; deeper nesting is not followed."""
    if not spf.get("found"):
        return []
    includes = [m[8:] for m in spf["mechanisms"] if m.lower().startswith("include:")]
    out = []
    for domain in includes[:10]:
        try:
            out.append({"domain": domain, **_parse_spf(await _fetch_txt(domain))})
        except (httpx.HTTPStatusError, httpx.TimeoutException) as exc:
            out.append({"domain": domain, "found": False, "verdict": f"Lookup failed: {exc}"})
    return out


def _parse_dmarc(txt_records: list[str]) -> dict:
    dmarc_records = [t for t in txt_records if t.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return {"found": False, "verdict": "No DMARC record found — this domain has no anti-spoofing policy at all."}

    record = dmarc_records[0]
    fields = _kv_fields(record)
    policy = fields.get("p", "none")
    verdicts = {
        "reject":     "p=reject — strict; spoofed mail should be rejected outright.",
        "quarantine": "p=quarantine — spoofed mail should be flagged/junked, not rejected.",
        "none":       "p=none — monitoring only; spoofed mail is NOT blocked by this policy.",
    }
    return {
        "found": True,
        "record": record,
        "fields": fields,
        "verdict": verdicts.get(policy, f"Unrecognized policy 'p={policy}'."),
    }


async def check_spf_dmarc(domain: str) -> dict:
    spf = _parse_spf(await _fetch_txt(domain))
    spf["includes"] = await _expand_includes(spf)
    dmarc = _parse_dmarc(await _fetch_txt(f"_dmarc.{domain}"))
    return {"spf": spf, "dmarc": dmarc}


async def check_dkim(domain: str, selector: str) -> dict:
    record_txt = await _fetch_txt(f"{selector}._domainkey.{domain}")
    dkim_records = [t for t in record_txt if "p=" in t.lower()]
    if not dkim_records:
        return {
            "found": False, "selector": selector,
            "verdict": "No DKIM record found at this selector — either the selector is wrong, "
                       "or DKIM isn't (or is no longer) configured for it.",
        }
    fields = _kv_fields(dkim_records[0])
    has_key = bool(fields.get("p"))
    return {
        "found": True,
        "selector": selector,
        "fields": fields,
        "verdict": "Public key present." if has_key else "Record found but no public key ('p=') — likely revoked/rotated out.",
    }
