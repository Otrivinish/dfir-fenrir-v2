"""Containment plan for an email analysis (P3, docs/phishing-fast-path-slices.md): which of its indicators
to block, and whether to quarantine the message -- each with a suggestion and the reason for it. Pure: the
route adds what the incident already has (IOCs, actions) and creates what the analyst confirms.

Sender rules: a From address that failed DMARC is forged, so blocking it (or its domain) would block its
real owner -- it is never suggested then. The sender is suggested only when DMARC passed AND the live DNS
check confirmed it (a pass written in the message's own header can be forged), and the verdict is red or
an earlier incident confirmed the address; the whole sender domain only for a punycode lookalike; a
Reply-To on another domain (BEC reply-redirect) is the attacker's mailbox and is suggested.

Links are suggested only when an earlier incident confirmed them: a risk signal alone can be steered by
the attacker onto a legitimate destination (link text "evil.example" over href login.microsoftonline.com
fires "link text hides its true destination" on Microsoft's sign-in host). The signal is still the reason.
"""
from core.url_indicator import classify_url_indicator
from email_analyzer.indicators import address, domain_of, link_target, public_ip
from email_analyzer.scoring import attachment_signals, url_signals

KINDS = ("message", "sender", "sender_domain", "reply_to", "url", "attachment", "origin_ip")
MAX_IOC_VALUE = 2048          # IOC.value is String(2048): a longer value can't become an IOC
BLOCK_TEMPLATE = {"url": "block_url", "domain": "block_domain", "ip": "block_ip"}
# Titles of the templates used here -- a mirror of frontend/src/pages/incident/respond/actionTemplates.js
# (the Respond form titles an action with its template's title), like containment.TEMPLATE_TARGET_TYPES.
TITLES = {
    "quarantine_email": "Quarantine email(s)",
    "block_sender":     "Block sender domain/address",
    "block_url":        "Block URL",
    "block_domain":     "Block domain",
    "block_ip":         "Block IP address",
    "block_hash":       "Block file hash",
}


def _strong_signal(signals) -> str | None:
    """The title of the first high or medium signal, or None."""
    return next((s[2] for s in signals if s[1] in ("high", "medium")), None)


def plan(a, strong_hits: frozenset = frozenset()) -> list[dict]:
    """[{kind, ref, ioc_type, value, template_id, title, suggested, reason}], one per (IOC, template).
    `strong_hits` = (type, value) pairs an earlier incident confirmed or marked malicious (seen-before)."""
    codes = {f.get("code") for f in a.findings or []}
    dmarc = ((a.headers or {}).get("auth") or {}).get("dmarc")
    av = getattr(a, "auth_verified", None) or {}
    dmarc_confirmed = (dmarc == "pass" and not av.get("error") and not av.get("skipped")
                       and bool((av.get("dmarc") or {}).get("found"))
                       and not codes & {"dmarc_claim_unverified", "spf_claim_unverified"})
    items: list[dict] = []
    index: dict[tuple, dict] = {}

    def add(kind, ref, ioc_type, value, template, suggested, reason):
        if ioc_type and (not value or len(value) > MAX_IOC_VALUE):
            return
        key = (ioc_type, value, template)
        if key in index:
            # The same IOC + action from another row (two links to one host, one hash under two names):
            # one item, suggested if any row suggests it, with that row's reason.
            if suggested and not index[key]["suggested"]:
                index[key].update(suggested=True, reason=reason)
            return
        index[key] = {"kind": kind, "ref": ref, "ioc_type": ioc_type, "value": value, "template_id": template,
                      "title": TITLES[template], "suggested": bool(suggested), "reason": reason}
        items.append(index[key])

    red_amber = a.verdict in ("red", "amber")
    add("message", None, None, None, "quarantine_email", red_amber,
        f"The verdict is {a.verdict}." if red_amber else "The verdict is green.")

    sender = address(a.from_addr)
    if sender:
        if dmarc == "fail":
            s, why = False, "DMARC failed: the From address is forged, and blocking it would block its real owner."
        elif dmarc_confirmed and (a.verdict == "red" or ("email", sender) in strong_hits):
            s, why = True, "DMARC passed (confirmed by the live DNS check), so this address really sent it" + (
                ", and the verdict is red." if a.verdict == "red" else ", and an earlier incident confirmed it.")
        elif dmarc == "pass":
            s, why = False, ("DMARC passed only in the message's own header, not confirmed by the live DNS check: "
                             "the address may be forged.")
        else:
            s, why = False, "Block it only if this address really sent the mail (DMARC didn't pass)."
        add("sender", None, "email", sender, "block_sender", s, why)
        lookalike = "punycode_from" in codes
        add("sender_domain", None, "domain", domain_of(sender), "block_sender", lookalike,
            "Punycode lookalike sender domain." if lookalike
            else "Blocking a whole domain also blocks its legitimate senders.")

    reply = address(a.reply_to)
    if reply and reply != sender:
        redirect = "replyto_mismatch" in codes
        add("reply_to", None, "email", reply, "block_sender", redirect,
            "Replies go to another domain: a BEC reply-redirect." if redirect else "Reply-To differs from the sender.")

    for i, u in enumerate(a.urls or []):
        kind = classify_url_indicator(link_target(u))
        if not kind:
            continue
        signal = _strong_signal(url_signals(u))
        strong = kind in strong_hits
        add("url", i, kind[0], kind[1], BLOCK_TEMPLATE[kind[0]], strong,
            "Seen in an earlier confirmed incident or on a malicious IOC." if strong
            else f"{signal}. Check it isn't a legitimate site before blocking." if signal
            else "No risk signal on this link.")

    for i, att in enumerate(a.attachments or []):
        sha = (att.get("sha256") or "").lower()
        signal = _strong_signal(attachment_signals(att))
        strong = ("hash_sha256", sha) in strong_hits
        add("attachment", i, "hash_sha256", sha, "block_hash", signal or strong,
            signal or ("Seen in an earlier confirmed incident or on a malicious IOC." if strong
                       else "No risk signal on this attachment."))

    ip = public_ip((a.headers or {}).get("origin_ip"))
    add("origin_ip", None, "ip", ip, "block_ip", False,
        "Usually a mail provider's relay: block it only if it is the attacker's own server.")
    return items
