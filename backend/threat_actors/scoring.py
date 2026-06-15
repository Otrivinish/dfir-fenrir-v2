"""Threat actor confidence scoring — adapted from v1 with 3 active signals.

We dropped v1's `infrastructure` and `campaign_timing` signals (no data source
in v2 today), and `ioc_hit` is deferred until threat_intel_iocs gains actor
attribution. That leaves three meaningful signals:

  ttp_match     15 pts × up to 3   = 45  (incident technique ∩ actor techniques)
  malware_match 25 pts × up to 1   = 25  (actor's software name in incident IOCs)
  victimology   10 pts × up to 1   = 10  (incident type ↔ actor motivation)

Max achievable = 80 (capped at 100; cap is preserved so adding `ioc_hit` later
doesn't require a confidence-band rewrite).

Confidence bands map to the existing `possible | probable | confirmed` literal:
  0–29   = possible
  30–59  = probable
  60–100 = confirmed
"""
from __future__ import annotations

from typing import Iterable

# ── Weights ──────────────────────────────────────────────────────────────────

SIGNAL_WEIGHTS = {
    "ttp_match":     15,
    "malware_match": 25,
    "victimology":   10,
}
SIGNAL_MAX_COUNT = {
    "ttp_match":     3,
    "malware_match": 1,
    "victimology":   1,
}
SIGNAL_LABELS = {
    "ttp_match":     "TTP / Technique overlap",
    "malware_match": "Malware / Tool family",
    "victimology":   "Victimology match",
}

# Map incident_type values to plausible actor motivations. Multiple motivations
# per type are OR-matched. Keep this conservative — false positives hurt more
# than misses, and the analyst still has to Accept.
INCIDENT_TYPE_TO_MOTIVATION = {
    "ransomware":       ["ransomware", "financial"],
    "data_breach":      ["espionage", "financial"],
    "data_theft":       ["espionage", "financial"],
    "credential_theft": ["financial", "espionage"],
    "phishing":         ["financial", "espionage"],
    "bec":              ["financial"],
    "ddos":             ["hacktivist", "destructive"],
    "insider":          ["financial", "espionage"],
    "supply_chain":     ["espionage", "destructive"],
    "espionage":        ["espionage"],
    "destructive":      ["destructive"],
}


def calculate_score(evidence: list[dict]) -> int:
    """0-100 from an evidence list. Counts per signal capped, weights summed."""
    counts: dict[str, int] = {}
    total = 0
    for item in evidence:
        sig = item.get("signal_type", "")
        if sig not in SIGNAL_WEIGHTS:
            continue
        count = counts.get(sig, 0)
        if count < SIGNAL_MAX_COUNT.get(sig, 1):
            total += SIGNAL_WEIGHTS[sig]
            counts[sig] = count + 1
    return min(total, 100)


def score_to_confidence(score: int) -> str:
    """Numeric score → categorical band matching the IncidentAttribution literal."""
    if score >= 60:
        return "confirmed"
    if score >= 30:
        return "probable"
    return "possible"


def build_evidence_for_actor(
    *,
    actor_techniques: Iterable[str],
    actor_software:   list[dict],
    actor_motivation: str,
    incident_techniques: set[str],
    incident_technique_name_map: dict[str, str],
    incident_ioc_values: list[str],
    incident_type: str,
) -> list[dict]:
    """Build the per-signal evidence list for one actor against one incident.

    Returns at most `SIGNAL_MAX_COUNT[sig]` entries per signal — the scoring
    cap is enforced here so callers can rely on the returned list being the
    scoring-relevant set.
    """
    evidence: list[dict] = []

    # ── TTP overlap ──────────────────────────────────────────────────────────
    matched_techs = sorted(
        set(t.upper() for t in actor_techniques if t)
        & set(t.upper() for t in incident_techniques if t)
    )
    for tid in matched_techs[: SIGNAL_MAX_COUNT["ttp_match"]]:
        evidence.append({
            "signal_type":  "ttp_match",
            "label":        SIGNAL_LABELS["ttp_match"],
            "points":       SIGNAL_WEIGHTS["ttp_match"],
            "technique_id": tid,
            "description":  f"Technique {tid}"
                            + (f" ({incident_technique_name_map.get(tid, '')})"
                               if incident_technique_name_map.get(tid) else "")
                            + " seen in timeline and attributed to this actor",
        })

    # ── Malware / tool name found in incident IOC values ─────────────────────
    # We look for the software name as a substring in any IOC value (lower-
    # cased). Short names (<4 chars) are skipped to avoid false positives
    # like 'csh' matching 'cisco'.
    iocs_lower = [v.lower() for v in incident_ioc_values if v]
    for sw in (actor_software or []):
        name = (sw.get("name") or "").lower()
        if len(name) < 4:
            continue
        hit = next((v for v in iocs_lower if name in v), None)
        if hit:
            evidence.append({
                "signal_type":  "malware_match",
                "label":        SIGNAL_LABELS["malware_match"],
                "points":       SIGNAL_WEIGHTS["malware_match"],
                "technique_id": None,
                "description":  f"Actor-associated {sw.get('type', 'software')} "
                                f"'{sw.get('name')}' found in incident IOCs",
            })
            break   # one malware_match is the per-actor cap

    # ── Victimology — incident type ↔ actor motivation ───────────────────────
    inc_key = (incident_type or "").lower().replace(" ", "_").replace("-", "_")
    motivations_for_type: set[str] = set()
    for key, motivations in INCIDENT_TYPE_TO_MOTIVATION.items():
        if key in inc_key:
            motivations_for_type.update(motivations)

    actor_mot = (actor_motivation or "").strip().lower()
    if actor_mot and motivations_for_type and actor_mot in motivations_for_type:
        evidence.append({
            "signal_type":  "victimology",
            "label":        SIGNAL_LABELS["victimology"],
            "points":       SIGNAL_WEIGHTS["victimology"],
            "technique_id": None,
            "description":  f"Incident type '{incident_type}' aligns with "
                            f"actor motivation '{actor_motivation}'",
        })

    return evidence
