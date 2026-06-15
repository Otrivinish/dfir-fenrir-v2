"""DNS reconstruction — derives a per-domain analyst view from existing
PCAP analyser output (`result_json["dns_queries"]`). No worker changes; the
raw tshark fields already carry everything we need.

Aggregates by FQDN: query count, unique resolved IPs, CNAME chain, record
types seen, querying clients, first/last seen offsets, union of suspicious
flags from the worker, plus a label-entropy DGA heuristic on top of the
worker's existing low_vowel_ratio/long_domain checks.
"""
from __future__ import annotations

import math
from collections import defaultdict

from pydantic import BaseModel


def _entropy(s: str) -> float:
    """Shannon entropy of a string in bits/char. 0 for empty."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_dga_candidate(domain: str) -> bool:
    """High-entropy + low-vowel + long-enough leftmost label. Tuned to keep
    false positives down on legitimate CDN hostnames (CDN labels are usually
    shorter or carry vowels)."""
    if not domain:
        return False
    label = domain.lower().split(".")[0]
    if len(label) < 10:
        return False
    vowels = sum(1 for c in label if c in "aeiou")
    vowel_ratio = vowels / len(label)
    return _entropy(label) > 3.5 and vowel_ratio < 0.3


class DnsDomainRow(BaseModel):
    query:             str
    query_count:       int
    resolved_ips:      list[str]
    cnames:            list[str]
    record_types:      list[str]
    clients:           list[str]
    first_seen:        str
    last_seen:         str
    suspicious_flags:  list[str]
    entropy:           float
    is_dga_candidate:  bool


class DnsTopClient(BaseModel):
    ip:           str
    query_count:  int


class DnsReconStats(BaseModel):
    total_queries:        int
    unique_domains:       int
    unique_clients:       int
    suspicious_count:     int
    dga_candidate_count:  int
    top_clients:          list[DnsTopClient]


class DnsReconResponse(BaseModel):
    result_id:  str
    stats:      DnsReconStats
    domains:    list[DnsDomainRow]


def build_recon(result_id: str, dns_queries: list[dict]) -> DnsReconResponse:
    """Aggregate raw tshark DNS query rows into a per-domain recon view.

    Robust to missing fields; the worker emits empty strings rather than nulls.
    Sort order: most-suspicious first, then DGA candidates, then by volume.
    """
    by_domain: dict[str, dict] = defaultdict(lambda: {
        "query_count":      0,
        "resolved_ips":     set(),
        "cnames":           set(),
        "record_types":     set(),
        "clients":          set(),
        "first_seen":       None,
        "last_seen":        None,
        "suspicious_flags": set(),
    })

    client_counts: dict[str, int] = defaultdict(int)
    total = 0

    for q in dns_queries or []:
        name = (q.get("query") or q.get("response") or "").strip().lower().strip(".")
        if not name:
            continue
        d = by_domain[name]
        d["query_count"] += 1
        total += 1

        for ip in (q.get("resolved_ip") or "").split(","):
            ip = ip.strip()
            if ip:
                d["resolved_ips"].add(ip)
        for cn in (q.get("cname") or "").split(","):
            cn = cn.strip()
            if cn:
                d["cnames"].add(cn)
        rtype = (q.get("type") or "").strip()
        if rtype:
            d["record_types"].add(rtype)
        src = (q.get("src") or "").strip()
        if src:
            d["clients"].add(src)
            client_counts[src] += 1
        t = (q.get("time") or "").strip()
        if t:
            if d["first_seen"] is None or t < d["first_seen"]:
                d["first_seen"] = t
            if d["last_seen"] is None or t > d["last_seen"]:
                d["last_seen"] = t
        for k in (q.get("suspicious") or {}).keys():
            d["suspicious_flags"].add(k)

    rows: list[DnsDomainRow] = []
    for name, d in by_domain.items():
        first_label = name.split(".")[0]
        rows.append(DnsDomainRow(
            query=name,
            query_count=d["query_count"],
            resolved_ips=sorted(d["resolved_ips"]),
            cnames=sorted(d["cnames"]),
            record_types=sorted(d["record_types"]),
            clients=sorted(d["clients"]),
            first_seen=d["first_seen"] or "",
            last_seen=d["last_seen"] or "",
            suspicious_flags=sorted(d["suspicious_flags"]),
            entropy=round(_entropy(first_label), 2),
            is_dga_candidate=_is_dga_candidate(name),
        ))

    rows.sort(key=lambda r: (
        -len(r.suspicious_flags),
        -int(r.is_dga_candidate),
        -r.query_count,
        r.query,
    ))

    top_clients = sorted(
        (DnsTopClient(ip=ip, query_count=cnt) for ip, cnt in client_counts.items()),
        key=lambda x: -x.query_count,
    )[:10]

    stats = DnsReconStats(
        total_queries=total,
        unique_domains=len(rows),
        unique_clients=len({c for r in rows for c in r.clients}),
        suspicious_count=sum(1 for r in rows if r.suspicious_flags),
        dga_candidate_count=sum(1 for r in rows if r.is_dga_candidate),
        top_clients=top_clients,
    )
    return DnsReconResponse(result_id=result_id, stats=stats, domains=rows)
