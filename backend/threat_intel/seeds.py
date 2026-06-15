"""Default threat intel feed definitions seeded on POST /api/threat-intel/feeds/init."""

DEFAULT_FEEDS = [
    {
        "name": "Abuse.ch ThreatFox — IPs",
        "url": "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "feed_type": "csv",
        "ioc_type": "ip",
        "pull_interval_hours": 1,
        "parser_config": {"csv_field": "ioc", "csv_value_strip_port": True},
    },
    {
        # ThreatFox does not serve domain/hash CSVs at /export/csv/{type}/recent/ —
        # those paths return 404. Replaced with Phishing Army domain blocklist.
        "name": "Phishing Army — Phishing Domains",
        "url": "https://phishing.army/download/phishing_army_blocklist.txt",
        "feed_type": "txt",
        "ioc_type": "domain",
        "pull_interval_hours": 24,
        "parser_config": {},
    },
    {
        # ThreatFox MD5 hash CSV also returns 404. Replaced with OpenPhish active
        # phishing URLs, which adds URL coverage not otherwise in the default set.
        "name": "OpenPhish — Active Phishing URLs",
        "url": "https://openphish.com/feed.txt",
        "feed_type": "txt",
        "ioc_type": "url",
        "pull_interval_hours": 12,
        "parser_config": {},
    },
    {
        "name": "Abuse.ch URLhaus — Malicious URLs",
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "feed_type": "txt",
        "ioc_type": "url",
        "pull_interval_hours": 4,
        "parser_config": {},
    },
    {
        "name": "Abuse.ch Feodo Tracker — C2 IPs",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "feed_type": "csv",
        "ioc_type": "ip",
        "pull_interval_hours": 12,
        # No header row; dst_ip is the second column (index 1)
        "parser_config": {"csv_index": 1},
    },
    {
        # MalwareBazaar's /export/json/recent/ now 404s — abuse.ch consolidated
        # to mb-api.abuse.ch/api/v1/ (POST + Auth-Key required), which our
        # GET-only ingest doesn't support. URLhaus SHA256 covers the same
        # use case (malware sample hashes) without auth or POST.
        "name": "Abuse.ch URLhaus — Payload SHA256",
        "url": "https://urlhaus.abuse.ch/downloads/sha256/",
        "feed_type": "txt",
        "ioc_type": "hash_sha256",
        "pull_interval_hours": 4,
        "parser_config": {},
    },
    {
        "name": "CINS Army — Hostile IPs",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "feed_type": "txt",
        "ioc_type": "ip",
        "pull_interval_hours": 24,
        "parser_config": {},
    },
    {
        "name": "Emerging Threats — Compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "feed_type": "txt",
        "ioc_type": "ip",
        "pull_interval_hours": 24,
        "parser_config": {},
    },
]

# Feeds that were seeded with broken URLs and need to be corrected on boot.
# Keyed by the old name; value is the new spec (all fields replaced).
_BAD_FEED_FIXES: dict[str, dict] = {
    "Abuse.ch ThreatFox — Domains": {
        "name": "Phishing Army — Phishing Domains",
        "url": "https://phishing.army/download/phishing_army_blocklist.txt",
        "feed_type": "txt",
        "ioc_type": "domain",
        "pull_interval_hours": 24,
        "parser_config": {},
    },
    "Abuse.ch ThreatFox — MD5 Hashes": {
        "name": "OpenPhish — Active Phishing URLs",
        "url": "https://openphish.com/feed.txt",
        "feed_type": "txt",
        "ioc_type": "url",
        "pull_interval_hours": 12,
        "parser_config": {},
    },
    # MalwareBazaar's /export/json/recent/ now 404s (abuse.ch moved the feed
    # behind mb-api.abuse.ch with POST + Auth-Key, which our GET-only ingest
    # doesn't support). URLhaus already serves SHA256 of payloads it tracks,
    # covering the same use case.
    "Abuse.ch MalwareBazaar — Recent SHA256": {
        "name": "Abuse.ch URLhaus — Payload SHA256",
        "url": "https://urlhaus.abuse.ch/downloads/sha256/",
        "feed_type": "txt",
        "ioc_type": "hash_sha256",
        "pull_interval_hours": 4,
        "parser_config": {},
    },
}


async def fix_bad_feeds(db) -> int:
    """
    Boot-time migration: update feeds that were seeded with URLs that return 404.
    Matched by old name; skipped if already fixed (URL already correct).
    Returns the count of rows updated.
    """
    from sqlalchemy import select
    from models import ThreatFeed

    fixed = 0
    for old_name, spec in _BAD_FEED_FIXES.items():
        row = (await db.execute(
            select(ThreatFeed).where(ThreatFeed.name == old_name)
        )).scalar_one_or_none()
        if not row:
            continue
        row.name             = spec["name"]
        row.url              = spec["url"]
        row.feed_type        = spec["feed_type"]
        row.ioc_type         = spec["ioc_type"]
        row.pull_interval_hours = spec["pull_interval_hours"]
        row.parser_config    = spec["parser_config"]
        fixed += 1

    if fixed:
        await db.commit()

    return fixed
