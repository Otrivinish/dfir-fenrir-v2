# Test data

## seed_demo_data.py

Injects 7 real-world IR demo incidents (SolarWinds, Colonial Pipeline, MOVEit, Log4Shell,
Change Healthcare, Kaseya, ProxyLogon) with timeline events, IOCs, affected systems,
respond actions, and lessons learned.

**Not idempotent** — running twice creates duplicates. Check first:
```
GET /api/incidents
```

### Prerequisites

- FENRIR v2 running (`docker compose up -d` from the repo root)
- First-run setup completed (visit `/setup` — bootstrap token is in `docker compose logs fenrir-backend`)
- `requests` installed: `pip install requests`

### Run

Via Caddy (standard):
```bash
python scripts/testdata/seed_demo_data.py \
    --url https://localhost \
    --user admin \
    --password <your-admin-password> \
    --insecure
```

Direct to backend (from inside the container, or if port 8000 is exposed):
```bash
docker compose exec fenrir-backend \
    python scripts/testdata/seed_demo_data.py \
        --url http://localhost:8000 \
        --user admin \
        --password <your-admin-password>
```

### Remove demo data

There is no delete endpoint in the API. Use psql directly:

```bash
docker compose exec -e PGPASSWORD="${POSTGRES_PASSWORD}" fenrir-postgres \
    psql -U fenrir -d fenrir
```

```sql
DELETE FROM incidents
WHERE title IN (
    'SolarWinds SUNBURST — Supply Chain Compromise',
    'Colonial Pipeline — DarkSide Ransomware',
    'MOVEit Transfer — Cl0p Mass Data Theft',
    'Log4Shell (CVE-2021-44228) — Active Exploitation',
    'Change Healthcare — ALPHV/BlackCat Ransomware',
    'Kaseya VSA — REvil Supply Chain Ransomware',
    'Microsoft Exchange ProxyLogon — Hafnium Campaign'
);
```

All related rows (timeline, IOCs, affected systems, respond actions, lessons learned,
audit log entries) cascade automatically.

---

## gen_evtl.py

Generates `test_windows_events.xml` — a ~1.8 MB synthetic Windows Event Log (Security,
System, Sysmon channels) for testing the forensic timeline importer. Run from the repo root:

```bash
python scripts/testdata/gen_evtl.py
```
