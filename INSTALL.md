# Manual installation — Linux VM

This guide installs DFIR-FENRIR v2 **by hand** on a fresh Linux virtual machine, doing
every step that [`setup.sh`](setup.sh) would otherwise automate. Use it when you want to
understand (or audit) exactly what happens, deploy without the helper script, or adapt the
process to your own provisioning tooling.

> If you just want it running, `./setup.sh` does all of this in one command. This document
> is the long way round, on purpose.

The stack is **8 Docker containers** behind a single TLS-terminating Caddy edge. Only ports
**80** and **443** are ever published to the host; everything else talks over private Docker
networks. The malware-analysis worker sits on an `internal: true` network with **no internet
route**.

---

## 1. Prerequisites

### 1.1 The VM

| Resource | Minimum | Notes |
|---|---|---|
| OS | Linux x86-64 | Ubuntu 22.04/24.04 or Debian 12 assumed below; any systemd distro with Docker works |
| vCPU | 4 | First image build is the heaviest moment |
| RAM | 8 GB | |
| Disk | 60 GB | Evidence, quarantine, Postgres data and backups all live in Docker volumes |
| Network | Outbound HTTPS during build | Pulls base images + Python/npm deps. **Runtime** needs no internet for the core workflow |

You will need a non-root user with `sudo`. Run the application steps as that user (not as root).

### 1.2 Required software

- **Docker Engine** + **Docker Compose v2** — the only hard dependency at runtime.
- **openssl** *or* **python3** — to generate secrets and the self-signed TLS certificate.
- **git** — to clone the repository.
- **curl** *(optional)* — for the health check at the end.

---

## 2. Install Docker Engine + Compose v2

### Ubuntu / Debian

```bash
# Remove any distro-packaged Docker that might conflict
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Install prerequisites and Docker's official GPG key + repo
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg openssl git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Engine + CLI + Compose plugin + Buildx
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
```

> On Debian, replace `ubuntu` with `debian` in both the GPG-key URL and the repo line.
> On RHEL/Fedora/Rocky, use the equivalent `dnf` repo from
> <https://docs.docker.com/engine/install/>.

### Enable Docker and grant your user access

```bash
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
newgrp docker          # apply the group in the current shell (or log out / back in)
```

### Verify

```bash
docker --version
docker compose version
docker run --rm hello-world      # confirms the daemon works without sudo
```

Both version commands must succeed before continuing.

---

## 3. Get the code

```bash
git clone https://github.com/Otrivinish/dfir-fenrir-v2.git
cd dfir-fenrir-v2
```

All remaining commands are run **from the repository root** (the directory containing
`docker-compose.yml`).

---

## 4. Create the environment file

```bash
cp .env.example .env
```

`.env` holds every secret and tunable. It is git-ignored — never commit it. The next two
sections fill it in.

---

## 5. Generate the secrets

The backend **refuses to start** unless `EVIDENCE_KEK` and `AUDIT_SIGNING_KEY` are set, and
the database/cache won't come up without their passwords. Generate five values:

| `.env` key | Command | What it is |
|---|---|---|
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` | Postgres password (rides inside `DATABASE_URL`, so keep it hex/URL-safe) |
| `REDIS_PASSWORD` | `openssl rand -hex 24` | Redis password |
| `SECRET_KEY` | `openssl rand -hex 64` | App session/signing secret |
| `EVIDENCE_KEK` | `openssl rand -hex 32` | **Required.** 32-byte AES-256 master key for evidence-at-rest |
| `AUDIT_SIGNING_KEY` | `openssl rand -base64 32` | **Required.** 32-byte Ed25519 seed (base64) for signed audit-log exports |

Generate and print all five at once:

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"
echo "REDIS_PASSWORD=$(openssl rand -hex 24)"
echo "SECRET_KEY=$(openssl rand -hex 64)"
echo "EVIDENCE_KEK=$(openssl rand -hex 32)"
echo "AUDIT_SIGNING_KEY=$(openssl rand -base64 32)"
```

Open `.env` in an editor and replace each `change_me_…` placeholder with the matching value.

> **No openssl?** Swap in python3:
> `python3 -c "import secrets; print(secrets.token_hex(24))"` for the hex values, and
> `python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"` for the base64 seed.

> **Want the audit public key too?** Instead of `openssl rand -base64 32`, run
> [`./scripts/generate-audit-key.sh`](scripts/generate-audit-key.sh). It prints the same kind of
> seed **plus** the matching Ed25519 public key and SHA-256 fingerprint (which verifiers use, and
> which the running app also exposes at `GET /api/version`). It needs `python3` with the
> `cryptography` package; if that's not on the host, the plain `openssl` line above is equivalent
> for the secret itself.

Treat `EVIDENCE_KEK` like a master password: if you lose it, encrypted evidence is
unrecoverable; if you rotate it, all existing evidence must be re-encrypted (there is no
rotation tooling yet). Rotating `AUDIT_SIGNING_KEY` invalidates previously issued
audit-export signatures.

---

## 6. Configure domain & network access

Edit the TLS/network block in `.env`. Pick the access pattern that matches your VM:

### A — Local only (`DOMAIN=localhost`, the default)

Leave `DOMAIN=localhost`. You can only reach it from the VM itself (or via an SSH tunnel).
Good for a first smoke test.

### B — Reachable from your LAN by IP

Set the VM's IP everywhere it appears:

```ini
DOMAIN=192.168.1.50
CORS_ORIGINS=https://192.168.1.50
ALLOWED_HOSTS=192.168.1.50,localhost,127.0.0.1
```

`CORS_ORIGINS` controls which browser origins may call the API; `ALLOWED_HOSTS` is the
backend's accepted `Host`-header allowlist. **Both must include the address you type in the
browser**, or the SPA will load but every API call will be rejected.

### C — Public hostname

You have two zero-touch TLS options (Caddy auto-selects based on what you set):

- **Let's Encrypt via DuckDNS** — set `DOMAIN=yourname.duckdns.org`, `LETSENCRYPT_EMAIL`,
  and `DUCKDNS_TOKEN`. Skip the cert step in §7 entirely.
- **Bring your own cert** — set `DOMAIN`, place your PEM files in `certs/`, and set
  `TLS_CERT_FILE=/certs/server.crt` and `TLS_KEY_FILE=/certs/server.key`. Also skip §7.

For Mode A or B (self-signed), continue to §7.

---

## 7. Generate the self-signed TLS certificate

*(Skip this section if you chose DuckDNS or bring-your-own-cert in §6-C.)*

[`generate-certs.sh`](generate-certs.sh) builds a local CA and a server certificate with the
right Subject Alternative Names. It reads `DOMAIN` from `.env` and also auto-adds the
detected LAN IP.

```bash
./generate-certs.sh                 # uses DOMAIN from .env
# or pin an explicit IP/hostname:
./generate-certs.sh 192.168.1.50
```

This writes into `certs/`:

| File | Purpose |
|---|---|
| `ca.crt` | **Import this into your browser/OS trust store** to silence TLS warnings |
| `ca.key` | CA private key — keep secret |
| `server.crt` / `server.key` | Used by Caddy at the edge |

Caddy mounts `certs/` read-only and picks up `server.crt` automatically.

---

## 8. Open the firewall

Only the Caddy edge needs to be reachable. If `ufw` is active:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw reload
```

Port 80 is used for HTTP→HTTPS redirect (and ACME challenges in DuckDNS mode); 443 serves
the app. No other port should be exposed to the host.

---

## 9. Build and start the stack

```bash
docker compose up -d --build
```

The first build compiles the Vite frontend and installs the backend/analysis-worker
dependencies — **expect a few minutes**. Compose brings up all eight services:

| Container | Role |
|---|---|
| `fenrir-v2-caddy` | TLS edge + reverse proxy (`:80`/`:443` → frontend/backend) |
| `fenrir-v2-frontend` | nginx serving the static React SPA (internal `:3000`) |
| `fenrir-v2-backend` | FastAPI API (internal `:8000`) |
| `fenrir-v2-postgres` | PostgreSQL 16 (primary data) |
| `fenrir-v2-redis` | Redis 7 (sessions, rate-limit, cache) |
| `fenrir-v2-analysis` | Air-gapped malware-analysis worker (no internet) |
| `fenrir-v2-backup` | Daily `pg_dump` + read-only evidence mirror |
| `fenrir-v2-audit-monitor` | Periodic audit-chain verification + anchoring |

Watch them settle:

```bash
docker compose ps
docker compose logs -f --tail=100 backend     # Ctrl-C to stop following
```

---

## 10. Verify the backend is healthy

```bash
curl -sk https://localhost/api/health
# Expected: {"status":"ok","service":"fenrir-v2-backend"}
```

`-k` skips cert verification (expected with a self-signed cert). If this returns `ok`,
Caddy → backend → Postgres/Redis are all wired up.

---

## 11. First-run admin setup

On first boot the backend writes a one-time **bootstrap token**. Retrieve it:

```bash
# Preferred — read it straight from the backend container:
docker compose exec -T backend cat /app/data/bootstrap_token.txt

# Or find it in the logs:
docker compose logs backend | grep -i token
```

Then, in a browser:

1. Go to **`https://<DOMAIN>/setup`** (e.g. `https://localhost/setup` or `https://192.168.1.50/setup`).
2. Paste the bootstrap token and create the first **admin** account.
3. Complete **TOTP enrolment** — required by default (`TOTP_REQUIRED=true`). Scan the QR with
   an authenticator app. (To make 2FA opt-in instead, set `TOTP_REQUIRED=false` in `.env`
   *before* first setup and recreate the backend.)

Once an admin exists, the bootstrap token stops working — that's expected.

> **Browser TLS warning?** Import `certs/ca.crt` (from §7) into your browser or OS trust
> store, then reload. The warning is only because the CA is self-signed and not yet trusted.

---

## 12. Day-2 operations

```bash
docker compose ps                       # status
docker compose logs -f --tail=100 backend
docker compose down                     # stop (volumes/data preserved)
docker compose up -d                    # start again
docker compose up -d --build            # rebuild after a code change
```

- **Backups:** the `backup` service runs `pg_dump` every 24h into the `backup-data` volume and
  mirrors evidence read-only. See [`docs/backup-restore.md`](docs/backup-restore.md) and
  [`scripts/restore.sh`](scripts/restore.sh) for restore.
- **Data location:** all state lives in named Docker volumes (`postgres-data`, `evidence-data`,
  `quarantine-data`, `backup-data`, `redis-data`, …). `docker compose down` keeps them;
  `docker compose down -v` **destroys them** — don't run `-v` unless you mean it.
- **Re-show the token later:** `./setup.sh --print-token` (works even in a manual install).

---

## 13. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `docker: permission denied … docker.sock` | Your user isn't in the `docker` group yet — run `newgrp docker` or re-login (§2) |
| Backend container restarts / exits on boot | A required secret is missing or still a `change_me_…` placeholder. Check `EVIDENCE_KEK` and `AUDIT_SIGNING_KEY` in `.env`, then `docker compose logs backend` |
| SPA loads but every API call fails (CORS / 400) | The address you typed isn't in `CORS_ORIGINS` / `ALLOWED_HOSTS` (§6-B). Update `.env`, then `docker compose up -d` |
| `curl` health check never returns `ok` | Give the first build time, then `docker compose logs backend` and `docker compose logs postgres` |
| Browser shows TLS error | Self-signed CA not trusted — import `certs/ca.crt` (§11). For LAN-by-IP access, confirm the IP is a SAN: re-run `./generate-certs.sh <IP>` |
| Health OK but can't reach it from another machine | Host firewall (§8) or the cloud/VM security group is blocking 443 |
| Port 80/443 already in use | Another web server is bound on the host — stop it, or change the published ports in `docker-compose.yml` (and your `DOMAIN`/cert SANs accordingly) |

---