# Manual installation — Linux VM

This guide installs DFIR-FENRIR v2 **by hand** on a fresh Linux virtual machine, doing
every step that [`setup.sh`](setup.sh) would otherwise automate. Use it when you want to
understand (or audit) exactly what happens, deploy without the helper script, or adapt the
process to your own provisioning tooling.

> If you just want it running, `./setup.sh` does all of this in one command. This document
> is the long way round, on purpose.

The stack is **8 long-running Docker containers** (plus a one-shot schema `migrate`) behind a
single TLS 1.3 Caddy edge. Only ports **80** and **443** are ever published to the host;
everything else talks over private Docker networks, encrypted and authenticated hop by hop.
The database tier and the malware-analysis worker sit on `internal: true` networks with **no
internet route**.

---

## 1. Prerequisites

<details>
<summary><strong>Upgrading from 0.3.x</strong></summary>
Version 0.3.0 Breaking changes

If you upgrade from a version prior to 0.3.0 you should follow these steps to avoid breaking your system.

# ── 0. Prerequisites (Debian/Ubuntu) ──
sudo apt-get install -y openssl age make curl
cd ~/dfir-fenrir-v2        # the scripts assume this directory name (it's the git clone default)

# ── 1. Before upgrading, with the old stack still running: age key + encrypted rollback point ──
(umask 077; [ -f ~/fenrir-backup.agekey ] || age-keygen -o ~/fenrir-backup.agekey)
R="$(age-keygen -y ~/fenrir-backup.agekey)"; TS="$(date -u +%Y%m%dT%H%M%SZ)"
(umask 077; set -eo pipefail
 git rev-parse HEAD > ~/fenrir-pre-upgrade-$TS.commit
 age -r "$R" -o ~/fenrir-pre-upgrade-$TS.env.age .env
 docker compose exec -T postgres pg_dump -U fenrir -d fenrir | gzip | age -r "$R" > ~/fenrir-pre-upgrade-$TS.sql.gz.age) \
 && ls -l ~/fenrir-pre-upgrade-$TS.*

# ── 2. Stop the old stack (never add -v) ──
docker compose down

# ── 3. Pull ──
git pull

# ── 4. New .env settings ──
setenv() { grep -q "^$1=" .env && sed -i "s|^$1=.*|$1=$2|" .env || echo "$1=$2" >> .env; }
setenv BACKUP_AGE_RECIPIENT "$R"
setenv TLS_MODE selfsigned          # or duckdns | byo | acme, whichever this instance used

# ── 5. Move the local CA private key out of ./certs (no-op if there is none) ──
./generate-certs.sh --migrate-only

# ── 6. Upgrade: creates ./secrets/ from the .env values (then blanks them), internal PKI, build, Caddy volumes, DB roles, start ──
./setup.sh

# ── 7. Verify ──
docker compose ps
make posture                        # if only the backup check fails, re-run in ~2 min (first dump still running)
# point each SIEM webhook sender at https://<DOMAIN>/api/health, then check for "version":772 (= TLS 1.3):
docker compose logs caddy | grep '/api/health' | tail -1

# ── 8. Encrypt the old plaintext DB dumps ──
scripts/encrypt-legacy-backups.sh
scripts/encrypt-legacy-backups.sh --apply

# ── 9. Back up the 4 keys to one AES-256 zip (asks for the passphrase twice) ──
sudo apt-get install -y 7zip
Z=~/fenrir-keys-$(hostname)-$TS.zip
7z a -tzip -mem=AES256 -p "$Z" ./secrets/evidence_kek ./secrets/secret_key ./secrets/audit_signing_key ~/fenrir-backup.agekey
7z t "$Z"                                  # asks for the passphrase; must say "Everything is Ok"
cp "$Z" /media/$USER/<USB-LABEL>/          # plus a second off-host copy; passphrase goes in a password manager, never next to the zip

# ── 10. Clean up the server (only once you're happy with the upgrade; rollback needs these files) ──
shred -fu ~/fenrir-backup.agekey "$B" ~/fenrir-pre-upgrade-$TS.*

# ── Restore on a new host (before ./setup.sh) ──
7z x ~/fenrir-keys-<host>-<ts>.zip -o"$HOME/kcheck"
install -m 0444 ~/kcheck/{evidence_kek,secret_key,audit_signing_key} secrets/   # after mkdir -m 700 -p secrets

# ── Rollback if step 6 or 7 fails and before step 10 ──
docker compose down
git checkout "$(cat ~/fenrir-pre-upgrade-$TS.commit)"
age -d -i ~/fenrir-backup.agekey ~/fenrir-pre-upgrade-$TS.env.age > .env && chmod 600 .env
docker compose up -d --build
</details>

### 1.1 The VM

| Resource | Minimum | Notes |
|---|---|---|
| OS | Linux x86-64 | Ubuntu 22.04/24.04 or Debian 12 assumed below; any systemd distro with Docker works |
| vCPU | 4 | First image build is the heaviest moment |
| RAM | 8 GB | 12 GB+ if you handle evidence near the 1 GiB upload cap (the backend needs ~4 GiB for that) |
| Disk | 60 GB | Evidence, quarantine, Postgres data and backups all live in Docker volumes |
| Network | Outbound HTTPS during build | Pulls base images + Python/npm deps. **Runtime** needs no internet for the core workflow |

You will need a non-root user with `sudo`. Run the application steps as that user (not as root).

### 1.2 Required software

- **Docker Engine** + **Docker Compose v2** — the only hard dependency at runtime.
- **openssl** — secrets, the self-signed edge certificate and the internal service CA.
- **age** — to generate the backup key pair (on an offline machine) and to restore backups.
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
cp .env.example .env && chmod 600 .env
```

`.env` holds **settings only** — no secrets (those are files in `./secrets/`, §5). It is
git-ignored; never commit it.

---

## 5. Generate the secrets

```bash
scripts/secrets.sh            # dry run: shows what it will create
scripts/secrets.sh --apply
```

Creates `./secrets/` (mode `0700`) with one file per secret (`0444`): Postgres
bootstrap + four per-service role passwords, Redis password + ACL, `secret_key`,
`evidence_kek`, `audit_signing_key`, the worker token and an (empty) DuckDNS token. Each
container receives **only its own** secrets, mounted at `/run/secrets` — never as
environment variables. Re-running never overwrites an existing secret.

Three of these files can **never be regenerated** — back them up as described in
[§5.2](#52-back-up-the-keys-offline--do-this-now) before you store any evidence.

### 5.1 Backup encryption key (offline)

On a **different, offline machine**:

```bash
age-keygen -o fenrir-backup.agekey      # prints "Public key: age1…"
```

Put only the public key in `.env`: `BACKUP_AGE_RECIPIENT=age1…`. Without it, DB dumps
are written **unencrypted**. Back up `fenrir-backup.agekey` with the other keys (§5.2).

### 5.2 Back up the keys (offline — do this now)

Four keys cannot be regenerated. Lose one and that data is gone for good:

| Key | Where | What it protects |
|---|---|---|
| `evidence_kek` | `./secrets/evidence_kek` | decrypts all evidence and the evidence-backup mirror |
| `secret_key` | `./secrets/secret_key` | decrypts every user's TOTP secret and the stored integration API keys |
| `audit_signing_key` | `./secrets/audit_signing_key` | signs audit exports — past exports verify against its public key |
| age identity | `fenrir-backup.agekey` (offline machine) | decrypts every DB backup |

Everything else in `./secrets/` (database, Redis and worker passwords, TLS certificates)
is regenerated by `./setup.sh` on a new host.

**1. Record fingerprints.** A SHA-256 of a random key reveals nothing about it, so keep
these in your notes *and* in the password-manager entry — they let you prove later that
a stored copy is the right one:

```bash
for f in evidence_kek secret_key audit_signing_key; do
  printf '%-18s ' "$f"; tr -d '\r\n' < "secrets/$f" | sha256sum | cut -c1-16
done
age-keygen -y fenrir-backup.agekey     # must print the BACKUP_AGE_RECIPIENT in .env
```

**2. Store them in your password manager** (one entry, e.g. "FENRIR `<host>` keys"):
attach the three files from `./secrets/` and `fenrir-backup.agekey` as **file
attachments** (KeePassXC, Bitwarden and 1Password support this) and paste the
fingerprints into the notes. Attachments never put the values on screen or in a
clipboard. *No attachment support?* Show each value once and paste it in, then clear the
terminal: `cat secrets/evidence_kek; echo` … `clear && printf '\033[3J'`.

**3. Keep a second copy elsewhere** — e.g. the same files on an encrypted USB stick in a
safe. A password manager alone is a single point of failure.

**4. Prove the copy works** before relying on it. Export the attachments into a private
temporary directory and compare:

```bash
umask 077 && mkdir -p ~/kcheck          # export the 4 attachments into ~/kcheck
for f in evidence_kek secret_key audit_signing_key; do
  printf '%-18s ' "$f"; tr -d '\r\n' < ~/kcheck/"$f" | sha256sum | cut -c1-16
done                                    # must match step 1
AGE_IDENTITY=~/kcheck/fenrir-backup.agekey make verify-restore   # must print OK
shred -fu ~/kcheck/* && rmdir ~/kcheck     # -f: the key files are read-only
```

**5. Don't keep the age identity on the server.** If you generated it there, delete it
once steps 2–4 succeeded: `shred -fu fenrir-backup.agekey`. You only need it to restore.

**6. Repeat** after rotating the KEK, changing `BACKUP_AGE_RECIPIENT` or replacing
`secret_key` / `audit_signing_key` — and **keep the old values** for as long as evidence
or backups encrypted with them are retained.

**Restoring the keys** (new host, or a lost `./secrets/`) — do this **before**
`./setup.sh`, which keeps existing secret files and generates only the missing ones:

```bash
umask 077 && mkdir -p secrets && chmod 700 secrets
for f in evidence_kek secret_key audit_signing_key; do
  install -m 0444 ~/kcheck/"$f" secrets/"$f"    # from the exported attachments
done
# typing a value instead?  read -rs V; printf '%s' "$V" > secrets/evidence_kek; unset V
# then re-check the fingerprints (step 1), run ./setup.sh, and shred ~/kcheck as in step 4.
# On a running stack: docker compose up -d --force-recreate backend
```

The age identity is needed only for a database restore:
`scripts/restore.sh --identity <file>` (docs/backup-restore.md).

---

## 6. Configure domain, TLS & network access

`DOMAIN` is the **exact** name or IP users type — the edge serves only that site.
`CORS_ORIGINS`/`ALLOWED_HOSTS` follow it automatically (leave them blank). The edge is
**TLS 1.3 only**: Windows 10 / Server 2019 PowerShell and `curl.exe` cannot connect —
browsers can.

| Access | `.env` |
|---|---|
| **A — Local only** | `DOMAIN=localhost`, `TLS_MODE=selfsigned` (reach it from the VM or an SSH tunnel) |
| **B — LAN by IP** | `DOMAIN=192.168.1.50`, `TLS_MODE=selfsigned` |
| **C1 — Public name, Let's Encrypt** | `DOMAIN=fenrir.example.org`, `TLS_MODE=acme`, `LETSENCRYPT_EMAIL=…` (80 + 443 reachable) |
| **C2 — DuckDNS** | `DOMAIN=yourname.duckdns.org`, `TLS_MODE=duckdns`, `LETSENCRYPT_EMAIL=…`; token in `./secrets/duckdns_token` |
| **C3 — Your own cert** | `TLS_MODE=byo`, PEMs in `certs/`, `TLS_CERT_FILE=/certs/server.crt`, `TLS_KEY_FILE=/certs/server.key` |

---

## 7. Certificates

### 7.1 Edge certificate (self-signed modes A/B only)

```bash
./generate-certs.sh                 # uses DOMAIN from .env (+ the detected LAN IP)
```

| File | Purpose |
|---|---|
| `certs/ca.crt` | **Import into your browser/OS trust store** |
| `ca/ca.key` | CA private key — in `./ca/` (0700), **never** mounted into a container |
| `certs/server.crt` / `server.key` | Edge certificate |

A newly created CA is name-constrained to `DOMAIN`, `localhost` and private IP ranges, so
even a stolen CA key cannot mint certificates your browser would trust for other sites.

### 7.2 Internal service certificates (always)

```bash
scripts/internal-pki.sh --apply
```

A separate internal CA (`./ca/internal`, never mounted) issues one certificate per service
for TLS 1.3 / mutual TLS between containers. Re-run it any time — it renews certificates
within 30 days of expiry (`make posture` warns before that).

---

## 8. Open the firewall

Only the Caddy edge needs to be reachable:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw reload
```

Port 80 only redirects to HTTPS (and answers ACME HTTP-01 challenges). **Note:** ports
published by Docker bypass `ufw` rules; to restrict *who* may reach 80/443, filter on the
`DOCKER-USER` iptables chain.

---

## 9. Build and start the stack

```bash
docker compose build                                   # first build: a few minutes
scripts/caddy-volume-prep.sh --apply                   # Caddy: uid 10001, no capabilities
docker compose up -d postgres && scripts/db-roles.sh --apply
docker compose up -d                                   # migrate runs, then the rest
```

| Container | Role |
|---|---|
| `fenrir-v2-caddy` | TLS 1.3 edge + reverse proxy (`:80`/`:443`) |
| `fenrir-v2-frontend` | nginx serving the static React SPA |
| `fenrir-v2-migrate` | one-shot schema migration (exits 0) |
| `fenrir-v2-backend` | FastAPI API (mutual TLS from Caddy only) |
| `fenrir-v2-postgres` | PostgreSQL 16 (TLS, per-service roles) |
| `fenrir-v2-redis` | Redis 7.4 (TLS + ACL; sessions, rate-limit) |
| `fenrir-v2-analysis` | Air-gapped malware-analysis worker (no internet) |
| `fenrir-v2-backup` | Daily age-encrypted `pg_dump` + evidence mirror |
| `fenrir-v2-audit-monitor` | Hourly audit-chain verification + anchoring |

```bash
docker compose ps                         # every service "healthy"; migrate "Exited (0)"
docker compose logs -f --tail=100 backend
```

---

## 10. Verify

```bash
curl -sk https://localhost/api/health     # {"status":"ok","service":"fenrir-v2-backend"}
make posture                              # container-security checks — expect 0 failures
```

---

## 11. First-run admin setup

On first boot the backend writes a one-time **bootstrap token**:

```bash
./setup.sh --print-token
# or: docker compose exec -T backend cat /app/data/bootstrap_token.txt
```

Then, in a browser:

1. Go to **`https://<DOMAIN>/setup`**.
2. Paste the bootstrap token and create the first **admin** account.
3. Complete **TOTP enrolment** — required by default (`TOTP_REQUIRED=true`).

Once an admin exists, the bootstrap token stops working — that's expected. (The token
lives in a private tmpfs: restarting the backend before setup issues a new one.)

> **Browser TLS warning?** Import `certs/ca.crt` (§7.1) into your browser or OS trust store.

---

## 12. Day-2 operations

```bash
docker compose ps                       # status
docker compose logs -f --tail=100 backend
docker compose down                     # stop (volumes/data preserved)
docker compose up -d                    # start again
docker compose up -d --build            # rebuild after a code change
```

- **Backups:** the `backup` service writes an age-encrypted `pg_dump` daily into the
  `backup-data` volume and mirrors evidence. Prove restorability with
  `AGE_IDENTITY=fenrir-backup.agekey make verify-restore`; restore with
  [`scripts/restore.sh`](scripts/restore.sh) ([`docs/backup-restore.md`](docs/backup-restore.md)).
- **Security checks:** `make posture` (running stack) and `make scan` (images) — run both
  after every change; `make pki` renews internal certificates.
- **Data location:** all state lives in named Docker volumes (`postgres-data`, `evidence-data`,
  `quarantine-data`, `backup-data`, `redis-data`, …). `docker compose down` keeps them;
  `docker compose down -v` **destroys them** — don't run `-v` unless you mean it.
- **Re-show the token later:** `./setup.sh --print-token` (works even in a manual install).

---