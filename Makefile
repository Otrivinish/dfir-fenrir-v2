# DFIR-FENRIR v2 — thin convenience wrappers. `make setup` is all you need to install.
.PHONY: setup up down logs token rebuild ps posture smoke scan sbom lock digests verify-restore pki db-roles

setup:   ## First-time install / resume (idempotent)
	./setup.sh

up:      ## Start the stack
	docker compose up -d

rebuild: ## Rebuild + start
	docker compose up -d --build

down:    ## Stop the stack (keeps volumes)
	docker compose down

logs:    ## Tail backend logs
	docker compose logs -f --tail=100 backend

token:   ## Re-show the first-run setup token
	./setup.sh --print-token

ps:      ## Show container status
	docker compose ps

# ── Security posture & supply chain ───────────────────────────────────────────
posture: ## Container security posture check (read-only; exit code = failures)
	scripts/posture-check.sh

smoke:   ## Functional smoke test (needs FENRIR_TOKEN or FENRIR_TOKEN_FILE; admin token)
	scripts/smoke-test.sh

scan:    ## Supply-chain scan: hadolint + grype + dockle (fails on fixable High/Critical)
	scripts/scan.sh

sbom:    ## scan + SPDX SBOM per image (scan-reports/)
	scripts/scan.sh --sbom

lock:    ## Re-lock Python deps with hashes (14-day cooldown)
	scripts/lock-python.sh

digests: ## Show base-image digest updates (dry run; scripts/refresh-digests.sh --apply writes)
	scripts/refresh-digests.sh

verify-restore: ## Prove the newest DB backup restores (throwaway DB; AGE_IDENTITY=… for .age)
	scripts/verify-restore.sh

pki:     ## Issue / renew internal service TLS certificates (then recreate services)
	scripts/internal-pki.sh --apply

db-roles: ## (Re)apply least-privilege Postgres roles, ownership and grants
	scripts/db-roles.sh --apply
