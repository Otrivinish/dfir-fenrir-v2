# DFIR-FENRIR v2 — thin convenience wrappers. `make setup` is all you need to install.
.PHONY: setup up down logs token rebuild ps

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
