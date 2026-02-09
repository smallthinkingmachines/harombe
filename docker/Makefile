.PHONY: help build up down logs restart clean health shell-gateway shell-browser shell-filesystem shell-code-exec shell-web-search

help: ## Show this help message
	@echo "Harombe Docker Management"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build all containers
	docker-compose build

up: ## Start all containers (detached)
	docker-compose up -d

down: ## Stop and remove all containers
	docker-compose down

logs: ## Follow logs for all containers
	docker-compose logs -f

restart: ## Restart all containers
	docker-compose restart

clean: ## Stop containers and remove volumes
	docker-compose down -v

health: ## Check health status of all containers
	@docker-compose ps
	@echo ""
	@echo "Gateway health:"
	@curl -s http://localhost:8100/health | python3 -m json.tool || echo "Gateway not responding"

shell-gateway: ## Open shell in gateway container
	docker exec -it harombe-gateway bash

shell-browser: ## Open shell in browser container
	docker exec -it harombe-browser bash

shell-filesystem: ## Open shell in filesystem container
	docker exec -it harombe-filesystem bash

shell-code-exec: ## Open shell in code-exec container
	docker exec -it harombe-code-exec bash

shell-web-search: ## Open shell in web-search container
	docker exec -it harombe-web-search bash

logs-gateway: ## Follow logs for gateway container
	docker-compose logs -f gateway

logs-browser: ## Follow logs for browser container
	docker-compose logs -f browser

logs-filesystem: ## Follow logs for filesystem container
	docker-compose logs -f filesystem

logs-code-exec: ## Follow logs for code-exec container
	docker-compose logs -f code-exec

logs-web-search: ## Follow logs for web-search container
	docker-compose logs -f web-search

rebuild: ## Rebuild and restart all containers
	docker-compose up --build -d

rebuild-gateway: ## Rebuild and restart gateway container
	docker-compose up --build -d gateway

rebuild-browser: ## Rebuild and restart browser container
	docker-compose up --build -d browser

rebuild-filesystem: ## Rebuild and restart filesystem container
	docker-compose up --build -d filesystem

rebuild-code-exec: ## Rebuild and restart code-exec container
	docker-compose up --build -d code-exec

rebuild-web-search: ## Rebuild and restart web-search container
	docker-compose up --build -d web-search
