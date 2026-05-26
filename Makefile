.PHONY: help demo demo-down test test-python test-go lint lint-python lint-go \
        build build-proxy build-hub clean cert

ARDUROOT := $(shell pwd)
PYDIR   := python
GODIR   := go

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	 awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

demo: ## Start the full MVP stack (docker compose up --build)
	docker compose up --build

demo-down: ## Stop and remove the full MVP stack
	docker compose down -v

# ── Testing ──────────────────────────────────────────────────────────────────

test-python: ## Run the Python test suite
	cd $(PYDIR) && pip install -e ".[dev]" -q && python -m pytest tests/ -q

test-go: ## Run the Go test suite
	cd $(GODIR) && go test -count=1 -timeout 120s ./...

test: test-python test-go ## Run both Python and Go tests

# ── Linting ───────────────────────────────────────────────────────────────────

lint-python: ## Lint Python with ruff
	cd $(PYDIR) && ruff check vibap/ tests/

lint-go: ## Lint Go with vet
	cd $(GODIR) && go vet ./...

lint: lint-python lint-go ## Lint both Python and Go

# ── Build ─────────────────────────────────────────────────────────────────────

build-proxy: ## Build the proxy Docker image
	docker build -f Dockerfile.proxy -t ardur-proxy:latest .

build-hub: ## Build the hub Docker image
	docker build -f Dockerfile.hub -t ardur-hub:latest .

build: build-proxy build-hub ## Build both Docker images

# ── Utilities ─────────────────────────────────────────────────────────────────

cert: ## Generate self-signed TLS certs for local dev
	cd $(PYDIR) && python -c "from vibap.tls import generate_self_signed_cert; \
		p = generate_self_signed_cert.__wrapped__ if hasattr(generate_self_signed_cert, '__wrapped__') else generate_self_signed_cert; \
		kp, cp, fp = p() if hasattr(p, '__code__') else None; \
		print(f'cert: {cp}\nkey: {kp}\nfingerprint: {fp}')" 2>/dev/null || \
	cd $(PYDIR) && python -c "from vibap.tls import resolve_tls_paths; r=resolve_tls_paths(); print(r if r else 'TLS disabled via ARDUR_NO_TLS')"

clean: ## Remove build artifacts
	find $(PYDIR) -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find $(PYDIR) -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find $(PYDIR) -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
