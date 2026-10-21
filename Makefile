GO ?= go
GOFMT ?= gofmt

.PHONY: build fmt fmt-check vet test integration integration-local check

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/secretwright ./cmd/secretwright

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted="$$($(GOFMT) -l $$(find cmd internal -type f -name '*.go'))" || exit $$?; \
	test -z "$$unformatted" || { \
		printf '%s\n' "$$unformatted"; \
		echo 'Run make fmt to format Go sources.' >&2; exit 1; \
	}

vet:
	$(GO) vet ./...

test:
	$(GO) test -race -count=1 ./...

integration:
	@test -n "$${VAULT_ADDR:-}" || { echo 'VAULT_ADDR is required; use make integration-local for an ephemeral server.' >&2; exit 1; }
	$(GO) test -race -count=1 -tags=integration ./...

integration-local:
	./scripts/integration.sh

check: fmt-check vet test build
