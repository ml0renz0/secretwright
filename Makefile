GO ?= go
GOFMT ?= gofmt

.PHONY: build fmt fmt-check vet test integration integration-local check package-test package playground playground-demo playground-down playground-test

build:
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/secretwright ./cmd/secretwright

fmt:
	$(GOFMT) -w $$(find cmd internal schemas -type f -name '*.go')

fmt-check:
	@unformatted="$$($(GOFMT) -l $$(find cmd internal schemas -type f -name '*.go'))" || exit $$?; \
	test -z "$$unformatted" || { \
		printf '%s\n' "$$unformatted"; \
		$(GOFMT) -d $$(find cmd internal schemas -type f -name '*.go'); \
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

package-test:
	python3 -m unittest discover -s tests/packaging -p 'test_*.py' -v

package: package-test
	bash scripts/package_ci.sh

playground: build
	python3 scripts/playground.py up

playground-demo:
	python3 scripts/playground.py demo

playground-down:
	python3 scripts/playground.py down

playground-test:
	python3 -m unittest discover -s tests/playground -p 'test_*.py' -v
