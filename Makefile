.PHONY: build build-failover-listener build-all test test-db db-up db-down lint clean generate verify-proto docker-build

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
GOBIN := $(shell go env GOPATH)/bin

# Local Postgres for the integration suite. The relay package's TestMain
# fails loudly when TEST_DATABASE_URL is unset, so the full suite cannot
# silently skip its DB-backed tests. Override TEST_DATABASE_URL to point at
# an existing database instead of the docker-compose one.
TEST_DATABASE_URL ?= postgres://cinch:cinch@localhost:5432/cinch?sslmode=disable

build:
	go build $(LDFLAGS) -o dist/relay ./cmd/relay

build-failover-listener:
	go build -o dist/failover-listener ./cmd/failover-listener

build-all: build build-failover-listener

test:
	go test ./... -v -race -count=1

# Bring up the docker-compose Postgres service and wait until it accepts
# connections. Safe to run repeatedly.
db-up:
	docker compose up -d postgres
	@echo "waiting for postgres..."
	@for i in $$(seq 1 30); do \
		docker compose exec -T postgres pg_isready -U cinch >/dev/null 2>&1 && exit 0; \
		sleep 1; \
	done; \
	echo "postgres did not become ready" >&2; exit 1

db-down:
	docker compose down

# Run the full suite against the local Postgres. Exports TEST_DATABASE_URL so
# the relay package's TestMain guard is satisfied and no DB-backed test skips.
test-db: db-up
	TEST_DATABASE_URL="$(TEST_DATABASE_URL)" go test ./... -race -count=1

lint:
	go vet ./...

clean:
	rm -rf dist/

# Regenerate Go bindings from the vendored .proto files. buf writes to
# internal/cinchv1/cinch/v1/ (because paths=source_relative preserves the
# proto package path); flatten back to internal/cinchv1/ so import paths
# stay short.
generate:
	PATH=$(GOBIN):$$PATH buf generate
	@if [ -d internal/cinchv1/cinch/v1 ]; then \
		cp -R internal/cinchv1/cinch/v1/* internal/cinchv1/; \
		rm -rf internal/cinchv1/cinch; \
	fi
	go mod tidy

# Detect drift between proto/cinch/v1/*.proto and the cinch monorepo.
# CI runs this to guarantee relay stays in lock-step with the wire schema.
verify-proto:
	./scripts/verify-proto.sh

docker-build:
	docker build -t ghcr.io/cinchcli/relay:latest .
