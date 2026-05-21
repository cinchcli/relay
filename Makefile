.PHONY: build build-failover-listener build-all test lint clean generate verify-proto docker-build

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"
GOBIN := $(shell go env GOPATH)/bin

build:
	go build $(LDFLAGS) -o dist/relay ./cmd/relay

build-failover-listener:
	go build -o dist/failover-listener ./cmd/failover-listener

build-all: build build-failover-listener

test:
	go test ./... -v -race -count=1

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
