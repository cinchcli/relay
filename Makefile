.PHONY: build build-failover-listener build-all test lint clean update-cinch-core docker-build

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

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

# The proto schema and generated Go bindings live in github.com/cinchcli/cinch-core.
# To pick up a wire-format change: bump cinch-core there, publish a new tag,
# then run `make update-cinch-core REV=<tag>` here.
update-cinch-core:
	@if [ -z "$(REV)" ]; then echo "usage: make update-cinch-core REV=v0.1.x"; exit 1; fi
	go get github.com/cinchcli/cinch-core@$(REV)
	go mod tidy

docker-build:
	docker build -t ghcr.io/cinchcli/relay:latest .
