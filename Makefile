.PHONY: build build-failover-listener build-all test lint clean generate docker-build

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
	buf lint && go vet ./...

clean:
	rm -rf dist/

generate:
	PATH="$(HOME)/go/bin:$(PATH)" buf generate
	go mod tidy

docker-build:
	docker build -t ghcr.io/cinchcli/relay:latest .
