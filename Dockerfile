# syntax=docker/dockerfile:1.6
#
# Single Dockerfile for both local builds and goreleaser.
#
#   docker build .                              # local: builds from source
#   goreleaser ... --build-arg=BIN_SRC=prebuilt # release: copies binary from context
#
# BuildKit skips unused stages, so each path only runs what it needs.

ARG GO_VERSION=1.26
ARG BIN_SRC=builder

FROM golang:${GO_VERSION}-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/cinch-relay ./cmd/relay

FROM scratch AS prebuilt
COPY cinch-relay /out/cinch-relay

FROM alpine:3.21 AS runtime

RUN apk add --no-cache ca-certificates curl && \
    curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
      -o /etc/ssl/certs/rds-global-bundle.pem && \
    apk del curl

COPY --from=${BIN_SRC} /out/cinch-relay /usr/local/bin/cinch-relay

RUN adduser -D -h /data cinch
USER cinch
WORKDIR /data

ENV PORT=8080

EXPOSE 8080

CMD ["cinch-relay"]
