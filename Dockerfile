# syntax=docker/dockerfile:1.6
#
# Single Dockerfile for both local builds and goreleaser.
#
#   docker build .                       # local: builds from source (runtime)
#   goreleaser --target=runtime-prebuilt # release: copies prebuilt binary
#
# The `base` stage holds everything common to both runtime images. The two
# thin runtime stages differ only by where the binary comes from.

ARG GO_VERSION=1.26

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

FROM alpine:3.21 AS base

RUN apk add --no-cache ca-certificates curl && \
    curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
      -o /etc/ssl/certs/rds-global-bundle.pem && \
    apk del curl

RUN adduser -D -h /data cinch
WORKDIR /data

ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://localhost:${PORT}/health" || exit 1
CMD ["cinch-relay"]

FROM base AS runtime-prebuilt
COPY cinch-relay /usr/local/bin/cinch-relay
USER cinch

FROM base AS runtime
COPY --from=builder /out/cinch-relay /usr/local/bin/cinch-relay
USER cinch
