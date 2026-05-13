FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /bin/cinch-relay ./cmd/relay

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o /bin/failover-listener ./cmd/failover-listener

FROM alpine:3.21

RUN apk add --no-cache ca-certificates curl && \
    curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
      -o /etc/ssl/certs/rds-global-bundle.pem && \
    apk del curl

COPY --from=builder /bin/cinch-relay /usr/local/bin/cinch-relay
COPY --from=builder /bin/failover-listener /usr/local/bin/failover-listener

RUN adduser -D -h /data cinch
USER cinch
WORKDIR /data

ENV PORT=8080

EXPOSE 8080

CMD ["cinch-relay"]
