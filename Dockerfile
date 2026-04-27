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

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/cinch-relay /usr/local/bin/cinch-relay

RUN adduser -D -h /data cinch
USER cinch
WORKDIR /data

ENV PORT=8080
ENV DB_PATH=/data/cinch.db

EXPOSE 8080

CMD ["cinch-relay"]
