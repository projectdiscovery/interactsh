# Base
FROM golang:1.25-alpine3.24 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build ./cmd/interactsh-client

# Release
FROM alpine:3.24
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools~=9.20 ca-certificates=20260909-r0
COPY --from=builder /app/interactsh-client /usr/local/bin/

ENTRYPOINT ["interactsh-client"]
