# Base
FROM golang:1.21.0-alpine AS builder
RUN apk add --no-cache git build-base gcc musl-dev
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/interactsh-client

# Release
FROM alpine:3.18.3
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/interactsh-client /usr/local/bin/

ENTRYPOINT ["interactsh-client"]