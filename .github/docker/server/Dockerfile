# Base
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git build-base gcc musl-dev
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/interactsh-server


# Release
FROM alpine:3.19
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates curl
WORKDIR "/usr/local/bin"
COPY --from=builder /app/interactsh-server /usr/local/bin/

ENTRYPOINT ["interactsh-server"]
