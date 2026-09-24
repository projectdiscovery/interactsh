# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/interactsh-server ./cmd/interactsh-server
RUN CGO_ENABLED=0 go build -trimpath -o /out/interactsh-client ./cmd/interactsh-client

FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates
COPY --from=builder /out/interactsh-server /usr/local/bin/interactsh-server
COPY --from=builder /out/interactsh-client /usr/local/bin/interactsh-client
ENTRYPOINT ["interactsh-server"]
