# syntax=docker/dockerfile:1
FROM golang:1.25-alpine3.24 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/interactsh-server ./cmd/interactsh-server \
    && CGO_ENABLED=0 go build -trimpath -o /out/interactsh-client ./cmd/interactsh-client

FROM alpine:3.24
RUN apk add --no-cache curl~=8.22 ca-certificates=20260909-r0
COPY --from=builder /out/interactsh-server /usr/local/bin/interactsh-server
COPY --from=builder /out/interactsh-client /usr/local/bin/interactsh-client
ENTRYPOINT ["interactsh-server"]
