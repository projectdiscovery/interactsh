# Build
FROM golang:1.18.0-alpine AS build-env
RUN apk add build-base
RUN go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

# Release
FROM alpine:3.15.0
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/interactsh-server /usr/local/bin/interactsh-server

ENTRYPOINT ["interactsh-server"]