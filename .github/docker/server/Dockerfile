# Build
FROM golang:1.20.1-alpine AS build-env
RUN apk add build-base
RUN go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

# Release
FROM alpine:3.17.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates python3 libffi curl \
    && apk add --no-cache --virtual .build-deps python3-dev py3-pip py3-wheel libffi-dev build-base \
    && python3 -m pip install impacket \
    && python3 -m pip cache purge \
    && apk del .build-deps
RUN curl -o /usr/local/bin/smb_server.py https://raw.githubusercontent.com/projectdiscovery/interactsh/main/cmd/interactsh-server/smb_server.py
WORKDIR "/usr/local/bin"
COPY --from=build-env /go/bin/interactsh-server /usr/local/bin/interactsh-server

ENTRYPOINT ["interactsh-server"]