FROM alpine:latest AS client

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Interactsh client - Go client to generate interactsh payloads and display interaction data."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="interactsh-client"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/interactsh"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/interactsh-client /usr/local/bin/

ENTRYPOINT ["interactsh-client"]

FROM alpine:latest AS server

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Interactsh server runs multiple services and captures all the incoming requests."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="interactsh-server"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/interactsh"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates curl
WORKDIR "/usr/local/bin"

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/interactsh-server /usr/local/bin/

ENTRYPOINT ["interactsh-server"]
