FROM python:3.11-slim-bookworm
WORKDIR /opt

# Build deps + runtime networking tools Responder shells out to (ip/ifconfig)
RUN apt-get update && apt-get install -y --no-install-recommends \
        git gcc python3-dev libffi-dev libssl-dev \
        iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --upgrade pip virtualenv \
    && virtualenv -p python3 /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Impacket (repo moved SecureAuthCorp -> fortra)
RUN git clone --depth 1 https://github.com/fortra/impacket.git \
    && python3 -m pip install --no-cache-dir ./impacket \
    && rm -rf impacket

# Responder deps: upstream pins netifaces, which fails to build on modern
# toolchains; netifaces-plus is a drop-in replacement (same import name).
RUN git clone --depth 1 https://github.com/lgandx/Responder.git \
    && python3 -m pip install --no-cache-dir aioquic netifaces-plus

# Keep HTTP/HTTPS/DNS off so Responder does not fight interactsh on those ports
# when someone runs with --network host.
RUN sed -i \
        -e 's/^HTTP     = On/HTTP     = Off/' \
        -e 's/^HTTPS    = On/HTTPS    = Off/' \
        -e 's/^DNS      = On/DNS      = Off/' \
        /opt/Responder/Responder.conf

WORKDIR /opt/Responder
ENTRYPOINT ["/opt/venv/bin/python3", "/opt/Responder/Responder.py", "-I", "eth0", "-v"]
