FROM python:3.8-alpine as compile
WORKDIR /opt
RUN apk add --no-cache git gcc musl-dev python3-dev libffi-dev openssl-dev cargo
RUN python3 -m pip install virtualenv
RUN virtualenv -p python venv
ENV PATH="/opt/venv/bin:$PATH"
RUN git clone --depth 1 https://github.com/SecureAuthCorp/impacket.git
RUN python3 -m pip install impacket/
RUN git clone --depth 1 https://github.com/lgandx/Responder.git
RUN python3 -m pip install netifaces
ENTRYPOINT ["python3","/opt/Responder/Responder.py","-I","eth0"]
