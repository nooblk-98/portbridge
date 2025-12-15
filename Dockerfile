FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    ca-certificates \
    ip6tables \
    iproute2 \
    iptables \
    python3 \
    py3-pip \
    wireguard-tools

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /tmp/requirements.txt

WORKDIR /app
COPY app /app
COPY config /app/config

ENV PYTHONUNBUFFERED=1
EXPOSE 20000 51820/udp

CMD ["python3", "/app/server.py"]
