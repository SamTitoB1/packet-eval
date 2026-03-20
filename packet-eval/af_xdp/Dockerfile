FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc make libc6-dev iproute2 iputils-ping \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /probe

COPY shared/timing.h /probe/shared/
COPY af_xdp/af_xdp_probe.c /probe/

RUN gcc -O3 -Wall -o af_xdp_probe af_xdp_probe.c \
        -I/probe -lm -march=native 2>&1 && \
    echo "Build OK"

ENV PROBE_MODE=receiver
ENV PROBE_IFACE=eth0

ENTRYPOINT ["/probe/af_xdp_probe"]
