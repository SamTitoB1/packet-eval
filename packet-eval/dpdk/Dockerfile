FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc make libc6-dev iproute2 iputils-ping \
    libpthread-stubs0-dev \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /probe

COPY shared/timing.h /probe/shared/
COPY dpdk/dpdk_probe.c /probe/

RUN gcc -O3 -Wall -o dpdk_probe dpdk_probe.c \
        -I/probe -lm -lpthread -march=native 2>&1 && \
    echo "Build OK"

ENV PROBE_MODE=receiver

ENTRYPOINT ["/probe/dpdk_probe"]
