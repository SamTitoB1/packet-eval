FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    gcc make libc6-dev iproute2 iputils-ping \
    --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /probe

COPY shared/timing.h /probe/shared/
COPY kernel/kernel_probe.c /probe/

RUN gcc -O2 -Wall -o kernel_probe kernel_probe.c \
        -I/probe -lm -march=native 2>&1 && \
    echo "Build OK"

ENV PROBE_MODE=receiver

ENTRYPOINT ["/probe/kernel_probe"]
