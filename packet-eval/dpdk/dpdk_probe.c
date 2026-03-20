/*
 * dpdk_probe.c — DPDK-class userspace PMD latency probe
 *
 * DPDK Overview:
 *   DPDK (Data Plane Development Kit) bypasses the kernel entirely by:
 *     - Using UIO/VFIO to map NIC BAR registers into userspace
 *     - Running a Poll Mode Driver (PMD) that busy-polls hardware RX rings
 *     - Pinning one thread per core with no interrupts (no scheduler jitter)
 *     - NUMA-aware hugepage-backed memory for DMA descriptors
 *
 *   Full DPDK requires hugepages, VFIO, and a supported NIC/PCI device —
 *   none of which are available inside unprivileged Docker containers.
 *
 *   This probe implements the same LOGICAL behaviour using:
 *     1. CPU-pinned thread  (sched_setaffinity)
 *     2. SCHED_FIFO real-time scheduling  (if CAP_SYS_NICE)
 *     3. Busy-poll tight loop on a UDP socket  (no epoll/select)
 *     4. SO_RCVBUFFORCE + SO_SNDBUFFORCE large buffers
 *     5. IP_TOS = IPTOS_LOWDELAY
 *     6. clock_gettime(CLOCK_MONOTONIC_RAW) — avoids NTP correction jitter
 *
 *   Expected latency inside Docker:  1 µs – 100 µs  (bridge overhead dominated)
 *   Bare-metal DPDK PMD (DPDK vHost / virtio_user):  100 ns – 2 µs
 *
 * Compile:  gcc -O3 -march=native -o dpdk_probe dpdk_probe.c -lm
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include "shared/timing.h"

#define DEFAULT_TARGET   "172.20.0.2"
#define DEFAULT_PKTS     2000
#define INTER_PKT_NS     100000        /* 100 µs — tighter than AF_XDP */
#define RX_CORE          1             /* CPU core for RX busy-poll */
#define TX_CORE          2             /* CPU core for TX */
#define SOCKET_BUFSIZE   (1 << 26)     /* 64 MB ring buffer */

static volatile int g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

/* ── CLOCK_MONOTONIC_RAW — immune to NTP adjustments ─────────────────────── */
static inline uint64_t now_mono_raw_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

/* ── Pin calling thread to a CPU core ────────────────────────────────────── */
static void pin_to_core(int core) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(core % (int)sysconf(_SC_NPROCESSORS_ONLN), &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0)
        fprintf(stderr, "[DPDK] Warning: could not pin to core %d\n", core);
    else
        printf("[DPDK] Thread pinned to CPU core %d\n", core);
}

/* ── Attempt SCHED_FIFO elevation ─────────────────────────────────────────── */
static void try_realtime(void) {
    struct sched_param sp = { .sched_priority = 50 };
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) == 0)
        printf("[DPDK] SCHED_FIFO priority=50 — real-time scheduling enabled\n");
    else
        printf("[DPDK] SCHED_FIFO unavailable (no CAP_SYS_NICE) — running SCHED_OTHER\n");
}

/* ── Create socket matching DPDK PMD characteristics ─────────────────────── */
static int make_dpdk_socket(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    /* Large ring buffers — DPDK typically uses 1–16 K descriptor rings */
    int bufsz = SOCKET_BUFSIZE;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));

    /* Attempt forced buffer expansion (requires CAP_NET_ADMIN) */
    setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &bufsz, sizeof(bufsz));

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* SO_BUSY_POLL — kernel busy-polls before sleeping; matches PMD spin */
    int busy = 100; /* µs */
    setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &busy, sizeof(busy));

    /* IP_TOS LOWDELAY */
    int tos = IPTOS_LOWDELAY;
    setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));

    /* Disable Nagle — UDP doesn't have it but keep for future TCP mode */
    int prio = 7;
    setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY,
    };
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    return fd;
}

/* ── RX: tight busy-poll loop (PMD poll() equivalent) ────────────────────── */
static void run_receiver(void) {
    pin_to_core(RX_CORE);
    try_realtime();

    printf("[DPDK-RX]  Busy-poll UDP receiver on port %d (PMD simulation)\n", PROBE_PORT);

    int fd = make_dpdk_socket(PROBE_PORT);

    /* Disable receive timestamps from kernel — we stamp in userspace */
    int opt = 0;
    setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt));

    stats_t stats;
    stats_init(&stats);
    signal(SIGINT, on_sigint);

    struct sockaddr_in peer;
    socklen_t plen  = sizeof(peer);
    probe_packet_t pkt;
    uint64_t pkt_count = 0;

    printf("[DPDK-RX]  %-6s  %-20s  %-20s  %-16s  %-12s  %-14s  %s\n",
           "SEQ", "SEND_NS(MONO)", "RECV_NS(MONO)", "LAT_NS", "LAT_US", "LAT_MS", "SEND_TSC");
    printf("[DPDK-RX]  %s\n",
           "─────────────────────────────────────────────────────────────────────────────────────────────");

    /* PMD-style busy-poll: spin without blocking */
    while (!g_stop) {
        ssize_t n = recvfrom(fd, &pkt, sizeof(pkt), MSG_DONTWAIT,
                             (struct sockaddr*)&peer, &plen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* No packet yet — spin (PMD poll loop) */
                __asm__ volatile("pause" ::: "memory"); /* x86 PAUSE hint */
                continue;
            }
            perror("recvfrom"); continue;
        }
        if (n < (ssize_t)sizeof(probe_packet_t)) continue;
        if (ntohl(pkt.magic) != PACKET_MAGIC) continue;

        /* Timestamp as soon as possible after recvfrom returns */
        uint64_t recv_mono = now_mono_raw_ns();
        uint64_t recv_wall = now_ns();

        uint64_t send_ns  = be64toh(pkt.send_ns);   /* sender wall clock */
        uint64_t send_tsc = be64toh(pkt.send_tsc);
        uint32_t seq      = ntohl(pkt.seq);

        /* Latency using wall clock (cross-host comparable) */
        uint64_t lat_ns   = recv_wall - send_ns;
        double   lat_us   = lat_ns / (double)NS_PER_US;
        double   lat_ms   = lat_ns / (double)NS_PER_MS;

        stats_record(&stats, send_ns, recv_wall, seq);
        pkt_count++;

        printf("[DPDK-RX]  %-6u  %-20lu  %-20lu  %-16lu  %-12.3f  %-14.6f  %lu\n",
               seq, send_ns, recv_mono, lat_ns, lat_us, lat_ms, send_tsc);
        fflush(stdout);

        if (pkt_count % 100 == 0) {
            printf("[DPDK-RX]  ── Running stats after %lu packets ──\n", pkt_count);
            stats_print(&stats, "DPDK PMD (simulated) — Running Statistics");
        }
    }

    stats_print(&stats, "DPDK PMD (simulated) — FINAL Statistics");
    close(fd);
}

/* ── TX: tight inter-packet gap using nanosleep ───────────────────────────── */
static void run_sender(const char *target_ip, int n_pkts) {
    pin_to_core(TX_CORE);
    try_realtime();

    printf("[DPDK-TX]  Target=%s:%d  packets=%d  gap=%dns\n",
           target_ip, PROBE_PORT, n_pkts, INTER_PKT_NS);

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    int tos = IPTOS_LOWDELAY;
    setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    int prio = 7;
    setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
    int bufsz = SOCKET_BUFSIZE;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &bufsz, sizeof(bufsz));

    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons(PROBE_PORT),
    };
    inet_pton(AF_INET, target_ip, &dst.sin_addr);

    sleep(3); /* wait for receiver */

    printf("[DPDK-TX]  %-6s  %-20s  %-12s  %-16s\n",
           "SEQ", "SEND_NS", "TSC", "INTER_NS");
    printf("[DPDK-TX]  %s\n",
           "────────────────────────────────────────────────────────────────");

    uint64_t prev_send = 0;

    for (int i = 0; i < n_pkts && !g_stop; i++) {
        probe_packet_t pkt = {0};
        pkt.magic   = htonl(PACKET_MAGIC);
        pkt.seq     = htonl(i);
        strncpy(pkt.stack_label, "DPDK", sizeof(pkt.stack_label));

        /* Stamp right before send — minimize instrumentation latency */
        uint64_t tsc  = rdtsc();
        uint64_t send = now_ns();
        pkt.send_ns   = htobe64(send);
        pkt.send_tsc  = htobe64(tsc);

        while (sendto(fd, &pkt, sizeof(pkt), MSG_DONTWAIT,
                      (struct sockaddr*)&dst, sizeof(dst)) < 0) {
            if (errno == EAGAIN) continue; /* busy spin TX retry */
            perror("sendto"); break;
        }

        uint64_t inter_ns = prev_send ? send - prev_send : 0;
        prev_send = send;

        printf("[DPDK-TX]  %-6d  %-20lu  %-12lu  %-16lu\n",
               i, send, tsc, inter_ns);
        fflush(stdout);

        /* High-resolution inter-packet gap */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = INTER_PKT_NS };
        nanosleep(&ts, NULL);
    }

    printf("[DPDK-TX]  Done — sent %d probes\n", n_pkts);
    close(fd);
}

int main(int argc, char *argv[]) {
    const char *mode   = getenv("PROBE_MODE");
    const char *target = argc > 1 ? argv[1] : DEFAULT_TARGET;
    int n              = argc > 2 ? atoi(argv[2]) : DEFAULT_PKTS;

    printf("═══════════════════════════════════════════════════════════\n");
    printf("  DPDK PMD PROBE (container sim)  |  mode=%s\n",
           mode ? mode : "receiver");
    printf("═══════════════════════════════════════════════════════════\n");

    if (mode && strcmp(mode, "sender") == 0) {
        run_sender(target, n);
    } else {
        run_receiver();
    }
    return 0;
}
