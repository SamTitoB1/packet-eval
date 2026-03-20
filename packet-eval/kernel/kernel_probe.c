/*
 * kernel_probe.c — Traditional Linux kernel network stack latency probe
 *
 * Methodology:
 *   Uses standard POSIX UDP sockets (AF_INET / SOCK_DGRAM).
 *   Every packet carries an embedded CLOCK_REALTIME send-timestamp.
 *   The receiver records CLOCK_REALTIME on arrival; delta = wire latency
 *   as seen through the full kernel network path:
 *     userspace → socket syscall → TCP/IP stack → driver → wire
 *                                               → driver → TCP/IP stack → socket syscall → userspace
 *
 *   Expected latency inside Docker bridge: 50 µs – 3 ms
 *   (kernel scheduling jitter dominates at this layer)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>
#include "shared/timing.h"

#define DEFAULT_TARGET  "172.20.0.3"   /* af_xdp container */
#define DEFAULT_PKTS    2000
#define INTER_PKT_US    500            /* 500 µs between probes */

static int make_udp_socket(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* SO_TIMESTAMP: ask kernel to stamp packets on arrival for reference */
    setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &opt, sizeof(opt));

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

/* ── Receiver thread (runs in separate process fork) ─────────────────────── */
static void run_receiver(void) {
    printf("[KERNEL-RX] Listening on UDP :%d\n", PROBE_PORT);
    int fd = make_udp_socket(PROBE_PORT);

    stats_t stats;
    stats_init(&stats);

    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    probe_packet_t pkt;

    printf("[KERNEL-RX] %-6s  %-20s  %-20s  %-16s  %-12s  %s\n",
           "SEQ", "SEND_NS", "RECV_NS", "LAT_NS", "LAT_US", "LAT_MS");
    printf("[KERNEL-RX] %s\n", "─────────────────────────────────────────────────────────────────────────────────");

    for (;;) {
        ssize_t n = recvfrom(fd, &pkt, sizeof(pkt), 0,
                             (struct sockaddr*)&peer, &plen);
        if (n < 0) { perror("recvfrom"); continue; }
        if (n < (ssize_t)sizeof(probe_packet_t)) continue;
        if (ntohl(pkt.magic) != PACKET_MAGIC) continue;

        uint64_t recv_ns  = now_ns();
        uint64_t send_ns  = be64toh(pkt.send_ns);
        uint32_t seq      = ntohl(pkt.seq);
        uint64_t lat_ns   = recv_ns - send_ns;
        double   lat_us   = lat_ns / (double)NS_PER_US;
        double   lat_ms   = lat_ns / (double)NS_PER_MS;

        stats_record(&stats, send_ns, recv_ns, seq);

        /* Verbose per-packet line */
        printf("[KERNEL-RX] %-6u  %-20lu  %-20lu  %-16lu  %-12.3f  %.6f\n",
               seq, send_ns, recv_ns, lat_ns, lat_us, lat_ms);
        fflush(stdout);

        /* Print running stats every 100 packets */
        if (seq > 0 && seq % 100 == 0) {
            printf("[KERNEL-RX] ── Running stats after %u packets ──\n", seq);
            stats_print(&stats, "KERNEL STACK — Running Statistics");
        }
    }
}

/* ── Sender ──────────────────────────────────────────────────────────────── */
static void run_sender(const char *target_ip, int n_pkts) {
    printf("[KERNEL-TX] Target=%s:%d  packets=%d  interval=%dµs\n",
           target_ip, PROBE_PORT, n_pkts, INTER_PKT_US);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }

    struct sockaddr_in dst = {
        .sin_family      = AF_INET,
        .sin_port        = htons(PROBE_PORT),
    };
    inet_pton(AF_INET, target_ip, &dst.sin_addr);

    /* SO_PRIORITY: best-effort high priority */
    int prio = 6;
    setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));

    printf("[KERNEL-TX] %-6s  %-20s  %-12s\n", "SEQ", "SEND_NS", "TSC");
    printf("[KERNEL-TX] %s\n", "────────────────────────────────────────────────");

    for (int i = 0; i < n_pkts; i++) {
        probe_packet_t pkt = {0};
        pkt.magic    = htonl(PACKET_MAGIC);
        pkt.seq      = htonl(i);
        strncpy(pkt.stack_label, "KERNEL", sizeof(pkt.stack_label));

        /* Stamp as late as possible before syscall */
        uint64_t tsc   = rdtsc();
        uint64_t send  = now_ns();
        pkt.send_ns    = htobe64(send);
        pkt.send_tsc   = htobe64(tsc);

        ssize_t sent = sendto(fd, &pkt, sizeof(pkt), 0,
                              (struct sockaddr*)&dst, sizeof(dst));
        if (sent < 0) { perror("sendto"); }

        printf("[KERNEL-TX] %-6d  %-20lu  %-12lu\n", i, send, tsc);
        fflush(stdout);

        /* Inter-packet gap */
        usleep(INTER_PKT_US);
    }

    printf("[KERNEL-TX] Done — sent %d probes\n", n_pkts);
    close(fd);
}

int main(int argc, char *argv[]) {
    /* MODE env: "sender" | "receiver" (default receiver) */
    const char *mode = getenv("PROBE_MODE");
    const char *target = argc > 1 ? argv[1] : DEFAULT_TARGET;
    int n = argc > 2 ? atoi(argv[2]) : DEFAULT_PKTS;

    printf("═══════════════════════════════════════════════════════════\n");
    printf("  KERNEL STACK PROBE  |  mode=%s\n", mode ? mode : "receiver");
    printf("═══════════════════════════════════════════════════════════\n");

    if (mode && strcmp(mode, "sender") == 0) {
        /* Small delay to let receiver start */
        sleep(3);
        run_sender(target, n);
    } else {
        run_receiver();
    }
    return 0;
}
