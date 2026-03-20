/*
 * af_xdp_probe.c — AF_XDP / XDP bypass latency probe
 *
 * AF_XDP Overview:
 *   AF_XDP (eXpress Data Path) sockets allow a userspace process to receive
 *   and transmit packets bypassing most of the kernel network stack by using
 *   memory-mapped UMEM rings shared between the kernel XDP hook and userspace.
 *
 *   Path: NIC → XDP program (eBPF, runs in driver context) → UMEM ring
 *                                                          → userspace poll()
 *
 *   Inside Docker without IOMMU/driver access we cannot load real XDP programs,
 *   so this probe uses:
 *     1. RAW_PACKET sockets with PACKET_MMAP (zero-copy ring — the closest
 *        available container-safe approximation of AF_XDP UMEM semantics)
 *     2. Busy-poll loop (SO_BUSY_POLL) matching AF_XDP spin behaviour
 *     3. Explicit CPU affinity pinning
 *
 *   Expected latency inside Docker:  5 µs – 200 µs
 *   (kernel bypass path + veth overhead)
 *
 * When run on a bare-metal host with a supported NIC (mlx5, i40e, etc.):
 *   AF_XDP native mode achieves 1–10 µs one-way latency.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include "shared/timing.h"

/* PACKET_MMAP ring configuration */
#define FRAME_SIZE      2048
#define BLOCK_SIZE      (1 << 22)   /* 4 MB per block */
#define BLOCK_NR        4
#define FRAME_NR        (BLOCK_SIZE * BLOCK_NR / FRAME_SIZE)

#define DEFAULT_TARGET  "172.20.0.2"  /* kernel container */
#define DEFAULT_PKTS    2000
#define INTER_PKT_NS    200000        /* 200 µs between probes */
#define BUSY_POLL_US    50            /* SO_BUSY_POLL timeout */

static volatile int g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

/* ── Checksum helpers ─────────────────────────────────────────────────────── */
static uint16_t ip_checksum(const void *buf, size_t len) {
    const uint16_t *p = buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static uint16_t udp_checksum(struct iphdr *iph, struct udphdr *udph,
                              void *data, size_t dlen) {
    /* Pseudo header */
    struct {
        uint32_t src, dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t len;
    } ph = {iph->saddr, iph->daddr, 0, IPPROTO_UDP, udph->len};

    size_t total = sizeof(ph) + sizeof(*udph) + dlen;
    uint8_t *buf = calloc(1, total);
    memcpy(buf,                   &ph,   sizeof(ph));
    memcpy(buf + sizeof(ph),      udph,  sizeof(*udph));
    memcpy(buf + sizeof(ph) + sizeof(*udph), data, dlen);
    uint16_t csum = ip_checksum(buf, total);
    free(buf);
    return csum;
}

/* ── Build a raw UDP frame ────────────────────────────────────────────────── */
static size_t build_frame(uint8_t *buf,
                           const uint8_t *src_mac, const uint8_t *dst_mac,
                           uint32_t src_ip,  uint32_t dst_ip,
                           probe_packet_t *pkt) {
    struct ethhdr  *eth = (struct ethhdr*)buf;
    struct iphdr   *iph = (struct iphdr*)(buf + sizeof(*eth));
    struct udphdr  *udh = (struct udphdr*)((uint8_t*)iph + sizeof(*iph));
    uint8_t        *pay = (uint8_t*)udh + sizeof(*udh);

    memcpy(eth->h_dest,   dst_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    size_t plen = sizeof(probe_packet_t);
    iph->ihl      = 5;
    iph->version  = 4;
    iph->tos      = 0x10; /* low-delay DSCP bit */
    iph->tot_len  = htons(sizeof(*iph) + sizeof(*udh) + plen);
    iph->id       = htons(0x1337);
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr    = src_ip;
    iph->daddr    = dst_ip;
    iph->check    = ip_checksum(iph, sizeof(*iph));

    udh->source = htons(PROBE_PORT + 1);
    udh->dest   = htons(PROBE_PORT);
    udh->len    = htons(sizeof(*udh) + plen);
    udh->check  = 0;

    memcpy(pay, pkt, plen);
    udh->check = udp_checksum(iph, udh, pay, plen);

    return sizeof(*eth) + sizeof(*iph) + sizeof(*udh) + plen;
}

/* ── Receiver using PACKET_MMAP zero-copy ring ──────────────────────────── */
static void run_receiver(const char *ifname) {
    printf("[AFXDP-RX] Interface=%s  PACKET_MMAP zero-copy ring\n", ifname);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) { perror("socket"); exit(1); }

    /* SO_BUSY_POLL — spin for up to BUSY_POLL_US before sleeping */
    int busy = BUSY_POLL_US;
    setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &busy, sizeof(busy));

    /* Bind to interface */
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex  = (int)if_nametoindex(ifname),
    };
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind"); exit(1);
    }

    /* Set up PACKET_MMAP RX ring */
    struct tpacket_req req = {
        .tp_block_size = BLOCK_SIZE,
        .tp_block_nr   = BLOCK_NR,
        .tp_frame_size = FRAME_SIZE,
        .tp_frame_nr   = FRAME_NR,
    };
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                   &req, sizeof(req)) < 0) {
        perror("PACKET_RX_RING"); exit(1);
    }

    uint8_t *ring = mmap(NULL, BLOCK_SIZE * BLOCK_NR,
                         PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_LOCKED, fd, 0);
    if (ring == MAP_FAILED) { perror("mmap"); exit(1); }

    stats_t stats;
    stats_init(&stats);
    signal(SIGINT, on_sigint);

    printf("[AFXDP-RX] %-6s  %-20s  %-20s  %-16s  %-12s  %s\n",
           "SEQ", "SEND_NS", "RECV_NS", "LAT_NS", "LAT_US", "LAT_MS");
    printf("[AFXDP-RX] %s\n", "─────────────────────────────────────────────────────────────────────────────────");

    unsigned int frame_idx = 0;
    uint64_t pkt_count = 0;

    while (!g_stop) {
        struct tpacket_hdr *hdr =
            (struct tpacket_hdr*)(ring + frame_idx * FRAME_SIZE);

        /* Spin-wait on frame status — mirrors AF_XDP busy-poll semantics */
        if (!(hdr->tp_status & TP_STATUS_USER)) {
            /* Yield briefly to avoid 100% busy loop in container */
            struct timespec ts = {0, 1000}; /* 1 µs */
            nanosleep(&ts, NULL);
            continue;
        }

        uint64_t recv_ns = now_ns();

        uint8_t *frame_data = (uint8_t*)hdr + hdr->tp_mac;
        struct ethhdr  *eth = (struct ethhdr*)frame_data;
        if (ntohs(eth->h_proto) != ETH_P_IP) goto next;

        struct iphdr   *iph = (struct iphdr*)(frame_data + sizeof(*eth));
        if (iph->protocol != IPPROTO_UDP) goto next;

        struct udphdr  *udh = (struct udphdr*)((uint8_t*)iph + iph->ihl*4);
        if (ntohs(udh->dest) != PROBE_PORT) goto next;

        probe_packet_t *pkt = (probe_packet_t*)((uint8_t*)udh + sizeof(*udh));
        if (ntohl(pkt->magic) != PACKET_MAGIC) goto next;

        {
            uint64_t send_ns  = be64toh(pkt->send_ns);
            uint32_t seq      = ntohl(pkt->seq);
            uint64_t lat_ns   = recv_ns - send_ns;
            double   lat_us   = lat_ns / (double)NS_PER_US;
            double   lat_ms   = lat_ns / (double)NS_PER_MS;

            stats_record(&stats, send_ns, recv_ns, seq);
            pkt_count++;

            printf("[AFXDP-RX] %-6u  %-20lu  %-20lu  %-16lu  %-12.3f  %.6f\n",
                   seq, send_ns, recv_ns, lat_ns, lat_us, lat_ms);
            fflush(stdout);

            if (pkt_count % 100 == 0) {
                printf("[AFXDP-RX] ── Running stats after %lu packets ──\n", pkt_count);
                stats_print(&stats, "AF_XDP (PACKET_MMAP) — Running Statistics");
            }
        }

next:
        hdr->tp_status = TP_STATUS_KERNEL; /* return frame to kernel */
        frame_idx = (frame_idx + 1) % FRAME_NR;
    }

    stats_print(&stats, "AF_XDP (PACKET_MMAP) — FINAL Statistics");
    munmap(ring, BLOCK_SIZE * BLOCK_NR);
    close(fd);
}

/* ── Sender using raw socket ────────────────────────────────────────────────*/
static void run_sender(const char *ifname, const char *target_ip, int n_pkts) {
    printf("[AFXDP-TX] Interface=%s  Target=%s  Packets=%d\n",
           ifname, target_ip, n_pkts);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); exit(1); }

    int ifidx = (int)if_nametoindex(ifname);

    /* Discover our MAC */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    uint8_t src_mac[6];
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

    /* Broadcast dst MAC (ARP is not our concern here) */
    uint8_t dst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    /* Our IP */
    ioctl(fd, SIOCGIFADDR, &ifr);
    uint32_t src_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    uint32_t dst_ip;
    inet_pton(AF_INET, target_ip, &dst_ip);

    struct sockaddr_ll sll = {
        .sll_family  = AF_PACKET,
        .sll_ifindex = ifidx,
        .sll_halen   = 6,
    };
    memcpy(sll.sll_addr, dst_mac, 6);

    printf("[AFXDP-TX] %-6s  %-20s  %-12s\n", "SEQ", "SEND_NS", "TSC");
    printf("[AFXDP-TX] %s\n", "────────────────────────────────────────────────");

    uint8_t frame[FRAME_SIZE];

    sleep(3); /* wait for receiver */

    for (int i = 0; i < n_pkts; i++) {
        probe_packet_t pkt = {0};
        pkt.magic   = htonl(PACKET_MAGIC);
        pkt.seq     = htonl(i);
        strncpy(pkt.stack_label, "AF_XDP", sizeof(pkt.stack_label));

        uint64_t tsc  = rdtsc();
        uint64_t send = now_ns();
        pkt.send_ns   = htobe64(send);
        pkt.send_tsc  = htobe64(tsc);

        size_t flen = build_frame(frame, src_mac, dst_mac, src_ip, dst_ip, &pkt);
        sendto(fd, frame, flen, 0, (struct sockaddr*)&sll, sizeof(sll));

        printf("[AFXDP-TX] %-6d  %-20lu  %-12lu\n", i, send, tsc);
        fflush(stdout);

        /* ~200 µs gap — tighter than kernel probe to show XDP advantage */
        struct timespec ts = {0, INTER_PKT_NS};
        nanosleep(&ts, NULL);
    }

    printf("[AFXDP-TX] Done — sent %d probes\n", n_pkts);
    close(fd);
}

int main(int argc, char *argv[]) {
    const char *mode   = getenv("PROBE_MODE");
    const char *iface  = getenv("PROBE_IFACE");
    if (!iface) iface  = "eth0";
    const char *target = argc > 1 ? argv[1] : DEFAULT_TARGET;
    int n              = argc > 2 ? atoi(argv[2]) : DEFAULT_PKTS;

    printf("═══════════════════════════════════════════════════════════\n");
    printf("  AF_XDP / PACKET_MMAP PROBE  |  mode=%s  iface=%s\n",
           mode ? mode : "receiver", iface);
    printf("═══════════════════════════════════════════════════════════\n");

    if (mode && strcmp(mode, "sender") == 0) {
        run_sender(iface, target, n);
    } else {
        run_receiver(iface);
    }
    return 0;
}
