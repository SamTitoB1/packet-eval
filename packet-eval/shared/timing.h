#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <string.h>

#define NS_PER_SEC  1000000000ULL
#define NS_PER_MS   1000000ULL
#define NS_PER_US   1000ULL

#define MAX_SAMPLES 10000
#define PACKET_MAGIC 0xDEADBEEF
#define PROBE_PORT   9999
#define RESULT_PORT  9998

// ── Packet payload embedded with high-resolution timestamps ──────────────────
typedef struct __attribute__((packed)) {
    uint32_t magic;           // 0xDEADBEEF
    uint32_t seq;             // sequence number
    uint64_t send_ns;         // sender CLOCK_REALTIME nanoseconds
    uint64_t send_tsc;        // sender rdtsc cycle count
    char     stack_label[16]; // "DPDK", "AF_XDP", "KERNEL"
    uint8_t  payload[32];     // padding to realistic packet size
} probe_packet_t;

// ── Per-sample latency record ────────────────────────────────────────────────
typedef struct {
    uint32_t seq;
    uint64_t send_ns;
    uint64_t recv_ns;
    uint64_t latency_ns;
    double   latency_us;
    double   latency_ms;
} latency_sample_t;

// ── Stats aggregator ─────────────────────────────────────────────────────────
typedef struct {
    uint64_t count;
    uint64_t min_ns;
    uint64_t max_ns;
    double   sum_ns;
    double   sum_sq_ns;
    latency_sample_t samples[MAX_SAMPLES];
} stats_t;

// ── Inline helpers ───────────────────────────────────────────────────────────
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

static inline uint64_t rdtsc(void) {
#if defined(__x86_64__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_SEC + (uint64_t)ts.tv_nsec;
#endif
}

static inline void stats_init(stats_t *s) {
    memset(s, 0, sizeof(*s));
    s->min_ns = UINT64_MAX;
}

static inline void stats_record(stats_t *s, uint64_t send_ns,
                                uint64_t recv_ns, uint32_t seq) {
    uint64_t lat = recv_ns - send_ns;
    if (s->count < MAX_SAMPLES) {
        s->samples[s->count].seq        = seq;
        s->samples[s->count].send_ns    = send_ns;
        s->samples[s->count].recv_ns    = recv_ns;
        s->samples[s->count].latency_ns = lat;
        s->samples[s->count].latency_us = lat / (double)NS_PER_US;
        s->samples[s->count].latency_ms = lat / (double)NS_PER_MS;
    }
    if (lat < s->min_ns) s->min_ns = lat;
    if (lat > s->max_ns) s->max_ns = lat;
    s->sum_ns   += lat;
    s->sum_sq_ns += (double)lat * (double)lat;
    s->count++;
}

static inline double stats_mean(const stats_t *s) {
    return s->count ? s->sum_ns / s->count : 0.0;
}

static inline double stats_stddev(const stats_t *s) {
    if (s->count < 2) return 0.0;
    double mean = stats_mean(s);
    double var  = (s->sum_sq_ns / s->count) - (mean * mean);
    return var > 0 ? __builtin_sqrt(var) : 0.0;
}

// Percentile — requires sorted copy; we compute inline approx via linear scan
static inline uint64_t stats_percentile(stats_t *s, double pct) {
    if (!s->count) return 0;
    // simple insertion sort on the stored samples (up to MAX_SAMPLES)
    uint64_t tmp[MAX_SAMPLES];
    uint64_t n = s->count < MAX_SAMPLES ? s->count : MAX_SAMPLES;
    for (uint64_t i = 0; i < n; i++) tmp[i] = s->samples[i].latency_ns;
    for (uint64_t i = 1; i < n; i++) {
        uint64_t key = tmp[i]; int64_t j = (int64_t)i - 1;
        while (j >= 0 && tmp[j] > key) { tmp[j+1] = tmp[j]; j--; }
        tmp[j+1] = key;
    }
    uint64_t idx = (uint64_t)(pct / 100.0 * (n - 1));
    return tmp[idx];
}

static inline void stats_print(const stats_t *s, const char *label) {
    double mean = stats_mean(s);
    double stddev = stats_stddev(s);
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║  %-60s║\n", label);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Packets measured : %-41lu║\n", s->count);
    printf("║  Min latency      : %-32.3f ns  (%.3f µs)║\n",
           (double)s->min_ns, s->min_ns / (double)NS_PER_US);
    printf("║  Max latency      : %-32.3f ns  (%.3f µs)║\n",
           (double)s->max_ns, s->max_ns / (double)NS_PER_US);
    printf("║  Mean latency     : %-32.3f ns  (%.3f µs)║\n",
           mean, mean / NS_PER_US);
    printf("║  Std deviation    : %-32.3f ns  (%.3f µs)║\n",
           stddev, stddev / NS_PER_US);
    printf("║  p50              : %-32lu ns  (%.3f µs)║\n",
           stats_percentile((stats_t*)s, 50.0),
           stats_percentile((stats_t*)s, 50.0) / (double)NS_PER_US);
    printf("║  p95              : %-32lu ns  (%.3f µs)║\n",
           stats_percentile((stats_t*)s, 95.0),
           stats_percentile((stats_t*)s, 95.0) / (double)NS_PER_US);
    printf("║  p99              : %-32lu ns  (%.3f µs)║\n",
           stats_percentile((stats_t*)s, 99.0),
           stats_percentile((stats_t*)s, 99.0) / (double)NS_PER_US);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

#endif /* TIMING_H */
