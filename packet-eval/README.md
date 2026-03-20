# Packet Processing Evaluation Lab
## DPDK vs AF_XDP vs Linux Kernel Stack — Container Latency Analysis

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Docker Bridge Network  172.20.0.0/24                           │
│  (Cilium-tuned sysctls; NetworkPolicy in cilium-config/)        │
│                                                                  │
│  ┌─────────────┐      probe pkts      ┌─────────────────┐      │
│  │  dpdk-tx    │ ──────────────────►  │  af-xdp-rx      │      │
│  │  .0.5       │  raw UDP + TSC stamp │  .0.3           │      │
│  │  DPDK path  │                      │  PACKET_MMAP    │      │
│  └─────────────┘                      └─────────────────┘      │
│                                                                  │
│  ┌─────────────┐      probe pkts      ┌─────────────────┐      │
│  │  af-xdp-tx  │ ──────────────────►  │  dpdk-rx        │      │
│  │  .0.6       │  raw Ethernet frame  │  .0.2           │      │
│  │  XDP path   │                      │  busy-poll spin │      │
│  └─────────────┘                      └─────────────────┘      │
│                                                                  │
│  ┌─────────────┐      probe pkts      ┌─────────────────┐      │
│  │  kernel-tx  │ ──────────────────►  │  kernel-rx      │      │
│  │  .0.7       │  standard UDP socket │  .0.4           │      │
│  │  full stack │                      │  full stack     │      │
│  └─────────────┘                      └─────────────────┘      │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  comparator sidecar — aggregates logs, prints stats     │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# 1. Clone / enter project directory
cd packet-eval/

# 2. Build and start all containers
docker-compose up --build

# 3. Watch live verbose output per stack
docker logs -f packet-eval-dpdk-rx
docker logs -f packet-eval-af-xdp-rx
docker logs -f packet-eval-kernel-rx

# 4. Run comparison analysis manually
docker logs packet-eval-dpdk-rx    2>&1 | python3 comparator.py --stdin DPDK
docker logs packet-eval-af-xdp-rx  2>&1 | python3 comparator.py --stdin AF_XDP
docker logs packet-eval-kernel-rx  2>&1 | python3 comparator.py --stdin KERNEL

# 5. Tear down
docker-compose down
```

---

## Verbose Packet Log Format

Every container prints one line per received packet:

```
[DPDK-RX]  SEQ    SEND_NS               RECV_NS               LAT_NS            LAT_US        LAT_MS          SEND_TSC
[DPDK-RX]  0      1718000000123456789   1718000000123512345   55556             55.556         0.000056        4521309876543
[DPDK-RX]  1      1718000000123976543   1718000000124031001   54458             54.458         0.000054        4521319876211
```

| Column      | Description                                          |
|-------------|------------------------------------------------------|
| `SEQ`       | Packet sequence number (0-indexed)                   |
| `SEND_NS`   | `CLOCK_REALTIME` nanoseconds at send site            |
| `RECV_NS`   | `CLOCK_REALTIME` nanoseconds at receive site         |
| `LAT_NS`    | One-way latency: `RECV_NS - SEND_NS` (nanoseconds)  |
| `LAT_US`    | Same in microseconds                                 |
| `LAT_MS`    | Same in milliseconds                                 |
| `SEND_TSC`  | CPU timestamp counter at send (DPDK/AF_XDP only)     |

Every 100 packets a running statistics block is printed:
```
╔══════════════════════════════════════════════════════════════╗
║  DPDK PMD (simulated) — Running Statistics                   ║
╠══════════════════════════════════════════════════════════════╣
║  Packets measured :  100                                     ║
║  Min latency      :  8243.000 ns  (8.243 µs)                ║
║  Max latency      :  312445.000 ns  (312.445 µs)            ║
║  Mean latency     :  42318.000 ns  (42.318 µs)              ║
║  Std deviation    :  28119.000 ns  (28.119 µs)              ║
║  p50              :  33210 ns  (33.210 µs)                   ║
║  p95              :  98443 ns  (98.443 µs)                   ║
║  p99              :  201233 ns  (201.233 µs)                 ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Latency Expectations

| Stack       | Inside Docker (veth bridge) | Bare-metal (native NIC)     |
|-------------|-----------------------------|-----------------------------|
| **DPDK**    | 10 µs – 200 µs             | **100 ns – 2 µs**           |
| **AF_XDP**  | 5 µs – 200 µs              | **1 µs – 10 µs**            |
| **Kernel**  | 50 µs – 3,000 µs           | 50 µs – 500 µs              |

### Why containers degrade theoretical gains

1. **veth pair overhead** — all traffic crosses a software veth pair regardless
   of how fast the userspace PMD runs.  RTT floor ≈ 5–20 µs.

2. **No IOMMU/hugepages** — DPDK's true advantage comes from DMA-mapped
   hugepages eliminating copies.  Not available without `--privileged` +
   `/dev/vfio`.

3. **No XDP native mode** — AF_XDP native mode requires the NIC driver to
   expose XDP hooks at the DMA ring level.  Inside a container with a veth
   interface, only `XDP_FLAGS_SKB_MODE` (generic XDP) is available, losing
   the key latency advantage.

4. **Scheduler interference** — Even with `SCHED_FIFO`, the container runtime
   and host OS schedule other workloads on the same CPUs unless NUMA+isolcpu
   are configured on the host.

---

## Cilium Integration

The `cilium-config/network-policy.yaml` defines:

- **CiliumNetworkPolicy** — identity-based L3/L4 policy allowing UDP 9999
  between the three probe pods, enforced via eBPF at the veth tc hook.
- **Cilium ConfigMap** — tuning parameters:
  - `xdp-acceleration: generic` — enables XDP offload on virtual interfaces
  - `enable-bpf-masquerade` — replaces iptables MASQUERADE with BPF
  - `routing-mode: native` — skips VXLAN encapsulation overhead

To deploy on Kubernetes with Cilium:
```bash
kubectl apply -f cilium-config/network-policy.yaml
kubectl apply -f k8s/  # (extend with Deployment manifests as needed)
```

---

## File Structure

```
packet-eval/
├── docker-compose.yml          ← Main orchestration
├── comparator.py               ← Cross-stack latency analysis
├── README.md
├── shared/
│   └── timing.h                ← Shared probe_packet_t, stats_t, helpers
├── dpdk/
│   ├── dpdk_probe.c            ← DPDK PMD simulation (busy-poll, SCHED_FIFO)
│   └── Dockerfile
├── af_xdp/
│   ├── af_xdp_probe.c          ← AF_XDP sim (PACKET_MMAP zero-copy ring)
│   └── Dockerfile
├── kernel/
│   ├── kernel_probe.c          ← Traditional Linux UDP socket probe
│   └── Dockerfile
└── cilium-config/
    └── network-policy.yaml     ← Cilium eBPF policy + ConfigMap
```

---

## Tuning for More Realistic Results

### Host-level (run before `docker-compose up`):
```bash
# Increase NAPI budget globally
echo 1000 > /proc/sys/net/core/netdev_budget

# Enable busy-poll system-wide
echo 50 > /proc/sys/net/core/busy_poll
echo 50 > /proc/sys/net/core/busy_read

# Isolate CPU cores 0-5 from the scheduler (requires kernel boot param)
# Add to /etc/default/grub: GRUB_CMDLINE_LINUX="isolcpus=0-5 nohz_full=0-5"

# Hugepages for real DPDK (optional)
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### For real AF_XDP (requires privileged container + supported NIC):
```yaml
# In docker-compose.yml, add to af-xdp-rx:
privileged: true
devices:
  - /dev/vfio:/dev/vfio
volumes:
  - /sys/bus/pci:/sys/bus/pci
```
