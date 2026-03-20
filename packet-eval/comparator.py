#!/usr/bin/env python3
"""
comparator.py — Reads Docker logs from all three probe containers and
produces a side-by-side latency comparison table + ASCII histogram.

Usage (run from host after docker-compose up):
    python3 comparator.py

Or pipe per-container stdin:
    docker logs packet-eval-kernel-rx-1 2>&1 | python3 comparator.py --stdin kernel
"""

import re
import sys
import math
import subprocess
import argparse
from dataclasses import dataclass, field
from typing import List, Dict

NS  = 1
US  = 1_000
MS  = 1_000_000

@dataclass
class Sample:
    seq: int
    lat_ns: float

@dataclass
class StackStats:
    name: str
    samples: List[Sample] = field(default_factory=list)

    def add(self, seq: int, lat_ns: float):
        self.samples.append(Sample(seq, lat_ns))

    @property
    def n(self): return len(self.samples)

    @property
    def lats(self): return sorted(s.lat_ns for s in self.samples)

    def percentile(self, p):
        l = self.lats
        if not l: return 0
        idx = max(0, int(p / 100 * (len(l) - 1)))
        return l[idx]

    def mean(self):
        l = self.lats
        return sum(l) / len(l) if l else 0

    def stddev(self):
        l = self.lats
        if len(l) < 2: return 0
        m = self.mean()
        return math.sqrt(sum((x - m)**2 for x in l) / len(l))

    def summary(self, unit='ns'):
        div = {'ns': 1, 'us': US, 'ms': MS}[unit]
        return {
            'count': self.n,
            'min':   self.percentile(0)  / div,
            'p50':   self.percentile(50) / div,
            'p95':   self.percentile(95) / div,
            'p99':   self.percentile(99) / div,
            'max':   self.percentile(100)/ div,
            'mean':  self.mean()          / div,
            'std':   self.stddev()        / div,
        }


# ── Log line parsers ─────────────────────────────────────────────────────────
RX_PAT = re.compile(
    r'\[(DPDK|AFXDP|KERNEL)-RX\]\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)'
)

def parse_log_line(line: str, stats: Dict[str, StackStats]):
    m = RX_PAT.search(line)
    if not m: return
    tag, seq, send_ns, recv_ns, lat_ns, lat_us, lat_ms = m.groups()
    name_map = {'DPDK': 'DPDK', 'AFXDP': 'AF_XDP', 'KERNEL': 'KERNEL'}
    name = name_map.get(tag, tag)
    if name not in stats:
        stats[name] = StackStats(name)
    stats[name].add(int(seq), float(lat_ns))


def fetch_docker_logs():
    stats = {}
    services = {
        'DPDK':   'packet-eval-dpdk-rx-1',
        'AF_XDP': 'packet-eval-af-xdp-rx-1',
        'KERNEL': 'packet-eval-kernel-rx-1',
    }
    for name, container in services.items():
        try:
            result = subprocess.run(
                ['docker', 'logs', container],
                capture_output=True, text=True, timeout=10
            )
            for line in (result.stdout + result.stderr).splitlines():
                parse_log_line(line, stats)
            print(f"  Loaded logs for {name} ({stats.get(name, StackStats('')).n} samples)")
        except Exception as e:
            print(f"  Could not fetch {container}: {e}")
    return stats


# ── ASCII histogram ──────────────────────────────────────────────────────────
def histogram(ss: StackStats, bins=20, width=50):
    lats = ss.lats
    if not lats: return
    lo, hi = lats[0], lats[-1]
    if lo == hi: hi = lo + 1
    step = (hi - lo) / bins
    counts = [0]*bins
    for v in lats:
        idx = min(bins-1, int((v - lo) / step))
        counts[idx] += 1
    mx = max(counts) or 1
    print(f"\n  Latency distribution — {ss.name}  (ns)")
    for i, c in enumerate(counts):
        bar_lo = lo + i*step
        bar = '█' * int(c / mx * width)
        print(f"  {bar_lo:>9.0f}ns │{bar:<{width}}│ {c}")


# ── Comparison table ─────────────────────────────────────────────────────────
def print_comparison(stats: Dict[str, StackStats]):
    stacks = ['DPDK', 'AF_XDP', 'KERNEL']
    present = [s for s in stacks if s in stats and stats[s].n > 0]

    print("\n" + "═"*90)
    print("  PACKET PROCESSING APPROACH — LATENCY COMPARISON  (nanoseconds)")
    print("═"*90)
    hdr = f"  {'Metric':<20}" + "".join(f"  {s:<22}" for s in present)
    print(hdr)
    print("  " + "─"*87)

    fields = ['count','min','mean','p50','p95','p99','max','std']
    labels = {
        'count': 'Samples',
        'min':   'Min (ns)',
        'mean':  'Mean (ns)',
        'p50':   'p50 (ns)',
        'p95':   'p95 (ns)',
        'p99':   'p99 (ns)',
        'max':   'Max (ns)',
        'std':   'Std Dev (ns)',
    }
    summaries = {s: stats[s].summary('ns') for s in present}

    for f in fields:
        row = f"  {labels[f]:<20}"
        for s in present:
            v = summaries[s][f]
            row += f"  {v:<22.1f}"
        print(row)

    print("\n" + "─"*90)
    print("  LATENCY IN MICROSECONDS")
    print("─"*90)
    summaries_us = {s: stats[s].summary('us') for s in present}
    for f in ['min','mean','p50','p95','p99','max']:
        row = f"  {labels[f].replace('(ns)','(µs)'):<20}"
        for s in present:
            v = summaries_us[s][f]
            row += f"  {v:<22.3f}"
        print(row)

    print("\n" + "─"*90)
    print("  OVERHEAD ANALYSIS vs DPDK baseline")
    print("─"*90)
    if 'DPDK' in summaries:
        dpdk_mean = summaries['DPDK']['mean']
        for s in present:
            if s == 'DPDK': continue
            overhead = summaries[s]['mean'] - dpdk_mean
            pct      = (overhead / dpdk_mean * 100) if dpdk_mean else 0
            print(f"  {s:<10}  additional mean overhead: {overhead:>10.0f} ns  ({pct:+.1f}%)")

    print("═"*90)

    print("\n  Theoretical performance context:")
    print("  ┌─────────────┬──────────────────┬───────────────────────────────────────────────┐")
    print("  │ Stack       │ Ideal latency    │ Limiting factor in container                  │")
    print("  ├─────────────┼──────────────────┼───────────────────────────────────────────────┤")
    print("  │ DPDK        │ 100 ns – 2 µs    │ veth bridge RTT, no IOMMU/hugepages           │")
    print("  │ AF_XDP      │ 1 µs – 10 µs     │ XDP prog load blocked, PACKET_MMAP used       │")
    print("  │ Linux Kernel│ 50 µs – 3 ms     │ Scheduler jitter, syscall overhead, softirq   │")
    print("  └─────────────┴──────────────────┴───────────────────────────────────────────────┘")

    for s in present:
        histogram(stats[s])


# ── Entry point ──────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser()
    p.add_argument('--stdin', metavar='STACK',
                   help='Read from stdin for a single stack (DPDK|AF_XDP|KERNEL)')
    args = p.parse_args()

    stats = {}

    if args.stdin:
        print(f"Reading {args.stdin} from stdin…")
        for line in sys.stdin:
            parse_log_line(line, stats)
        # If tag not found in lines, register under provided name
        if not stats and args.stdin.upper() in ('DPDK','AF_XDP','KERNEL'):
            stats[args.stdin.upper()] = StackStats(args.stdin.upper())
    else:
        print("Fetching Docker container logs…")
        stats = fetch_docker_logs()

    if not any(v.n > 0 for v in stats.values()):
        print("No latency samples found. Run containers first or pass --stdin.")
        sys.exit(1)

    print_comparison(stats)


if __name__ == '__main__':
    main()
