#!/usr/bin/env python3
"""
Stage 2 Wire Ingestion Benchmark Harness.

Measures end-to-end raw Ethernet II frame decoding, stateful anomaly detection,
and corrective Layer-2 healing serialization across:
  1. Direct in-memory raw Ethernet wire frames (ARP + DNS).
  2. Kernel-mediated VirtualWirePair (AF_UNIX / SOCK_DGRAM) IPC transport.
  3. Offline libpcap stream replay.
"""

from __future__ import annotations

import os
import statistics
import sys
import tempfile
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from net_spoof_defense.blue_engine import (
    ArpMonitor,
    DnsValidator,
    MitigationEngine,
    PacketIngestor,
    PcapFrameSource,
)
from net_spoof_defense.codec import PcapWriter, encode_arp_frame, encode_dns_frame
from net_spoof_defense.config import ArpDefenseConfig, DnsDefenseConfig
from net_spoof_defense.models import ArpPacketData, DnsPacketData
from net_spoof_defense.virtual_net import VirtualWirePair


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * pct))
    return sorted_vals[idx]


def _print_report(label: str, count: int, total_bytes: int, wall_sec: float, latencies_us: list[float], alerts: int) -> None:
    ordered = sorted(latencies_us)
    mean_us = statistics.mean(ordered)
    stdev_us = statistics.stdev(ordered) if len(ordered) > 1 else 0.0
    p50_us = _percentile(ordered, 0.50)
    p99_us = _percentile(ordered, 0.99)
    pps = count / wall_sec if wall_sec > 0 else 0.0
    mbps = (total_bytes * 8.0) / (wall_sec * 1_000_000.0) if wall_sec > 0 else 0.0

    print("-" * 64)
    print(f" {label} ({count} frames)")
    print("-" * 64)
    print(f"  Alerts Triggered        : {alerts}")
    print(f"  Wall Time               : {wall_sec * 1000.0:.2f} ms")
    print(f"  Mean Latency            : {mean_us:.2f} us (stdev {stdev_us:.2f} us)")
    print(f"  Median (P50) Latency    : {p50_us:.2f} us")
    print(f"  99th Pct (P99) Latency  : {p99_us:.2f} us")
    print(f"  Throughput              : {pps:,.0f} frames/sec ({mbps:.2f} Mbps)")


def benchmark_in_memory_wire_decode(iterations: int = 5000) -> None:
    arp_frame = encode_arp_frame(
        ArpPacketData(
            op=2,
            sender_ip="192.168.1.1",
            sender_mac="de:ad:be:ef:00:01",
            target_ip="192.168.1.50",
            target_mac="aa:bb:cc:dd:ee:ff",
        )
    )
    ingestor = PacketIngestor(
        arp_monitor=ArpMonitor(ArpDefenseConfig(), trusted_gateways={"192.168.1.1": "00:00:5e:00:01:01"}),
        dns_validator=DnsValidator(DnsDefenseConfig()),
        mitigation_engine=MitigationEngine(interface="nsd-mem"),
    )

    latencies_us: list[float] = []
    alerts = 0
    t_start = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        alert = ingestor.process_raw_frame(arp_frame)
        t1 = time.perf_counter()
        latencies_us.append((t1 - t0) * 1_000_000.0)
        if alert is not None:
            alerts += 1
    wall = time.perf_counter() - t_start
    _print_report("1. In-Memory Raw Ethernet Decode + ARP State + Heal", iterations, iterations * len(arp_frame), wall, latencies_us, alerts)


def benchmark_virtual_wire_ipc(iterations: int = 2000) -> None:
    arp_frame = encode_arp_frame(
        ArpPacketData(
            op=2,
            sender_ip="192.168.1.1",
            sender_mac="de:ad:be:ef:00:02",
            target_ip="192.168.1.50",
            target_mac="aa:bb:cc:dd:ee:ff",
        )
    )
    with VirtualWirePair() as wire:
        ingestor = PacketIngestor(
            arp_monitor=ArpMonitor(ArpDefenseConfig(), trusted_gateways={"192.168.1.1": "00:00:5e:00:01:01"}),
            dns_validator=DnsValidator(DnsDefenseConfig()),
            mitigation_engine=MitigationEngine(interface="nsd-wire-blue"),
            sink=wire.blue_end,
            healing_broadcast_count=1,
        )

        latencies_us: list[float] = []
        alerts = 0
        t_start = time.perf_counter()
        for _ in range(iterations):
            t0 = time.perf_counter()
            wire.red_end.send_frame(arp_frame)
            raw = wire.blue_end.recv_frame(timeout=0.05)
            assert raw is not None
            alert = ingestor.process_raw_frame(raw)
            heal_raw = wire.red_end.recv_frame(timeout=0.05)
            assert heal_raw is not None
            t1 = time.perf_counter()
            latencies_us.append((t1 - t0) * 1_000_000.0)
            if alert is not None:
                alerts += 1
        wall = time.perf_counter() - t_start
        _print_report("2. VirtualWirePair Full-Duplex Kernel IPC Round-Trip", iterations, iterations * len(arp_frame), wall, latencies_us, alerts)


def benchmark_pcap_stream(iterations: int = 5000) -> None:
    arp_frame = encode_arp_frame(
        ArpPacketData(
            op=2,
            sender_ip="192.168.1.1",
            sender_mac="de:ad:be:ef:00:03",
            target_ip="192.168.1.50",
            target_mac="aa:bb:cc:dd:ee:ff",
        )
    )
    dns_q = encode_dns_frame(DnsPacketData(transaction_id=0x1001, query_name="bench.internal", is_response=False))
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = os.path.join(tmpdir, "bench.pcap")
        total_bytes = 0
        with PcapWriter(pcap_path) as writer:
            for i in range(iterations):
                frame = arp_frame if i % 2 == 0 else dns_q
                writer.write_frame(frame, timestamp=1700000000.0 + i * 0.0001)
                total_bytes += len(frame)

        ingestor = PacketIngestor(
            arp_monitor=ArpMonitor(ArpDefenseConfig(), trusted_gateways={"192.168.1.1": "00:00:5e:00:01:01"}),
            dns_validator=DnsValidator(DnsDefenseConfig()),
            mitigation_engine=MitigationEngine(interface="nsd-pcap"),
        )
        t_start = time.perf_counter()
        stats = ingestor.ingest_from_source(PcapFrameSource(pcap_path), poll_timeout=0.0)
        wall = time.perf_counter() - t_start
        _print_report("3. Offline PCAP Stream Ingestion (Mixed ARP + DNS)", stats.frames_received, stats.bytes_received, wall, stats.latencies_us, stats.alerts_triggered)


if __name__ == "__main__":
    print("=" * 64)
    print(" NetSpoof-Defense Stage 2: Wire Ingestion Empirical Benchmarks")
    print("=" * 64)
    benchmark_in_memory_wire_decode()
    benchmark_virtual_wire_ipc()
    benchmark_pcap_stream()
    print("=" * 64)
