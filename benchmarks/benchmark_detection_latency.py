#!/usr/bin/env python3
"""
Benchmark suite: Evaluates Time-to-Detect (TTD) and State Machine Latency.
"""

import time
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from net_spoof_defense.config import ArpDefenseConfig
from net_spoof_defense.blue_engine import ArpMonitor, MitigationEngine
from net_spoof_defense.models import ArpPacketData

def run_benchmarks(iterations: int = 5000):
    cfg = ArpDefenseConfig()
    gateways = {"192.168.1.1": "00:00:5e:00:01:01"}
    monitor = ArpMonitor(config=cfg, trusted_gateways=gateways)
    mitigator = MitigationEngine()

    poison_pkt = ArpPacketData(
        op=2,
        sender_ip="192.168.1.1",
        sender_mac="aa:bb:cc:dd:ee:01",
        target_ip="192.168.1.50",
        target_mac="00:11:22:33:44:55"
    )

    latencies = []
    detection_count = 0

    start_total = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        score, alert = monitor.process_packet(poison_pkt)
        if alert:
            detection_count += 1
            mitigator.execute_arp_healing(alert, broadcast_count=1)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1_000_000)  # Microseconds

    total_time = time.perf_counter() - start_total
    avg_latency_us = sum(latencies) / len(latencies)
    p99_latency_us = sorted(latencies)[int(len(latencies) * 0.99)]

    print(f"============================================================")
    print(f" NetSpoof-Defense Benchmark Results ({iterations} iterations)")
    print(f"============================================================")
    print(f"• Total Processed Packets   : {iterations}")
    print(f"• Detection Accuracy        : {detection_count / iterations * 100:.1f}%")
    print(f"• Total Wall Time           : {total_time * 1000:.2f} ms")
    print(f"• Average TTD + Healing     : {avg_latency_us:.2f} µs")
    print(f"• 99th Percentile Latency   : {p99_latency_us:.2f} µs")
    print(f"• Throughput Capacity       : {iterations / total_time:.0f} packets/sec")
    print(f"============================================================")

if __name__ == "__main__":
    run_benchmarks()
