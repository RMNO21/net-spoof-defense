#!/usr/bin/env python3
"""
Stage 3 Wireless Telemetry Ingestion & Anomaly Scoring Benchmark Harness.

Measures end-to-end 802.11 management frame decoding and stateful `BeaconMonitor`
evaluation across:
  1. Direct Radiotap + 802.11 binary frame decode + BeaconMonitor scoring.
  2. Offline DLT_IEEE802_11_RADIO (127) PCAP stream replay (mixed beacons + deauths).
  3. Simulated ESP32 UART JSON telemetry ingestion (`SimulatedEsp32Source`).
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
    BeaconMonitor,
    DnsValidator,
    MitigationEngine,
    PacketIngestor,
    RadiotapPcapSource,
    SimulatedEsp32Source,
)
from net_spoof_defense.config import ArpDefenseConfig, DnsDefenseConfig, WirelessDefenseConfig
from net_spoof_defense.models import WirelessFrameData
from net_spoof_defense.wireless_codec import (
    RadiotapPcapWriter,
    decode_radiotap_mgmt_frame,
    encode_esp32_telemetry_line,
    encode_radiotap_mgmt_frame,
)


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    return sorted_vals[min(len(sorted_vals) - 1, int(len(sorted_vals) * pct))]


def _report(label: str, count: int, total_bytes: int, wall_sec: float, latencies_us: list[float], alerts: int) -> None:
    ordered = sorted(latencies_us)
    mean_us = statistics.mean(ordered)
    stdev_us = statistics.stdev(ordered) if len(ordered) > 1 else 0.0
    p50_us = _percentile(ordered, 0.50)
    p99_us = _percentile(ordered, 0.99)
    fps = count / wall_sec if wall_sec > 0 else 0.0
    mbps = (total_bytes * 8.0) / (wall_sec * 1_000_000.0) if wall_sec > 0 else 0.0
    print("-" * 68)
    print(f" {label} ({count} frames)")
    print("-" * 68)
    print(f"  Alerts Triggered        : {alerts}")
    print(f"  Wall Time               : {wall_sec * 1000.0:.2f} ms")
    print(f"  Mean Latency            : {mean_us:.2f} us (stdev {stdev_us:.2f} us)")
    print(f"  Median (P50) Latency    : {p50_us:.2f} us")
    print(f"  99th Pct (P99) Latency  : {p99_us:.2f} us")
    print(f"  Throughput              : {fps:,.0f} frames/sec ({mbps:.2f} Mbps)")


def benchmark_radiotap_decode(iterations: int = 5000) -> None:
    rogue_beacon = WirelessFrameData(
        frame_subtype="beacon",
        ssid="CorpNet",
        bssid="de:ad:be:ef:00:99",
        src_mac="de:ad:be:ef:00:99",
        channel=6,
        rssi_dbm=-40,
        rsn_enabled=False,
        timestamp=1700000000.0,
    )
    raw = encode_radiotap_mgmt_frame(rogue_beacon)
    ingestor = PacketIngestor(
        arp_monitor=ArpMonitor(ArpDefenseConfig()),
        dns_validator=DnsValidator(DnsDefenseConfig()),
        mitigation_engine=MitigationEngine(interface="nsd-wmon"),
        beacon_monitor=BeaconMonitor(
            WirelessDefenseConfig(),
            trusted_aps={"CorpNet": {"bssid": "00:11:22:33:44:55", "channel": 6, "require_rsn": True}},
        ),
    )

    latencies_us: list[float] = []
    alerts = 0
    t_start = time.perf_counter()
    for i in range(iterations):
        t0 = time.perf_counter()
        decoded = decode_radiotap_mgmt_frame(raw, timestamp=1700000000.0 + i * 0.001)
        alert = ingestor.process_wireless_frame(decoded)
        t1 = time.perf_counter()
        latencies_us.append((t1 - t0) * 1_000_000.0)
        if alert is not None:
            alerts += 1
    wall = time.perf_counter() - t_start
    _report("1. Radiotap + 802.11 Decode & BeaconMonitor", iterations, iterations * len(raw), wall, latencies_us, alerts)


def benchmark_radiotap_pcap(iterations: int = 5000) -> None:
    legit = WirelessFrameData(
        frame_subtype="beacon",
        ssid="CorpNet",
        bssid="00:11:22:33:44:55",
        src_mac="00:11:22:33:44:55",
        channel=6,
        rssi_dbm=-61,
        rsn_enabled=True,
    )
    rogue = WirelessFrameData(
        frame_subtype="beacon",
        ssid="CorpNet",
        bssid="de:ad:be:ef:00:99",
        src_mac="de:ad:be:ef:00:99",
        channel=11,
        rssi_dbm=-39,
        rsn_enabled=False,
    )
    raw_legit = encode_radiotap_mgmt_frame(legit)
    raw_rogue = encode_radiotap_mgmt_frame(rogue)

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "radiotap_bench.pcap")
        total_bytes = 0
        with RadiotapPcapWriter(path) as writer:
            for i in range(iterations):
                frame = raw_legit if i % 2 == 0 else raw_rogue
                writer.write_frame(frame, timestamp=1700000000.0 + i * 0.0005)
                total_bytes += len(frame)

        ingestor = PacketIngestor(
            arp_monitor=ArpMonitor(ArpDefenseConfig()),
            dns_validator=DnsValidator(DnsDefenseConfig()),
            beacon_monitor=BeaconMonitor(
                WirelessDefenseConfig(),
                trusted_aps={"CorpNet": {"bssid": "00:11:22:33:44:55", "channel": 6, "require_rsn": True}},
            ),
        )
        t_start = time.perf_counter()
        stats = ingestor.ingest_wireless_from_source(RadiotapPcapSource(path))
        wall = time.perf_counter() - t_start
        _report(
            "2. Radiotap PCAP (DLT 127) Mixed Stream Ingestion",
            stats.wireless_frames,
            total_bytes,
            wall,
            stats.latencies_us,
            stats.alerts_triggered,
        )


def benchmark_esp32_uart_sim(iterations: int = 5000) -> None:
    legit_line = encode_esp32_telemetry_line(
        WirelessFrameData(
            frame_subtype="beacon",
            ssid="CorpNet",
            bssid="00:11:22:33:44:55",
            src_mac="00:11:22:33:44:55",
            channel=6,
            rssi_dbm=-62,
            rsn_enabled=True,
            timestamp=1700000000.0,
        )
    )
    rogue_line = encode_esp32_telemetry_line(
        WirelessFrameData(
            frame_subtype="beacon",
            ssid="CorpNet",
            bssid="de:ad:be:ef:00:99",
            src_mac="de:ad:be:ef:00:99",
            channel=11,
            rssi_dbm=-38,
            rsn_enabled=False,
            timestamp=1700000000.1,
        )
    )
    lines = [legit_line if i % 2 == 0 else rogue_line for i in range(iterations)]
    total_bytes = sum(len(l) + 1 for l in lines)
    source = SimulatedEsp32Source(lines)

    ingestor = PacketIngestor(
        arp_monitor=ArpMonitor(ArpDefenseConfig()),
        dns_validator=DnsValidator(DnsDefenseConfig()),
        beacon_monitor=BeaconMonitor(
            WirelessDefenseConfig(),
            trusted_aps={"CorpNet": {"bssid": "00:11:22:33:44:55", "channel": 6, "require_rsn": True}},
        ),
    )
    t_start = time.perf_counter()
    stats = ingestor.ingest_wireless_from_source(source)
    wall = time.perf_counter() - t_start
    _report(
        "3. ESP32 UART Telemetry Stream Ingestion (Simulated)",
        stats.wireless_frames,
        total_bytes,
        wall,
        stats.latencies_us,
        stats.alerts_triggered,
    )


if __name__ == "__main__":
    print("=" * 68)
    print(" NetSpoof-Defense Stage 3: Wireless Ingestion Benchmarks")
    print("=" * 68)
    benchmark_radiotap_decode()
    benchmark_radiotap_pcap()
    benchmark_esp32_uart_sim()
    print("=" * 68)
