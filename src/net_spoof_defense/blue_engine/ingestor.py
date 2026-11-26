"""
Raw socket and virtual-wire packet ingestion pipeline for the Blue Engine.

Connects Layer-2/Layer-7 wire frame sources (`RawSocketSource` on isolated veth
interfaces, `VirtualWireEndpoint` kernel IPC wires, or `PcapFrameSource` streams)
to `ArpMonitor`, `DnsValidator`, and `MitigationEngine`.
"""

from __future__ import annotations

import os
import select
import socket
import time
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Protocol, runtime_checkable

from net_spoof_defense.blue_engine.arp_monitor import ArpMonitor
from net_spoof_defense.blue_engine.dns_validator import DnsValidator
from net_spoof_defense.blue_engine.mitigation import MitigationEngine
from net_spoof_defense.blue_engine.wireless_monitor import BeaconMonitor, WirelessFrameSource
from net_spoof_defense.codec import (
    PcapReader,
    WireDecodeError,
    decode_ethernet_frame,
    encode_arp_frame,
)
from net_spoof_defense.models import ArpPacketData, DnsPacketData, SpoofAlert, WirelessFrameData
from net_spoof_defense.virtual_net import validate_isolated_interface

ETH_P_ALL = 0x0003


@runtime_checkable
class FrameSource(Protocol):
    """Source yielding raw Ethernet II frames."""

    def recv_frame(self, timeout: Optional[float] = 0.05) -> Optional[bytes]:
        ...


@runtime_checkable
class FrameSink(Protocol):
    """Sink transmitting corrective raw Ethernet II frames."""

    def send_frame(self, frame: bytes) -> int:
        ...


class RawSocketSource:
    """
    Linux `AF_PACKET` raw socket bound strictly to an isolated virtual interface.
    Rejects physical NICs and host-routed interfaces via `validate_isolated_interface`.
    """

    def __init__(self, interface: str, bufsize: int = 65535):
        validate_isolated_interface(interface)
        self.interface = interface
        self.bufsize = bufsize
        self._sock: Optional[socket.socket] = None

    def open(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError(
                f"CAP_NET_RAW / root privilege required to bind AF_PACKET on {self.interface!r}"
            )
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        sock.bind((self.interface, 0))
        sock.setblocking(False)
        self._sock = sock

    def recv_frame(self, timeout: Optional[float] = 0.05) -> Optional[bytes]:
        if self._sock is None:
            raise RuntimeError("RawSocketSource is not open")
        if timeout is not None:
            ready, _, _ = select.select([self._sock], [], [], timeout)
            if not ready:
                return None
        return self._sock.recv(self.bufsize)

    def send_frame(self, frame: bytes) -> int:
        if self._sock is None:
            raise RuntimeError("RawSocketSource is not open")
        return self._sock.send(frame)

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "RawSocketSource":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class PcapFrameSource:
    """Adapts a `PcapReader` stream into a `FrameSource` with captured timestamps."""

    def __init__(self, pcap_path: str):
        self._reader = PcapReader(pcap_path)
        self._iterator: Optional[Iterator[tuple[float, bytes]]] = None
        self.last_timestamp: Optional[float] = None

    def recv_frame(self, timeout: Optional[float] = 0.0) -> Optional[bytes]:
        if self._iterator is None:
            self._iterator = iter(self._reader)
        try:
            ts, frame = next(self._iterator)
            self.last_timestamp = ts
            return frame
        except StopIteration:
            return None


@dataclass
class IngestionStats:
    """Operational telemetry collected across a wire ingestion run."""

    frames_received: int = 0
    bytes_received: int = 0
    arp_frames: int = 0
    dns_queries: int = 0
    dns_responses: int = 0
    wireless_frames: int = 0
    beacon_frames: int = 0
    deauth_frames: int = 0
    ignored_frames: int = 0
    decode_errors: int = 0
    alerts_triggered: int = 0
    healing_frames_emitted: int = 0
    latencies_us: List[float] = field(default_factory=list)
    alerts: List[SpoofAlert] = field(default_factory=list)

    @property
    def avg_latency_us(self) -> float:
        return sum(self.latencies_us) / len(self.latencies_us) if self.latencies_us else 0.0

    @property
    def p99_latency_us(self) -> float:
        if not self.latencies_us:
            return 0.0
        ordered = sorted(self.latencies_us)
        idx = min(len(ordered) - 1, int(len(ordered) * 0.99))
        return ordered[idx]


class PacketIngestor:
    """
    Real-time wire ingestion and dispatch loop for NetSpoof-Defense Blue Engine.

    Decodes raw Ethernet II frames, feeds ARP and DNS state machines, triggers
    `MitigationEngine` healing on alerts, and optionally transmits serialized
    corrective ARP broadcast frames onto the attached `FrameSink`.
    """

    def __init__(
        self,
        arp_monitor: ArpMonitor,
        dns_validator: DnsValidator,
        mitigation_engine: Optional[MitigationEngine] = None,
        sink: Optional[FrameSink] = None,
        healing_broadcast_count: int = 1,
        beacon_monitor: Optional[BeaconMonitor] = None,
    ):
        self.arp_monitor = arp_monitor
        self.dns_validator = dns_validator
        self.mitigation_engine = mitigation_engine or MitigationEngine()
        self.sink = sink
        self.healing_broadcast_count = healing_broadcast_count
        self.beacon_monitor = beacon_monitor or BeaconMonitor()

    def process_raw_frame(
        self,
        frame: bytes,
        timestamp: Optional[float] = None,
        stats: Optional[IngestionStats] = None,
    ) -> Optional[SpoofAlert]:
        """Decode and evaluate a single raw Ethernet II frame."""
        t0 = time.perf_counter()
        if stats is not None:
            stats.frames_received += 1
            stats.bytes_received += len(frame)

        try:
            _, pkt = decode_ethernet_frame(frame, timestamp=timestamp)
        except WireDecodeError:
            if stats is not None:
                stats.decode_errors += 1
            return None

        alert: Optional[SpoofAlert] = None
        if isinstance(pkt, ArpPacketData):
            if stats is not None:
                stats.arp_frames += 1
            _, alert = self.arp_monitor.process_packet(pkt)
            if alert is not None:
                corrective = self.mitigation_engine.execute_arp_healing(
                    alert, broadcast_count=self.healing_broadcast_count
                )
                if self.sink is not None:
                    for heal_pkt in corrective:
                        self.sink.send_frame(encode_arp_frame(heal_pkt))
                        if stats is not None:
                            stats.healing_frames_emitted += 1
        elif isinstance(pkt, DnsPacketData):
            if pkt.is_response:
                if stats is not None:
                    stats.dns_responses += 1
                _, alert = self.dns_validator.validate_response(pkt)
                if alert is not None:
                    self.mitigation_engine.mitigation_log.append(alert)
            else:
                if stats is not None:
                    stats.dns_queries += 1
                self.dns_validator.register_query(
                    pkt.transaction_id, pkt.query_name, timestamp=pkt.timestamp
                )
        else:
            if stats is not None:
                stats.ignored_frames += 1

        elapsed_us = (time.perf_counter() - t0) * 1_000_000.0
        if stats is not None:
            stats.latencies_us.append(elapsed_us)
            if alert is not None:
                stats.alerts_triggered += 1
                stats.alerts.append(alert)

        return alert

    def process_wireless_frame(
        self,
        frame: WirelessFrameData,
        stats: Optional[IngestionStats] = None,
    ) -> Optional[SpoofAlert]:
        """Evaluate a normalized IEEE 802.11 management frame through `BeaconMonitor`."""
        t0 = time.perf_counter()
        if stats is not None:
            stats.frames_received += 1
            stats.wireless_frames += 1
            if frame.frame_subtype in ("beacon", "probe_resp"):
                stats.beacon_frames += 1
            elif frame.frame_subtype in ("deauth", "disassoc"):
                stats.deauth_frames += 1

        _, alert = self.beacon_monitor.process_frame(frame)
        if alert is not None:
            self.mitigation_engine.mitigation_log.append(alert)

        elapsed_us = (time.perf_counter() - t0) * 1_000_000.0
        if stats is not None:
            stats.latencies_us.append(elapsed_us)
            if alert is not None:
                stats.alerts_triggered += 1
                stats.alerts.append(alert)

        return alert

    def ingest_wireless_from_source(
        self,
        source: WirelessFrameSource,
        max_frames: Optional[int] = None,
    ) -> IngestionStats:
        """Consume 802.11 management telemetry from a Radiotap PCAP or ESP32 UART source."""
        stats = IngestionStats()
        while max_frames is None or stats.frames_received < max_frames:
            frame = source.recv_wireless_frame()
            if frame is None:
                break
            self.process_wireless_frame(frame, stats=stats)
        stats.decode_errors = getattr(source, "decode_errors", 0)
        return stats

    def ingest_from_source(
        self,
        source: FrameSource,
        max_frames: Optional[int] = None,
        poll_timeout: Optional[float] = 0.01,
    ) -> IngestionStats:
        """Consume frames from `source` until exhausted or `max_frames` reached."""
        stats = IngestionStats()
        while max_frames is None or stats.frames_received < max_frames:
            frame = source.recv_frame(timeout=poll_timeout)
            if frame is None:
                break
            ts = getattr(source, "last_timestamp", None)
            self.process_raw_frame(frame, timestamp=ts, stats=stats)
        return stats
