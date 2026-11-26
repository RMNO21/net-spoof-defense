"""
Stateful IEEE 802.11 Wireless Beacon & Deauthentication Anomaly Engine,
ESP32 UART Hardware Telemetry Hook, and Radiotap PCAP Stream Ingestion.
"""

from __future__ import annotations

import io
import os
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Protocol, Tuple, runtime_checkable

from net_spoof_defense.codec import WireDecodeError
from net_spoof_defense.config import WirelessDefenseConfig
from net_spoof_defense.models import (
    AttackType,
    MitigationStatus,
    SpoofAlert,
    WirelessFrameData,
)
from net_spoof_defense.wireless_codec import (
    RadiotapPcapReader,
    decode_radiotap_mgmt_frame,
    parse_esp32_telemetry_line,
)

ALLOWED_SERIAL_PREFIXES = ("/dev/ttyUSB", "/dev/ttyACM", "/dev/cu.usb", "loop://")


def validate_serial_port(port: str) -> None:
    """Restrict hardware serial ports to recognized USB-UART nodes or pyserial loop://."""
    if not port.startswith(ALLOWED_SERIAL_PREFIXES):
        raise ValueError(
            f"Refusing unsafe serial device {port!r}; expected one of {ALLOWED_SERIAL_PREFIXES}"
        )


@runtime_checkable
class WirelessFrameSource(Protocol):
    """Source yielding normalized `WirelessFrameData` management events."""

    def recv_wireless_frame(self) -> Optional[WirelessFrameData]:
        ...


class RadiotapPcapSource:
    """Streams DLT_IEEE802_11_RADIO (127) PCAP records into `WirelessFrameData`."""

    def __init__(self, pcap_path: str):
        self._reader = RadiotapPcapReader(pcap_path)
        self._iterator: Optional[Iterator[Tuple[float, bytes]]] = None
        self.decode_errors: int = 0

    def recv_wireless_frame(self) -> Optional[WirelessFrameData]:
        if self._iterator is None:
            self._iterator = iter(self._reader)
        while True:
            try:
                ts, raw = next(self._iterator)
            except StopIteration:
                return None
            try:
                return decode_radiotap_mgmt_frame(raw, timestamp=ts)
            except WireDecodeError:
                self.decode_errors += 1
                continue


class SimulatedEsp32Source:
    """In-memory / StringIO UART stream simulator for ESP32 passive-sniffer telemetry."""

    def __init__(self, lines: Iterable[str]):
        self._buf = io.StringIO("".join(line if line.endswith("\n") else f"{line}\n" for line in lines))
        self.decode_errors: int = 0

    def recv_wireless_frame(self) -> Optional[WirelessFrameData]:
        while True:
            line = self._buf.readline()
            if not line:
                return None
            stripped = line.strip()
            if not stripped:
                continue
            try:
                return parse_esp32_telemetry_line(stripped)
            except WireDecodeError:
                self.decode_errors += 1
                continue


class Esp32SerialSource:
    """
    Hardware UART ingestion hook for a passive ESP32 Wi-Fi sniffer node.
    Reads `ESP32_WMON` JSON lines at `baudrate` without altering host NIC state.
    """

    def __init__(
        self,
        port: str,
        baudrate: int = 115200,
        timeout_s: float = 0.05,
    ):
        validate_serial_port(port)
        self.port = port
        self.baudrate = baudrate
        self.timeout_s = timeout_s
        self._serial: Any = None
        self.decode_errors: int = 0

    def open(self) -> None:
        if not self.port.startswith("loop://") and not os.path.exists(self.port):
            raise FileNotFoundError(
                f"ESP32 UART device {self.port!r} not found. Connect ESP32 passive sniffer via USB."
            )
        import serial  # type: ignore

        self._serial = serial.serial_for_url(
            self.port,
            baudrate=self.baudrate,
            timeout=self.timeout_s,
        )

    def recv_wireless_frame(self) -> Optional[WirelessFrameData]:
        if self._serial is None:
            raise RuntimeError("Esp32SerialSource is not open")
        raw = self._serial.readline()
        if not raw:
            return None
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            return None
        try:
            return parse_esp32_telemetry_line(line)
        except WireDecodeError:
            self.decode_errors += 1
            return None

    def close(self) -> None:
        if self._serial is not None:
            self._serial.close()
            self._serial = None

    def __enter__(self) -> "Esp32SerialSource":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass
class _ApProfile:
    bssid: str
    channel: int
    rsn_enabled: bool
    baseline_rssi: float
    seen_count: int = 1


class BeaconMonitor:
    """
    Stateful IEEE 802.11 Rogue AP / Evil-Twin & Deauthentication Flood Detector.

    Computes normalized anomaly score S_80211 in [0, 1] across four signals:
    1. Trusted AP policy enforcement (BSSID mismatch, RSN downgrade, channel drift).
    2. Dynamic SSID-to-BSSID divergence against learned legitimate AP profiles.
    3. Abrupt RSSI step change (|delta_rssi| > threshold) paired with AP drift.
    4. Sliding 1.0 s window deauthentication / disassociation burst rate.
    """

    def __init__(
        self,
        config: Optional[WirelessDefenseConfig] = None,
        trusted_aps: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.config = config or WirelessDefenseConfig()
        self.trusted_aps: Dict[str, Dict[str, Any]] = trusted_aps or {}
        self.ap_profiles: Dict[str, _ApProfile] = {}
        self.deauth_history: Dict[str, List[float]] = {}

    def process_frame(self, frame: WirelessFrameData) -> Tuple[float, Optional[SpoofAlert]]:
        """Evaluate an 802.11 management frame and return `(score, Optional[SpoofAlert])`."""
        now = frame.timestamp
        bssid = frame.bssid.lower()
        src_mac = frame.src_mac.lower()

        if frame.frame_subtype in ("deauth", "disassoc"):
            return self._score_deauth(frame, bssid, src_mac, now)

        return self._score_beacon(frame, bssid, now)

    def _score_deauth(
        self,
        frame: WirelessFrameData,
        bssid: str,
        src_mac: str,
        now: float,
    ) -> Tuple[float, Optional[SpoofAlert]]:
        key = f"{bssid}:{src_mac}"
        history = [t for t in self.deauth_history.get(key, []) if now - t <= 1.0]
        history.append(now)
        self.deauth_history[key] = history

        rate = float(len(history))
        score = 0.0
        reasons: List[str] = []
        if rate > self.config.max_deauth_per_sec:
            excess = rate - self.config.max_deauth_per_sec
            score = min(1.0, 0.70 + 0.08 * excess)
            reasons.append(
                f"802.11 {frame.frame_subtype} flood ({rate:.0f} frames/s > {self.config.max_deauth_per_sec:.1f}) for BSSID {bssid}"
            )

        if score < self.config.anomaly_threshold:
            return score, None

        alert = SpoofAlert(
            alert_id=str(uuid.uuid4())[:8],
            attack_type=AttackType.DEAUTH_FLOOD,
            source_mac=src_mac,
            target_ip=frame.dst_mac.lower(),
            claimed_mac=bssid,
            legitimate_mac=bssid,
            anomaly_score=score,
            mitigation_status=MitigationStatus.ALERTED,
            timestamp=now,
            details={
                "reasons": reasons,
                "subtype": frame.frame_subtype,
                "reason_code": frame.reason_code,
                "rate_per_sec": rate,
                "channel": frame.channel,
            },
        )
        return score, alert

    def _score_beacon(
        self,
        frame: WirelessFrameData,
        bssid: str,
        now: float,
    ) -> Tuple[float, Optional[SpoofAlert]]:
        ssid = frame.ssid
        score = 0.0
        reasons: List[str] = []
        expected_bssid: Optional[str] = None

        if ssid and ssid in self.trusted_aps:
            policy = self.trusted_aps[ssid]
            expected_bssid = str(policy["bssid"]).lower()
            if bssid != expected_bssid:
                score += 0.85
                reasons.append(
                    f"Rogue BSSID {bssid} advertising protected SSID {ssid!r} (expected {expected_bssid})"
                )
            if policy.get("require_rsn", True) and not frame.rsn_enabled:
                score += 0.30
                reasons.append(f"WPA2/RSN security downgrade on SSID {ssid!r}")
            expected_ch = policy.get("channel")
            if expected_ch is not None and int(frame.channel) != int(expected_ch):
                score += 0.25
                reasons.append(
                    f"Channel drift on SSID {ssid!r}: ch {frame.channel} != expected {expected_ch}"
                )
        elif ssid and ssid in self.ap_profiles:
            prof = self.ap_profiles[ssid]
            expected_bssid = prof.bssid
            if bssid != prof.bssid:
                score += 0.75
                reasons.append(
                    f"SSID {ssid!r} BSSID conflict: learned {prof.bssid}, observed {bssid}"
                )
            if prof.rsn_enabled and not frame.rsn_enabled:
                score += 0.25
                reasons.append(f"RSN downgrade on learned SSID {ssid!r}")
            if frame.channel != prof.channel:
                score += 0.15
                reasons.append(f"Channel shift on SSID {ssid!r}: {prof.channel} -> {frame.channel}")
            rssi_delta = abs(frame.rssi_dbm - prof.baseline_rssi)
            if rssi_delta >= self.config.rssi_jump_threshold_dbm:
                score += 0.20
                reasons.append(
                    f"Abrupt RSSI step ({rssi_delta:.1f} dBm) on SSID {ssid!r}"
                )

        score = min(1.0, score)

        if score < self.config.anomaly_threshold:
            if ssid:
                if ssid not in self.ap_profiles:
                    self.ap_profiles[ssid] = _ApProfile(
                        bssid=bssid,
                        channel=frame.channel,
                        rsn_enabled=frame.rsn_enabled,
                        baseline_rssi=float(frame.rssi_dbm),
                    )
                else:
                    prof = self.ap_profiles[ssid]
                    prof.seen_count += 1
                    # Exponentially weighted moving average (alpha = 0.2)
                    prof.baseline_rssi = 0.8 * prof.baseline_rssi + 0.2 * float(frame.rssi_dbm)
            return score, None

        alert = SpoofAlert(
            alert_id=str(uuid.uuid4())[:8],
            attack_type=AttackType.BEACON_SPOOF,
            source_mac=frame.src_mac.lower(),
            target_ip=ssid or "<hidden>",
            claimed_mac=bssid,
            legitimate_mac=expected_bssid,
            anomaly_score=score,
            mitigation_status=MitigationStatus.ALERTED,
            timestamp=now,
            details={
                "reasons": reasons,
                "ssid": ssid,
                "channel": frame.channel,
                "rssi_dbm": frame.rssi_dbm,
                "rsn_enabled": frame.rsn_enabled,
            },
        )
        return score, alert
