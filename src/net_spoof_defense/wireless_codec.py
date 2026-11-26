"""
Wire-format binary codec for IEEE 802.11 Radiotap (DLT_IEEE802_11_RADIO = 127)
management frames and ESP32 UART passive-scanner telemetry records.

Zero external runtime dependencies: implemented strictly using Python stdlib.
"""

from __future__ import annotations

import json
import struct
import time
from typing import Iterator, Optional, Tuple

from net_spoof_defense.codec import (
    PCAP_GLOBAL_HEADER_FMT,
    PCAP_MAGIC_LE,
    PCAP_PACKET_HEADER_FMT,
    PCAP_VERSION_MAJOR,
    PCAP_VERSION_MINOR,
    WireDecodeError,
    bytes_to_mac,
    mac_to_bytes,
)
from net_spoof_defense.models import WirelessFrameData

PCAP_LINKTYPE_RADIOTAP = 127

# IEEE 802.11 Management Frame Subtypes (Frame Control byte 0)
MGMT_SUBTYPE_PROBE_RESP = 0x50
MGMT_SUBTYPE_BEACON = 0x80
MGMT_SUBTYPE_DISASSOC = 0xA0
MGMT_SUBTYPE_DEAUTH = 0xC0

_SUBTYPE_TO_NAME = {
    MGMT_SUBTYPE_PROBE_RESP: "probe_resp",
    MGMT_SUBTYPE_BEACON: "beacon",
    MGMT_SUBTYPE_DISASSOC: "disassoc",
    MGMT_SUBTYPE_DEAUTH: "deauth",
}
_NAME_TO_SUBTYPE = {v: k for k, v in _SUBTYPE_TO_NAME.items()}

# Minimal 14-byte Radiotap header carrying Channel (bit 3) and dBm Antenna Signal (bit 5)
# Present flags: 0x00000028 (bit 3 = Channel 4 bytes, bit 5 = dBm signal 1 byte + 1 byte pad)
RADIOTAP_PRESENT_CH_RSSI = (1 << 3) | (1 << 5)
RADIOTAP_MIN_LEN = 8

# Information Element IDs (IEEE 802.11-2020 Section 9.4.2)
IE_SSID = 0
IE_DS_PARAM_CHANNEL = 3
IE_RSN = 48


def channel_to_freq_mhz(channel: int) -> int:
    """Convert an IEEE 802.11 2.4/5 GHz channel number to center frequency in MHz."""
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if channel == 14:
        return 2484
    if 36 <= channel <= 177:
        return 5000 + channel * 5
    return 2412


def freq_mhz_to_channel(freq_mhz: int) -> int:
    """Convert center frequency in MHz to IEEE 802.11 channel number."""
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if 5180 <= freq_mhz <= 5885:
        return (freq_mhz - 5000) // 5
    return 0


def encode_radiotap_mgmt_frame(frame_data: WirelessFrameData) -> bytes:
    """
    Encode a `WirelessFrameData` instance into a Radiotap + IEEE 802.11
    management frame byte string for deterministic PCAP/test fixture creation.
    """
    if frame_data.frame_subtype not in _NAME_TO_SUBTYPE:
        raise ValueError(f"Unsupported 802.11 subtype: {frame_data.frame_subtype!r}")

    fc_byte0 = _NAME_TO_SUBTYPE[frame_data.frame_subtype]
    freq_mhz = channel_to_freq_mhz(frame_data.channel)
    rssi_clamped = max(-128, min(127, int(frame_data.rssi_dbm)))

    # 8-byte radiotap header + 4-byte channel field + 1-byte signed RSSI + 1-byte pad = 14 bytes
    rt_len = 14
    radiotap = struct.pack(
        "<BBHIHHbx",
        0,  # it_version
        0,  # it_pad
        rt_len,
        RADIOTAP_PRESENT_CH_RSSI,
        freq_mhz,
        0x00A0,  # 2 GHz / CCK-OFDM channel flags
        rssi_clamped,
    )

    # 24-byte 802.11 MAC management header
    mac_hdr = struct.pack(
        "<BBH6s6s6sH",
        fc_byte0,
        0x00,  # flags
        0,     # duration
        mac_to_bytes(frame_data.dst_mac),
        mac_to_bytes(frame_data.src_mac),
        mac_to_bytes(frame_data.bssid),
        0x0000,  # sequence control
    )

    if frame_data.frame_subtype in ("deauth", "disassoc"):
        body = struct.pack("<H", frame_data.reason_code & 0xFFFF)
        return radiotap + mac_hdr + body

    # Beacon / Probe Response fixed parameters (12 bytes: 8-byte TS + 2-byte BI + 2-byte Cap)
    cap_info = 0x0411 if frame_data.rsn_enabled else 0x0401  # Privacy bit 0x0010
    fixed = struct.pack("<QHH", 0, frame_data.beacon_interval & 0xFFFF, cap_info)

    ssid_bytes = frame_data.ssid.encode("utf-8", errors="replace")[:32]
    ies = bytearray()
    ies.extend(struct.pack("BB", IE_SSID, len(ssid_bytes)))
    ies.extend(ssid_bytes)
    ies.extend(struct.pack("BBB", IE_DS_PARAM_CHANNEL, 1, frame_data.channel & 0xFF))
    if frame_data.rsn_enabled:
        # Minimal RSN IE (version 1, CCMP group/pairwise, PSK AKM)
        rsn_payload = struct.pack("<HIHIH4s", 1, 0x04AC0F00, 1, 0x04AC0F00, 1, b"\x00\x0f\xac\x02")
        ies.extend(struct.pack("BB", IE_RSN, len(rsn_payload)))
        ies.extend(rsn_payload)

    return radiotap + mac_hdr + fixed + bytes(ies)


def decode_radiotap_mgmt_frame(
    raw: bytes, timestamp: Optional[float] = None
) -> WirelessFrameData:
    """
    Decode a Radiotap + IEEE 802.11 management frame into `WirelessFrameData`.
    Raises `WireDecodeError` on truncated headers or unsupported frame types.
    """
    if len(raw) < RADIOTAP_MIN_LEN:
        raise WireDecodeError(f"Truncated Radiotap header: {len(raw)} bytes")

    it_version, _, it_len, present = struct.unpack("<BBHI", raw[:8])
    if it_version != 0 or it_len < RADIOTAP_MIN_LEN or it_len > len(raw):
        raise WireDecodeError(
            f"Invalid Radiotap header: version={it_version}, len={it_len}, total={len(raw)}"
        )

    channel = 0
    rssi_dbm = -60

    # Walk optional extended it_present bitmasks (bit 31)
    cursor = 8
    last_present = present
    while (last_present & 0x80000000) and cursor + 4 <= it_len:
        last_present = struct.unpack("<I", raw[cursor : cursor + 4])[0]
        cursor += 4

    # Fast-path field extraction for standard TSFT/Flags/Rate/Channel/FHSS/RSSI
    if present & (1 << 0):  # TSFT (8 bytes, 8-byte aligned)
        cursor = (cursor + 7) & ~7
        cursor += 8
    if present & (1 << 1):  # Flags (1 byte)
        cursor += 1
    if present & (1 << 2):  # Rate (1 byte)
        cursor += 1
    if present & (1 << 3):  # Channel (4 bytes, 2-byte aligned)
        cursor = (cursor + 1) & ~1
        if cursor + 4 <= it_len:
            freq_mhz, _ = struct.unpack("<HH", raw[cursor : cursor + 4])
            channel = freq_mhz_to_channel(freq_mhz)
        cursor += 4
    if present & (1 << 4):  # FHSS (2 bytes, 2-byte aligned)
        cursor = (cursor + 1) & ~1
        cursor += 2
    if present & (1 << 5):  # Antenna Signal dBm (1 signed byte)
        if cursor + 1 <= it_len:
            rssi_dbm = struct.unpack("<b", raw[cursor : cursor + 1])[0]
        cursor += 1

    mac_offset = it_len
    if len(raw) < mac_offset + 24:
        raise WireDecodeError("Truncated IEEE 802.11 MAC header")

    fc0 = raw[mac_offset]
    frame_type = (fc0 >> 2) & 0x03
    if frame_type != 0:
        raise WireDecodeError(f"Expected 802.11 management frame (type=0), got {frame_type}")

    subtype_key = fc0 & 0xF0
    if subtype_key not in _SUBTYPE_TO_NAME:
        raise WireDecodeError(f"Unsupported 802.11 management subtype 0x{subtype_key:02x}")

    subtype_name = _SUBTYPE_TO_NAME[subtype_key]
    dst_mac = bytes_to_mac(raw[mac_offset + 4 : mac_offset + 10])
    src_mac = bytes_to_mac(raw[mac_offset + 10 : mac_offset + 16])
    bssid = bytes_to_mac(raw[mac_offset + 16 : mac_offset + 22])
    ts = timestamp if timestamp is not None else time.time()

    body_offset = mac_offset + 24
    if subtype_name in ("deauth", "disassoc"):
        if len(raw) < body_offset + 2:
            raise WireDecodeError("Truncated deauth/disassoc reason code")
        reason_code = struct.unpack("<H", raw[body_offset : body_offset + 2])[0]
        return WirelessFrameData(
            frame_subtype=subtype_name,
            ssid="",
            bssid=bssid,
            src_mac=src_mac,
            dst_mac=dst_mac,
            channel=channel or 1,
            rssi_dbm=rssi_dbm,
            beacon_interval=0,
            rsn_enabled=False,
            reason_code=reason_code,
            timestamp=ts,
        )

    if len(raw) < body_offset + 12:
        raise WireDecodeError("Truncated 802.11 beacon/probe fixed parameters")

    _, beacon_interval, cap_info = struct.unpack("<QHH", raw[body_offset : body_offset + 12])
    rsn_enabled = bool(cap_info & 0x0010)
    ssid = ""
    ie_cursor = body_offset + 12

    while ie_cursor + 2 <= len(raw):
        ie_id = raw[ie_cursor]
        ie_len = raw[ie_cursor + 1]
        ie_cursor += 2
        if ie_cursor + ie_len > len(raw):
            break
        ie_val = raw[ie_cursor : ie_cursor + ie_len]
        if ie_id == IE_SSID:
            ssid = ie_val.decode("utf-8", errors="replace")
        elif ie_id == IE_DS_PARAM_CHANNEL and ie_len >= 1:
            channel = ie_val[0]
        elif ie_id == IE_RSN:
            rsn_enabled = True
        ie_cursor += ie_len

    return WirelessFrameData(
        frame_subtype=subtype_name,
        ssid=ssid,
        bssid=bssid,
        src_mac=src_mac,
        dst_mac=dst_mac,
        channel=channel or 1,
        rssi_dbm=rssi_dbm,
        beacon_interval=beacon_interval,
        rsn_enabled=rsn_enabled,
        reason_code=0,
        timestamp=ts,
    )


def encode_esp32_telemetry_line(frame_data: WirelessFrameData) -> str:
    """Serialize `WirelessFrameData` to an ESP32 UART JSON telemetry line."""
    payload = {
        "proto": "ESP32_WMON",
        "ts": round(frame_data.timestamp, 6),
        "subtype": frame_data.frame_subtype,
        "ssid": frame_data.ssid,
        "bssid": frame_data.bssid.lower(),
        "src": frame_data.src_mac.lower(),
        "dst": frame_data.dst_mac.lower(),
        "ch": int(frame_data.channel),
        "rssi": int(frame_data.rssi_dbm),
        "bi": int(frame_data.beacon_interval),
        "rsn": bool(frame_data.rsn_enabled),
        "reason": int(frame_data.reason_code),
    }
    return json.dumps(payload, separators=(",", ":"))


def parse_esp32_telemetry_line(line: str, fallback_ts: Optional[float] = None) -> WirelessFrameData:
    """
    Parse a UART JSON telemetry line emitted by the ESP32 passive scanner firmware.
    Raises `WireDecodeError` if the line is malformed or missing required fields.
    """
    try:
        obj = json.loads(line.strip())
    except json.JSONDecodeError as exc:
        raise WireDecodeError(f"Malformed ESP32 telemetry JSON: {exc}") from exc

    if not isinstance(obj, dict) or obj.get("proto") != "ESP32_WMON":
        raise WireDecodeError("Missing or invalid ESP32_WMON telemetry header")

    subtype = str(obj.get("subtype", "")).lower()
    if subtype not in _NAME_TO_SUBTYPE:
        raise WireDecodeError(f"Unsupported 802.11 subtype in ESP32 stream: {subtype!r}")

    try:
        bssid = str(obj["bssid"]).lower()
        src = str(obj.get("src", bssid)).lower()
        dst = str(obj.get("dst", "ff:ff:ff:ff:ff:ff")).lower()
        channel = int(obj["ch"])
        rssi = int(obj["rssi"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WireDecodeError(f"Missing required ESP32 telemetry field: {exc}") from exc

    ts = float(obj["ts"]) if "ts" in obj else (fallback_ts if fallback_ts is not None else time.time())
    return WirelessFrameData(
        frame_subtype=subtype,
        ssid=str(obj.get("ssid", "")),
        bssid=bssid,
        src_mac=src,
        dst_mac=dst,
        channel=channel,
        rssi_dbm=rssi,
        beacon_interval=int(obj.get("bi", 100)),
        rsn_enabled=bool(obj.get("rsn", True)),
        reason_code=int(obj.get("reason", 0)),
        timestamp=ts,
    )


class RadiotapPcapWriter:
    """Standard libpcap writer using linktype 127 (DLT_IEEE802_11_RADIO)."""

    def __init__(self, path: str, snaplen: int = 65535):
        self.path = path
        self.snaplen = snaplen
        self._fh = open(path, "wb")
        self._fh.write(
            struct.pack(
                PCAP_GLOBAL_HEADER_FMT,
                PCAP_MAGIC_LE,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,
                0,
                snaplen,
                PCAP_LINKTYPE_RADIOTAP,
            )
        )

    def write_frame(self, frame: bytes, timestamp: Optional[float] = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        cap_len = min(len(frame), self.snaplen)
        self._fh.write(struct.pack(PCAP_PACKET_HEADER_FMT, ts_sec, ts_usec, cap_len, len(frame)))
        self._fh.write(frame[:cap_len])

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    def __enter__(self) -> "RadiotapPcapWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class RadiotapPcapReader:
    """Standard libpcap reader enforcing linktype 127 (DLT_IEEE802_11_RADIO)."""

    def __init__(self, path: str):
        self.path = path

    def __iter__(self) -> Iterator[Tuple[float, bytes]]:
        with open(self.path, "rb") as fh:
            ghdr = fh.read(24)
            if len(ghdr) < 24:
                raise WireDecodeError("Truncated PCAP global header")
            magic = struct.unpack("<I", ghdr[:4])[0]
            if magic == PCAP_MAGIC_LE:
                endian = "<"
            elif magic == 0xD4C3B2A1:
                endian = ">"
            else:
                raise WireDecodeError(f"Unsupported PCAP magic: 0x{magic:08x}")

            _, _, _, _, _, _, network = struct.unpack(f"{endian}IHHIIII", ghdr)
            if network != PCAP_LINKTYPE_RADIOTAP:
                raise WireDecodeError(
                    f"Unsupported PCAP linktype {network}; expected Radiotap (127)"
                )

            pkt_hdr_size = struct.calcsize(PCAP_PACKET_HEADER_FMT)
            while True:
                phdr = fh.read(pkt_hdr_size)
                if not phdr:
                    break
                if len(phdr) < pkt_hdr_size:
                    raise WireDecodeError("Truncated PCAP packet header")
                ts_sec, ts_usec, incl_len, _ = struct.unpack(f"{endian}IIII", phdr)
                payload = fh.read(incl_len)
                if len(payload) < incl_len:
                    raise WireDecodeError("Truncated PCAP packet payload")
                yield ts_sec + (ts_usec / 1_000_000.0), payload
