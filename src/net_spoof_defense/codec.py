"""
Wire-format binary codec for IEEE 802.3 Ethernet, RFC 826 ARP, IPv4/UDP,
RFC 1035 DNS, and standard libpcap capture streams.

Zero external runtime dependencies: implemented strictly using the Python
standard library (`struct`, `socket`, `ipaddress`).
"""

from __future__ import annotations

import ipaddress
import struct
import time
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple, Union

from net_spoof_defense.models import ArpPacketData, DnsPacketData

ETH_HEADER_LEN = 14
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

ARP_HEADER_LEN = 28
ARP_HTYPE_ETHERNET = 1
ARP_PTYPE_IPV4 = 0x0800
ARP_HLEN_MAC = 6
ARP_PLEN_IPV4 = 4

IP_PROTO_UDP = 17
DNS_PORT = 53
DNS_HEADER_LEN = 12

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_ETHERNET = 1
PCAP_GLOBAL_HEADER_FMT = "<IHHIIII"
PCAP_PACKET_HEADER_FMT = "<IIII"


class WireDecodeError(ValueError):
    """Raised when a raw wire frame is truncated or violates protocol invariants."""


@dataclass(frozen=True)
class EthernetHeader:
    """Decoded IEEE 802.3 Ethernet II frame header."""

    dst_mac: str
    src_mac: str
    ethertype: int


def mac_to_bytes(mac: str) -> bytes:
    """Convert a colon-separated MAC string into 6 raw network-order bytes."""
    parts = mac.strip().split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return bytes(int(p, 16) for p in parts)


def bytes_to_mac(raw: bytes) -> str:
    """Convert 6 raw bytes into a lowercase colon-separated MAC string."""
    if len(raw) != 6:
        raise ValueError(f"Expected 6 MAC bytes, got {len(raw)}")
    return ":".join(f"{b:02x}" for b in raw)


def ipv4_to_bytes(ip: str) -> bytes:
    """Convert a dotted-quad IPv4 string into 4 network-order bytes."""
    return ipaddress.IPv4Address(ip).packed


def bytes_to_ipv4(raw: bytes) -> str:
    """Convert 4 raw bytes into a dotted-quad IPv4 string."""
    if len(raw) != 4:
        raise ValueError(f"Expected 4 IPv4 bytes, got {len(raw)}")
    return str(ipaddress.IPv4Address(raw))


def _ipv4_checksum(header: bytes) -> int:
    """Compute RFC 1071 one's-complement IPv4 header checksum."""
    if len(header) % 2 == 1:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def encode_ethernet_header(dst_mac: str, src_mac: str, ethertype: int) -> bytes:
    """Serialize a 14-byte Ethernet II header."""
    return mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack("!H", ethertype)


def decode_ethernet_header(frame: bytes) -> EthernetHeader:
    """Decode a 14-byte Ethernet II header."""
    if len(frame) < ETH_HEADER_LEN:
        raise WireDecodeError(
            f"Truncated Ethernet frame: {len(frame)} bytes < {ETH_HEADER_LEN}"
        )
    dst_raw, src_raw, ethertype = struct.unpack("!6s6sH", frame[:ETH_HEADER_LEN])
    return EthernetHeader(
        dst_mac=bytes_to_mac(dst_raw),
        src_mac=bytes_to_mac(src_raw),
        ethertype=ethertype,
    )


def encode_arp_frame(
    pkt: ArpPacketData,
    src_eth_mac: Optional[str] = None,
    dst_eth_mac: Optional[str] = None,
) -> bytes:
    """
    Serialize an ArpPacketData instance into an Ethernet II + RFC 826 ARP frame.
    Broadcasts gratuitous frames to ff:ff:ff:ff:ff:ff when dst_eth_mac is omitted.
    """
    eth_src = src_eth_mac or pkt.sender_mac
    if dst_eth_mac is not None:
        eth_dst = dst_eth_mac
    elif pkt.is_gratuitous or pkt.target_mac.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        eth_dst = "ff:ff:ff:ff:ff:ff"
    else:
        eth_dst = pkt.target_mac

    eth_hdr = encode_ethernet_header(eth_dst, eth_src, ETH_P_ARP)
    arp_payload = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HTYPE_ETHERNET,
        ARP_PTYPE_IPV4,
        ARP_HLEN_MAC,
        ARP_PLEN_IPV4,
        pkt.op,
        mac_to_bytes(pkt.sender_mac),
        ipv4_to_bytes(pkt.sender_ip),
        mac_to_bytes(pkt.target_mac),
        ipv4_to_bytes(pkt.target_ip),
    )
    return eth_hdr + arp_payload


def decode_arp_frame(frame: bytes, timestamp: Optional[float] = None) -> ArpPacketData:
    """Decode an Ethernet II + RFC 826 ARP frame into ArpPacketData."""
    eth = decode_ethernet_header(frame)
    if eth.ethertype != ETH_P_ARP:
        raise WireDecodeError(f"Expected EtherType 0x0806, got 0x{eth.ethertype:04x}")

    if len(frame) < ETH_HEADER_LEN + ARP_HEADER_LEN:
        raise WireDecodeError(
            f"Truncated ARP packet: {len(frame) - ETH_HEADER_LEN} bytes < {ARP_HEADER_LEN}"
        )

    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = struct.unpack(
        "!HHBBH6s4s6s4s",
        frame[ETH_HEADER_LEN : ETH_HEADER_LEN + ARP_HEADER_LEN],
    )
    if htype != ARP_HTYPE_ETHERNET or ptype != ARP_PTYPE_IPV4 or hlen != 6 or plen != 4:
        raise WireDecodeError(
            f"Unsupported ARP hardware/protocol tuple: htype={htype}, ptype=0x{ptype:04x}"
        )

    sender_ip = bytes_to_ipv4(spa)
    target_ip = bytes_to_ipv4(tpa)
    target_mac = bytes_to_mac(tha)
    is_gratuitous = (
        sender_ip == target_ip
        or target_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
        or eth.dst_mac == "ff:ff:ff:ff:ff:ff"
    )

    return ArpPacketData(
        op=op,
        sender_ip=sender_ip,
        sender_mac=bytes_to_mac(sha),
        target_ip=target_ip,
        target_mac=target_mac,
        timestamp=timestamp if timestamp is not None else time.time(),
        is_gratuitous=is_gratuitous,
    )


def encode_dns_name(domain: str) -> bytes:
    """Encode a domain name into RFC 1035 length-prefixed DNS labels."""
    clean = domain.strip(".")
    if not clean:
        return b"\x00"
    out = bytearray()
    for label in clean.split("."):
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"DNS label exceeds 63 bytes: {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def decode_dns_name(message: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode an RFC 1035 domain name starting at `offset`, resolving label
    compression pointers (0xC0) with loop protection.
    Returns (domain_name, next_offset_after_name_field).
    """
    labels = []
    jumped = False
    original_next = offset
    visited_offsets = set()
    pos = offset

    while pos < len(message):
        if pos in visited_offsets:
            raise WireDecodeError("DNS compression pointer cycle detected")
        visited_offsets.add(pos)

        length = message[pos]
        if length == 0:
            if not jumped:
                original_next = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(message):
                raise WireDecodeError("Truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[pos + 1]
            if not jumped:
                original_next = pos + 2
                jumped = True
            pos = pointer
            continue
        if length > 63:
            raise WireDecodeError(f"Invalid DNS label length {length}")
        end = pos + 1 + length
        if end > len(message):
            raise WireDecodeError("Truncated DNS label")
        labels.append(message[pos + 1 : end].decode("ascii", errors="replace"))
        pos = end
    else:
        raise WireDecodeError("Unterminated DNS QNAME")

    return ".".join(labels), original_next


def encode_dns_payload(pkt: DnsPacketData) -> bytes:
    """Serialize a DnsPacketData instance into an RFC 1035 DNS wire payload."""
    qname = encode_dns_name(pkt.query_name)
    flags = 0x8180 if pkt.is_response else 0x0100
    ancount = len(pkt.response_ips) if pkt.is_response else 0

    header = struct.pack(
        "!HHHHHH",
        pkt.transaction_id & 0xFFFF,
        flags,
        1,        # QDCOUNT
        ancount,  # ANCOUNT
        0,        # NSCOUNT
        0,        # ARCOUNT
    )
    question = qname + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN

    answers = bytearray()
    if pkt.is_response:
        for ip_str in pkt.response_ips:
            # Compression pointer 0xC00C points directly to QNAME at byte offset 12
            answers.extend(
                struct.pack(
                    "!HHHIH4s",
                    0xC00C,
                    1,  # TYPE A
                    1,  # CLASS IN
                    max(0, int(pkt.ttl)),
                    4,  # RDLENGTH
                    ipv4_to_bytes(ip_str),
                )
            )

    return header + question + bytes(answers)


def decode_dns_payload(message: bytes, timestamp: Optional[float] = None) -> DnsPacketData:
    """Decode an RFC 1035 DNS wire payload into DnsPacketData."""
    if len(message) < DNS_HEADER_LEN:
        raise WireDecodeError(f"Truncated DNS header: {len(message)} bytes < {DNS_HEADER_LEN}")

    tx_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", message[:DNS_HEADER_LEN])
    is_response = bool((flags >> 15) & 0x1)
    offset = DNS_HEADER_LEN

    query_name = ""
    for idx in range(qdcount):
        qname, offset = decode_dns_name(message, offset)
        if offset + 4 > len(message):
            raise WireDecodeError("Truncated DNS question section")
        offset += 4  # QTYPE + QCLASS
        if idx == 0:
            query_name = qname

    response_ips = []
    ttl_value = 300
    if is_response and ancount > 0:
        for _ in range(ancount):
            if offset >= len(message):
                break
            _, offset = decode_dns_name(message, offset)
            if offset + 10 > len(message):
                raise WireDecodeError("Truncated DNS resource record header")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", message[offset : offset + 10])
            offset += 10
            if offset + rdlength > len(message):
                raise WireDecodeError("Truncated DNS RDATA")
            rdata = message[offset : offset + rdlength]
            offset += rdlength
            if rtype == 1 and rclass == 1 and rdlength == 4:
                response_ips.append(bytes_to_ipv4(rdata))
                ttl_value = ttl

    return DnsPacketData(
        transaction_id=tx_id,
        query_name=query_name,
        response_ips=response_ips,
        ttl=ttl_value,
        is_response=is_response,
        timestamp=timestamp if timestamp is not None else time.time(),
    )


def encode_dns_frame(
    pkt: DnsPacketData,
    src_mac: str = "00:00:5e:00:01:01",
    dst_mac: str = "aa:bb:cc:dd:ee:ff",
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
) -> bytes:
    """Serialize a DnsPacketData packet wrapped in Ethernet II + IPv4 + UDP."""
    dns_payload = encode_dns_payload(pkt)
    s_ip = src_ip or ("8.8.8.8" if pkt.is_response else "192.168.1.50")
    d_ip = dst_ip or ("192.168.1.50" if pkt.is_response else "8.8.8.8")
    s_port = src_port if src_port is not None else (DNS_PORT if pkt.is_response else 53530)
    d_port = dst_port if dst_port is not None else (53530 if pkt.is_response else DNS_PORT)

    udp_len = 8 + len(dns_payload)
    udp_header = struct.pack("!HHHH", s_port, d_port, udp_len, 0)

    total_len = 20 + udp_len
    ip_wo_cksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,           # Version 4, IHL 5
        0,              # DSCP/ECN
        total_len,
        pkt.transaction_id & 0xFFFF,
        0x4000,         # Don't Fragment
        64,             # TTL
        IP_PROTO_UDP,
        0,
        ipv4_to_bytes(s_ip),
        ipv4_to_bytes(d_ip),
    )
    cksum = _ipv4_checksum(ip_wo_cksum)
    ip_header = ip_wo_cksum[:10] + struct.pack("!H", cksum) + ip_wo_cksum[12:]

    eth_header = encode_ethernet_header(dst_mac, src_mac, ETH_P_IP)
    return eth_header + ip_header + udp_header + dns_payload


def decode_ethernet_frame(
    frame: bytes,
    timestamp: Optional[float] = None,
) -> Tuple[EthernetHeader, Union[ArpPacketData, DnsPacketData, None]]:
    """
    Decode an Ethernet II frame into `(EthernetHeader, packet_data)`.
    Returns `(header, None)` for supported non-ARP/non-DNS traffic.
    """
    eth = decode_ethernet_header(frame)
    ts = timestamp if timestamp is not None else time.time()

    if eth.ethertype == ETH_P_ARP:
        return eth, decode_arp_frame(frame, timestamp=ts)

    if eth.ethertype != ETH_P_IP:
        return eth, None

    if len(frame) < ETH_HEADER_LEN + 20:
        raise WireDecodeError("Truncated IPv4 header")

    ver_ihl = frame[ETH_HEADER_LEN]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(frame) < ETH_HEADER_LEN + ihl:
        raise WireDecodeError(f"Invalid IPv4 header: version={version}, ihl={ihl}")

    proto = frame[ETH_HEADER_LEN + 9]
    if proto != IP_PROTO_UDP:
        return eth, None

    udp_offset = ETH_HEADER_LEN + ihl
    if len(frame) < udp_offset + 8:
        raise WireDecodeError("Truncated UDP header")

    src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", frame[udp_offset : udp_offset + 8])
    if src_port != DNS_PORT and dst_port != DNS_PORT:
        return eth, None

    dns_offset = udp_offset + 8
    dns_end = udp_offset + udp_len
    if dns_end > len(frame) or dns_end < dns_offset:
        raise WireDecodeError("UDP length exceeds captured frame bounds")

    return eth, decode_dns_payload(frame[dns_offset:dns_end], timestamp=ts)


class PcapWriter:
    """Minimal standard libpcap writer (Ethernet link-layer type 1)."""

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
                PCAP_LINKTYPE_ETHERNET,
            )
        )

    def write_frame(self, frame: bytes, timestamp: Optional[float] = None) -> None:
        ts = timestamp if timestamp is not None else time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        cap_len = min(len(frame), self.snaplen)
        self._fh.write(
            struct.pack(PCAP_PACKET_HEADER_FMT, ts_sec, ts_usec, cap_len, len(frame))
        )
        self._fh.write(frame[:cap_len])

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class PcapReader:
    """Standard libpcap reader yielding `(timestamp, raw_ethernet_frame)` tuples."""

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
            if network != PCAP_LINKTYPE_ETHERNET:
                raise WireDecodeError(f"Unsupported PCAP linktype {network}; expected Ethernet (1)")

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
