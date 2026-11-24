import struct
import pytest

from net_spoof_defense.codec import (
    ETH_P_ARP,
    ETH_P_IP,
    PcapReader,
    PcapWriter,
    WireDecodeError,
    decode_arp_frame,
    decode_dns_name,
    decode_ethernet_frame,
    encode_arp_frame,
    encode_dns_frame,
    encode_ethernet_header,
)
from net_spoof_defense.models import ArpPacketData, DnsPacketData


def test_arp_frame_roundtrip_and_gratuitous_flag():
    pkt = ArpPacketData(
        op=2,
        sender_ip="192.168.1.1",
        sender_mac="00:00:5e:00:01:01",
        target_ip="192.168.1.50",
        target_mac="aa:bb:cc:dd:ee:ff",
        timestamp=1700000000.5,
        is_gratuitous=False,
    )
    raw = encode_arp_frame(pkt)
    assert len(raw) == 42  # 14B Ethernet II + 28B RFC 826 ARP
    eth, decoded = decode_ethernet_frame(raw, timestamp=1700000000.5)
    assert eth.ethertype == ETH_P_ARP
    assert isinstance(decoded, ArpPacketData)
    assert decoded.op == 2
    assert decoded.sender_ip == "192.168.1.1"
    assert decoded.sender_mac == "00:00:5e:00:01:01"
    assert decoded.target_ip == "192.168.1.50"
    assert decoded.target_mac == "aa:bb:cc:dd:ee:ff"
    assert decoded.is_gratuitous is False

    grat_pkt = ArpPacketData(
        op=2,
        sender_ip="192.168.1.1",
        sender_mac="de:ad:be:ef:00:01",
        target_ip="255.255.255.255",
        target_mac="ff:ff:ff:ff:ff:ff",
        is_gratuitous=True,
    )
    grat_raw = encode_arp_frame(grat_pkt)
    eth_g, decoded_g = decode_ethernet_frame(grat_raw)
    assert eth_g.dst_mac == "ff:ff:ff:ff:ff:ff"
    assert isinstance(decoded_g, ArpPacketData)
    assert decoded_g.is_gratuitous is True


def test_dns_query_and_compressed_response_roundtrip():
    query = DnsPacketData(
        transaction_id=0xCAFE,
        query_name="auth.corp.local",
        is_response=False,
    )
    query_raw = encode_dns_frame(query)
    eth_q, decoded_q = decode_ethernet_frame(query_raw)
    assert eth_q.ethertype == ETH_P_IP
    assert isinstance(decoded_q, DnsPacketData)
    assert decoded_q.transaction_id == 0xCAFE
    assert decoded_q.query_name == "auth.corp.local"
    assert decoded_q.is_response is False
    assert decoded_q.response_ips == []

    resp = DnsPacketData(
        transaction_id=0xCAFE,
        query_name="auth.corp.local",
        response_ips=["10.20.30.40", "10.20.30.41"],
        ttl=120,
        is_response=True,
    )
    resp_raw = encode_dns_frame(resp)
    _, decoded_r = decode_ethernet_frame(resp_raw)
    assert isinstance(decoded_r, DnsPacketData)
    assert decoded_r.transaction_id == 0xCAFE
    assert decoded_r.query_name == "auth.corp.local"
    assert decoded_r.is_response is True
    assert decoded_r.response_ips == ["10.20.30.40", "10.20.30.41"]
    assert decoded_r.ttl == 120


def test_malformed_wire_frames_raise_wire_decode_error():
    with pytest.raises(WireDecodeError):
        decode_ethernet_frame(b"\x00\x01\x02")

    # Ethernet ARP header with truncated payload
    bad_arp = encode_ethernet_header("ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", ETH_P_ARP) + b"\x00" * 10
    with pytest.raises(WireDecodeError):
        decode_arp_frame(bad_arp)

    # Self-referential DNS compression pointer loop
    loop_msg = b"\x00" * 12 + struct.pack("!H", 0xC00C)
    with pytest.raises(WireDecodeError):
        decode_dns_name(loop_msg, 12)


def test_pcap_writer_and_reader_roundtrip(tmp_path):
    pcap_file = tmp_path / "capture.pcap"
    arp_frame = encode_arp_frame(
        ArpPacketData(
            op=2,
            sender_ip="10.0.0.1",
            sender_mac="00:00:5e:00:01:01",
            target_ip="10.0.0.2",
            target_mac="aa:bb:cc:dd:ee:02",
        )
    )
    dns_frame = encode_dns_frame(
        DnsPacketData(
            transaction_id=0x4242,
            query_name="gateway.internal",
            response_ips=["10.0.0.1"],
            ttl=300,
            is_response=True,
        )
    )

    with PcapWriter(str(pcap_file)) as writer:
        writer.write_frame(arp_frame, timestamp=1700000001.125)
        writer.write_frame(dns_frame, timestamp=1700000001.250)

    records = list(PcapReader(str(pcap_file)))
    assert len(records) == 2
    assert abs(records[0][0] - 1700000001.125) < 1e-5
    assert records[0][1] == arp_frame
    assert abs(records[1][0] - 1700000001.250) < 1e-5
    assert records[1][1] == dns_frame
