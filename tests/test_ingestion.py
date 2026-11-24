import os
import pytest

from net_spoof_defense.blue_engine import (
    ArpMonitor,
    DnsValidator,
    MitigationEngine,
    PacketIngestor,
    PcapFrameSource,
    RawSocketSource,
)
from net_spoof_defense.codec import PcapWriter, decode_arp_frame, encode_arp_frame, encode_dns_frame
from net_spoof_defense.config import ArpDefenseConfig, DnsDefenseConfig
from net_spoof_defense.models import AttackType, DnsPacketData, MitigationStatus
from net_spoof_defense.red_engine import ArpSpoofer, DnsSpoofer
from net_spoof_defense.virtual_net import (
    SafetyViolationError,
    VethNetnsManager,
    VirtualWirePair,
    get_default_route_interfaces,
    validate_isolated_interface,
)


def test_host_interface_safety_guard(tmp_path):
    fake_route = tmp_path / "route"
    fake_route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "wlo1\t00000000\t010E1FAC\t0003\t0\t0\t600\t00000000\t0\t0\t0\n",
        encoding="utf-8",
    )
    routed = get_default_route_interfaces(str(fake_route))
    assert "wlo1" in routed

    # Default/physical interfaces must be rejected
    for forbidden in ("wlo1", "wlan0", "eth0", "ens33"):
        with pytest.raises(SafetyViolationError):
            validate_isolated_interface(forbidden, route_table_path=str(fake_route))

    # Physical sysfs device link on a veth-named interface must also be rejected
    fake_sysfs = tmp_path / "sys_net"
    (fake_sysfs / "nsd-fake-phys" / "device").mkdir(parents=True)
    with pytest.raises(SafetyViolationError):
        validate_isolated_interface(
            "nsd-fake-phys",
            route_table_path=str(fake_route),
            sysfs_net_root=str(fake_sysfs),
        )

    # Clean isolated virtual interface passes validation
    validate_isolated_interface(
        "nsd-veth-blue",
        route_table_path=str(fake_route),
        sysfs_net_root=str(fake_sysfs),
    )


def test_raw_socket_and_netns_require_privileges_when_unprivileged():
    if os.geteuid() == 0:
        pytest.skip("Privilege check applies only to non-root test execution")

    src = RawSocketSource("nsd-veth-blue")
    with pytest.raises(PermissionError):
        src.open()

    mgr = VethNetnsManager()
    with pytest.raises(PermissionError):
        mgr.create_topology()


def test_virtual_wire_end_to_end_arp_and_dns_ingestion_and_healing():
    gateways = {"192.168.1.1": "00:00:5e:00:01:01"}
    arp_monitor = ArpMonitor(config=ArpDefenseConfig(), trusted_gateways=gateways)
    dns_validator = DnsValidator(config=DnsDefenseConfig())
    mitigator = MitigationEngine(interface="nsd-wire-blue")

    red_arp = ArpSpoofer(attacker_mac="de:ad:be:ef:00:01", attacker_ip="192.168.1.99")
    red_dns = DnsSpoofer(malicious_ip="10.99.99.99")

    with VirtualWirePair() as wire:
        ingestor = PacketIngestor(
            arp_monitor=arp_monitor,
            dns_validator=dns_validator,
            mitigation_engine=mitigator,
            sink=wire.blue_end,
            healing_broadcast_count=2,
        )

        # 1. Benign DNS query followed by legitimate response
        tx_id = 0x1337
        dns_q = DnsPacketData(transaction_id=tx_id, query_name="api.internal", is_response=False)
        dns_legit = DnsPacketData(
            transaction_id=tx_id,
            query_name="api.internal",
            response_ips=["192.168.1.25"],
            ttl=300,
            is_response=True,
        )
        # 2. Forged fast-race DNS response
        dns_forged = red_dns.craft_spoofed_response(transaction_id=tx_id, query_domain="api.internal")
        # 3. Malicious ARP gateway poison frame
        arp_poison = red_arp.craft_poison_packet(
            victim_ip="192.168.1.50",
            victim_mac="aa:bb:cc:dd:ee:ff",
            spoofed_ip="192.168.1.1",
        )

        wire.red_end.send_frame(encode_dns_frame(dns_q))
        wire.red_end.send_frame(encode_dns_frame(dns_legit))
        wire.red_end.send_frame(encode_dns_frame(dns_forged))
        wire.red_end.send_frame(encode_arp_frame(arp_poison))

        stats = ingestor.ingest_from_source(wire.blue_end, max_frames=4, poll_timeout=0.1)

        assert stats.frames_received == 4
        assert stats.decode_errors == 0
        assert stats.dns_queries == 1
        assert stats.dns_responses == 2
        assert stats.arp_frames == 1
        assert stats.alerts_triggered == 2
        assert stats.healing_frames_emitted == 2

        attack_types = {a.attack_type for a in stats.alerts}
        assert attack_types == {AttackType.DNS_SPOOF, AttackType.ARP_POISON}

        # Verify corrective Layer-2 healing Ethernet frames arrived on red_end
        heal_frame_1 = wire.red_end.recv_frame(timeout=0.1)
        heal_frame_2 = wire.red_end.recv_frame(timeout=0.1)
        assert heal_frame_1 is not None and heal_frame_2 is not None
        decoded_heal = decode_arp_frame(heal_frame_1)
        assert decoded_heal.sender_ip == "192.168.1.1"
        assert decoded_heal.sender_mac == "00:00:5e:00:01:01"
        assert decoded_heal.is_gratuitous is True


def test_pcap_stream_ingestion(tmp_path):
    pcap_path = tmp_path / "attack_trace.pcap"
    red_arp = ArpSpoofer(attacker_mac="de:ad:be:ef:00:02", attacker_ip="10.10.0.99")
    poison_pkt = red_arp.craft_poison_packet(
        victim_ip="10.10.0.5",
        victim_mac="11:22:33:44:55:66",
        spoofed_ip="10.10.0.1",
    )

    with PcapWriter(str(pcap_path)) as writer:
        writer.write_frame(encode_arp_frame(poison_pkt), timestamp=1700001000.0)

    ingestor = PacketIngestor(
        arp_monitor=ArpMonitor(
            config=ArpDefenseConfig(),
            trusted_gateways={"10.10.0.1": "00:00:5e:00:01:01"},
        ),
        dns_validator=DnsValidator(config=DnsDefenseConfig()),
        mitigation_engine=MitigationEngine(interface="nsd-pcap"),
    )
    stats = ingestor.ingest_from_source(PcapFrameSource(str(pcap_path)), poll_timeout=0.0)
    assert stats.frames_received == 1
    assert stats.alerts_triggered == 1
    assert stats.alerts[0].mitigation_status == MitigationStatus.HEALED
