import pytest
from net_spoof_defense.config import ArpDefenseConfig, DnsDefenseConfig
from net_spoof_defense.blue_engine import ArpMonitor, DnsValidator
from net_spoof_defense.models import ArpPacketData, DnsPacketData, AttackType

def test_arp_monitor_gateway_spoofing():
    cfg = ArpDefenseConfig()
    gateways = {"192.168.1.1": "00:00:5e:00:01:01"}
    monitor = ArpMonitor(config=cfg, trusted_gateways=gateways)

    # Legitimate packet
    legit_pkt = ArpPacketData(
        op=2,
        sender_ip="192.168.1.1",
        sender_mac="00:00:5e:00:01:01",
        target_ip="192.168.1.20",
        target_mac="aa:bb:cc:dd:ee:ff"
    )
    score, alert = monitor.process_packet(legit_pkt)
    assert score < cfg.anomaly_threshold
    assert alert is None

    # Poison packet claiming gateway IP from malicious MAC
    poison_pkt = ArpPacketData(
        op=2,
        sender_ip="192.168.1.1",
        sender_mac="de:ad:be:ef:00:01",
        target_ip="192.168.1.20",
        target_mac="aa:bb:cc:dd:ee:ff"
    )
    score, alert = monitor.process_packet(poison_pkt)
    assert score >= cfg.anomaly_threshold
    assert alert is not None
    assert alert.attack_type == AttackType.ARP_POISON
    assert alert.claimed_mac == "de:ad:be:ef:00:01"
    assert alert.legitimate_mac == "00:00:5e:00:01:01"

def test_dns_validator_race_detection():
    cfg = DnsDefenseConfig()
    validator = DnsValidator(config=cfg)
    tx_id = 0xbeef

    # Register initial query
    validator.register_query(tx_id, "portal.local")

    # First legitimate response
    first_resp = DnsPacketData(
        transaction_id=tx_id,
        query_name="portal.local",
        response_ips=["192.168.1.200"],
        ttl=300,
        is_response=True
    )
    score1, alert1 = validator.validate_response(first_resp)
    assert score1 < 0.70
    assert alert1 is None

    # Second conflicting race response (e.g. from malicious injector)
    race_resp = DnsPacketData(
        transaction_id=tx_id,
        query_name="portal.local",
        response_ips=["10.99.99.99"],
        ttl=60,
        is_response=True
    )
    score2, alert2 = validator.validate_response(race_resp)
    assert score2 >= 0.70
    assert alert2 is not None
    assert alert2.attack_type == AttackType.DNS_SPOOF
