from net_spoof_defense.red_engine import ArpSpoofer, DnsSpoofer, BeaconSpoofer

def test_arp_spoofer_crafting():
    spoofer = ArpSpoofer(attacker_mac="00:11:22:33:44:55", attacker_ip="192.168.1.100")
    pkt = spoofer.craft_poison_packet(
        victim_ip="192.168.1.50",
        victim_mac="aa:bb:cc:dd:ee:ff",
        spoofed_ip="192.168.1.1"
    )
    assert pkt.sender_ip == "192.168.1.1"
    assert pkt.sender_mac == "00:11:22:33:44:55"
    assert pkt.target_ip == "192.168.1.50"
    assert pkt.op == 2

def test_dns_spoofer_crafting():
    spoofer = DnsSpoofer(malicious_ip="10.0.0.66")
    resp = spoofer.craft_spoofed_response(transaction_id=0x1234, query_domain="bank.internal")
    assert resp.transaction_id == 0x1234
    assert resp.response_ips == ["10.0.0.66"]
    assert resp.is_response is True

def test_beacon_spoofer():
    b_spoofer = BeaconSpoofer(attacker_mac="12:34:56:78:90:ab")
    beacon = b_spoofer.craft_evil_twin_beacon(target_ssid="Corporate-WLAN", legitimate_bssid="00:14:22:01:23:45")
    assert beacon["ssid"] == "Corporate-WLAN"
    assert beacon["bssid"] == "12:34:56:78:90:ab"
