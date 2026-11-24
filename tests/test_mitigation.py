from net_spoof_defense.blue_engine import MitigationEngine
from net_spoof_defense.models import SpoofAlert, AttackType, MitigationStatus

def test_mitigation_cache_healing():
    mitigator = MitigationEngine(interface="eth0")
    alert = SpoofAlert(
        alert_id="alert-001",
        attack_type=AttackType.ARP_POISON,
        source_mac="de:ad:be:ef:00:01",
        target_ip="192.168.1.1",
        claimed_mac="de:ad:be:ef:00:01",
        legitimate_mac="00:00:5e:00:01:01",
        anomaly_score=0.95,
        mitigation_status=MitigationStatus.DETECTED
    )
    healed_packets = mitigator.execute_arp_healing(alert, broadcast_count=2)
    assert len(healed_packets) == 2
    assert healed_packets[0].sender_ip == "192.168.1.1"
    assert healed_packets[0].sender_mac == "00:00:5e:00:01:01"
    assert healed_packets[0].target_mac == "ff:ff:ff:ff:ff:ff"
    assert alert.mitigation_status == MitigationStatus.HEALED
