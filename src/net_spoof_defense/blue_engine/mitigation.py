"""
Active Mitigation and Cache Auto-Healing Dispatcher.
"""

from typing import List, Optional
import time
from net_spoof_defense.models import SpoofAlert, ArpPacketData, MitigationStatus

class MitigationEngine:
    """
    Executes automated defense reactions:
    - Broadcasts corrective ARP packets to restore poisoned victim caches
    - Tracks active containment state
    """
    def __init__(self, interface: str = "eth0"):
        self.interface = interface
        self.mitigation_log: List[SpoofAlert] = []

    def execute_arp_healing(
        self,
        alert: SpoofAlert,
        broadcast_count: int = 3
    ) -> List[ArpPacketData]:
        """
        Generates corrective ARP packets to overwrite the attacker's poison
        in victim and gateway caches.
        """
        if not alert.legitimate_mac:
            alert.mitigation_status = MitigationStatus.ALERTED
            self.mitigation_log.append(alert)
            return []

        corrective_packets = []
        for _ in range(broadcast_count):
            pkt = ArpPacketData(
                op=2,  # Reply
                sender_ip=alert.target_ip,
                sender_mac=alert.legitimate_mac,
                target_ip="255.255.255.255",
                target_mac="ff:ff:ff:ff:ff:ff",
                timestamp=time.time(),
                is_gratuitous=True
            )
            corrective_packets.append(pkt)

        alert.mitigation_status = MitigationStatus.HEALED
        self.mitigation_log.append(alert)
        return corrective_packets
