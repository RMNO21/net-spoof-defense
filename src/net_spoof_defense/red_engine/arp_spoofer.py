"""
Adversarial ARP Poisoning and Gratuitous Injection Engine.
"""

from typing import Optional, List
import time
from net_spoof_defense.models import ArpPacketData

class ArpSpoofer:
    """
    Adversarial ARP packet crafter and cache poisoning generator.
    Enables precise simulation of unidirectional and bidirectional MITM spoofing.
    """
    def __init__(self, attacker_mac: str, attacker_ip: str):
        self.attacker_mac = attacker_mac
        self.attacker_ip = attacker_ip

    def craft_poison_packet(
        self,
        victim_ip: str,
        victim_mac: str,
        spoofed_ip: str,
        is_gratuitous: bool = False
    ) -> ArpPacketData:
        """
        Crafts an ARP response poisoning the victim's ARP table by associating
        spoofed_ip (e.g., Gateway IP) with the attacker's MAC.
        """
        target_mac = "ff:ff:ff:ff:ff:ff" if is_gratuitous else victim_mac
        return ArpPacketData(
            op=2,  # ARP Reply
            sender_ip=spoofed_ip,
            sender_mac=self.attacker_mac,
            target_ip=victim_ip,
            target_mac=target_mac,
            timestamp=time.time(),
            is_gratuitous=is_gratuitous
        )

    def craft_mitm_pair(
        self,
        target_a_ip: str,
        target_a_mac: str,
        target_b_ip: str,
        target_b_mac: str
    ) -> List[ArpPacketData]:
        """
        Crafts a dual poison payload to place the attacker in the middle of target A and target B.
        """
        # Tell Target A that Attacker is Target B
        pkt_to_a = self.craft_poison_packet(
            victim_ip=target_a_ip,
            victim_mac=target_a_mac,
            spoofed_ip=target_b_ip
        )
        # Tell Target B that Attacker is Target A
        pkt_to_b = self.craft_poison_packet(
            victim_ip=target_b_ip,
            victim_mac=target_b_mac,
            spoofed_ip=target_a_ip
        )
        return [pkt_to_a, pkt_to_b]
