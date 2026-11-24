"""
Stateful Dynamic ARP Monitor and Anomaly Scoring Engine.
"""

from typing import Dict, Optional, Tuple
import time
import uuid
from net_spoof_defense.models import ArpPacketData, SpoofAlert, AttackType, MitigationStatus
from net_spoof_defense.config import ArpDefenseConfig

class ArpMonitor:
    """
    Tracks IP-to-MAC bindings and analyzes ARP traffic anomalies:
    - Rapid MAC reassignments for known IP addresses
    - Bursts of unsolicited gratuitous ARP replies
    - Gateway spoofing detection against trusted static bindings
    """
    def __init__(self, config: ArpDefenseConfig, trusted_gateways: Optional[Dict[str, str]] = None):
        self.config = config
        self.trusted_gateways = trusted_gateways or {}
        # Dynamic cache table: ip -> {"mac": mac, "last_seen": timestamp, "seen_count": int}
        self.ip_mac_table: Dict[str, Dict] = {}
        # Unsolicited rate tracker: ip -> list of timestamps
        self.unsolicited_history: Dict[str, list] = {}

    def process_packet(self, pkt: ArpPacketData) -> Tuple[float, Optional[SpoofAlert]]:
        """
        Evaluates an ARP packet and computes anomaly score S_arp in [0, 1].
        Returns (score, Optional[SpoofAlert]).
        """
        ip = pkt.sender_ip
        mac = pkt.sender_mac.lower()
        now = pkt.timestamp
        score = 0.0
        reason = []

        # 1. Authoritative Gateway Check
        if ip in self.trusted_gateways:
            legit_mac = self.trusted_gateways[ip].lower()
            if mac != legit_mac:
                score += 0.90
                reason.append(f"Gateway IP {ip} claimed by untrusted MAC {mac} (Expected {legit_mac})")

        # 2. Existing Dynamic Binding Conflict Check
        elif ip in self.ip_mac_table:
            current_entry = self.ip_mac_table[ip]
            current_mac = current_entry["mac"]
            if mac != current_mac:
                score += 0.70
                reason.append(f"IP {ip} MAC conflict: Previously {current_mac}, now claimed by {mac}")

        # 3. Unsolicited / Gratuitous Rate Check
        if pkt.is_gratuitous or pkt.op == 2:
            history = self.unsolicited_history.setdefault(ip, [])
            # Filter timestamps within 1.0 second window
            history = [t for t in history if now - t <= 1.0]
            history.append(now)
            self.unsolicited_history[ip] = history
            
            rate = len(history)
            if rate > self.config.max_unsolicited_rate_per_sec:
                score += min(0.35, 0.10 * (rate - self.config.max_unsolicited_rate_per_sec))
                reason.append(f"Unsolicited ARP rate anomaly: {rate} packets/sec from {ip}")

        score = min(1.0, score)

        # Update cache if score is within acceptable threshold
        if score < self.config.anomaly_threshold:
            if ip not in self.ip_mac_table:
                self.ip_mac_table[ip] = {"mac": mac, "last_seen": now, "seen_count": 1}
            else:
                self.ip_mac_table[ip]["mac"] = mac
                self.ip_mac_table[ip]["last_seen"] = now
                self.ip_mac_table[ip]["seen_count"] += 1
            return score, None

        # Build Alert if score exceeds threshold
        alert = SpoofAlert(
            alert_id=str(uuid.uuid4())[:8],
            attack_type=AttackType.ARP_POISON,
            source_mac=mac,
            target_ip=ip,
            claimed_mac=mac,
            legitimate_mac=self.trusted_gateways.get(ip) or (self.ip_mac_table.get(ip, {}).get("mac")),
            anomaly_score=score,
            mitigation_status=MitigationStatus.DETECTED,
            timestamp=now,
            details={"reasons": reason, "raw_op": pkt.op}
        )
        return score, alert
