"""
Data models and telemetry schemas for NetSpoof-Defense using standard library dataclasses.
"""

from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
import time

class AttackType(str, Enum):
    ARP_POISON = "T1557.002_ARP_SPOOFING"
    DNS_SPOOF = "T1557.001_DNS_SPOOFING"
    BEACON_SPOOF = "T1498_ROGUE_AP_BEACON_SPOOF"

class MitigationStatus(str, Enum):
    DETECTED = "DETECTED"
    HEALED = "HEALED"
    DROPPED = "DROPPED"
    ALERTED = "ALERTED"

@dataclass
class ArpPacketData:
    op: int  # 1 for request, 2 for reply
    sender_ip: str
    sender_mac: str
    target_ip: str
    target_mac: str
    timestamp: float = field(default_factory=time.time)
    is_gratuitous: bool = False

@dataclass
class DnsPacketData:
    transaction_id: int
    query_name: str
    response_ips: List[str] = field(default_factory=list)
    ttl: int = 300
    is_response: bool = False
    timestamp: float = field(default_factory=time.time)

@dataclass
class SpoofAlert:
    alert_id: str
    attack_type: AttackType
    source_mac: str
    target_ip: str
    claimed_mac: str
    anomaly_score: float
    mitigation_status: MitigationStatus
    legitimate_mac: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)
