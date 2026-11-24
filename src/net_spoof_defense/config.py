"""
Configuration schema for NetSpoof-Defense using standard library dataclasses.
"""

from dataclasses import dataclass, field
from typing import Dict

@dataclass
class NetworkConfig:
    interface: str = "eth0"
    promiscuous: bool = True

@dataclass
class ArpDefenseConfig:
    max_unsolicited_rate_per_sec: float = 3.0
    mac_conflict_tolerance: int = 0
    auto_heal_cache: bool = True
    anomaly_threshold: float = 0.75

@dataclass
class DnsDefenseConfig:
    max_query_response_delta_ms: float = 500.0
    ttl_variance_threshold: int = 300
    flag_duplicate_responses: bool = True

@dataclass
class GlobalConfig:
    network: NetworkConfig = field(default_factory=NetworkConfig)
    arp: ArpDefenseConfig = field(default_factory=ArpDefenseConfig)
    dns: DnsDefenseConfig = field(default_factory=DnsDefenseConfig)
    trusted_gateways: Dict[str, str] = field(default_factory=dict)
