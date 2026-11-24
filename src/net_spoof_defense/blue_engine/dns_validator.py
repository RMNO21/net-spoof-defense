"""
DNS Response Integrity and Transaction Race Validator.
"""

from typing import Dict, Optional, Tuple
import time
import uuid
from net_spoof_defense.models import DnsPacketData, SpoofAlert, AttackType, MitigationStatus
from net_spoof_defense.config import DnsDefenseConfig

class DnsValidator:
    """
    Validates DNS query/response integrity:
    - Tracks pending queries and catches multiple conflicting responses (Race Conditions)
    - Flags unexpected TTL drops and anomalies
    """
    def __init__(self, config: DnsDefenseConfig):
        self.config = config
        # Pending queries: tx_id -> {"domain": domain, "timestamp": timestamp, "responded": bool}
        self.pending_queries: Dict[int, Dict] = {}

    def register_query(self, transaction_id: int, domain: str) -> None:
        self.pending_queries[transaction_id] = {
            "domain": domain.lower(),
            "timestamp": time.time(),
            "responded": False
        }

    def validate_response(self, resp: DnsPacketData) -> Tuple[float, Optional[SpoofAlert]]:
        score = 0.0
        reasons = []
        now = resp.timestamp
        tx_id = resp.transaction_id

        if tx_id not in self.pending_queries:
            # Unsolicited DNS response
            score += 0.85
            reasons.append(f"Unsolicited DNS response with TxID 0x{tx_id:04x}")
        else:
            query = self.pending_queries[tx_id]
            if query["responded"]:
                # Second response arriving for the same transaction ID (classic fast-response race)
                score += 0.95
                reasons.append(f"Duplicate/Race DNS response detected for TxID 0x{tx_id:04x} domain {resp.query_name}")
            else:
                query["responded"] = True
                delta_ms = (now - query["timestamp"]) * 1000.0
                if delta_ms > self.config.max_query_response_delta_ms:
                    score += 0.30
                    reasons.append(f"Suspiciously high query-response latency ({delta_ms:.1f}ms)")

        if resp.ttl < 10:
            score += 0.20
            reasons.append(f"Abnormally low DNS TTL ({resp.ttl}s)")

        score = min(1.0, score)

        if score < 0.70:
            return score, None

        alert = SpoofAlert(
            alert_id=str(uuid.uuid4())[:8],
            attack_type=AttackType.DNS_SPOOF,
            source_mac="00:00:00:00:00:00",
            target_ip=resp.response_ips[0] if resp.response_ips else "0.0.0.0",
            claimed_mac="N/A",
            anomaly_score=score,
            mitigation_status=MitigationStatus.DETECTED,
            timestamp=now,
            details={"reasons": reasons, "tx_id": hex(tx_id), "domain": resp.query_name}
        )
        return score, alert
