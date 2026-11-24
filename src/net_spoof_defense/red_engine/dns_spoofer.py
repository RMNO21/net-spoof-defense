"""
Adversarial DNS Response Spoofing & Race Generator.
"""

from typing import List
import time
from net_spoof_defense.models import DnsPacketData

class DnsSpoofer:
    """
    Crafts forged DNS responses to execute DNS cache poisoning / race condition attacks.
    """
    def __init__(self, malicious_ip: str):
        self.malicious_ip = malicious_ip

    def craft_spoofed_response(
        self,
        transaction_id: int,
        query_domain: str,
        ttl: int = 60,
        override_ip: str = None
    ) -> DnsPacketData:
        """
        Crafts a fraudulent DNS answer answering query_domain with malicious_ip.
        """
        resolved_ip = override_ip or self.malicious_ip
        return DnsPacketData(
            transaction_id=transaction_id,
            query_name=query_domain,
            response_ips=[resolved_ip],
            ttl=ttl,
            is_response=True,
            timestamp=time.time()
        )
