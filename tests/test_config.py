from net_spoof_defense.config import GlobalConfig, NetworkConfig, ArpDefenseConfig, DnsDefenseConfig

def test_default_config():
    cfg = GlobalConfig()
    assert cfg.network.interface == "eth0"
    assert cfg.arp.anomaly_threshold == 0.75
    assert cfg.arp.auto_heal_cache is True
    assert cfg.dns.max_query_response_delta_ms == 500.0
