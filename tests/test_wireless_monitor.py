import tempfile
import os
import pytest

from net_spoof_defense.blue_engine import (
    ArpMonitor,
    BeaconMonitor,
    DnsValidator,
    Esp32SerialSource,
    PacketIngestor,
    RadiotapPcapSource,
    SimulatedEsp32Source,
    validate_serial_port,
)
from net_spoof_defense.codec import WireDecodeError
from net_spoof_defense.config import ArpDefenseConfig, DnsDefenseConfig, WirelessDefenseConfig
from net_spoof_defense.models import AttackType, WirelessFrameData
from net_spoof_defense.wireless_codec import (
    RadiotapPcapWriter,
    decode_radiotap_mgmt_frame,
    encode_esp32_telemetry_line,
    encode_radiotap_mgmt_frame,
    parse_esp32_telemetry_line,
)


def test_radiotap_beacon_and_deauth_roundtrip():
    beacon = WirelessFrameData(
        frame_subtype="beacon",
        ssid="LabSecureNet",
        bssid="aa:bb:cc:11:22:33",
        src_mac="aa:bb:cc:11:22:33",
        dst_mac="ff:ff:ff:ff:ff:ff",
        channel=6,
        rssi_dbm=-48,
        beacon_interval=100,
        rsn_enabled=True,
        timestamp=1700000001.25,
    )
    raw = encode_radiotap_mgmt_frame(beacon)
    decoded = decode_radiotap_mgmt_frame(raw, timestamp=1700000001.25)
    assert decoded.frame_subtype == "beacon"
    assert decoded.ssid == "LabSecureNet"
    assert decoded.bssid == "aa:bb:cc:11:22:33"
    assert decoded.channel == 6
    assert decoded.rssi_dbm == -48
    assert decoded.rsn_enabled is True

    deauth = WirelessFrameData(
        frame_subtype="deauth",
        ssid="",
        bssid="aa:bb:cc:11:22:33",
        src_mac="aa:bb:cc:11:22:33",
        dst_mac="11:22:33:44:55:66",
        channel=6,
        rssi_dbm=-39,
        reason_code=7,
        timestamp=1700000002.0,
    )
    raw_deauth = encode_radiotap_mgmt_frame(deauth)
    dec_deauth = decode_radiotap_mgmt_frame(raw_deauth, timestamp=1700000002.0)
    assert dec_deauth.frame_subtype == "deauth"
    assert dec_deauth.reason_code == 7
    assert dec_deauth.dst_mac == "11:22:33:44:55:66"


def test_esp32_uart_line_roundtrip_and_invalid_raises():
    frame = WirelessFrameData(
        frame_subtype="beacon",
        ssid="CampusWiFi",
        bssid="00:11:22:33:44:55",
        src_mac="00:11:22:33:44:55",
        channel=11,
        rssi_dbm=-55,
        rsn_enabled=True,
        timestamp=1700000010.5,
    )
    line = encode_esp32_telemetry_line(frame)
    parsed = parse_esp32_telemetry_line(line)
    assert parsed.ssid == "CampusWiFi"
    assert parsed.bssid == "00:11:22:33:44:55"
    assert parsed.channel == 11
    assert parsed.rssi_dbm == -55

    with pytest.raises(WireDecodeError):
        parse_esp32_telemetry_line('{"proto":"WRONG","subtype":"beacon"}')


def test_serial_port_safety_guard_and_loopback():
    with pytest.raises(ValueError):
        validate_serial_port("/dev/sda1")
    with pytest.raises(ValueError):
        validate_serial_port("/etc/passwd")

    validate_serial_port("/dev/ttyUSB0")
    validate_serial_port("loop://")

    beacon = WirelessFrameData(
        frame_subtype="beacon",
        ssid="CorpAP",
        bssid="de:ad:be:ef:10:20",
        src_mac="de:ad:be:ef:10:20",
        channel=1,
        rssi_dbm=-35,
        rsn_enabled=False,
        timestamp=1700000020.0,
    )
    line = encode_esp32_telemetry_line(beacon) + "\n"
    with Esp32SerialSource("loop://", timeout_s=0.05) as src:
        src._serial.write(line.encode("utf-8"))
        rec = src.recv_wireless_frame()
        assert rec is not None
        assert rec.ssid == "CorpAP"
        assert rec.rsn_enabled is False


def test_beacon_monitor_evil_twin_and_deauth_flood_detection():
    monitor = BeaconMonitor(
        config=WirelessDefenseConfig(rssi_jump_threshold_dbm=15, max_deauth_per_sec=4.0),
        trusted_aps={
            "CorpWiFi": {"bssid": "00:11:22:33:44:55", "channel": 6, "require_rsn": True}
        },
    )

    # Legitimate beacon produces zero alert
    legit = WirelessFrameData(
        frame_subtype="beacon",
        ssid="CorpWiFi",
        bssid="00:11:22:33:44:55",
        src_mac="00:11:22:33:44:55",
        channel=6,
        rssi_dbm=-62,
        rsn_enabled=True,
        timestamp=100.0,
    )
    score, alert = monitor.process_frame(legit)
    assert score == 0.0
    assert alert is None

    # Evil-twin rogue beacon with wrong BSSID, RSN downgrade, and channel drift
    rogue = WirelessFrameData(
        frame_subtype="beacon",
        ssid="CorpWiFi",
        bssid="de:ad:be:ef:99:99",
        src_mac="de:ad:be:ef:99:99",
        channel=11,
        rssi_dbm=-38,
        rsn_enabled=False,
        timestamp=100.1,
    )
    score, alert = monitor.process_frame(rogue)
    assert score >= 0.99
    assert alert is not None
    assert alert.attack_type == AttackType.BEACON_SPOOF
    assert alert.legitimate_mac == "00:11:22:33:44:55"

    # Dynamic learning + conflict detection for non-preconfigured SSID
    guest_legit = WirelessFrameData(
        frame_subtype="beacon",
        ssid="GuestNet",
        bssid="aa:aa:aa:aa:aa:01",
        src_mac="aa:aa:aa:aa:aa:01",
        channel=1,
        rssi_dbm=-68,
        rsn_enabled=True,
        timestamp=101.0,
    )
    assert monitor.process_frame(guest_legit)[1] is None

    guest_rogue = WirelessFrameData(
        frame_subtype="beacon",
        ssid="GuestNet",
        bssid="bb:bb:bb:bb:bb:02",
        src_mac="bb:bb:bb:bb:bb:02",
        channel=1,
        rssi_dbm=-40,
        rsn_enabled=True,
        timestamp=101.2,
    )
    score_dyn, alert_dyn = monitor.process_frame(guest_rogue)
    assert score_dyn >= 0.70
    assert alert_dyn is not None
    assert alert_dyn.attack_type == AttackType.BEACON_SPOOF

    # Deauthentication burst exceeding max_deauth_per_sec=4.0
    deauth_alerts = []
    for i in range(7):
        d_frame = WirelessFrameData(
            frame_subtype="deauth",
            ssid="",
            bssid="00:11:22:33:44:55",
            src_mac="00:11:22:33:44:55",
            dst_mac="12:34:56:78:9a:bc",
            channel=6,
            rssi_dbm=-45,
            reason_code=7,
            timestamp=200.0 + i * 0.05,
        )
        _, d_alert = monitor.process_frame(d_frame)
        if d_alert is not None:
            deauth_alerts.append(d_alert)

    assert len(deauth_alerts) == 3
    assert deauth_alerts[0].attack_type == AttackType.DEAUTH_FLOOD


def test_radiotap_pcap_and_esp32_sim_ingestion_pipeline():
    legit = WirelessFrameData(
        frame_subtype="beacon",
        ssid="IoT-Mesh",
        bssid="10:20:30:40:50:60",
        src_mac="10:20:30:40:50:60",
        channel=6,
        rssi_dbm=-60,
        rsn_enabled=True,
        timestamp=1700000100.0,
    )
    rogue = WirelessFrameData(
        frame_subtype="beacon",
        ssid="IoT-Mesh",
        bssid="de:ad:00:11:22:33",
        src_mac="de:ad:00:11:22:33",
        channel=6,
        rssi_dbm=-36,
        rsn_enabled=False,
        timestamp=1700000100.1,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = os.path.join(tmpdir, "wireless.pcap")
        with RadiotapPcapWriter(pcap_path) as writer:
            writer.write_frame(encode_radiotap_mgmt_frame(legit), timestamp=legit.timestamp)
            writer.write_frame(encode_radiotap_mgmt_frame(rogue), timestamp=rogue.timestamp)

        ingestor = PacketIngestor(
            arp_monitor=ArpMonitor(ArpDefenseConfig()),
            dns_validator=DnsValidator(DnsDefenseConfig()),
            beacon_monitor=BeaconMonitor(
                WirelessDefenseConfig(),
                trusted_aps={"IoT-Mesh": {"bssid": "10:20:30:40:50:60", "channel": 6, "require_rsn": True}},
            ),
        )
        pcap_stats = ingestor.ingest_wireless_from_source(RadiotapPcapSource(pcap_path))
        assert pcap_stats.wireless_frames == 2
        assert pcap_stats.beacon_frames == 2
        assert pcap_stats.alerts_triggered == 1
        assert pcap_stats.alerts[0].attack_type == AttackType.BEACON_SPOOF

    sim_source = SimulatedEsp32Source([
        encode_esp32_telemetry_line(legit),
        "{corrupt json",
        encode_esp32_telemetry_line(rogue),
    ])
    sim_ingestor = PacketIngestor(
        arp_monitor=ArpMonitor(ArpDefenseConfig()),
        dns_validator=DnsValidator(DnsDefenseConfig()),
        beacon_monitor=BeaconMonitor(
            WirelessDefenseConfig(),
            trusted_aps={"IoT-Mesh": {"bssid": "10:20:30:40:50:60", "channel": 6, "require_rsn": True}},
        ),
    )
    sim_stats = sim_ingestor.ingest_wireless_from_source(sim_source)
    assert sim_stats.wireless_frames == 2
    assert sim_stats.decode_errors == 1
    assert sim_stats.alerts_triggered == 1
