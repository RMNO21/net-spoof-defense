# ESP32 Passive 802.11 Sniffer & Hardware Telemetry Setup

## Host Network Safety Policy
Do **not** place the host's primary wireless interface (e.g., `wlo1` / `wlan0`) into monitor mode. Host Wi-Fi remains untouched in managed mode to preserve control-plane connectivity. All live RF telemetry must be captured off-host via either:
1. An **ESP32 microcontroller** running the read-only passive sniffer firmware in [`firmware/esp32_passive_sniffer/esp32_passive_sniffer.ino`](../firmware/esp32_passive_sniffer/esp32_passive_sniffer.ino) connected over USB-UART (`/dev/ttyUSB0` or `/dev/ttyACM0`).
2. A **dedicated secondary USB Wi-Fi adapter** capable of monitor mode, outputting `DLT_IEEE802_11_RADIO` (linktype 127) PCAP streams into `RadiotapPcapSource`.

## Flashing the ESP32 Passive Sensor
1. Connect the ESP32 development board over USB and verify the serial node appears:
   ```bash
   ls -l /dev/ttyUSB* /dev/ttyACM*
   ```
2. Compile and flash using `arduino-cli` or Arduino IDE (`esp32:esp32:esp32`):
   ```bash
   arduino-cli compile --fqbn esp32:esp32:esp32 firmware/esp32_passive_sniffer
   arduino-cli upload -p /dev/ttyUSB0 --fqbn esp32:esp32:esp32 firmware/esp32_passive_sniffer
   ```
3. Stream live telemetry into the Blue Engine:
   ```python
   from net_spoof_defense.blue_engine import (
       ArpMonitor, BeaconMonitor, DnsValidator, Esp32SerialSource, PacketIngestor
   )
   from net_spoof_defense.config import ArpDefenseConfig, DnsDefenseConfig, WirelessDefenseConfig

   ingestor = PacketIngestor(
       arp_monitor=ArpMonitor(ArpDefenseConfig()),
       dns_validator=DnsValidator(DnsDefenseConfig()),
       beacon_monitor=BeaconMonitor(
           WirelessDefenseConfig(),
           trusted_aps={"CorpNet": {"bssid": "00:11:22:33:44:55", "channel": 6, "require_rsn": True}},
       ),
   )
   with Esp32SerialSource("/dev/ttyUSB0", baudrate=115200) as src:
       stats = ingestor.ingest_wireless_from_source(src, max_frames=500)
   ```

## Software-Only Validation (No Physical Hardware)
When no ESP32 or secondary monitor-mode NIC is attached, `SimulatedEsp32Source`, `Esp32SerialSource("loop://")`, and `RadiotapPcapSource` exercise the exact same `parse_esp32_telemetry_line`, `decode_radiotap_mgmt_frame`, and `BeaconMonitor` state machine.
