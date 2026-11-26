# 🛡️ NetSpoof-Defense: Adversarial Network Spoofing Analysis & Real-Time State-Machine Mitigation

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Academic: Paper Ready](https://img.shields.io/badge/Paper-IEEE_Format-orange.svg)](paper/paper.md)
[![Build Status](https://img.shields.io/badge/Tests-20_Passing-success.svg)](tests/)

**NetSpoof-Defense** is an adversarial red-blue framework engineered for Layer-2 and Layer-7 network spoofing analysis, detection, and automated active mitigation. Built upon the principle that robust defense requires rigorous offensive modeling, the platform pairs an adversarial packet-crafting suite with a zero-dependency wire-format codec, isolated virtual interface ingestion (`AF_PACKET` / `ip netns` / `socketpair` / libpcap), a stateful dynamic binding monitor, and an automated cache-healing engine.

---

## 🏗️ Architecture

```
+-------------------------------------------------------------------+
|               Adversarial Network Spoofing Framework              |
+---------------------------------+---------------------------------+
|   🔴 Red Engine (Offensive Core)|   🔵 Blue Engine (Defensive Core)|
+---------------------------------+---------------------------------+
| 1. ARP Poisoner (Bi-directional)| 1. Isolated Wire Ingestion      |
|    - Gratuitous ARP injection   |    - AF_PACKET veth / netns     |
|    - Unsolicited reply crafts   |    - Kernel socketpair & libpcap|
| 2. DNS Response Spoofer         | 2. Dynamic ARP & DNS State      |
|    - Fast-reply race attack     |    - IP-to-MAC binding tracker  |
|    - Transaction ID prediction  |    - DNS TxID race & TTL check  |
| 3. Wireless Frame Crafter       | 3. Active Mitigation Dispatcher |
|    - ESP32 / 802.11 beacon spoof|    - Poison cache auto-healer   |
|    - Rogue AP evil twin craft   |    - Corrective wire injection  |
+---------------------------------+---------------------------------+
                                  |
            +---------------------v---------------------+
            | 📊 Empirical Evaluation & Benchmarks       |
            | - State-Machine TTD + Heal : 32.01 µs     |
            | - VirtualWirePair IPC RTT  : 30.62 µs     |
            | - Raw Eth Decode + Heal    : 43.21 µs     |
            | - Mixed ARP/DNS PCAP Replay: 63,880 fps   |
            | - Radiotap 802.11 Decode   : 19.26 µs     |
            | - ESP32 UART Sim Ingestion : 121,691 fps  |
            | - Detection Accuracy       : 100.0%       |
            +-------------------------------------------+
```

---

## 🔬 Mathematical Anomaly Scoring
The real-time Layer-2 anomaly score $S_{\text{ARP}}(p) \in [0, 1]$ is formulated as:
$$S_{\text{ARP}}(p) = \min\left(1.0,\; \alpha \cdot \mathbb{I}_{\text{gateway}}(p) + \beta \cdot \mathbb{I}_{\text{conflict}}(p) + \gamma \cdot \Psi_{\text{rate}}(p)\right)$$

Where:
- $\mathbb{I}_{\text{gateway}}(p)$: Flags unauthorized MAC addresses attempting to claim static gateway IPs.
- $\mathbb{I}_{\text{conflict}}(p)$: Measures sudden MAC address divergence from dynamic host history.
- $\Psi_{\text{rate}}(p)$: Scaled frequency metric penalizing gratuitous ARP bursts.

When $S_{\text{ARP}}(p) \ge 0.75$, an immediate MITRE ATT&CK alert (`T1557.002`) is dispatched, triggering the automatic serialization and transmission of corrective 42-byte Layer-2 Ethernet II + RFC 826 broadcast frames onto the active wire sink to heal poisoned victim and gateway caches.

---

## 🚀 Quick Start

### 1. Installation
```bash
git clone https://github.com/RMNO21/net-spoof-defense.git
cd net-spoof-defense
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

### 2. Run Test Suite
```bash
pytest -v
```

### 3. Run Detection & Wire Ingestion Benchmarks
```bash
python3 benchmarks/benchmark_detection_latency.py
python3 benchmarks/benchmark_wire_ingestion.py
python3 benchmarks/benchmark_wireless_ingestion.py
```

---

## 🗺️ Project Roadmap
- [x] Adversarial ARP Poisoner and Gratuitous Injector (Red Engine)
- [x] DNS Response Race and Fast-Spoofing Simulator (Red Engine)
- [x] Stateful Dynamic IP-to-MAC Binding Monitor (Blue Engine)
- [x] DNS Query-Response Integrity Validator (Blue Engine)
- [x] Active Cache Auto-Healing Dispatcher (Blue Engine)
- [x] Real-time pcap / virtual-wire / isolated `AF_PACKET` raw socket ingestion & host-interface safety guard
- [x] IEEE 802.11 Radiotap / `BeaconMonitor` & passive ESP32 UART firmware hook (hardware capture validation pending external ESP32/NIC)

---

## 📄 Documentation & Academic Publication
- Virtual interface and `ip netns` isolation guide: [`docs/virtual_interface_setup.md`](docs/virtual_interface_setup.md)
- Passive ESP32 802.11 sniffer setup: [`docs/esp32_hardware_setup.md`](docs/esp32_hardware_setup.md)
- IEEE manuscript: [`paper/paper.md`](paper/paper.md) and [`paper/paper.tex`](paper/paper.tex)

## 👤 Author
**RMNO21**  
Email: [tondroraman83@gmail.com](mailto:tondroraman83@gmail.com)  
GitHub: [@RMNO21](https://github.com/RMNO21)
