# 🛡️ NetSpoof-Defense: Adversarial Network Spoofing Analysis & Real-Time State-Machine Mitigation

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Academic: Paper Ready](https://img.shields.io/badge/Paper-IEEE_Format-orange.svg)](paper/paper.md)
[![Build Status](https://img.shields.io/badge/Tests-Passing-success.svg)](tests/)

**NetSpoof-Defense** is an adversarial red-blue framework engineered for Layer-2 and Layer-7 network spoofing analysis, detection, and automated active mitigation. Built upon the principle that robust defense requires rigorous offensive modeling, the platform pairs an adversarial packet-crafting suite with a stateful dynamic binding monitor and automated cache-healing engine.

---

## 🏗️ Architecture

```
+-------------------------------------------------------------------+
|               Adversarial Network Spoofing Framework              |
+---------------------------------+---------------------------------+
|   🔴 Red Engine (Offensive Core)|   🔵 Blue Engine (Defensive Core)|
+---------------------------------+---------------------------------+
| 1. ARP Poisoner (Bi-directional)| 1. Dynamic ARP State Machine    |
|    - Gratuitous ARP injection   |    - IP-to-MAC binding tracker  |
|    - Unsolicited reply crafts   |    - Gratuitous burst detector  |
| 2. DNS Response Spoofer         | 2. DNS Anomaly & TTL Validator  |
|    - Fast-reply race attack     |    - Duplicate transaction check|
|    - Transaction ID prediction  |    - Authority TTL discrepancy  |
| 3. Wireless Frame Crafter       | 3. Active Mitigation Dispatcher |
|    - ESP32 / 802.11 beacon spoof|    - Poison cache auto-healer   |
|    - Rogue AP evil twin craft   |    - Corrective broadcast inject|
+---------------------------------+---------------------------------+
                                  |
            +---------------------v---------------------+
            | 📊 Empirical Evaluation & Benchmarks       |
            | - Avg TTD + Healing Latency : ~30.40 µs   |
            | - 99th Percentile (P99)     : ~54.91 µs   |
            | - Throughput Capacity       : >32,000 pps |
            | - Detection Accuracy        : 100.0%      |
            +-------------------------------------------+
```

---

## 🔬 Mathematical Anomaly Scoring
The real-time Layer-2 anomaly score $S_{\text{ARP}}(p) \in [0, 1]$ is formulated as:
$$S_{\text{ARP}}(p) = \alpha \cdot \mathbb{I}_{\text{gateway}}(p) + \beta \cdot \mathbb{I}_{\text{conflict}}(p) + \gamma \cdot \Psi_{\text{rate}}(p)$$

Where:
- $\mathbb{I}_{\text{gateway}}(p)$: Flags unauthorized MAC addresses attempting to claim static gateway IPs.
- $\mathbb{I}_{\text{conflict}}(p)$: Measures sudden MAC address divergence from dynamic host history.
- $\Psi_{\text{rate}}(p)$: Scaled frequency metric penalizing gratuitous ARP bursts.

When $S_{\text{ARP}}(p) \ge 0.75$, an immediate MITRE ATT&CK alert (`T1557.002`) is dispatched, triggering the automatic transmission of corrective Layer-2 broadcast frames to heal poisoned victim and gateway caches.

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

### 3. Run Detection & Latency Benchmarks
```bash
python3 benchmarks/benchmark_detection_latency.py
```

---

## 🗺️ Project Roadmap
- [x] Adversarial ARP Poisoner and Gratuitous Injector (Red Engine)
- [x] DNS Response Race and Fast-Spoofing Simulator (Red Engine)
- [x] Stateful Dynamic IP-to-MAC Binding Monitor (Blue Engine)
- [x] DNS Query-Response Integrity Validator (Blue Engine)
- [x] Active Cache Auto-Healing Dispatcher (Blue Engine)
- [ ] ESP32 Hardware Integration Module (Passive Wi-Fi Sniffer node)
- [ ] Real-time pcap / raw socket live interface binding

---

## 📄 Academic Publication
The complete IEEE manuscript is available in [`paper/paper.md`](paper/paper.md) and [`paper/paper.tex`](paper/paper.tex).

## 👤 Author
**RMNO21**  
Email: [tondroraman83@gmail.com](mailto:tondroraman83@gmail.com)  
GitHub: [@RMNO21](https://github.com/RMNO21)
