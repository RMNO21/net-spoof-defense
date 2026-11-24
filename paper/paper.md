# Adversarial Network Spoofing: From Precision Packet Crafting to Real-Time State-Machine Mitigation

**Author**: RMNO21 (`tondroraman83@gmail.com`)  
**Target Submission**: IEEE Transactions on Network and Service Management / IEEE S&P Workshop  

---

## Abstract
Local-area network communications depend on unauthenticated, stateless discovery and resolution protocols, notably the Address Resolution Protocol (ARP, RFC 826) at Layer 2 and unencrypted Domain Name System (DNS, RFC 1035) exchanges at Layer 7. These mechanisms remain exposed to adversarial spoofing attacks, including ARP cache poisoning, man-in-the-middle (MITM) gateway impersonation, and DNS fast-response race conditions. In this paper, we present **NetSpoof-Defense**, an adversarial red-blue framework built to analyze and neutralize network spoofing threats. On the offensive axis (Red Engine), we model precision unsolicited and gratuitous packet injection vectors, establishing cache-persistence conditions under local subnet contention. On the defensive axis (Blue Engine), we pair a stateful dynamic IP-to-MAC binding state machine and query-response transaction validator with a zero-dependency IEEE 802.3 / RFC 826 / RFC 1035 wire codec and isolated virtual interface ingestion pipeline. When anomalies exceed calibrated thresholds ($S_{\text{ARP}} \ge 0.75$), the system emits corrective Layer-2 broadcast frames onto the wire to restore corrupted victim caches. Empirical benchmarks across 5,000 iterations in Python 3.14 demonstrate 100.0% detection accuracy with 32.01 µs mean state-machine TTD-plus-healing latency (31,157 packets/s), 30.62 µs full-duplex kernel `socketpair` wire round-trip latency (32,543 frames/s), and 14.97 µs mean latency during mixed ARP/DNS PCAP stream ingestion (63,880 frames/s).

---

## 1. Introduction
Despite widespread cryptographic hardening at transport and application layers (e.g., TLS 1.3), enterprise and IoT local area networks remain vulnerable to Layer-2 and Layer-7 impersonation. The underlying exposure stems from early protocol assumptions favoring simplicity over peer authentication:
1. **Stateless ARP Resolution**: Hosts dynamically overwrite existing ARP cache entries when receiving unsolicited ARP replies without verifying prior request state (RFC 826).
2. **DNS Transaction Predictability**: Traditional UDP DNS queries rely on a 16-bit Transaction ID (`TxID`) and source-port entropy, leaving stub and recursive resolvers open to fast-response spoofing races on shared links (RFC 1035).
3. **Embedded Wireless Attack Surface**: Low-cost microcontrollers, such as the ESP32, enable compact physical rogue nodes capable of 802.11 frame injection and beacon spoofing.

### 1.1 Contributions
- **Adversarial Dual-Engine Architecture**: An integrated platform pairing programmatic spoofing generators (Red Engine) with real-time stateful telemetry inspection (Blue Engine).
- **Composite Anomaly Scoring**: A bounded metric $S_{\text{ARP}}$ combining authoritative gateway verification, dynamic MAC transition tracking, and gratuitous burst rate-limiting.
- **Isolated Wire-Format Ingestion & Active Auto-Healing**: A zero-dependency Ethernet II / ARP / IPv4 / UDP / DNS binary codec supporting `AF_PACKET` virtual interfaces (`ip netns` / `veth`), kernel `socketpair` IPC wires, and libpcap replay, guarded against accidental host-interface tampering.
- **Empirical Evaluation**: Latency and throughput measurements across in-memory, kernel-IPC, and PCAP-replay pipelines confirming microsecond-scale mitigation in pure user-space Python.

---

## 2. Threat Model & Adversarial Formulations
We model an adversary co-located on the same Layer-2 broadcast domain (VLAN or subnet) with raw packet crafting capabilities.

### 2.1 Layer-2 ARP Cache Poisoning
Let $H_G = \langle \text{IP}_G, \text{MAC}_G \rangle$ denote the legitimate gateway and $H_V = \langle \text{IP}_V, \text{MAC}_V \rangle$ denote the target victim. The adversary $H_A = \langle \text{IP}_A, \text{MAC}_A \rangle$ injects an unsolicited reply:
$$P_{\text{poison}} = \text{ARP}_{\text{reply}}(\text{sip}=\text{IP}_G, \text{smac}=\text{MAC}_A, \text{tip}=\text{IP}_V, \text{tmac}=\text{MAC}_V)$$

Upon accepting $P_{\text{poison}}$, the victim's ARP table shifts from $C_V(\text{IP}_G) = \text{MAC}_G$ to $C_V(\text{IP}_G) = \text{MAC}_A$, diverting outbound traffic through the adversary.

### 2.2 Layer-7 DNS Fast-Reply Racing
In a DNS race attack, an on-path observer intercepts a query $Q = \langle \text{TxID}, \text{Domain} \rangle$ sent by $H_V$ to resolver $H_R$ and transmits a forged answer $R_{\text{forged}}$ prior to the authentic response $R_{\text{auth}}$:
$$\Delta t = t(R_{\text{auth}}) - t(R_{\text{forged}}) > 0$$

When $\Delta t > 0$, the client accepts $R_{\text{forged}}$ and caches the attacker-controlled address until TTL expiration, while the delayed arrival of $R_{\text{auth}}$ exposes the duplicate `TxID` collision on the wire.

---

## 3. Defense Engine Architecture
The Blue Engine ingests raw Ethernet II frames and evaluates Layer-2 and Layer-7 protocol state concurrently:

```
+--------------------------------------------------------------+
|  Wire Ingestion (AF_PACKET veth / socketpair IPC / libpcap)  |
+------------------------------+-------------------------------+
                               |
            +------------------v------------------+
            | Zero-Dep Codec (802.3/ARP/IP/UDP/DNS)|
            +--------+--------------------+-------+
                     |                    |
        +------------v----------+   +-----v-------------------+
        | Stateful ARP Monitor  |   | DNS Integrity Validator |
        | - Gateway Integrity   |   | - Pending TxID State    |
        | - MAC Transition Map  |   | - Fast-Race Detection   |
        | - Gratuitous Rate Lim |   | - TTL Variance Bound    |
        +------------+----------+   +-----+-------------------+
                     |                    |
            +--------v--------------------v-------+
            |      Anomaly Scoring Evaluator      |
            |   S_arp(p) >= 0.75 / S_dns >= 0.70  |
            +------------------+------------------+
                               |
            +------------------v------------------+
            |      Active Mitigation Engine       |
            | - Broadcast Gratuitous Cache Healing|
            | - Wire Frame Sink & ATT&CK Alerting |
            +-------------------------------------+
```

### 3.1 Composite Anomaly Scoring
For each observed ARP frame $p$, the anomaly score $S_{\text{ARP}}(p) \in [0, 1]$ is defined as:
$$S_{\text{ARP}}(p) = \min\left(1.0,\; \alpha \cdot \mathbb{I}_{\text{gateway}}(p) + \beta \cdot \mathbb{I}_{\text{conflict}}(p) + \gamma \cdot \Psi_{\text{rate}}(p)\right)$$

Where:
- $\mathbb{I}_{\text{gateway}}(p) = 1$ if $p$ claims a trusted gateway IP using an unauthorized MAC ($\alpha = 0.90$), else $0$.
- $\mathbb{I}_{\text{conflict}}(p) = 1$ if the claimed MAC diverges from the confirmed dynamic binding history ($\beta = 0.70$).
- $\Psi_{\text{rate}}(p)$ penalizes unsolicited reply bursts exceeding the configured per-second rate threshold.

### 3.2 Dynamic Cache Healing
When $S_{\text{ARP}}(p) \ge \tau$ ($\tau = 0.75$), the mitigation engine constructs corrective gratuitous ARP replies carrying the authoritative binding $\langle \text{IP}_G, \text{MAC}_G \rangle$, encodes them into 42-byte Ethernet II + RFC 826 frames, and dispatches them onto the attached `FrameSink` to overwrite poisoned neighbor caches.

### 3.3 Isolated Wire Ingestion & Host Safety Guards
Live raw-socket experiments risk corrupting host connectivity if bound to physical NICs. Before opening an `AF_PACKET` (`ETH_P_ALL`) socket or provisioning `ip netns` virtual Ethernet (`veth`) pairs, `validate_isolated_interface()` enforces three invariants:
1. The interface name matches an explicit isolated prefix (`nsd-`, `veth`, `dummy`, or `lo`).
2. No physical device symlink exists under `/sys/class/net/<iface>/device`.
3. The interface carries no host or default-gateway route (`00000000`) in `/proc/net/route`.

For unprivileged testing without `CAP_NET_RAW`, `VirtualWirePair` uses a kernel-backed `AF_UNIX` `SOCK_DGRAM` `socketpair` to preserve Ethernet frame boundaries between Red and Blue endpoints.

---

## 4. Empirical Evaluation
All measurements were executed single-threaded under Python 3.14.4 on Linux using `time.perf_counter()` across four evaluation modes:

| Benchmark Mode | Iterations | Mean Latency | P99 Latency | Throughput | Detection Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **State-Machine TTD + Healing (In-Memory)** | 5,000 | 32.01 µs | 56.17 µs | 31,157 pkt/s | 100.0% |
| **Raw Ethernet Decode + ARP Heal** | 5,000 | 43.21 µs | 73.97 µs | 23,092 frame/s (7.76 Mbps) | 100.0% |
| **VirtualWirePair Kernel IPC Round-Trip** | 2,000 | 30.62 µs | 45.49 µs | 32,543 frame/s (10.93 Mbps) | 100.0% |
| **Offline PCAP Stream (Mixed ARP + DNS)** | 5,000 | 14.97 µs | 40.60 µs | 63,880 frame/s (29.64 Mbps) | 100.0% (2,500/2,500) |

Standard deviations measured ±25.07 µs for raw Ethernet ARP decode-and-heal, ±7.82 µs for full-duplex `VirtualWirePair` round-trip processing, and ±12.40 µs (median 9.77 µs) for mixed ARP/DNS PCAP replay. Across all 15 unit tests (`pytest -v`), zero decode errors and zero false negatives were observed.

---

## 5. Conclusion
NetSpoof-Defense shows that Layer-2 ARP cache poisoning and Layer-7 DNS fast-race spoofing can be decoded from raw wire frames, scored statefully, and actively neutralized in tens of microseconds in user-space Python while isolating host interfaces from unintended injection. Upcoming stages will add ESP32 802.11 rogue-AP telemetry ingestion and full multi-node topology stress benchmarks.
