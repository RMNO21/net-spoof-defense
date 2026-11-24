# Isolated Virtual Interface & Network Namespace Setup

To preserve host internet connectivity and prevent accidental Layer-2 ARP cache corruption on physical adapters (`wlan0`, `wlo1`, `eth0`), NetSpoof-Defense enforces strict interface isolation.

## Host Interface Integrity Guard

Before binding an `AF_PACKET` raw socket or invoking `ip netns`, `validate_isolated_interface()` verifies three invariants:
1. The interface name uses an approved virtual prefix (`nsd-`, `veth`, `dummy`, or `lo`).
2. `/sys/class/net/<iface>/device` does not exist (excluding physical PCI/USB NICs).
3. The interface does not appear as an active or default-gateway route in `/proc/net/route`.

Any violation raises `SafetyViolationError`.

## Two-Mode Execution Model

1. **Unprivileged Kernel IPC Wire (`VirtualWirePair`)**:
   Uses `socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)` to stream raw 42-byte Ethernet II + RFC 826 ARP and IPv4/UDP/DNS frames between the Red Engine and Blue Engine with zero root privileges and zero host routing impact.

2. **Privileged Linux `ip netns` + `veth` Pair (`VethNetnsManager` + `RawSocketSource`)**:
   When executed with `CAP_NET_ADMIN` / `CAP_NET_RAW`, `VethNetnsManager` isolates `nsd_red` and `nsd_blue` namespaces connected exclusively via `nsd-veth-red` <-> `nsd-veth-blue`:
   ```bash
   sudo ip netns add nsd_red
   sudo ip netns add nsd_blue
   sudo ip link add nsd-veth-red type veth peer name nsd-veth-blue
   sudo ip link set nsd-veth-red netns nsd_red
   sudo ip link set nsd-veth-blue netns nsd_blue
   ```
   Teardown removes both namespaces and their virtual links cleanly without touching host interfaces.
