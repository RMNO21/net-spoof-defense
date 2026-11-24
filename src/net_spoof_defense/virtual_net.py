"""
Isolated virtual interface and Linux network namespace (netns) orchestration,
host-interface integrity guards, and kernel socketpair Layer-2 wire emulation.

Safety Policy:
    Never mutate, sniff, or inject packets onto the host's primary internet or
    default-gateway interfaces (e.g., wlo1, wlan0, eth0). All raw socket and
    virtual-interface operations strictly validate interface isolation via
    `/proc/net/route` and `/sys/class/net/<iface>/device`.
"""

from __future__ import annotations

import os
import select
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional, Set, Tuple


class SafetyViolationError(RuntimeError):
    """Raised when an operation targets a non-isolated or default-route host NIC."""


def get_default_route_interfaces(route_table_path: str = "/proc/net/route") -> Set[str]:
    """Return network interfaces that carry a route entry in `/proc/net/route`."""
    routed: Set[str] = set()
    if not os.path.exists(route_table_path):
        return routed
    with open(route_table_path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()[1:]
    for line in lines:
        parts = line.strip().split()
        if not parts:
            continue
        iface = parts[0]
        dest = parts[1] if len(parts) > 1 else ""
        # Default route (00000000) or active host-routed interfaces are protected.
        if dest == "00000000" or iface not in ("lo",):
            routed.add(iface)
    return routed


def is_physical_interface(iface: str, sysfs_net_root: str = "/sys/class/net") -> bool:
    """Return True if sysfs indicates the interface is backed by a physical device."""
    device_link = os.path.join(sysfs_net_root, iface, "device")
    return os.path.exists(device_link)


def validate_isolated_interface(
    iface: str,
    allowed_prefixes: Tuple[str, ...] = ("nsd-", "veth", "dummy", "lo"),
    route_table_path: str = "/proc/net/route",
    sysfs_net_root: str = "/sys/class/net",
) -> None:
    """
    Enforce host-internet integrity before opening raw sockets or modifying links.
    Raises SafetyViolationError if `iface` is physical, carries host routes, or
    lacks an approved isolated interface prefix.
    """
    if not iface or "/" in iface or " " in iface:
        raise SafetyViolationError(f"Invalid interface identifier: {iface!r}")

    if not iface.startswith(allowed_prefixes):
        raise SafetyViolationError(
            f"Interface {iface!r} does not match isolated prefixes {allowed_prefixes}"
        )

    if iface != "lo":
        if is_physical_interface(iface, sysfs_net_root=sysfs_net_root):
            raise SafetyViolationError(
                f"Refusing operation on physical hardware NIC {iface!r}"
            )
        routed = get_default_route_interfaces(route_table_path=route_table_path)
        if iface in routed:
            raise SafetyViolationError(
                f"Refusing operation on host-routed interface {iface!r}"
            )


@dataclass(frozen=True)
class VirtualTopologySpec:
    """Specification for an isolated two-namespace veth testbed."""

    ns_red: str = "nsd_red"
    ns_blue: str = "nsd_blue"
    veth_red: str = "nsd-veth-red"
    veth_blue: str = "nsd-veth-blue"
    red_ip_cidr: str = "10.250.0.10/24"
    blue_ip_cidr: str = "10.250.0.20/24"


class VethNetnsManager:
    """
    Manages isolated Linux network namespaces (`ip netns`) and `veth` pairs.
    Requires CAP_NET_ADMIN / root privileges; raises PermissionError otherwise.
    """

    def __init__(self, spec: Optional[VirtualTopologySpec] = None):
        self.spec = spec or VirtualTopologySpec()
        validate_isolated_interface(self.spec.veth_red)
        validate_isolated_interface(self.spec.veth_blue)

    @staticmethod
    def has_net_admin() -> bool:
        return os.geteuid() == 0

    def _run_ip(self, args: list[str]) -> subprocess.CompletedProcess:
        if not self.has_net_admin():
            raise PermissionError(
                "CAP_NET_ADMIN / root privilege required for `ip netns` veth orchestration"
            )
        return subprocess.run(
            ["ip", *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def create_topology(self) -> None:
        """Create isolated namespaces and link them via a dedicated veth pair."""
        s = self.spec
        self._run_ip(["netns", "add", s.ns_red])
        self._run_ip(["netns", "add", s.ns_blue])
        self._run_ip(["link", "add", s.veth_red, "type", "veth", "peer", "name", s.veth_blue])
        self._run_ip(["link", "set", s.veth_red, "netns", s.ns_red])
        self._run_ip(["link", "set", s.veth_blue, "netns", s.ns_blue])

        for ns, dev, cidr in [
            (s.ns_red, s.veth_red, s.red_ip_cidr),
            (s.ns_blue, s.veth_blue, s.blue_ip_cidr),
        ]:
            self._run_ip(["netns", "exec", ns, "ip", "link", "set", "lo", "up"])
            self._run_ip(["netns", "exec", ns, "ip", "addr", "add", cidr, "dev", dev])
            self._run_ip(["netns", "exec", ns, "ip", "link", "set", dev, "up"])

    def teardown_topology(self) -> None:
        """Remove isolated namespaces and any attached veth interfaces."""
        s = self.spec
        for ns in (s.ns_red, s.ns_blue):
            if self.has_net_admin():
                subprocess.run(["ip", "netns", "del", ns], check=False, capture_output=True)


class VirtualWireEndpoint:
    """One end of a kernel-mediated Layer-2 frame channel (`AF_UNIX`, `SOCK_DGRAM`)."""

    def __init__(self, sock: socket.socket, name: str):
        self._sock = sock
        self.name = name

    def send_frame(self, frame: bytes) -> int:
        return self._sock.send(frame)

    def recv_frame(self, timeout: Optional[float] = 0.05, bufsize: int = 65535) -> Optional[bytes]:
        if timeout is not None:
            ready, _, _ = select.select([self._sock], [], [], timeout)
            if not ready:
                return None
        return self._sock.recv(bufsize)

    def close(self) -> None:
        self._sock.close()


class VirtualWirePair:
    """
    Full-duplex virtual Layer-2 wire backed by a kernel `socketpair`.
    Provides deterministic boundary-preserving Ethernet frame transport between
    the Red Engine and Blue Engine in unprivileged environments without touching
    any physical NIC.
    """

    def __init__(self, red_name: str = "nsd-wire-red", blue_name: str = "nsd-wire-blue"):
        sock_a, sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.red_end = VirtualWireEndpoint(sock_a, red_name)
        self.blue_end = VirtualWireEndpoint(sock_b, blue_name)

    def close(self) -> None:
        self.red_end.close()
        self.blue_end.close()

    def __enter__(self) -> "VirtualWirePair":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
