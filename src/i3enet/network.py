"""Read macOS inventory and scoped routes. No vehicle sockets or configuration writes."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
import math
import os
import platform
import re
import socket
import subprocess
import sys
import time
from typing import Callable

from . import REPORT_SCHEMA_VERSION, __version__

LOCAL_COMMANDS = (
    ("/sbin/ifconfig", "-a"),
    ("/usr/sbin/networksetup", "-listallhardwareports"),
)

# Apple XNU xnu-12377.1.9, bsd/netinet/in.h: integer interface-index option.
# Darwin interface binding uses IP_BOUND_IF; it is unavailable on other platforms.
DARWIN_IP_BOUND_IF = 25
IP_BOUND_IF = getattr(socket, "IP_BOUND_IF", DARWIN_IP_BOUND_IF)
_ETHERNET_NAME = re.compile(r"en[0-9]{1,4}")

# Source-confirmed one-based bit positions in pinned XNU bsd/net/route.h.
# route.c/bprintf tests bit (position - 1); its b016 label uses an octal
# position (decimal 14), so it means NOIFREF rather than PRCLONING.
# Positions 20 and 32 have no assigned meaning and intentionally remain absent.
_ROUTE_FLAGS_BY_BIT = {
    1: "UP", 2: "GATEWAY", 3: "HOST", 4: "REJECT", 5: "DYNAMIC",
    6: "MODIFIED", 7: "DONE", 8: "DELCLONE", 9: "CLONING", 10: "XRESOLVE",
    11: "LLINFO", 12: "STATIC", 13: "BLACKHOLE", 14: "NOIFREF", 15: "PROTO2",
    16: "PROTO1", 17: "PRCLONING", 18: "WASCLONED", 19: "PROTO3",
    21: "PINNED", 22: "LOCAL", 23: "BROADCAST", 24: "MULTICAST", 25: "IFSCOPE",
    26: "CONDEMNED", 27: "IFREF", 28: "PROXY", 29: "ROUTER", 30: "DEAD", 31: "GLOBAL",
}
_ROUTE_FLAG_NAMES = frozenset(_ROUTE_FLAGS_BY_BIT.values())
_FORBIDDEN_ROUTE_FLAGS = frozenset({
    "GATEWAY", "REJECT", "BLACKHOLE", "CONDEMNED", "LOCAL", "MULTICAST",
    "ROUTER", "PROXY", "XRESOLVE", "DEAD", "GLOBAL",
})


class NetworkPreflightError(ValueError):
    """Fixed local failure reason; never include raw operating-system output."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class DiscoveryNetwork:
    """One observed, local, direct Ethernet scope; not a vehicle identity."""

    interface: str
    source_address: str
    broadcast_address: str
    interface_index: int
    netmask: str
    hardware_port: str
    route_verified: bool = True

    def __post_init__(self) -> None:
        if (not isinstance(self.interface, str)
                or _ETHERNET_NAME.fullmatch(self.interface) is None
                or type(self.interface_index) is not int
                or not 0 < self.interface_index <= 0x7fffffff
                or self.route_verified is not True
                or not _wired_hardware_label(self.hardware_port)):
            raise NetworkPreflightError("invalid_discovery_network_snapshot")
        try:
            source = ipaddress.IPv4Address(self.source_address)
            network = ipaddress.IPv4Network((self.source_address, self.netmask), strict=False)
        except (ValueError, TypeError):
            raise NetworkPreflightError("invalid_discovery_network_snapshot") from None
        if (str(source) != self.source_address or self.netmask != "255.255.0.0"
                or network != ipaddress.IPv4Network("169.254.0.0/16")
                or source in (network.network_address, network.broadcast_address)
                or self.broadcast_address != str(network.broadcast_address)):
            raise NetworkPreflightError("invalid_discovery_network_snapshot")


def _gateway_address(gateway_address: object, source_address: str) -> str:
    """Require an explicit canonical peer; never resolve or infer an address."""
    if type(gateway_address) is not str:
        raise NetworkPreflightError("link_local_unicast_gateway_required")
    try:
        gateway = ipaddress.IPv4Address(gateway_address)
    except ValueError:
        raise NetworkPreflightError("link_local_unicast_gateway_required") from None
    subnet = ipaddress.IPv4Network("169.254.0.0/16")
    if (str(gateway) != gateway_address or gateway not in subnet
            or gateway in (subnet.network_address, subnet.broadcast_address)
            or gateway_address == source_address):
        raise NetworkPreflightError("link_local_unicast_gateway_required")
    return str(gateway)


@dataclass(frozen=True)
class GatewayNetwork:
    """One explicit gateway and observed local route; no head-unit inference."""

    interface: str
    source_address: str
    gateway_address: str
    interface_index: int
    netmask: str
    hardware_port: str
    route_verified: bool = True

    def __post_init__(self) -> None:
        if any(type(value) is not str for value in (
            self.interface, self.source_address, self.gateway_address,
            self.netmask, self.hardware_port,
        )):
            raise NetworkPreflightError("invalid_gateway_network_snapshot")
        try:
            # Share the existing strict local snapshot checks, without implying
            # that construction itself performed a route query.
            DiscoveryNetwork(self.interface, self.source_address, "169.254.255.255",
                             self.interface_index, self.netmask, self.hardware_port,
                             self.route_verified)
            _gateway_address(self.gateway_address, self.source_address)
        except NetworkPreflightError:
            raise NetworkPreflightError("invalid_gateway_network_snapshot") from None


def _wired_hardware_label(label: object) -> bool:
    prohibited = ("wi-fi", "wifi", "wireless", "bridge", "tunnel", "vpn", "virtual")
    return (isinstance(label, str) and "ethernet" in label.casefold()
            and not any(word in label.casefold() for word in prohibited))


@dataclass
class Interface:
    name: str
    up: bool
    link_status: str = "unknown"
    hardware_port: str | None = None
    ipv4: list[str] = field(default_factory=list)


def parse_ifconfig(text: str) -> list[Interface]:
    """Keep observed flags/link/IPv4; deliberately omit MAC addresses and IPv6."""
    result: list[Interface] = []
    current: Interface | None = None
    for line in text.splitlines():
        header = re.match(r"^([A-Za-z][A-Za-z0-9_.-]*): flags=[0-9a-fA-F]+<([^>]*)>", line)
        if header:
            current = Interface(header[1], "UP" in header[2].split(","))
            result.append(current)
            continue
        if current is None:
            continue
        words = line.split()
        if len(words) == 2 and words[0] == "status:":
            if words[1] in ("active", "inactive"):
                current.link_status = words[1]
        if len(words) >= 2 and words[0] == "inet":
            try:
                address = str(ipaddress.IPv4Address(words[1]))
            except ipaddress.AddressValueError:
                continue
            if address not in current.ipv4:
                current.ipv4.append(address)
    return result


def parse_hardware_ports(text: str) -> dict[str, str]:
    """Read observed labels; do not infer which device is an ENET cable."""
    labels: dict[str, str] = {}
    label: str | None = None
    for line in text.splitlines():
        if line.startswith("Hardware Port: "):
            label = line.removeprefix("Hardware Port: ").strip()
        elif line.startswith("Device: ") and label:
            device = line.removeprefix("Device: ").strip()
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", device):
                labels[device] = label
            label = None
    return labels


def _run_local(command: tuple[str, ...], *, timeout: float = 5) -> subprocess.CompletedProcess[str]:
    selected_read = (len(command) == 2 and command[0] == "/sbin/ifconfig"
                     and _ETHERNET_NAME.fullmatch(command[1]) is not None)
    # Fixed numeric RTM_GET only: the observed /16 broadcast or an explicit
    # unicast peer in that /16. This reads local routing state, without ARP/probes.
    # Pinned XNU rtsock.c RTM_GET uses rt_lookup(TRUE), not RTM_RESOLVE/output.
    route_destination = False
    if len(command) == 6 and type(command[5]) is str:
        try:
            address = ipaddress.IPv4Address(command[5])
            subnet = ipaddress.IPv4Network("169.254.0.0/16")
            route_destination = (str(address) == command[5] and address in subnet
                                 and address != subnet.network_address)
        except ValueError:
            pass
    scoped_read = (len(command) == 6
                   and command[:4] == ("/sbin/route", "-n", "get", "-ifscope")
                   and _ETHERNET_NAME.fullmatch(command[4]) is not None
                   and route_destination)
    if command not in LOCAL_COMMANDS and not (selected_read or scoped_read):
        raise ValueError("Unreviewed local command")
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 0 < timeout <= 5):
        raise ValueError("Invalid local command timeout")
    return subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, check=False,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    )


def _checked_local_read(
    command: tuple[str, ...],
    runner: Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]],
    reason: str,
) -> str:
    try:
        completed = runner(command)
    except (OSError, subprocess.TimeoutExpired):
        raise NetworkPreflightError(reason) from None
    # route(8) can report certain RTM_GET errors with exit status zero.
    if completed.returncode != 0 or completed.stderr.strip() or not completed.stdout:
        raise NetworkPreflightError(reason)
    return completed.stdout


def _selected_ipv4_details(text: str, source: str) -> tuple[str, str | None]:
    """Validate one observed source record and its actual mask, omitting identifiers."""
    records = [line.split() for line in text.splitlines()
               if line.split()[:2] == ["inet", source]]
    if len(records) != 1:
        raise NetworkPreflightError("source_address_not_uniquely_observed")
    words = records[0]
    if words.count("netmask") != 1:
        raise NetworkPreflightError("source_netmask_unavailable")
    try:
        value = words[words.index("netmask") + 1]
        mask = str(ipaddress.IPv4Address(int(value, 16) if value.startswith("0x") else value))
        network = ipaddress.IPv4Network((source, mask), strict=False)
    except (IndexError, ValueError):
        raise NetworkPreflightError("source_netmask_invalid") from None
    if network != ipaddress.IPv4Network("169.254.0.0/16"):
        raise NetworkPreflightError("unsupported_discovery_subnet")
    broadcast = None
    if "broadcast" in words:
        if words.count("broadcast") != 1:
            raise NetworkPreflightError("observed_broadcast_invalid")
        try:
            broadcast = str(ipaddress.IPv4Address(words[words.index("broadcast") + 1]))
        except (IndexError, ValueError):
            raise NetworkPreflightError("observed_broadcast_invalid") from None
        if broadcast != str(network.broadcast_address):
            raise NetworkPreflightError("observed_broadcast_mismatch")
    return mask, broadcast


def _parse_route_flags(text: str) -> frozenset[str]:
    """Normalize only pinned flag names/bit meanings; unknown bits fail closed."""
    token_shape = r"(?:[A-Z][A-Z0-9]*|b[0-7]{3})"
    if re.fullmatch(rf"<{token_shape}(?:,{token_shape})*>", text) is None:
        raise NetworkPreflightError("route_flags_unavailable")
    result: set[str] = set()
    for token in text[1:-1].split(","):
        if token.startswith("b"):
            # The placeholder's suffix is octal and its position is one-based.
            # Decode before safety checks, so even a numeric GATEWAY/REJECT
            # rendering cannot evade the forbidden-name checks below.
            name = _ROUTE_FLAGS_BY_BIT.get(int(token[1:], 8))
        else:
            name = token if token in _ROUTE_FLAG_NAMES else None
        if name is None:
            raise NetworkPreflightError("route_flags_unknown")
        if name in result:
            raise NetworkPreflightError("route_flags_ambiguous")
        result.add(name)
    return frozenset(result)


def _validate_scoped_route(text: str, interface: str, destination_address: str,
                           netmask: str, *, unicast: bool = False) -> None:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\s*(route to|destination|mask|gateway|interface|flags):\s*(.*?)\s*", line)
        if match:
            if match[1] in fields:
                raise NetworkPreflightError("route_output_ambiguous")
            fields[match[1]] = match[2]
    if fields.get("route to") != destination_address or fields.get("interface") != interface:
        raise NetworkPreflightError("scoped_route_not_verified")
    observed_flags = _parse_route_flags(fields.get("flags", ""))
    forbidden = _FORBIDDEN_ROUTE_FLAGS | ({"BROADCAST"} if unicast else set())
    if "UP" not in observed_flags or observed_flags & forbidden or "gateway" in fields:
        raise NetworkPreflightError("route_not_direct_ethernet")
    # Numeric route(8) output can return the containing network or a host route.
    # Admit only the observed /16 itself or the exact selected host, never default.
    destination = fields.get("destination")
    network = ipaddress.IPv4Network((destination_address, netmask), strict=False)
    if destination == str(network.network_address):
        if fields.get("mask") != netmask or "HOST" in observed_flags:
            raise NetworkPreflightError("route_scope_mismatch")
    elif destination == destination_address:
        if "HOST" not in observed_flags or fields.get("mask") not in (None, "255.255.255.255"):
            raise NetworkPreflightError("route_scope_mismatch")
    else:
        raise NetworkPreflightError("route_scope_mismatch")


def _observe_ethernet(
    interface: str,
    source_address: str,
    *,
    system: str | None = None,
    runner: Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]] = _run_local,
    index_lookup: Callable[[str], int] | None = None,
) -> tuple[str, int, str, str, tuple[str, ...]]:
    """Read the selected wired interface/source; do not yet assert any route."""
    if (system or platform.system()) != "Darwin":
        raise NetworkPreflightError("macos_required")
    if not isinstance(interface, str) or _ETHERNET_NAME.fullmatch(interface) is None:
        raise NetworkPreflightError("explicit_ethernet_interface_required")
    try:
        address = ipaddress.IPv4Address(source_address)
    except (ValueError, TypeError):
        raise NetworkPreflightError("explicit_ipv4_source_required") from None
    network = ipaddress.IPv4Network("169.254.0.0/16")
    if (str(address) != source_address or address not in network
            or address in (network.network_address, network.broadcast_address)):
        raise NetworkPreflightError("link_local_unicast_source_required")
    observed = _checked_local_read(("/sbin/ifconfig", interface), runner, "selected_interface_unavailable")
    interfaces = parse_ifconfig(observed)
    if len(interfaces) != 1 or interfaces[0].name != interface:
        raise NetworkPreflightError("selected_interface_not_observed")
    selected = interfaces[0]
    header = re.match(r"^[^:]+: flags=[0-9a-fA-F]+<([^>]*)>", observed)
    flags = set(header[1].split(",")) if header else set()
    if (not selected.up or selected.link_status != "active" or "BROADCAST" not in flags
            or len(re.findall(r"^\s*status:", observed, re.MULTILINE)) != 1
            or flags & {"LOOPBACK", "POINTOPOINT"}):
        raise NetworkPreflightError("selected_ethernet_link_not_active")
    if str(address) not in selected.ipv4:
        raise NetworkPreflightError("source_address_not_observed")
    mask, _ = _selected_ipv4_details(observed, str(address))
    hardware_text = _checked_local_read(LOCAL_COMMANDS[1], runner, "hardware_port_labels_unavailable")
    if len(re.findall(rf"^Device: {re.escape(interface)}\s*$", hardware_text, re.MULTILINE)) != 1:
        raise NetworkPreflightError("hardware_port_label_not_uniquely_observed")
    hardware = parse_hardware_ports(hardware_text).get(interface)
    # Positive observed Ethernet label plus explicit rejection of virtual/wireless
    # labels. Device names alone do not identify an ENET adapter.
    if not _wired_hardware_label(hardware):
        raise NetworkPreflightError("selected_hardware_not_wired_ethernet")
    try:
        index = (index_lookup or socket.if_nametoindex)(interface)
    except OSError:
        raise NetworkPreflightError("interface_index_unavailable") from None
    if type(index) is not int or not 0 < index <= 0x7fffffff:
        raise NetworkPreflightError("interface_index_invalid")
    return str(address), index, mask, hardware, tuple(selected.ipv4)


def discovery_preflight(
    interface: str,
    source_address: str,
    *,
    system: str | None = None,
    runner: Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]] = _run_local,
    index_lookup: Callable[[str], int] | None = None,
) -> DiscoveryNetwork:
    """Validate local Ethernet/source/broadcast route; no DNS or vehicle probe."""
    address, index, mask, hardware, _ = _observe_ethernet(
        interface, source_address, system=system, runner=runner, index_lookup=index_lookup,
    )
    broadcast = str(ipaddress.IPv4Network((address, mask), strict=False).broadcast_address)
    route_text = _checked_local_read(("/sbin/route", "-n", "get", "-ifscope", interface, broadcast),
                                    runner, "scoped_route_unavailable")
    _validate_scoped_route(route_text, interface, broadcast, mask)
    return DiscoveryNetwork(interface, address, broadcast, index, mask, hardware)


def identity_preflight(
    interface: str,
    source_address: str,
    gateway_address: str,
    *,
    system: str | None = None,
    runner: Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]] = _run_local,
    index_lookup: Callable[[str], int] | None = None,
    deadline: float | None = None,
) -> GatewayNetwork:
    """Read exact local interface/source/unicast route; never contact the gateway.

    The caller must select a previously reviewed discovery peer. This function
    validates host state, not provenance, reachability or vehicle identity.
    """
    if type(interface) is not str:
        raise NetworkPreflightError("explicit_ethernet_interface_required")
    if type(source_address) is not str:
        raise NetworkPreflightError("explicit_ipv4_source_required")
    if deadline is not None:
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise NetworkPreflightError("identity_preflight_deadline_invalid")
        original_runner = runner

        def bounded_runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NetworkPreflightError("identity_preflight_deadline_exhausted")
            if original_runner is _run_local:
                completed = _run_local(command, timeout=min(5.0, remaining))
            else:
                # Custom runners exist for mocked offline tests; production has
                # only the fixed local subprocess runner above.
                completed = original_runner(command)
            if time.monotonic() >= deadline:
                raise NetworkPreflightError("identity_preflight_deadline_exhausted")
            return completed

        runner = bounded_runner
    gateway = _gateway_address(gateway_address, source_address)
    address, index, mask, hardware, local_addresses = _observe_ethernet(
        interface, source_address, system=system, runner=runner, index_lookup=index_lookup,
    )
    if gateway in local_addresses:
        raise NetworkPreflightError("gateway_is_local_interface_address")
    route_text = _checked_local_read(("/sbin/route", "-n", "get", "-ifscope", interface, gateway),
                                    runner, "scoped_gateway_route_unavailable")
    _validate_scoped_route(route_text, interface, gateway, mask, unicast=True)
    return GatewayNetwork(interface, address, gateway, index, mask, hardware)


def doctor(
    *,
    system: str | None = None,
    runner: Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]] = _run_local,
) -> dict[str, object]:
    """Collect local facts. No DNS, socket construction, route probe or car access."""
    system = system or platform.system()
    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "implementation_version": __version__,
        "command": "doctor", "mode": "local_only",
        "platform": {"system": system, "release": platform.release(),
                     "macos_version": platform.mac_ver()[0] if system == "Darwin" else None,
                     "architecture": platform.machine(), "python": platform.python_version(),
                     "python_supported": sys.version_info >= (3, 11)},
        "vehicle_contacted": False, "vehicle_packets_sent": 0,
        "transport_identity_status": "not_tested",
        "vehicle_identity_status": "unknown", "writes_supported": False,
        "route_verified": False, "interfaces": [], "issues": [],
        "local_inspection_status": "complete",
        "evidence_status": "LOCAL_OBSERVATION",
    }
    issues: list[str] = []
    if system != "Darwin":
        report.update(local_inspection_status="unsupported_platform", issues=["macos_required"])
        return report
    outputs: list[str] = []
    for command in LOCAL_COMMANDS:
        try:
            completed = runner(command)
            # Some networksetup failures return 0: require expected content too.
            expected = "flags=" if command[0] == "/sbin/ifconfig" else "Hardware Port: "
            if completed.returncode != 0 or expected not in completed.stdout:
                issues.append("ifconfig_unavailable" if command[0] == "/sbin/ifconfig"
                              else "hardware_port_labels_unavailable")
                outputs.append("")
            else:
                outputs.append(completed.stdout)
        except (OSError, subprocess.TimeoutExpired):
            issues.append("ifconfig_unavailable" if command[0] == "/sbin/ifconfig"
                          else "hardware_port_labels_unavailable")
            outputs.append("")
    interfaces = parse_ifconfig(outputs[0])
    labels = parse_hardware_ports(outputs[1])
    for interface in interfaces:
        interface.hardware_port = labels.get(interface.name)
    report["interfaces"] = [asdict(interface) for interface in interfaces]
    report["issues"] = issues
    if issues:
        report["local_inspection_status"] = "partial"
    return report
