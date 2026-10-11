"""One explicitly selected, bounded macOS UDP discovery experiment.

This module never connects diagnostic TCP or retransmits. Importing it does not
open sockets. Raw datagrams remain private and must be persisted by the caller
after this experiment closes its socket; public_report deliberately omits them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import socket
import time

from .discovery import (
    DEFAULT_MAX_DISCOVERY_BODY_LENGTH,
    DISCOVERY_PORT,
    DISCOVERY_REQUEST,
    DiscoveryError,
    DiscoveryResponse,
    parse_discovery_response,
)
from .network import DiscoveryNetwork, IP_BOUND_IF, NetworkPreflightError, discovery_preflight
from .policy import LiveDiscoveryPolicy, Phase, PolicyViolation


RECEIVE_WINDOW_SECONDS = 3.0  # Project experiment bound, not a protocol deadline.
MAX_RECEIVED_DATAGRAMS = 32
MAX_RECEIVED_DATAGRAM_BYTES = 65535  # Full IPv4 UDP payload fits; parser still caps bodies at 4096.


@dataclass(frozen=True, slots=True)
class ReceivedDatagram:
    """Private bytes, including rejected replies and incomplete truncated prefixes."""

    data: bytes = field(repr=False)
    peer_address: str
    peer_port: int
    truncated: bool
    disposition: str
    reason: str | None
    received_after_seconds: float | None


@dataclass(frozen=True, slots=True)
class GatewayCandidate:
    address: str
    port: int
    responses: tuple[DiscoveryResponse, ...] = field(repr=False)

    @property
    def identity_conflict(self) -> bool:
        return any(
            len({value for reply in self.responses
                 if (value := getattr(reply, attribute)) is not None}) > 1
            for attribute in ("vin_candidate", "mac_candidate")
        )

    def public_report(self) -> dict[str, object]:
        return {
            "address": self.address,
            "port": self.port,
            "reply_count": len(self.responses),
            "layouts": sorted({reply.layout for reply in self.responses}),
            "masked_vin_candidates": sorted({reply.masked_vin for reply in self.responses
                                             if reply.masked_vin is not None}),
            "identity_conflict": self.identity_conflict,
            "identity_status": "unverified_candidate",
            "head_unit_status": "unknown",
            "warnings": sorted({warning for reply in self.responses for warning in reply.warnings}),
            "decoder_evidence_status": "SOURCE_CONFIRMED",
            "response_evidence_status": "UNVERIFIED",
        }


@dataclass(frozen=True, slots=True)
class LiveDiscoveryResult:
    outcome: str
    reason: str | None
    vehicle_packets_attempted: int
    vehicle_packets_sent: int
    vehicle_bytes_confirmed_sent: int
    transmission_uncertain: bool
    datagrams: tuple[ReceivedDatagram, ...] = field(repr=False)
    candidates: tuple[GatewayCandidate, ...]
    elapsed_seconds: float | None
    timing_complete: bool = True
    socket_close_uncertain: bool = False

    def public_report(self) -> dict[str, object]:
        """Only non-identifying protocol summaries and masked candidate VINs."""
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "vehicle_packets_attempted": self.vehicle_packets_attempted,
            "vehicle_packets_sent": self.vehicle_packets_sent,
            "vehicle_bytes_confirmed_sent": self.vehicle_bytes_confirmed_sent,
            "transmission_uncertain": self.transmission_uncertain,
            "socket_close_uncertain": self.socket_close_uncertain,
            "received_datagrams": len(self.datagrams),
            "captured_bytes": sum(len(item.data) for item in self.datagrams),
            "truncated_datagrams": sum(item.truncated for item in self.datagrams),
            "rejected_datagrams": sum(item.disposition != "candidate" for item in self.datagrams),
            "candidates": [candidate.public_report() for candidate in self.candidates],
            "gateway_selection_status": "explicit_selection_required" if self.candidates else "unavailable",
            "vehicle_identity_status": "unknown",
            "elapsed_seconds": self.elapsed_seconds,
            "timing_complete": self.timing_complete,
            "receive_window_seconds": RECEIVE_WINDOW_SECONDS,
            "receive_datagram_limit": MAX_RECEIVED_DATAGRAMS,
            "receive_datagram_byte_limit": MAX_RECEIVED_DATAGRAM_BYTES,
            "writes_supported": False,
        }


def _peer_reason(peer_address: str, peer_port: int, network: DiscoveryNetwork) -> str | None:
    try:
        peer = ipaddress.IPv4Address(peer_address)
        subnet = ipaddress.IPv4Network(f"{network.source_address}/{network.netmask}", strict=False)
    except ipaddress.AddressValueError:
        return "invalid_peer_address"
    if peer_port != DISCOVERY_PORT:
        return "unexpected_peer_port"
    if peer_address == network.source_address:
        return "local_source_echo"
    if peer not in subnet or peer in (subnet.network_address, subnet.broadcast_address):
        return "peer_outside_selected_host_range"
    return None


def discover_once(network: DiscoveryNetwork) -> LiveDiscoveryResult:
    """Send one approved request and receive for at most three seconds.

    The CLI must explicitly authorize this live experiment. A frozen, previously
    reviewed local preflight is required and is rechecked here. Tests patch the
    real module APIs; production exposes no socket/sender/clock injection.
    """
    if type(network) is not DiscoveryNetwork:
        raise TypeError("discovery requires an exact frozen DiscoveryNetwork")
    start: float | None = None
    captured: list[ReceivedDatagram] = []
    responses: dict[str, list[DiscoveryResponse]] = {}
    attempted = sent = confirmed_bytes = 0
    uncertain = False
    timing_complete = True
    socket_close_uncertain = False
    outcome, reason = "timeout", None
    sock: socket.socket | None = None
    stage = "preflight"
    try:
        start = time.monotonic()
        policy = LiveDiscoveryPolicy(network, phase=Phase.LIVE_DISCOVERY)
        if discovery_preflight(network.interface, network.source_address) != network:
            outcome, reason = "network_changed", "preflight_changed"
        else:
            stage = "socket_creation"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            stage = "socket_binding"
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, network.interface_index)
            sock.bind((network.source_address, 0))
            stage = "final_preflight"
            if discovery_preflight(network.interface, network.source_address) != network:
                outcome, reason = "network_changed", "preflight_changed"
            elif sock.getsockopt(socket.IPPROTO_IP, IP_BOUND_IF) != network.interface_index:
                outcome, reason = "network_changed", "interface_binding_not_confirmed"
            elif (local := sock.getsockname())[0] != network.source_address or not 1 <= local[1] <= 65535:
                outcome, reason = "network_changed", "source_binding_not_confirmed"
            else:
                destination = (network.broadcast_address, DISCOVERY_PORT)
                stage = "send"
                sock.settimeout(RECEIVE_WINDOW_SECONDS)
                # This is the sole network send boundary. No retry or helper send
                # exists. Check the complete immutable payload and endpoint last.
                policy.validate(DISCOVERY_REQUEST, destination, sent_count=attempted)
                attempted = 1
                uncertain = True
                count = sock.sendto(DISCOVERY_REQUEST, destination)
                if type(count) is not int or not 0 <= count <= len(DISCOVERY_REQUEST):
                    outcome, reason = "socket_error", "invalid_send_accounting"
                elif count != len(DISCOVERY_REQUEST):
                    confirmed_bytes = count
                    outcome, reason = "socket_error", "partial_datagram_send"
                else:
                    confirmed_bytes = count
                    sent = 1
                    uncertain = False
                    send_time = time.monotonic()
                    deadline = send_time + RECEIVE_WINDOW_SECONDS
                    stage = "receive"
                    while len(captured) < MAX_RECEIVED_DATAGRAMS:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            break
                        sock.settimeout(remaining)
                        try:
                            data, _ancillary, flags, peer = sock.recvmsg(MAX_RECEIVED_DATAGRAM_BYTES)
                        except socket.timeout:
                            break
                        # Retain the original bytes before even sampling the
                        # clock. An interrupted sample leaves an explicitly
                        # unknown timestamp rather than losing the datagram.
                        truncated = bool(flags & socket.MSG_TRUNC)
                        peer_address, peer_port = peer[0], peer[1]
                        captured.append(ReceivedDatagram(
                            data, peer_address, peer_port, truncated, "unprocessed",
                            "classification_incomplete", None,
                        ))
                        try:
                            received_at = time.monotonic()
                        except KeyboardInterrupt:
                            timing_complete = False
                            raise
                        received_after = round(max(0.0, received_at - send_time), 6)
                        captured[-1] = ReceivedDatagram(
                            data, peer_address, peer_port, truncated, "unprocessed",
                            "classification_incomplete", received_after,
                        )
                        rejection = _peer_reason(peer_address, peer_port, network)
                        disposition = "rejected_peer" if rejection else "malformed"
                        if truncated:
                            rejection, disposition = "truncated_datagram", "malformed"
                        elif rejection is None:
                            try:
                                reply = parse_discovery_response(
                                    data, max_body_length=DEFAULT_MAX_DISCOVERY_BODY_LENGTH,
                                )
                            except DiscoveryError:
                                rejection = "invalid_discovery_reply"
                            else:
                                disposition = "candidate"
                                responses.setdefault(peer_address, []).append(reply)
                        captured[-1] = ReceivedDatagram(
                            data, peer_address, peer_port, truncated, disposition,
                            rejection, received_after,
                        )
                    if len(captured) >= MAX_RECEIVED_DATAGRAMS:
                        outcome, reason = "reply_limit", "receive_datagram_budget_exhausted"
                    elif len(responses) > 1:
                        outcome, reason = "multiple_gateways", "explicit_gateway_selection_required"
                    elif responses:
                        candidate = GatewayCandidate(next(iter(responses)), DISCOVERY_PORT,
                                                     tuple(next(iter(responses.values()))))
                        if candidate.identity_conflict:
                            outcome, reason = "ambiguous_gateway", "conflicting_identity_candidates"
                        else:
                            outcome, reason = "gateway_found", None
                    elif any(item.disposition == "malformed" for item in captured):
                        outcome, reason = "malformed_response", "no_valid_gateway_reply"
                    elif captured:
                        outcome, reason = "unexpected_peer_only", "no_eligible_gateway_peer"
    except NetworkPreflightError:
        outcome, reason = "network_changed", "preflight_no_longer_valid"
    except PolicyViolation:
        outcome, reason = "policy_denied", "final_send_policy_rejected"
    except KeyboardInterrupt:
        outcome, reason = "interrupted", "user_interrupt"
    except OSError:
        outcome, reason = "socket_error", f"{stage}_failed"
    finally:
        if sock is not None:
            try:
                sock.close()
            except KeyboardInterrupt:
                outcome, reason = "interrupted", "socket_close_interrupted"
                socket_close_uncertain = True
            except OSError:
                outcome, reason = "socket_error", "socket_close_failed"
                socket_close_uncertain = True
    try:
        finished = time.monotonic()
    except KeyboardInterrupt:
        outcome, reason = "interrupted", "final_clock_sampling_interrupted"
        elapsed = None
        timing_complete = False
    else:
        if start is None:
            elapsed = None
            timing_complete = False
        else:
            elapsed = round(max(0.0, finished - start), 6)
    candidates = tuple(GatewayCandidate(address, DISCOVERY_PORT, tuple(replies))
                       for address, replies in sorted(responses.items()))
    return LiveDiscoveryResult(
        outcome, reason, attempted, sent, confirmed_bytes, uncertain,
        tuple(captured), candidates, elapsed,
        timing_complete=timing_complete, socket_close_uncertain=socket_close_uncertain,
    )
