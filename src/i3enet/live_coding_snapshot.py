"""Prepared fixed module-group reader; import performs no vehicle operation.

Only an explicitly selected caller may invoke this client. It acquires the
selected CAFD's fixed coding groups on one connection, with one attempt per
fixed request and no helper, retry, authentication, signing or write path.
Original chunks and opaque values remain private. Success describes bounded
acquisition, not atomic ECU state, signature validity or safe writing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import socket
import time

from .evidence import GatewayVINReadEvidence
from .hsfz import Control, HSFZError, IncrementalParser
from .live_block import _exbox_svk_evidence_matches, _bdc_svk_evidence_matches, _exbox_vin_evidence_matches
from .coding_contract import contract
from .live_identity import (
    CONNECT_TIMEOUT_SECONDS, DIAGNOSTIC_PORT, FIRST_RESPONSE_WINDOW_SECONDS,
    MAX_FRAME_BODY_BYTES, MAX_RAW_RECEIVE_BYTES, MAX_RECEIVE_CHUNKS,
    OVERALL_REQUEST_WINDOW_SECONDS, PENDING_RESPONSE_WINDOW_SECONDS,
    RECEIVE_CHUNK_BYTES, ReceivedTCPChunk, TESTER_ADDRESS, _DeadlineExpired,
    _bound_source_reason, _remaining_seconds,
)
from .network import GatewayNetwork, IP_BOUND_IF, NetworkPreflightError, identity_preflight
from .policy import PolicyViolation
from .svk import HeadUnitSVKEvidence, BDCSVKEvidence, VSGSVKEvidence
from .uds import (
    MalformedResponseError, NegativeResponse, ReadDataByIdentifierRequest,
    UnexpectedResponseError, parse_read_data_response,
)


GROUP_LENGTHS = ((0x3000, 152), (0x3001, 151), (0x3002, 150),
                 (0x3003, 150), (0x3004, 150), (0x3005, 150),
                 (0x3006, 8), (0x3007, 132))
SNAPSHOT_REQUESTS = tuple(bytes.fromhex("000000050001f46322") + group.to_bytes(2, "big")
                          for group, _length in GROUP_LENGTHS)
SNAPSHOT_WINDOW_SECONDS = 30.0
MAX_APPLICATION_ATTEMPTS = 8
MAX_APPLICATION_BYTES = 88
HEAD_UNIT_ADDRESS = 0x63


class SnapshotPhase(Enum):
    DENY = "deny"
    LIVE_CURRENT_CODING_SNAPSHOT = "live_current_coding_snapshot"


@dataclass(frozen=True, slots=True)
class LiveCodingSnapshotPolicy:
    """Default-deny next-frame policy, separate from every other live phase."""

    network: GatewayNetwork
    phase: SnapshotPhase = SnapshotPhase.DENY
    module: str = "HU"

    def validate(self, payload: bytes, destination: tuple[str, int], *,
                 sent_count: int = 0, completed_groups: int = 0) -> None:
        if type(self.phase) is not SnapshotPhase or self.phase is not SnapshotPhase.LIVE_CURRENT_CODING_SNAPSHOT:
            raise PolicyViolation("snapshot_phase_denied")
        if type(self.network) is not GatewayNetwork:
            raise PolicyViolation("snapshot_network_invalid")
        try:
            GatewayNetwork.__post_init__(self.network)
        except (NetworkPreflightError, TypeError, ValueError, AttributeError):
            raise PolicyViolation("snapshot_network_invalid") from None
        spec = contract(self.module)
        if (type(sent_count) is not int or type(completed_groups) is not int
                or not 0 <= sent_count < len(spec.groups)
                or completed_groups != sent_count):
            raise PolicyViolation("snapshot_attempt_sequence_invalid")
        if type(payload) is not bytes or payload != spec.requests[sent_count]:
            raise PolicyViolation("snapshot_next_frame_invalid")
        if (type(destination) is not tuple or len(destination) != 2
                or type(destination[0]) is not str or type(destination[1]) is not int
                or destination != (self.network.gateway_address, DIAGNOSTIC_PORT)):
            raise PolicyViolation("snapshot_destination_invalid")


@dataclass(frozen=True, slots=True)
class CodingSnapshotResult:
    outcome: str
    reason: str | None
    tcp_connections_attempted: int
    tcp_connections_opened: int
    tcp_connection_uncertain: bool
    application_frames_attempted: int
    application_frames_sent: int
    vehicle_bytes_confirmed_sent: int
    transmission_uncertain: bool
    request_bytes: tuple[bytes, ...] = field(repr=False)
    recv_chunks: tuple[ReceivedTCPChunk, ...] = field(repr=False)
    chunk_group_addresses: tuple[int, ...]
    groups: tuple[tuple[int, bytes], ...] = field(repr=False)
    ack_count: int
    pending_count: int
    nrc: int | None
    last_control: int | None
    elapsed_seconds: float | None
    experiment_elapsed_seconds: float | None
    timing_complete: bool
    tcp_close_uncertain: bool
    module: str = "HU"

    def public_report(self) -> dict[str, object]:
        spec = contract(self.module)
        complete = (self.outcome == "snapshot_observed" and self.timing_complete
                    and not self.tcp_close_uncertain and not self.transmission_uncertain
                    and not self.tcp_connection_uncertain
                    and self.tcp_connections_attempted == self.tcp_connections_opened == 1
                    and self.application_frames_attempted == self.application_frames_sent == len(spec.groups)
                    and self.vehicle_bytes_confirmed_sent == 11*len(spec.groups) and self.ack_count == len(spec.groups)
                    and self.nrc is None and self.last_control == int(Control.DIAGNOSTIC)
                    and tuple((a, len(v)) for a, v in self.groups) == spec.groups)
        return {
            "outcome": self.outcome, "reason": self.reason,
            "tcp_connections_attempted": self.tcp_connections_attempted,
            "tcp_connections_opened": self.tcp_connections_opened,
            "tcp_connection_uncertain": self.tcp_connection_uncertain,
            "application_frames_attempted": self.application_frames_attempted,
            "application_frames_sent": self.application_frames_sent,
            "vehicle_bytes_confirmed_sent": self.vehicle_bytes_confirmed_sent,
            "transmission_uncertain": self.transmission_uncertain,
            "tcp_close_uncertain": self.tcp_close_uncertain,
            "tcp_control_traffic_counted": False,
            "received_chunks": len(self.recv_chunks),
            "received_bytes": sum(len(chunk.data) for chunk in self.recv_chunks),
            "completed_group_count": len(self.groups),
            "snapshot_complete": complete,
            "groups": [{"address": f"0x{address:04X}", "value_byte_count": len(value),
                        "value_sha256": hashlib.sha256(value).hexdigest()}
                       for address, value in self.groups] if complete else [],
            "ack_count": self.ack_count, "pending_count": self.pending_count,
            "nrc": None if self.nrc is None else f"0x{self.nrc:02X}",
            "last_control": None if self.last_control is None else f"0x{self.last_control:04X}",
            "elapsed_seconds": self.elapsed_seconds,
            "experiment_elapsed_seconds": self.experiment_elapsed_seconds,
            "timing_complete": self.timing_complete,
            "experiment_overall_window_seconds": SNAPSHOT_WINDOW_SECONDS,
            "connect_timeout_seconds": CONNECT_TIMEOUT_SECONDS,
            "first_response_window_seconds": FIRST_RESPONSE_WINDOW_SECONDS,
            "pending_response_window_seconds": PENDING_RESPONSE_WINDOW_SECONDS,
            "overall_request_window_seconds": OVERALL_REQUEST_WINDOW_SECONDS,
            "maximum_application_frames": len(spec.groups),
            "maximum_application_bytes": 11*len(spec.groups),
            "receive_byte_limit": MAX_RAW_RECEIVE_BYTES,
            "receive_chunk_limit": spec.receive_chunks,
            "receive_frame_body_limit": MAX_FRAME_BODY_BYTES,
            "timing_source": "project_bounds_not_ecu_reported_timings",
            "target_address": f"0x{spec.target:02X}", "ecu_software_status": "prior_svk_observed",
            "snapshot_coherence_status": "sequential_bounded_reads_not_atomic",
            "original_signature_status": "not_checked",
            "writes_supported": False,
        }


class _Stopped(Exception):
    def __init__(self, outcome: str, reason: str) -> None:
        self.outcome, self.reason = outcome, reason


def read_current_coding_snapshot(network: GatewayNetwork, evidence: GatewayVINReadEvidence,
                                 svk: HeadUnitSVKEvidence) -> CodingSnapshotResult:
    """Acquire only the fixed ordered groups, once each, on one connection.

    The caller must first prepare private storage and explicitly select this
    operation. Evidence loaders must have verified pinned immutable originals.
    There is no sender/clock/socket injection argument or arbitrary read input.
    """
    if (type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence
            or type(svk) is not HeadUnitSVKEvidence):
        raise TypeError("snapshot requires exact frozen network, VIN and SVK evidence types")
    return _read_snapshot(network, evidence, svk, 'HU')

def read_bdc_coding_snapshot(network: GatewayNetwork, evidence: GatewayVINReadEvidence,
                             svk: BDCSVKEvidence) -> CodingSnapshotResult:
    """One fixed 82-group BDC capture; no session, authentication or writes."""
    if (type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence
            or type(svk) is not BDCSVKEvidence):
        raise TypeError('BDC snapshot requires exact frozen network, VIN and BDC SVK proofs')
    return _read_snapshot(network, evidence, svk, 'BDC')


def read_vsg_coding_snapshot(network: GatewayNetwork, evidence: GatewayVINReadEvidence,
                             svk: VSGSVKEvidence) -> CodingSnapshotResult:
    if (type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence
            or type(svk) is not VSGSVKEvidence):
        raise TypeError('VSG snapshot requires exact network, VIN and VSG SVK proofs')
    return _read_snapshot(network, evidence, svk, 'VSG01')

def _read_snapshot(network, evidence, svk, module):
    spec = contract(module)
    chunk_cap = MAX_RECEIVE_CHUNKS if module == 'HU' else spec.receive_chunks
    start = deadline = None
    captured: list[ReceivedTCPChunk] = []
    chunk_groups: list[int] = []
    groups: list[tuple[int, bytes]] = []
    requests: list[bytes] = []
    received_bytes = 0
    connection_attempts = connections_opened = attempts = sent = confirmed_bytes = 0
    connection_uncertain = transmission_uncertain = close_uncertain = False
    timing_complete = True
    ack_count = pending_count = 0
    nrc = last_control = None
    outcome, reason = "timeout", "response_deadline_exhausted"
    sock: socket.socket | None = None
    stage = "preflight"

    def stop(failure: str, why: str) -> None:
        raise _Stopped(failure, why)

    def fresh_network() -> None:
        if identity_preflight(network.interface, network.source_address, network.gateway_address,
                              deadline=deadline) != network:
            stop("network_changed", "preflight_changed")
        _remaining_seconds(deadline)

    try:
        start = time.monotonic()
        deadline = start + SNAPSHOT_WINDOW_SECONDS
        GatewayNetwork.__post_init__(network)
        if not _exbox_vin_evidence_matches(network, evidence):
            stop("evidence_mismatch", "verified_vin_evidence_not_bound_to_network")
        from .live_block import _block_svk_matches
        if not _block_svk_matches(network, evidence, svk, module=module):
            stop("evidence_mismatch", "verified_svk_evidence_not_bound_to_network_or_identity")
        fresh_network()
        policy = LiveCodingSnapshotPolicy(network, SnapshotPhase.LIVE_CURRENT_CODING_SNAPSHOT, module)
        stage = "socket_creation"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        stage = "socket_binding"
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, network.interface_index)
        sock.bind((network.source_address, 0))
        stage = "connect_preflight"
        fresh_network()
        if (binding_reason := _bound_source_reason(sock, network)):
            stop("network_changed", binding_reason)
        endpoint = (network.gateway_address, DIAGNOSTIC_PORT)
        stage = "connect"
        sock.settimeout(min(CONNECT_TIMEOUT_SECONDS, _remaining_seconds(deadline)))
        _remaining_seconds(deadline)
        connection_attempts = 1
        connection_uncertain = True
        sock.connect(endpoint)
        connections_opened = 1
        connection_uncertain = False

        for index, (address, expected_length) in enumerate(spec.groups):
            stage = "send_preflight"
            fresh_network()
            if sock.getpeername() != endpoint:
                stop("network_changed", "connected_peer_not_confirmed")
            if (binding_reason := _bound_source_reason(sock, network)):
                stop("network_changed", binding_reason)
            request_started = time.monotonic()
            group_deadline = min(deadline, request_started + OVERALL_REQUEST_WINDOW_SECONDS)
            stage = "send"
            sock.settimeout(min(FIRST_RESPONSE_WINDOW_SECONDS, _remaining_seconds(group_deadline)))
            payload = spec.requests[index]
            _remaining_seconds(group_deadline)
            policy.validate(payload, endpoint, sent_count=attempts, completed_groups=len(groups))
            _remaining_seconds(group_deadline)
            # Record the attempt before socket.send; never finish a short send.
            requests.append(payload)
            attempts += 1
            transmission_uncertain = True
            count = sock.send(payload)
            if type(count) is not int or not 0 <= count <= len(payload):
                stop("socket_error", "invalid_send_accounting")
            confirmed_bytes += count
            if count != len(payload):
                stop("socket_error", "partial_application_frame_send")
            sent += 1
            transmission_uncertain = False
            parser = IncrementalParser(max_body_length=MAX_FRAME_BODY_BYTES)
            request = ReadDataByIdentifierRequest(address)
            response_deadline = min(group_deadline, time.monotonic() + FIRST_RESPONSE_WINDOW_SECONDS)
            group_ack_count = 0
            stage = "receive"

            while True:
                if len(captured) >= chunk_cap:
                    stop("receive_limit", "receive_chunk_budget_exhausted")
                if received_bytes >= MAX_RAW_RECEIVE_BYTES:
                    stop("receive_limit", "receive_byte_budget_exhausted")
                sock.settimeout(_remaining_seconds(min(group_deadline, response_deadline)))
                data = sock.recv(min(RECEIVE_CHUNK_BYTES, MAX_RAW_RECEIVE_BYTES - received_bytes))
                if type(data) is not bytes:
                    stop("socket_error", "invalid_receive_accounting")
                if data:
                    # Raw receipt and attribution precede every clock/parse call.
                    captured.append(ReceivedTCPChunk(data, None))
                    chunk_groups.append(address)
                    received_bytes += len(data)
                received_at = time.monotonic()
                if not data:
                    try:
                        parser.finish()
                    except HSFZError:
                        stop("truncated_response", "eof_during_hsfz_frame")
                    stop("eof", "gateway_closed_before_terminal_response")
                captured[-1] = ReceivedTCPChunk(data, round(max(0.0, received_at - start), 6))
                if received_at >= min(group_deadline, response_deadline):
                    stop("timeout", "response_deadline_exhausted")
                terminal_value = None
                for incoming in parser.feed(data):
                    last_control = int(incoming.control)
                    if terminal_value is not None:
                        stop("unexpected_response", "additional_frame_after_terminal_response")
                    if incoming.control is Control.ACK:
                        if group_ack_count:
                            stop("unexpected_response", "duplicate_ack")
                        if ((incoming.source, incoming.target) != (TESTER_ADDRESS, spec.target)
                                or incoming.diagnostic_payload != payload[8:]):
                            stop("unexpected_response", "ack_not_correlated")
                        group_ack_count += 1
                        ack_count += 1
                        continue
                    if incoming.control is not Control.DIAGNOSTIC:
                        stop("unexpected_control", "unsupported_hsfz_control")
                    if (incoming.source, incoming.target) != (spec.target, TESTER_ADDRESS):
                        stop("unexpected_response", "diagnostic_addresses_not_correlated")
                    response = parse_read_data_response(incoming.diagnostic_payload, request)
                    if isinstance(response, NegativeResponse):
                        nrc = response.code
                        if not response.pending:
                            stop("negative_response", "candidate_negative_response")
                        pending_count += 1
                        response_deadline = min(group_deadline,
                                                received_at + PENDING_RESPONSE_WINDOW_SECONDS)
                        continue
                    if group_ack_count != 1:
                        stop("unexpected_response", "terminal_response_without_correlated_ack")
                    if len(response.value) != expected_length:
                        stop("malformed_response", "coding_group_length_mismatch")
                    terminal_value = response.value
                    nrc = None
                if terminal_value is not None:
                    # A terminal frame cannot carry even a partial extra frame.
                    parser.finish()
                    _remaining_seconds(min(group_deadline, response_deadline))
                    groups.append((address, terminal_value))
                    break
        outcome, reason = "snapshot_observed", None
    except _Stopped as stopped:
        outcome, reason = stopped.outcome, stopped.reason
    except _DeadlineExpired:
        outcome, reason = "timeout", "snapshot_or_response_deadline_exhausted"
    except NetworkPreflightError as error:
        if error.reason == "identity_preflight_deadline_exhausted":
            outcome, reason = "timeout", "snapshot_deadline_exhausted"
        else:
            outcome, reason = "network_changed", "preflight_no_longer_valid"
    except PolicyViolation:
        outcome, reason = "policy_denied", "final_send_policy_rejected"
    except socket.timeout:
        outcome = "connect_timeout" if stage == "connect" else "timeout"
        reason = "connect_deadline_exhausted" if stage == "connect" else f"{stage}_deadline_exhausted"
    except UnexpectedResponseError:
        outcome, reason = "unexpected_response", "uds_response_not_correlated"
    except MalformedResponseError:
        outcome, reason = "malformed_response", "invalid_coding_value_response"
    except HSFZError:
        outcome, reason = "malformed_response", "invalid_hsfz_stream"
    except KeyboardInterrupt:
        outcome, reason = "interrupted", "user_interrupt"
        timing_complete = False
    except OSError:
        outcome, reason = "socket_error", f"{stage}_failed"
    finally:
        if sock is not None:
            try:
                sock.close()
            except KeyboardInterrupt:
                outcome, reason = "interrupted", "socket_close_interrupted"
                close_uncertain = True
            except OSError:
                outcome, reason = "socket_error", "socket_close_failed"
                close_uncertain = True
    try:
        finished = time.monotonic()
    except KeyboardInterrupt:
        outcome, reason = "interrupted", "final_clock_sampling_interrupted"
        elapsed = None
        timing_complete = False
    else:
        elapsed = None if start is None else round(max(0.0, finished - start), 6)
        if start is None:
            timing_complete = False
        if outcome == "snapshot_observed" and finished >= deadline:
            outcome, reason = "timeout", "snapshot_deadline_exhausted"
    return CodingSnapshotResult(
        outcome, reason, connection_attempts, connections_opened, connection_uncertain,
        attempts, sent, confirmed_bytes, transmission_uncertain, tuple(requests), tuple(captured),
        tuple(chunk_groups), tuple(groups), ack_count, pending_count, nrc, last_control,
        elapsed, elapsed, timing_complete, close_uncertain, module,
    )
