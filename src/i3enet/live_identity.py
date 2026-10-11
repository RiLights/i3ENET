"""Fixed VIN/SVK/EXBOX exchanges and shared bounded TCP accounting.

Importing this module opens no sockets. Each reader selects its exact request,
proof gate and final policy. There are no retries, control sends, session
changes or keepalives. Original chunks remain private."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import socket
import time

from .evidence import GatewayIdentityEvidence, GatewayVINReadEvidence, _hash_shape
from .hsfz import DIAGNOSTIC_PORT, Control, HSFZError, IncrementalParser
from .network import GatewayNetwork, IP_BOUND_IF, NetworkPreflightError, identity_preflight
from .policy import LiveGatewayIdentityPolicy, Phase, PolicyViolation
from .uds import (
    MalformedResponseError,
    NegativeResponse,
    ReadDataByIdentifierRequest,
    UnexpectedResponseError,
    parse_read_data_response,
)


GATEWAY_VIN_REQUEST = bytes.fromhex("000000050001f41022f190")
VIN_ASCII_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
TESTER_ADDRESS = 0xF4
GATEWAY_DIAGNOSTIC_ADDRESS = 0x10
CONNECT_TIMEOUT_SECONDS = 3.0
FIRST_RESPONSE_WINDOW_SECONDS = 3.0
PENDING_RESPONSE_WINDOW_SECONDS = 3.0
OVERALL_REQUEST_WINDOW_SECONDS = 6.0
EXPERIMENT_WINDOW_SECONDS = 10.0
MAX_FRAME_BODY_BYTES = 4096
MAX_RAW_RECEIVE_BYTES = 64 * 1024
MAX_RECEIVE_CHUNKS = 64
RECEIVE_CHUNK_BYTES = 4096


class _DeadlineExpired(Exception):
    """A project clock budget expired before the next operation."""


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _DeadlineExpired()
    return remaining


@dataclass(frozen=True, slots=True)
class ReceivedTCPChunk:
    data: bytes = field(repr=False)
    received_after_seconds: float | None


@dataclass(frozen=True, slots=True)
class GatewayIdentityResult:
    outcome: str
    reason: str | None
    tcp_connections_attempted: int
    tcp_connections_opened: int
    tcp_connection_uncertain: bool
    application_frames_attempted: int
    application_frames_sent: int
    vehicle_bytes_confirmed_sent: int
    transmission_uncertain: bool
    request_bytes: bytes = field(repr=False)
    recv_chunks: tuple[ReceivedTCPChunk, ...] = field(repr=False)
    response_vin: str | None = field(repr=False)
    ack_count: int
    pending_count: int
    nrc: int | None
    last_control: int | None
    elapsed_seconds: float | None
    response_elapsed_seconds: float | None
    experiment_elapsed_seconds: float | None = 0.0
    vin_comparison: bool | None = None
    timing_complete: bool = True
    tcp_close_uncertain: bool = False

    def public_report(self) -> dict[str, object]:
        return {
            **_tcp_read_report(self),
            "masked_vin_candidate": None if self.response_vin is None else "*" * 13 + self.response_vin[-4:],
            "vin_matches_discovery": self.vin_comparison,
            "vehicle_identity_status": "gateway_vin_matches_discovery" if self.outcome == "vin_match" else "unknown",
            "head_unit_status": "unknown",
        }


def _tcp_read_report(result) -> dict[str, object]:
    """Common accounting only; operation-specific values stay with their readers."""
    return {
        "outcome": result.outcome,
        "reason": result.reason,
        "tcp_connections_attempted": result.tcp_connections_attempted,
        "tcp_connections_opened": result.tcp_connections_opened,
        "tcp_connection_uncertain": result.tcp_connection_uncertain,
        "application_frames_attempted": result.application_frames_attempted,
        "application_frames_sent": result.application_frames_sent,
        "vehicle_bytes_confirmed_sent": result.vehicle_bytes_confirmed_sent,
        "transmission_uncertain": result.transmission_uncertain,
        "tcp_close_uncertain": result.tcp_close_uncertain,
        "tcp_control_traffic_counted": False,
        "received_chunks": len(result.recv_chunks),
        "received_bytes": sum(len(chunk.data) for chunk in result.recv_chunks),
        "ack_count": result.ack_count,
        "pending_count": result.pending_count,
        "nrc": None if result.nrc is None else f"0x{result.nrc:02X}",
        "last_control": None if result.last_control is None else f"0x{result.last_control:04X}",
        "writes_supported": False,
        "elapsed_seconds": result.elapsed_seconds,
        "response_elapsed_seconds": result.response_elapsed_seconds,
        "experiment_elapsed_seconds": result.experiment_elapsed_seconds,
        "timing_complete": result.timing_complete,
        "experiment_overall_window_seconds": EXPERIMENT_WINDOW_SECONDS,
        "connect_timeout_seconds": CONNECT_TIMEOUT_SECONDS,
        "first_response_window_seconds": FIRST_RESPONSE_WINDOW_SECONDS,
        "pending_response_window_seconds": PENDING_RESPONSE_WINDOW_SECONDS,
        "overall_request_window_seconds": OVERALL_REQUEST_WINDOW_SECONDS,
        "timing_source": "project_bounds_not_ecu_reported_timings",
        "receive_byte_limit": MAX_RAW_RECEIVE_BYTES,
        "receive_chunk_limit": MAX_RECEIVE_CHUNKS,
    }


def _bound_source_reason(sock: socket.socket, network: GatewayNetwork) -> str | None:
    if sock.getsockopt(socket.IPPROTO_IP, IP_BOUND_IF) != network.interface_index:
        return "interface_binding_not_confirmed"
    local = sock.getsockname()
    if local[0] != network.source_address or not 1 <= local[1] <= 65535:
        return "source_binding_not_confirmed"
    return None


def _evidence_matches_network(network: GatewayNetwork, evidence: GatewayIdentityEvidence) -> bool:
    return (
        (evidence.gateway_address, evidence.source_interface, evidence.source_address, evidence.interface_index)
        == (network.gateway_address, network.interface, network.source_address, network.interface_index)
        and type(evidence.interface_index) is int
        and type(evidence.diagnostic_address) is int
        and evidence.diagnostic_address == GATEWAY_DIAGNOSTIC_ADDRESS
        and type(evidence.vin_candidate) is str
        and len(evidence.vin_candidate) == 17
        and all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for character in evidence.vin_candidate)
        and all(type(value) is str and len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
                for value in (evidence.manifest_sha256, evidence.reply_sha256))
    )


def _verified_vin_matches(network: GatewayNetwork, evidence: GatewayVINReadEvidence) -> bool:
    return (type(evidence.discovery) is GatewayIdentityEvidence
            and _evidence_matches_network(network, evidence.discovery)
            and type(evidence.manifest_sha256) is str
            and _hash_shape(evidence.manifest_sha256)
            and type(evidence.request_sha256) is str
            and evidence.request_sha256 == hashlib.sha256(GATEWAY_VIN_REQUEST).hexdigest())


def _read_once(kind: str, network: GatewayNetwork, evidence, svk=None):
    """Shared bounded exchange for fixed VIN, HU/BDC SVK or EXBOX reads.

    Each public reader retains its proof/type gate and fixed final-send policy.
    Selecting a kind cannot change the endpoint, payload, budgets or ACK rules.
    """
    if kind == "vin":
        from . import live_identity as client
        request_bytes, target, did = GATEWAY_VIN_REQUEST, 0x10, 0xF190
        result_type, policy_type, phase = GatewayIdentityResult, LiveGatewayIdentityPolicy, Phase.LIVE_GATEWAY_IDENTITY
        success, invalid_response = "vin_match", "invalid_vin_response"
    elif kind in ("svk", "bdc_svk", "vsg_svk"):
        from . import live_svk as client
        request_bytes, target, did = client.HEAD_UNIT_SVK_REQUEST, 0x63, 0xF101
        result_type, policy_type, phase = client.ModuleSVKResult, client.LiveHeadUnitSVKPolicy, Phase.LIVE_HEAD_UNIT_SVK
        if kind == "bdc_svk":
            request_bytes, target = client.BDC_SVK_REQUEST, 0x40
            policy_type, phase = client.LiveBDCSVKPolicy, Phase.LIVE_BDC_SVK
        elif kind == "vsg_svk":
            request_bytes, target = client.VSG_SVK_REQUEST, 0x2D
            policy_type, phase = client.LiveVSGSVKPolicy, Phase.LIVE_VSG_SVK
        success, invalid_response = "identity_value_observed", "invalid_identity_value_response"
    elif kind in ("exbox", "bdc_pffes", "vsg_config", "bdc_timing", "bdc_state", "bdc_cps", "vsg_timing", "vsg_state", "vsg_cps"):
        from . import live_block as client
        request_bytes, target, did = client.EXBOX_REQUEST, 0x63, 0x3001
        result_type, policy_type, phase = client.ModuleBlockResult, client.LiveHeadUnitEXBOXPolicy, Phase.LIVE_HEAD_UNIT_EXBOX
        if kind == "bdc_pffes":
            request_bytes, target, did = client.BDC_PFFES_REQUEST, 0x40, 0x3221
            policy_type, phase = client.LiveBDCPfFesPolicy, Phase.LIVE_BDC_PFFES
        elif kind == 'vsg_config':
            request_bytes, target, did = client.VSG_CONFIG_REQUEST, 0x2D, 0x3000
            policy_type, phase = client.LiveVSGConfigPolicy, Phase.LIVE_VSG_CONFIG
        elif kind in client.METADATA:
            did = client.METADATA[kind][0]; target = 0x2D if kind in client.VSG_METADATA else 0x40
            request_bytes = bytes.fromhex('000000050001f4') + bytes((target,0x22)) + did.to_bytes(2, "big")
            policy_type, phase = ((client.LiveVSGMetadataPolicy,Phase.LIVE_VSG_METADATA) if target == 0x2D else
                                  (client.LiveBDCMetadataPolicy,Phase.LIVE_BDC_METADATA))
        success, invalid_response = "coding_value_observed", "invalid_coding_value_response"
    else:
        raise ValueError("unsupported fixed read")
    start: float | None = None
    request_started: float | None = None
    experiment_started: float | None = None
    experiment_deadline: float | None = None
    captured: list[ReceivedTCPChunk] = []
    received_bytes = 0
    connection_attempts = connections_opened = application_attempts = application_sent = confirmed_bytes = 0
    connection_uncertain = transmission_uncertain = False
    tcp_close_uncertain = False
    timing_complete = True
    ack_count = pending_count = 0
    nrc = last_control = None
    value = None
    vin_comparison = None
    outcome, reason = "timeout", "response_deadline_exhausted"
    sock: socket.socket | None = None
    stage = "preflight"

    def fresh_network(deadline: float | None = None) -> bool:
        keywords = {} if deadline is None else {"deadline": deadline}
        return client.identity_preflight(network.interface, network.source_address, network.gateway_address,
                                  **keywords) == network

    try:
        start = time.monotonic()
        GatewayNetwork.__post_init__(network)
        valid_evidence = (_evidence_matches_network(network, evidence) if kind == "vin"
                          else _verified_vin_matches(network, evidence))
        if not valid_evidence:
            outcome, reason = "evidence_mismatch", ("discovery_evidence_not_bound_to_network" if kind == "vin"
                                                     else "verified_vin_evidence_not_bound_to_network")
        elif kind == "exbox" and not client._exbox_svk_evidence_matches(network, evidence, svk):
            outcome, reason = "evidence_mismatch", "verified_svk_evidence_not_bound_to_network_or_identity"
        elif kind.startswith('vsg_') and kind != 'vsg_svk' and not client._vsg_svk_evidence_matches(network, evidence, svk):
            outcome, reason = 'evidence_mismatch', 'verified_vsg_svk_evidence_not_bound_to_network_or_identity'
        elif kind.startswith("bdc_") and kind != "bdc_svk" and not client._bdc_svk_evidence_matches(network, evidence, svk):
            outcome, reason = "evidence_mismatch", "verified_bdc_svk_evidence_not_bound_to_network_or_identity"
        elif not fresh_network():
            outcome, reason = "network_changed", "preflight_changed"
        else:
            policy = policy_type(network, phase=phase, **({"kind": kind} if kind in ("bdc_timing", "bdc_state", "bdc_cps", "vsg_timing", "vsg_state", "vsg_cps") else {}))
            stage = "socket_creation"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            stage = "socket_binding"
            sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, network.interface_index)
            sock.bind((network.source_address, 0))
            stage = "connect_preflight"
            if not fresh_network():
                outcome, reason = "network_changed", "preflight_changed"
            elif (binding_reason := _bound_source_reason(sock, network)):
                outcome, reason = "network_changed", binding_reason
            else:
                endpoint = (network.gateway_address, DIAGNOSTIC_PORT)
                stage = "connect"
                experiment_started = time.monotonic()
                experiment_deadline = experiment_started + EXPERIMENT_WINDOW_SECONDS
                sock.settimeout(min(CONNECT_TIMEOUT_SECONDS, _remaining_seconds(experiment_deadline)))
                _remaining_seconds(experiment_deadline)
                connection_attempts = 1
                connection_uncertain = True
                sock.connect(endpoint)
                connections_opened = 1
                connection_uncertain = False
                stage = "send_preflight"
                network_fresh = fresh_network(experiment_deadline)
                if time.monotonic() >= experiment_deadline:
                    outcome, reason = "timeout", "experiment_deadline_exhausted"
                elif not network_fresh:
                    outcome, reason = "network_changed", "preflight_changed"
                elif sock.getpeername() != endpoint:
                    outcome, reason = "network_changed", "connected_peer_not_confirmed"
                elif (binding_reason := _bound_source_reason(sock, network)):
                    outcome, reason = "network_changed", binding_reason
                else:
                    request_started = time.monotonic()
                    overall_deadline = min(experiment_deadline, request_started + OVERALL_REQUEST_WINDOW_SECONDS)
                    stage = "send"
                    sock.settimeout(min(FIRST_RESPONSE_WINDOW_SECONDS, _remaining_seconds(overall_deadline)))
                    # Sole application send boundary. No sendall/retry/control
                    # path exists; a short or uncertain send closes this session.
                    _remaining_seconds(overall_deadline)
                    policy.validate(request_bytes, endpoint, sent_count=application_attempts)
                    _remaining_seconds(overall_deadline)
                    application_attempts = 1
                    transmission_uncertain = True
                    count = sock.send(request_bytes)
                    if type(count) is not int or not 0 <= count <= len(request_bytes):
                        outcome, reason = "socket_error", "invalid_send_accounting"
                    elif count != len(request_bytes):
                        confirmed_bytes = count
                        outcome, reason = "socket_error", "partial_application_frame_send"
                    else:
                        application_sent = 1
                        confirmed_bytes = count
                        transmission_uncertain = False
                        parser = IncrementalParser(max_body_length=MAX_FRAME_BODY_BYTES)
                        request = ReadDataByIdentifierRequest(did)
                        response_deadline = min(overall_deadline, time.monotonic() + FIRST_RESPONSE_WINDOW_SECONDS)
                        stage = "receive"
                        done = False
                        while not done:
                            if len(captured) >= MAX_RECEIVE_CHUNKS:
                                outcome, reason = "receive_limit", "receive_chunk_budget_exhausted"
                                break
                            if received_bytes >= MAX_RAW_RECEIVE_BYTES:
                                outcome, reason = "receive_limit", "receive_byte_budget_exhausted"
                                break
                            remaining = _remaining_seconds(min(overall_deadline, response_deadline))
                            sock.settimeout(remaining)
                            data = sock.recv(min(RECEIVE_CHUNK_BYTES, MAX_RAW_RECEIVE_BYTES - received_bytes))
                            if data:
                                # Preserve bytes before even sampling the clock;
                                # an interrupt there leaves an explicitly unknown
                                # chunk timestamp rather than losing the receipt.
                                captured.append(ReceivedTCPChunk(data, None))
                                received_bytes += len(data)
                            try:
                                received_at = time.monotonic()
                            except KeyboardInterrupt:
                                timing_complete = False
                                raise
                            if not data:
                                try:
                                    parser.finish()
                                except HSFZError:
                                    outcome, reason = "truncated_response", "eof_during_hsfz_frame"
                                else:
                                    outcome, reason = "eof", "gateway_closed_before_terminal_response"
                                break
                            # Retain every original chunk before parsing it,
                            # including malformed input or interrupted processing.
                            captured[-1] = ReceivedTCPChunk(data, round(max(0.0, received_at - request_started), 6))
                            if received_at >= min(overall_deadline, response_deadline):
                                break
                            terminal_value = None
                            for incoming in parser.feed(data):
                                last_control = int(incoming.control)
                                if terminal_value is not None:
                                    outcome, reason = "unexpected_response", "additional_frame_after_terminal_response"
                                    done = True
                                    break
                                if incoming.control is Control.ACK:
                                    if ack_count:
                                        outcome, reason = "unexpected_response", "duplicate_ack"
                                        done = True
                                        break
                                    if ((incoming.source, incoming.target) != (TESTER_ADDRESS, target)
                                            or incoming.diagnostic_payload != request_bytes[8:]):
                                        outcome, reason = "unexpected_response", "ack_not_correlated"
                                        done = True
                                        break
                                    ack_count += 1
                                    continue
                                if incoming.control is not Control.DIAGNOSTIC:
                                    outcome, reason = "unexpected_control", "unsupported_hsfz_control"
                                    done = True
                                    break
                                if (incoming.source, incoming.target) != (target, TESTER_ADDRESS):
                                    outcome, reason = "unexpected_response", "diagnostic_addresses_not_correlated"
                                    done = True
                                    break
                                response = parse_read_data_response(incoming.diagnostic_payload, request,
                                                                    expected_value_length=(17 if kind in ("vin", "bdc_pffes") else 8 if kind == 'vsg_config' else
                                                                        client.METADATA[kind][1] if kind in ("bdc_timing", "bdc_state", "bdc_cps", "vsg_timing", "vsg_state", "vsg_cps") else None))
                                if isinstance(response, NegativeResponse):
                                    nrc = response.code
                                    if not response.pending:
                                        outcome, reason = "negative_response", "gateway_negative_response" if kind == "vin" else "candidate_negative_response"
                                        done = True
                                        break
                                    pending_count += 1
                                    response_deadline = min(overall_deadline, received_at + PENDING_RESPONSE_WINDOW_SECONDS)
                                    continue
                                if kind in ("bdc_pffes", "vsg_config", "bdc_timing", "bdc_state", "bdc_cps", "vsg_timing", "vsg_state", "vsg_cps") and ack_count != 1:
                                    outcome, reason = "unexpected_response", "ack_missing_or_out_of_order"
                                    done = True
                                    break
                                if kind in ("bdc_timing", "bdc_state", "bdc_cps", "vsg_timing", "vsg_state", "vsg_cps") and not 1 <= len(response.value) <= 32:
                                    outcome, reason = "malformed_response", "metadata_value_length"
                                    done = True
                                    break
                                if kind == "vin":
                                    if any(byte not in VIN_ASCII_ALPHABET for byte in response.value):
                                        outcome, reason = "malformed_response", "unsupported_vin_ascii_shape"
                                        done = True
                                        break
                                    value = response.value.decode("ascii")
                                    vin_comparison = value == evidence.vin_candidate
                                    if not vin_comparison:
                                        outcome, reason = "vin_mismatch", "response_vin_differs_from_discovery"
                                        done = True
                                        break
                                else:
                                    value = response.value  # Opaque bytes; no repair or text decoding.
                                terminal_value = value
                            if terminal_value is not None and not done:
                                # Reject a positive response followed by even a
                                # partial extra frame in the same receive chunk.
                                parser.finish()
                                _remaining_seconds(min(overall_deadline, response_deadline))
                                outcome, reason = success, None
                                done = True
    except _DeadlineExpired:
        try:
            experiment_expired = (experiment_deadline is not None
                                  and time.monotonic() >= experiment_deadline)
        except KeyboardInterrupt:
            outcome, reason = "interrupted", "user_interrupt"
        else:
            outcome = "timeout"
            reason = "experiment_deadline_exhausted" if experiment_expired else "response_deadline_exhausted"
    except NetworkPreflightError:
        try:
            experiment_expired = (experiment_deadline is not None
                                  and time.monotonic() >= experiment_deadline)
        except KeyboardInterrupt:
            outcome, reason = "interrupted", "user_interrupt"
        else:
            if experiment_expired:
                outcome, reason = "timeout", "experiment_deadline_exhausted"
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
        outcome, reason = "malformed_response", invalid_response
    except HSFZError:
        outcome, reason = "malformed_response", "invalid_hsfz_stream"
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
                tcp_close_uncertain = True
            except OSError:
                outcome, reason = "socket_error", "socket_close_failed"
                tcp_close_uncertain = True
    try:
        finished = time.monotonic()
    except KeyboardInterrupt:
        outcome, reason = "interrupted", "final_clock_sampling_interrupted"
        timing_complete = False
        elapsed = response_elapsed = experiment_elapsed = None
    else:
        if start is None:
            elapsed = None
            timing_complete = False
        else:
            elapsed = round(max(0.0, finished - start), 6)
        response_elapsed = (0.0 if request_started is None
                            else round(max(0.0, finished - request_started), 6))
        experiment_elapsed = (0.0 if experiment_started is None
                              else round(max(0.0, finished - experiment_started), 6))
    if kind != "vin" and outcome != success:
        value = None
    return result_type(
        outcome, reason, connection_attempts, connections_opened, connection_uncertain,
        application_attempts, application_sent, confirmed_bytes, transmission_uncertain,
        request_bytes, tuple(captured), value, ack_count, pending_count, nrc, last_control,
        elapsed, response_elapsed, experiment_elapsed,
        **({"vin_comparison": vin_comparison} if kind == "vin" else
           {"diagnostic_address": target} if kind in ("svk", "bdc_svk", "vsg_svk") else {}),
        **({"diagnostic_address": target, "identifier": did} if kind in ("exbox", "bdc_pffes", "vsg_config", "bdc_timing", "bdc_state", "bdc_cps", "vsg_timing", "vsg_state", "vsg_cps") else {}),
        timing_complete=timing_complete, tcp_close_uncertain=tcp_close_uncertain,
    )


def identify_gateway_once(network: GatewayNetwork, evidence: GatewayIdentityEvidence) -> GatewayIdentityResult:
    """One fixed VIN read; frozen network and discovery evidence are mandatory."""
    if type(network) is not GatewayNetwork or type(evidence) is not GatewayIdentityEvidence:
        raise TypeError("gateway identification requires exact frozen network and evidence types")
    return _read_once("vin", network, evidence)
