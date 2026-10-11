"""Bounded session observation and seed capture before native coding.

These APIs implement a reviewed exchange but do not authorize execution. Three
current original proofs and fresh source/interface/peer checks are mandatory.
The one-request observation never selects a session layout; seed capture
requires an explicitly selected profile. No coding write,
helper, keepalive, retry, restoration or automatic follow-up exists here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import math
import socket
import time

from .coding_protocol import (
    CodingProtocolError, MAX_SEED_BYTES, negative_response,
    parse_seed_response, parse_session_response, parse_key_response, parse_ping_response, key_request,
)
from .auth_provider import _provider_matches, AuthProviderError
from .coding_signature import RSA1024PublicKey, verify_security_access, SignatureError
from .evidence import GatewayVINReadEvidence
from .hsfz import Control, HSFZError, IncrementalParser, expected_ack_echo
from .live_block import _exbox_svk_evidence_matches, _exbox_vin_evidence_matches, _bdc_svk_evidence_matches
from .auth_evidence import auth_requests, auth_stages, auth_request, MODES, svk_module, AuthenticationSeedEvidence
from .coding_contract import contract
from .live_identity import (
    CONNECT_TIMEOUT_SECONDS, DIAGNOSTIC_PORT, FIRST_RESPONSE_WINDOW_SECONDS,
    MAX_FRAME_BODY_BYTES, MAX_RAW_RECEIVE_BYTES, MAX_RECEIVE_CHUNKS,
    OVERALL_REQUEST_WINDOW_SECONDS, PENDING_RESPONSE_WINDOW_SECONDS,
    RECEIVE_CHUNK_BYTES, ReceivedTCPChunk, _DeadlineExpired, _bound_source_reason,
)
from .network import GatewayNetwork, IP_BOUND_IF, NetworkPreflightError, identity_preflight
from .policy import PolicyViolation
from .svk import HeadUnitSVKEvidence, BDCSVKEvidence, VSGSVKEvidence

AUTH_EXPERIMENT_WINDOW_SECONDS = 30.0
MAX_AUTH_SEED_BYTES = min(MAX_SEED_BYTES, MAX_FRAME_BODY_BYTES - 4)
MAX_PENDING_PER_REQUEST = 4  # Project resource bound, not an ECU capability.
EXTENDED_SESSION_REQUEST = bytes.fromhex('000000040001f4631003')
CODING_SESSION_REQUEST = bytes.fromhex('000000040001f4631041')
SECURITY_SEED_REQUEST = bytes.fromhex('000000080001f4632701ffffffff')
AUTH_PREFIX_REQUESTS = (EXTENDED_SESSION_REQUEST, CODING_SESSION_REQUEST, SECURITY_SEED_REQUEST)
AUTH_STAGE_NAMES = ('extended_session', 'coding_session', 'security_seed')


class AuthPhase(Enum):
    DENY = 'deny'
    OBSERVE_EXTENDED_SESSION = 'observe_extended_session'
    CAPTURE_AUTH_SEED = 'capture_auth_seed'
    VALIDATE_BDC_AUTH = 'validate_bdc_auth'
    CAPTURE_BDC_SEED_AND_DEFAULT = 'capture_bdc_seed_and_default'
    CAPTURE_VSG_SEED_AND_DEFAULT = 'capture_vsg_seed_and_default'


class AuthContractError(ValueError):
    """Fixed safe reason with no seed, signature or original response bytes."""
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class AuthProfile:
    session_layout: str
    seed_byte_length: int | None = None

    def __post_init__(self) -> None:
        if type(self.session_layout) is not str or self.session_layout not in ('p2_timing', 'opaque_parameters'):
            raise AuthContractError('session_layout_not_explicitly_selected')
        if self.seed_byte_length is not None and (type(self.seed_byte_length) is not int
                or not 1 <= self.seed_byte_length <= MAX_AUTH_SEED_BYTES):
            raise AuthContractError('reviewed_seed_length_invalid')


@dataclass(frozen=True, slots=True)
class LiveHeadUnitAuthPolicy:
    """Default-deny ordered final-frame boundary, separate from all read policies."""
    network: GatewayNetwork
    phase: AuthPhase = AuthPhase.DENY
    module: str = 'HU'
    as_frame: bytes | None = field(default=None, repr=False)

    def validate(self, payload: bytes, destination: tuple[str, int], *,
                 sent_count: int = 0, completed_stages: int = 0) -> None:
        if type(self.phase) is not AuthPhase or self.phase is AuthPhase.DENY:
            raise PolicyViolation('authentication_phase_denied')
        if type(self.network) is not GatewayNetwork:
            raise PolicyViolation('authentication_network_invalid')
        try:
            GatewayNetwork.__post_init__(self.network)
        except (NetworkPreflightError, TypeError, ValueError, AttributeError):
            raise PolicyViolation('authentication_network_invalid') from None
        maximum = {AuthPhase.OBSERVE_EXTENDED_SESSION: 1, AuthPhase.CAPTURE_AUTH_SEED: 3,
                   AuthPhase.VALIDATE_BDC_AUTH: 6, AuthPhase.CAPTURE_BDC_SEED_AND_DEFAULT: 5,
                   AuthPhase.CAPTURE_VSG_SEED_AND_DEFAULT: 5}[self.phase]
        if self.phase in (AuthPhase.VALIDATE_BDC_AUTH, AuthPhase.CAPTURE_BDC_SEED_AND_DEFAULT) and self.module != 'BDC':
            raise PolicyViolation('authentication_module_invalid')
        if self.phase is AuthPhase.CAPTURE_VSG_SEED_AND_DEFAULT and self.module != 'VSG01':
            raise PolicyViolation('authentication_module_invalid')
        if self.module == 'VSG01' and self.phase not in (AuthPhase.OBSERVE_EXTENDED_SESSION,AuthPhase.CAPTURE_VSG_SEED_AND_DEFAULT):
            raise PolicyViolation('authentication_module_invalid')
        if (type(sent_count) is not int or type(completed_stages) is not int
                or not 0 <= sent_count < maximum or completed_stages != sent_count):
            raise PolicyViolation('authentication_attempt_sequence_invalid')
        if (type(destination) is not tuple or len(destination) != 2
                or type(destination[0]) is not str or type(destination[1]) is not int
                or destination != (self.network.gateway_address, DIAGNOSTIC_PORT)):
            raise PolicyViolation('authentication_destination_invalid')
        expected = auth_request(self.phase.value, self.module, sent_count, self.as_frame)
        if auth_stages(self.phase.value)[sent_count] == 'security_key':
            if (type(expected) is not bytes or len(expected) != 142
                    or expected[:10] != bytes.fromhex('000000880001f4402702')):
                raise PolicyViolation('authentication_key_frame_invalid')
        if type(payload) is not bytes or payload != expected:
            raise PolicyViolation('authentication_next_frame_invalid')


@dataclass(frozen=True, slots=True)
class HeadUnitAuthResult:
    mode: str
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
    request_started_after_seconds: tuple[float | None, ...]
    recv_chunks: tuple[ReceivedTCPChunk, ...] = field(repr=False)
    chunk_stage_names: tuple[str, ...]
    completed_stage_names: tuple[str, ...]
    session_parameters: tuple[tuple[int, bytes], ...] = field(repr=False)
    seed: bytes | None = field(repr=False)
    ack_count: int
    pending_count: int
    nrc: int | None
    last_control: int | None
    elapsed_seconds: float | None
    response_elapsed_seconds: float | None
    experiment_elapsed_seconds: float | None
    timing_complete: bool
    tcp_close_uncertain: bool
    module: str = 'HU'
    as_public_key: RSA1024PublicKey | None = field(default=None, repr=False)

    def public_report(self) -> dict[str, object]:
        modes = {
            AuthPhase.OBSERVE_EXTENDED_SESSION.value: (1, 10, 'extended_session_observed'),
            AuthPhase.CAPTURE_AUTH_SEED.value: (3, 34, 'authentication_seed_observed'),
            AuthPhase.VALIDATE_BDC_AUTH.value: (6, 197, 'bdc_authentication_default_session_observed'),
            AuthPhase.CAPTURE_BDC_SEED_AND_DEFAULT.value: (5, 55, 'authentication_seed_default_session_observed'),
            AuthPhase.CAPTURE_VSG_SEED_AND_DEFAULT.value: (5,55,'authentication_seed_default_session_observed'),
        }
        count, maximum_bytes, success = modes.get(self.mode, (0, 0, 'invalid'))
        complete = (count > 0 and self.outcome == success and self.timing_complete and not self.tcp_close_uncertain
                    and not self.tcp_connection_uncertain and not self.transmission_uncertain
                    and self.tcp_connections_attempted == self.tcp_connections_opened == 1
                    and self.application_frames_attempted == self.application_frames_sent == count
                    and self.vehicle_bytes_confirmed_sent == maximum_bytes and self.ack_count == count
                    and self.completed_stage_names == auth_stages(self.mode)
                    and len(self.request_bytes) == len(self.request_started_after_seconds) == count
                    and self.request_bytes[:min(count, 3)] == auth_requests(self.module)[:min(count, 3)]
                    and len(self.recv_chunks) == len(self.chunk_stage_names)
                    and self.nrc is None and self.last_control == int(Control.DIAGNOSTIC)
                    and (count < 3 or (type(self.seed) is bytes and 1 <= len(self.seed) <= MAX_AUTH_SEED_BYTES and any(self.seed)))
)
        if count == 6:
            complete = (complete and self.module == 'BDC' and type(self.as_public_key) is RSA1024PublicKey
                        and len(self.seed) == 8 and len(self.request_bytes[3]) == 142
                        and self.request_bytes[3][:10] == bytes.fromhex('000000880001f4402702')
                        and verify_security_access(self.seed, self.request_bytes[3][10:], self.as_public_key, module='BDC')
                        )
        if count in (5,6):
            complete = (complete and self.module == ('VSG01' if self.mode == 'capture_vsg_seed_and_default' else 'BDC')
                        and self.request_bytes[-2:] == tuple(auth_request(self.mode,self.module,i) for i in range(count-2,count)))
        seed = self.seed if complete and count >= 3 else None
        return {
            'mode': self.mode, 'outcome': self.outcome, 'reason': self.reason,
            'tcp_connections_attempted': self.tcp_connections_attempted,
            'tcp_connections_opened': self.tcp_connections_opened,
            'tcp_connection_uncertain': self.tcp_connection_uncertain,
            'application_frames_attempted': self.application_frames_attempted,
            'application_frames_sent': self.application_frames_sent,
            'vehicle_bytes_confirmed_sent': self.vehicle_bytes_confirmed_sent,
            'transmission_uncertain': self.transmission_uncertain,
            'tcp_close_uncertain': self.tcp_close_uncertain, 'tcp_control_traffic_counted': False,
            'received_chunks': len(self.recv_chunks), 'received_bytes': sum(len(c.data) for c in self.recv_chunks),
            'completed_stage_names': list(self.completed_stage_names), 'completed_stage_count': len(self.completed_stage_names),
            'ack_count': self.ack_count, 'pending_count': self.pending_count,
            'nrc': None if self.nrc is None else f'0x{self.nrc:02X}',
            'last_control': None if self.last_control is None else f'0x{self.last_control:04X}',
            'exchange_complete': bool(complete),
            'session_parameter_records': [
                {'subfunction': f'0x{sub:02X}', 'byte_length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                for sub, raw in self.session_parameters] if complete else [],
            'seed_byte_count': None if seed is None else len(seed),
            'seed_sha256': None if seed is None else hashlib.sha256(seed).hexdigest(),
            'as_signature_verified': bool(complete and count == 6),
            'authentication_acceptance_observed': bool(complete and count == 6),
            'authentication_status': 'acceptance_observed_connection_closed' if complete and count == 6 else 'not_established',
            'current_authentication_state': 'unverified_after_connection_close',
            'session_restoration_attempted': count in (5,6) and len(self.request_bytes) >= count - 1,
            'default_session_observed': bool(complete and count in (5,6)),
            'session_reset_assumed_on_close': False,
            'coding_readiness_established': False, 'writes_supported': False,
            'layout_selection': ('unselected_opaque_observation' if count == 1 else 'explicit_caller_profile_only'),
            'automatic_P2_deadline_selection': False,
            'elapsed_seconds': self.elapsed_seconds, 'response_elapsed_seconds': self.response_elapsed_seconds,
            'experiment_elapsed_seconds': self.experiment_elapsed_seconds, 'timing_complete': self.timing_complete,
            'maximum_application_frames': count, 'maximum_application_bytes': maximum_bytes,
            'connect_timeout_seconds': CONNECT_TIMEOUT_SECONDS,
            'first_response_window_seconds': FIRST_RESPONSE_WINDOW_SECONDS,
            'pending_response_window_seconds': PENDING_RESPONSE_WINDOW_SECONDS,
            'overall_request_window_seconds': OVERALL_REQUEST_WINDOW_SECONDS,
            'experiment_overall_window_seconds': AUTH_EXPERIMENT_WINDOW_SECONDS,
            'receive_byte_limit': MAX_RAW_RECEIVE_BYTES, 'receive_chunk_limit': MAX_RECEIVE_CHUNKS,
            'receive_frame_body_limit': MAX_FRAME_BODY_BYTES, 'seed_byte_limit': MAX_AUTH_SEED_BYTES,
            'maximum_pending_per_request': MAX_PENDING_PER_REQUEST,
            'chunk_timestamp_origin': 'experiment_start_before_connect',
            'request_timestamp_origin': 'experiment_start_before_connect',
            'timing_source': 'project_bounds_not_ecu_reported_timings',
        }


class _Stop(Exception):
    def __init__(self, outcome: str, reason: str):
        self.outcome, self.reason = outcome, reason


def observe_extended_session_once(network: GatewayNetwork, evidence: GatewayVINReadEvidence,
                                  svk: HeadUnitSVKEvidence) -> HeadUnitAuthResult:
    """Send only 10 03 once; retain a bounded matched opaque parameter record."""
    return _exchange(network, evidence, svk, AuthPhase.OBSERVE_EXTENDED_SESSION, None)


def capture_auth_seed_once(network: GatewayNetwork, evidence: GatewayVINReadEvidence,
                           svk: HeadUnitSVKEvidence, profile: AuthProfile) -> HeadUnitAuthResult:
    """Prepare extended/coding session and capture a seed; never invoke a signer."""
    return _exchange(network, evidence, svk, AuthPhase.CAPTURE_AUTH_SEED, profile)


def capture_bdc_seed_once(network, evidence, svk, profile):
    """Observe a fresh seed, then explicitly return BDC to default session."""
    if type(svk) is not BDCSVKEvidence:
        raise AuthContractError('bdc_auth_module_required')
    return _exchange(network, evidence, svk, AuthPhase.CAPTURE_BDC_SEED_AND_DEFAULT, profile)


def capture_vsg_seed_once(network, evidence, svk, profile):
    if type(svk) is not VSGSVKEvidence: raise AuthContractError('vsg_auth_module_required')
    return _exchange(network,evidence,svk,AuthPhase.CAPTURE_VSG_SEED_AND_DEFAULT,profile)


def validate_bdc_auth_once(network, evidence, svk, prerequisite, provider, *, phase=AuthPhase.DENY):
    """Fresh AS acceptance and default-session observation; no coding-data write."""
    if (phase is not AuthPhase.VALIDATE_BDC_AUTH or type(svk) is not BDCSVKEvidence
            or type(evidence) is not GatewayVINReadEvidence
            or type(prerequisite) is not AuthenticationSeedEvidence
            or prerequisite.module != 'BDC' or prerequisite.seed_byte_length != 8
            or prerequisite.session_layout != 'opaque_parameters'
            or (prerequisite.discovery_manifest_sha256, prerequisite.identity_manifest_sha256,
                prerequisite.svk_manifest_sha256) !=
               (evidence.discovery.manifest_sha256, evidence.manifest_sha256, svk.manifest_sha256)):
        raise AuthContractError('bdc_auth_prerequisites_invalid')
    return _exchange(network, evidence, svk, phase, AuthProfile('opaque_parameters', 8), provider)


def _exchange(network, evidence, svk, phase, profile, provider=None) -> HeadUnitAuthResult:
    if (type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence
            or type(svk) not in (HeadUnitSVKEvidence, BDCSVKEvidence, VSGSVKEvidence)):
        raise TypeError('authentication requires exact frozen network, VIN and SVK types')
    module = svk_module(svk); target = contract(module).target
    start = experiment_started = experiment_deadline = first_request_started = None
    last_clock = None
    requests, request_times, captured, chunk_stages, completed, parameters = [], [], [], [], [], []
    connection_attempts = opened = attempts = sent = confirmed = received_bytes = 0
    connection_uncertain = transmission_uncertain = close_uncertain = False
    timing_complete = True
    ack_total = pending_total = 0
    nrc = last_control = None
    seed = None
    outcome, reason = 'timeout', 'response_deadline_exhausted'
    sock = None
    operation = 'preflight'

    def clock():
        nonlocal last_clock, timing_complete
        value = time.monotonic()
        if (type(value) not in (int, float) or not math.isfinite(value)
                or (last_clock is not None and value < last_clock)):
            timing_complete = False
            raise _Stop('invalid_timing', 'monotonic_clock_invalid')
        last_clock = float(value)
        return float(value)

    def deadline(at, window):
        nonlocal timing_complete
        result = at + window
        if not math.isfinite(result) or result <= at:
            timing_complete = False
            raise _Stop('invalid_timing', 'computed_deadline_invalid')
        return result

    def remaining(end):
        value = end - clock()
        if value <= 0:
            raise _DeadlineExpired()
        return value

    def fresh(end=None):
        kwargs = {} if end is None else {'deadline': end}
        return identity_preflight(network.interface, network.source_address, network.gateway_address, **kwargs) == network

    try:
        start = clock()
        GatewayNetwork.__post_init__(network)
        if not _exbox_vin_evidence_matches(network, evidence):
            raise _Stop('evidence_mismatch', 'verified_vin_evidence_not_bound_to_network')
        from .live_block import _block_svk_matches
        if not _block_svk_matches(network,evidence,svk,module=module):
            raise _Stop('evidence_mismatch', 'verified_svk_evidence_not_bound_to_network_or_identity')
        if phase is not AuthPhase.OBSERVE_EXTENDED_SESSION:
            if type(profile) is not AuthProfile:
                raise _Stop('profile_invalid', 'reviewed_authentication_profile_required')
            AuthProfile.__post_init__(profile)
            if phase in (AuthPhase.CAPTURE_AUTH_SEED, AuthPhase.CAPTURE_BDC_SEED_AND_DEFAULT, AuthPhase.CAPTURE_VSG_SEED_AND_DEFAULT) and profile.seed_byte_length is not None:
                raise _Stop('profile_invalid', 'capture_must_not_assume_seed_length')
        if phase is AuthPhase.VALIDATE_BDC_AUTH and (module != 'BDC' or
                not _provider_matches(provider, unused_required=True, module='BDC')):
            raise _Stop('provider_invalid', 'bdc_as_provider_required')
        if not fresh():
            raise _Stop('network_changed', 'preflight_changed')
        policy = LiveHeadUnitAuthPolicy(network, phase, module)
        operation = 'socket_creation'
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        operation = 'socket_binding'
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, network.interface_index)
        sock.bind((network.source_address, 0))
        operation = 'connect_preflight'
        if not fresh():
            raise _Stop('network_changed', 'preflight_changed')
        if (binding := _bound_source_reason(sock, network)):
            raise _Stop('network_changed', binding)
        endpoint = (network.gateway_address, DIAGNOSTIC_PORT)
        operation = 'connect'
        experiment_started = clock()
        experiment_deadline = deadline(experiment_started, AUTH_EXPERIMENT_WINDOW_SECONDS)
        sock.settimeout(min(CONNECT_TIMEOUT_SECONDS, remaining(experiment_deadline)))
        remaining(experiment_deadline)
        connection_attempts = 1
        connection_uncertain = True
        sock.connect(endpoint)
        opened = 1
        connection_uncertain = False
        maximum = len(auth_stages(phase.value))
        for index in range(maximum):
            stage_name = auth_stages(phase.value)[index]
            if stage_name == 'security_key':
                envelope = provider.sign_seed(seed)
                if (not _provider_matches(provider, module='BDC') or
                        not verify_security_access(seed, envelope, provider.public_key, module='BDC')):
                    raise AuthContractError('bdc_as_signature_invalid')
                payload = bytes.fromhex('000000880001f440') + key_request(envelope)
                policy = LiveHeadUnitAuthPolicy(network, phase, module, payload)
            else:
                payload = auth_request(phase.value, module, index)
            operation = 'send_preflight'
            if not fresh(experiment_deadline):
                raise _Stop('network_changed', 'preflight_changed')
            remaining(experiment_deadline)
            if sock.getpeername() != endpoint:
                raise _Stop('network_changed', 'connected_peer_not_confirmed')
            if (binding := _bound_source_reason(sock, network)):
                raise _Stop('network_changed', binding)
            request_started = clock()
            overall_end = min(experiment_deadline, deadline(request_started, OVERALL_REQUEST_WINDOW_SECONDS))
            operation = 'send'
            sock.settimeout(min(FIRST_RESPONSE_WINDOW_SECONDS, remaining(overall_end)))
            policy.validate(payload, endpoint, sent_count=attempts, completed_stages=len(completed))
            remaining(overall_end)
            if first_request_started is None:
                first_request_started = request_started
            requests.append(payload)
            request_times.append(round(request_started - experiment_started, 6))
            attempts += 1
            transmission_uncertain = True
            count = sock.send(payload)
            if type(count) is not int or not 0 <= count <= len(payload):
                raise _Stop('socket_error', 'invalid_send_accounting')
            confirmed += count
            if count != len(payload):
                raise _Stop('socket_error', 'partial_application_frame_send')
            sent += 1
            transmission_uncertain = False
            parser = IncrementalParser(max_body_length=MAX_FRAME_BODY_BYTES)
            uds_request = payload[8:]
            response_end = min(overall_end, deadline(clock(), FIRST_RESPONSE_WINDOW_SECONDS))
            stage_ack = stage_pending = 0
            operation = 'receive'
            terminal = None
            while terminal is None:
                if len(captured) >= MAX_RECEIVE_CHUNKS:
                    raise _Stop('receive_limit', 'receive_chunk_budget_exhausted')
                if received_bytes >= MAX_RAW_RECEIVE_BYTES:
                    raise _Stop('receive_limit', 'receive_byte_budget_exhausted')
                active_end = min(overall_end, response_end)
                sock.settimeout(remaining(active_end))
                raw = sock.recv(min(RECEIVE_CHUNK_BYTES, MAX_RAW_RECEIVE_BYTES - received_bytes))
                if type(raw) is not bytes:
                    raise _Stop('socket_error', 'invalid_receive_accounting')
                if raw:
                    captured.append(ReceivedTCPChunk(raw, None))
                    chunk_stages.append(stage_name)
                    received_bytes += len(raw)
                    if received_bytes > MAX_RAW_RECEIVE_BYTES or len(raw) > RECEIVE_CHUNK_BYTES:
                        raise _Stop('receive_limit', 'received_bytes_exceed_resource_bound')
                try:
                    received_at = clock()
                except KeyboardInterrupt:
                    timing_complete = False
                    raise
                if not raw:
                    parser.finish()
                    raise _Stop('eof', 'gateway_closed_before_terminal_response')
                captured[-1] = ReceivedTCPChunk(raw, round(received_at - experiment_started, 6))
                if received_at >= active_end:
                    raise _DeadlineExpired()
                for incoming in parser.feed(raw):
                    last_control = int(incoming.control)
                    if terminal is not None:
                        raise _Stop('unexpected_response', 'additional_frame_after_terminal_response')
                    if incoming.control is Control.ACK:
                        if stage_ack:
                            raise _Stop('unexpected_response', 'duplicate_ack')
                        if ((incoming.source, incoming.target) != (0xF4, target)
                                or incoming.diagnostic_payload != expected_ack_echo(uds_request)):
                            raise _Stop('unexpected_response', 'ack_not_correlated')
                        stage_ack = 1
                        ack_total += 1
                        continue
                    if incoming.control is not Control.DIAGNOSTIC:
                        raise _Stop('unexpected_control', 'unsupported_hsfz_control')
                    if (incoming.source, incoming.target) != (target, 0xF4):
                        raise _Stop('unexpected_response', 'diagnostic_addresses_not_correlated')
                    pdu = incoming.diagnostic_payload
                    if pdu[:1] == b'\x7f':
                        nrc = negative_response(pdu, uds_request[0])
                        if nrc != 0x78:
                            raise _Stop('negative_response', 'correlated_negative_response')
                        stage_pending += 1
                        pending_total += 1
                        if stage_pending > MAX_PENDING_PER_REQUEST:
                            raise _Stop('receive_limit', 'pending_count_budget_exhausted')
                        response_end = min(overall_end, deadline(received_at, PENDING_RESPONSE_WINDOW_SECONDS))
                        continue
                    if stage_ack != 1:
                        raise _Stop('unexpected_response', 'terminal_response_without_correlated_ack')
                    if index < 2:
                        subfunction = (0x03, 0x41)[index]
                        layout = 'opaque_parameters' if phase is AuthPhase.OBSERVE_EXTENDED_SESSION else profile.session_layout
                        terminal = parse_session_response(pdu, subfunction, layout=layout).parameters
                    elif index == 2:
                        candidate = parse_seed_response(pdu).seed
                        if len(candidate) > MAX_AUTH_SEED_BYTES:
                            raise AuthContractError('seed_exceeds_authentication_frame_bound')
                        if profile.seed_byte_length is not None and len(candidate) != profile.seed_byte_length:
                            raise AuthContractError('seed_length_does_not_match_reviewed_contract')
                        terminal = candidate
                    elif stage_name == 'security_key':
                        parse_key_response(pdu); terminal = b''
                    elif stage_name == 'default_session':
                        terminal = parse_session_response(pdu, 0x01, layout=profile.session_layout).parameters
                    else:
                        response = parse_ping_response(pdu, layout='f186_state')
                        if (response.session, response.state) != (1, 0x81):
                            raise AuthContractError('bdc_default_session_state_mismatch')
                        terminal = b''
                    nrc = None
                if terminal is not None:
                    parser.finish()
                    remaining(min(overall_end, response_end))
            if index < 2:
                parameters.append(((0x03, 0x41)[index], terminal))
            elif index == 2:
                seed = terminal
            elif stage_name == 'default_session':
                parameters.append((0x01, terminal))
            completed.append(stage_name)
        outcome = MODES[phase.value][1]
        reason = None
    except _Stop as exc:
        outcome, reason = exc.outcome, exc.reason
    except _DeadlineExpired:
        outcome, reason = 'timeout', 'request_or_experiment_deadline_exhausted'
    except NetworkPreflightError:
        outcome, reason = 'network_changed', 'preflight_no_longer_valid'
    except AuthContractError as exc:
        outcome, reason = 'authentication_contract_failed', exc.reason
    except (AuthProviderError, SignatureError):
        outcome, reason = 'authentication_contract_failed', 'bdc_as_signing_failed'
    except CodingProtocolError as exc:
        outcome, reason = 'malformed_response', exc.reason
    except PolicyViolation:
        outcome, reason = 'policy_denied', 'final_send_policy_rejected'
    except HSFZError:
        outcome, reason = 'malformed_response', 'invalid_hsfz_stream'
    except socket.timeout:
        outcome = 'connect_timeout' if operation == 'connect' else 'timeout'
        reason = 'connect_deadline_exhausted' if operation == 'connect' else 'request_deadline_exhausted'
    except KeyboardInterrupt:
        outcome, reason = 'interrupted', 'user_interrupt'
        timing_complete = False
    except OSError:
        outcome, reason = 'socket_error', operation + '_failed'
    finally:
        if sock is not None:
            try:
                sock.close()
            except KeyboardInterrupt:
                outcome, reason = 'interrupted', 'socket_close_interrupted'
                close_uncertain = True
            except OSError:
                outcome, reason = 'socket_error', 'socket_close_failed'
                close_uncertain = True
    try:
        finished = clock()
    except (KeyboardInterrupt, _Stop):
        outcome, reason = 'interrupted', 'final_clock_sampling_incomplete'
        timing_complete = False
        elapsed = response_elapsed = experiment_elapsed = None
    else:
        elapsed = None if start is None else round(finished - start, 6)
        response_elapsed = 0.0 if first_request_started is None else round(finished - first_request_started, 6)
        experiment_elapsed = 0.0 if experiment_started is None else round(finished - experiment_started, 6)
        if start is None:
            timing_complete = False
        if (outcome in tuple(v[1] for v in MODES.values())
                and experiment_deadline is not None and finished >= experiment_deadline):
            outcome, reason = 'timeout', 'experiment_deadline_exhausted'
    return HeadUnitAuthResult(
        phase.value, outcome, reason, connection_attempts, opened, connection_uncertain,
        attempts, sent, confirmed, transmission_uncertain, tuple(requests), tuple(request_times),
        tuple(captured), tuple(chunk_stages), tuple(completed), tuple(parameters), seed,
        ack_total, pending_total, nrc, last_control, elapsed, response_elapsed, experiment_elapsed,
        timing_complete, close_uncertain, module, None if provider is None else provider.public_key,
    )
