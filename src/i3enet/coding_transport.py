"""Native profile-bound field transaction with fixed framing and operations.

The coding command supplies an exact edit and explicit selection after review.
Default DENY precedes provider/socket use. An invocation requires an authorized
operation, risk acknowledgement and recovery. Attestations are caller inputs, not
measured vehicle facts. There is no retry, restore, helper or general sender.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import hmac
import math
import re
import socket
import time

from . import coding_protocol as p
from .auth_evidence import AuthSessionEvidence, AuthenticationSeedEvidence
from .coding_frame_plan import CodingFramePlan, CodingFramePlanError
from .coding_preparation import (CodingSnapshot, CodingPreparationError, GROUP_LENGTHS,
                                 PreparedCoding, verify_coding_readback, CodingEdit)
from .coding_signature import RSA1024PublicKey
from .evidence import EvidenceError, GatewayVINReadEvidence
from .hsfz import Control, HSFZError, IncrementalParser, expected_ack_echo
from .live_block import _exbox_svk_evidence_matches, _exbox_vin_evidence_matches, _bdc_svk_evidence_matches
from .coding_contract import contract, transaction_stages, transaction_bounds, initial_read_frames
from .auth_provider import _provider_matches
from .live_identity import _bound_source_reason
from .network import GatewayNetwork, IP_BOUND_IF, identity_preflight
from .policy import PolicyViolation
from .svk import HeadUnitSVKEvidence, BDCSVKEvidence, VSGSVKEvidence, parse_svk_value, _software_tuple

STAGES = sum(transaction_stages('HU'), ())
_READS = tuple(bytes.fromhex("000000050001f46322") + address.to_bytes(2, "big")
               for address, _ in GROUP_LENGTHS)
_INITIAL = (bytes.fromhex("000000050001f41022f190"), bytes.fromhex("000000050001f46322f101"), *_READS)
_PIN = re.compile(r"[0-9a-f]{64}\Z")


class TransactionPhase(Enum):
    DENY = "deny"
    CODING = "coding_transaction"


@dataclass(frozen=True, slots=True)
class TransactionSelection:
    phase: TransactionPhase = TransactionPhase.DENY
    change_approved: bool = False
    risk_acknowledged: bool = False
    recovery_confirmed: bool = False
    exclusive_diagnostics_confirmed: bool = False
    parked_awake_confirmed: bool = False

    def validate(self) -> None:
        if (type(self.phase) is not TransactionPhase or self.phase is not TransactionPhase.CODING
                or any(type(getattr(self, name)) is not bool or getattr(self, name) is not True
                       for name in self.__dataclass_fields__ if name != "phase")):
            raise PolicyViolation("coding_transaction_not_selected")


@dataclass(frozen=True, slots=True, repr=False)
class TransactionInputs:
    network: GatewayNetwork
    identity: GatewayVINReadEvidence
    svk: HeadUnitSVKEvidence
    original: CodingSnapshot
    probe: AuthSessionEvidence
    seed: AuthenticationSeedEvidence
    edit: CodingEdit = field(repr=False)
    original_cps: bytes | None = field(default=None, repr=False)
    cps_manifest_sha256: str | None = None

    def validate(self) -> None:
        if (type(self.network) is not GatewayNetwork or type(self.identity) is not GatewayVINReadEvidence
                or type(self.svk) not in (HeadUnitSVKEvidence, BDCSVKEvidence, VSGSVKEvidence) or type(self.original) is not CodingSnapshot
                or type(self.probe) is not AuthSessionEvidence or type(self.seed) is not AuthenticationSeedEvidence
                or type(self.edit) is not CodingEdit):
            raise PolicyViolation("coding_transaction_inputs_invalid")
        GatewayNetwork.__post_init__(self.network)
        CodingSnapshot.__post_init__(self.original)
        CodingEdit.__post_init__(self.edit)
        spec = contract(self.edit.module)
        if ((self.original.cafd, self.original.btld) != (spec.cafd, spec.btld)
                or self.probe.module != spec.module or self.seed.module != spec.module):
            raise PolicyViolation('coding_transaction_module_mismatch')
        if spec.module != 'HU' and (type(self.original_cps) is not bytes or
                self.original_cps != self.identity.discovery.vin_candidate[-7:].encode('ascii') or
                type(self.cps_manifest_sha256) is not str or _PIN.fullmatch(self.cps_manifest_sha256) is None):
            raise PolicyViolation('bdc_original_cps_required')
        from .live_block import _block_svk_matches
        if not (_exbox_vin_evidence_matches(self.network, self.identity)
                and _block_svk_matches(self.network,self.identity,self.svk,module=spec.module)):
            raise PolicyViolation("coding_transaction_proof_binding_invalid")
        pins = (self.identity.discovery.manifest_sha256, self.identity.manifest_sha256, self.svk.manifest_sha256)
        if (self.probe.session_layout != "opaque_parameters" or self.seed.session_layout != "opaque_parameters"
                or type(self.seed.seed_byte_length) is not int or self.seed.seed_byte_length != 8
                or self.seed.session_manifest_sha256 != self.probe.manifest_sha256
                or (self.probe.discovery_manifest_sha256, self.probe.identity_manifest_sha256,
                    self.probe.svk_manifest_sha256) != pins
                or (self.seed.discovery_manifest_sha256, self.seed.identity_manifest_sha256,
                    self.seed.svk_manifest_sha256) != pins
                or any(type(pin) is not str or _PIN.fullmatch(pin) is None for pin in
                       (self.probe.manifest_sha256, self.seed.manifest_sha256, self.seed.seed_sha256,
                        self.probe.parameter_sha256))):
            raise PolicyViolation("coding_transaction_auth_proofs_invalid")

    def __repr__(self) -> str:
        return f"TransactionInputs(module={self.edit.module}, group=0x{self.edit.group:04X}, offset={self.edit.offset}, originals=<private>)"


@dataclass(frozen=True, slots=True)
class CodingTransportPolicy:
    """Exact ordered boundary; a static plan alone cannot select this phase."""
    selection: TransactionSelection = TransactionSelection()
    plan: CodingFramePlan | None = field(default=None, repr=False)
    module: str = 'HU'

    def validate(self, frame: bytes, *, index: int, completed: int, destination: tuple[str, int],
                 network: GatewayNetwork) -> None:
        if type(self.selection) is not TransactionSelection:
            raise PolicyViolation("coding_transaction_selection_invalid")
        self.selection.validate()
        try: spec = contract(self.module)
        except ValueError: raise PolicyViolation('coding_transaction_module_invalid') from None
        coding, post = transaction_stages(self.module)
        if (type(index) is not int or type(completed) is not int or index != completed or not 0 <= index < len(coding) + len(post)
                or type(network) is not GatewayNetwork
                or type(destination) is not tuple or len(destination) != 2
                or type(destination[0]) is not str or type(destination[1]) is not int
                or destination != (network.gateway_address, 6801)):
            raise PolicyViolation("coding_transaction_stage_or_destination_invalid")
        try:
            GatewayNetwork.__post_init__(network)
        except Exception:
            raise PolicyViolation("coding_transaction_final_network_invalid") from None
        initial = initial_read_frames(self.module)
        if index < len(initial):
            expected = initial[index]
        else:
            if type(self.plan) is not CodingFramePlan or self.plan.module != self.module:
                raise PolicyViolation("coding_transaction_candidate_not_verified")
            try:
                expected = self.plan.expected_frame("coding" if index < len(coding) else "verification",
                                                    index if index < len(coding) else index - len(coding))
            except CodingFramePlanError:
                raise PolicyViolation("coding_transaction_frame_unresolved") from None
        if type(frame) is not bytes or frame != expected:
            raise PolicyViolation("coding_transaction_frame_not_exact")


class _Stop(Exception):
    def __init__(self, outcome: str, reason: str):
        self.outcome, self.reason = outcome, reason


class NativeCodingConnection:
    """One privately owned socket; no raw public command/CLI is exposed."""
    def __init__(self, sock):
        self._sock = sock

    def assert_bound(self, network, deadline):
        if (identity_preflight(network.interface, network.source_address, network.gateway_address,
                               deadline=deadline) != network
                or self._sock.getpeername() != (network.gateway_address, 6801)
                or _bound_source_reason(self._sock, network)):
            raise _Stop("network_changed", "coding_transaction_binding_changed")

    def settimeout(self, value): self._sock.settimeout(value)
    def send(self, frame): return self._sock.send(frame)
    def recv(self, size): return self._sock.recv(size)
    def close(self): self._sock.close()


class NativeCodingConnector:
    def open(self, network, deadline, on_attempt, on_opened, on_connecting):
        sock = None
        try:
            if identity_preflight(network.interface, network.source_address, network.gateway_address,
                                  deadline=deadline) != network:
                raise _Stop("network_changed", "coding_transaction_preflight_changed")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, network.interface_index)
            sock.bind((network.source_address, 0))
            if _bound_source_reason(sock, network):
                raise _Stop("network_changed", "coding_transaction_source_not_bound")
            on_attempt()  # Durable intent; it is not yet a connect attempt.
            if (identity_preflight(network.interface, network.source_address, network.gateway_address,
                                   deadline=deadline) != network
                    or _bound_source_reason(sock, network)):
                raise _Stop("network_changed", "coding_transaction_connect_preflight_changed")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _Stop("timeout", "coding_transaction_connect_deadline")
            sock.settimeout(min(3.0, remaining))
            on_connecting()
            sock.connect((network.gateway_address, 6801))
            on_opened()
            result = NativeCodingConnection(sock)
            result.assert_bound(network, deadline)
            return result
        except BaseException:
            if sock is not None:
                try:
                    sock.close()
                except (OSError, KeyboardInterrupt):
                    raise _Stop("close_uncertain", "coding_transaction_failed_connect_close_uncertain") from None
            raise


def _ncds_matches(provider, module='HU') -> bool:
    from .coding_provider import NCDSCodingProvider
    if type(provider) is not NCDSCodingProvider:
        return False
    try:
        safe = provider.safe_summary()
        public = provider.public_key
        if type(public) is not RSA1024PublicKey:
            return False
        RSA1024PublicKey.__post_init__(public)
        required = {"role": "NCDS", "module": module, "target_role_bound": True,
                    "core_dumps_disabled": True, "btld_identifier": contract(module).btld.split('/')[0], "cafd": contract(module).cafd,
                    "provider_kind": "supplied_key_ncds", "key_bits": 1024,
                    "digest": "MD5", "signature_scheme": "BMWSigVerify"}
        return (type(safe) is dict
                and all(type(safe.get(k)) is type(v) and safe.get(k) == v for k, v in required.items())
                and safe.get("signing_attempted") is False and safe.get("provider_closed") is False
                and type(safe.get("configuration_sha256")) is str
                and _PIN.fullmatch(safe["configuration_sha256"]) is not None
                and type(safe.get("key_file_sha256")) is str and _PIN.fullmatch(safe["key_file_sha256"]) is not None)
    except (Exception, KeyboardInterrupt):
        return False


@dataclass(frozen=True, slots=True, repr=False)
class CodingTransportResult:
    evidence_status: str
    provenance: str
    outcome: str
    reason: str | None
    connection_attempts: int
    connections_opened: int
    connection_uncertain: bool
    application_attempts: int
    application_frames_sent: int
    application_bytes_sent: int
    transmission_uncertain: bool
    received_bytes: int
    received_chunks: int
    completed_stages: tuple[str, ...]
    write_attempts: int
    reset_attempted: bool
    close_uncertain: bool
    timing_complete: bool
    elapsed_seconds: float | None
    prepared: PreparedCoding | None = field(repr=False)
    readback: CodingSnapshot | None = field(repr=False)
    current_svk: bytes | None = field(repr=False)
    expected_cps: bytes | None = field(repr=False)
    fresh_seed: bytes | None = field(repr=False)
    module: str = 'HU'

    def __repr__(self):
        return f"CodingTransportResult(outcome={self.outcome!r}, private_values=<omitted>)"

    def public_report(self):
        spec = contract(self.module); stages = sum(transaction_stages(self.module), ())
        frames, byte_cap, chunk_cap = transaction_bounds(self.module)
        verified = (self.outcome == "candidate_readback_verified" and self.completed_stages == stages
                    and self.connection_attempts == self.connections_opened == 2
                    and self.application_attempts == self.application_frames_sent == frames
                    and self.application_bytes_sent == byte_cap and self.write_attempts == len(spec.groups)
                    and not any((self.connection_uncertain, self.transmission_uncertain, self.close_uncertain))
                    and self.timing_complete)
        return {
            "evidence_status": self.evidence_status, "original_provenance": self.provenance,
            "vehicle_traffic_performed": self.evidence_status == "LOCAL_OBSERVATION" and self.application_attempts > 0,
            "vehicle_contacted": False if self.evidence_status == "SYNTHETIC_FIXTURE" or not self.connection_attempts else None,
            "outcome": self.outcome, "reason": self.reason, "tcp_connections_attempted": self.connection_attempts,
            "tcp_connections_opened": self.connections_opened, "tcp_connection_uncertain": self.connection_uncertain,
            "application_frames_attempted": self.application_attempts, "application_frames_sent": self.application_frames_sent,
            "vehicle_bytes_confirmed_sent": self.application_bytes_sent, "transmission_uncertain": self.transmission_uncertain,
            "received_bytes": self.received_bytes, "received_chunks": self.received_chunks,
            "completed_stage_names": list(self.completed_stages), "coding_group_write_attempts": self.write_attempts,
            "reset_attempted": self.reset_attempted, "tcp_close_uncertain": self.close_uncertain,
            "default_session_observed": self.module != 'HU' and 'default_session' in self.completed_stages,
            "timing_complete": self.timing_complete, "elapsed_seconds": self.elapsed_seconds,
            "complete_candidate_signature_cps_readback_verified": verified,
            "partial_or_uncertain_coding": self.write_attempts > 0 and not verified,
            "authentication_scope": ("writing_connection_only_closed" if "security_key" in self.completed_stages
                                     else "not_established"),
            "authenticated_connection_available": False,
            "activation_predicate": ("project_one_observation_default_01_flash_deactivated_81" if self.module == 'HU' else
                                     "default_session_positive_then_observed_session_01_state_81"),
            "activation_scheduling_verified_on_hardware": False, "effect_verified_on_car": False,
            "recovery_established": False, "writes_supported": False, "live_ready": False,
            "maximum_connections": 2, "maximum_fixed_application_frames": frames,
            "maximum_fixed_application_bytes": byte_cap, "connection_window_seconds": 30.0,
            "reset_wait_seconds": 30.0 if self.module == 'HU' else 0.0, "per_request_window_seconds": 6.0,
            "initial_pending_windows_seconds": 3.0, "maximum_pending_per_request": 4,
            "receive_bytes_per_connection": 65536, "receive_chunks_per_connection": chunk_cap,
        }


def execute_coding_transaction(inputs: TransactionInputs, selection: TransactionSelection,
                                ncds_provider, as_provider, journal, *,
                                connector=None, clock=None, wait=None) -> CodingTransportResult:
    """Execute only the separately approved, profile-bound transaction.

    Provider loading/closing and private journal finalization belong to the
    caller. Injected connectors/clocks/waits are used only by synthetic tests.
    Failure terminates advancement; an uncertain mutation never auto-restores.
    """
    attempts = opened = app_attempts = sent = confirmed = received_bytes = received_chunks = writes = 0
    connection_uncertain = transmission_uncertain = close_uncertain = reset_attempted = False
    timing_complete = True
    completed = []
    prepared = readback = current_svk = cps = seed = None
    conn = None
    conn_index = 0
    start = last_at = None
    outcome, reason = "denied", "coding_transaction_not_selected"
    monotonic = time.monotonic if clock is None else clock
    pause = time.sleep if wait is None else wait
    factory = NativeCodingConnector() if connector is None else connector
    synthetic = connector is not None or clock is not None or wait is not None
    module = 'HU'

    def now():
        nonlocal last_at, timing_complete
        value = monotonic()
        if (type(value) not in (int, float) or not math.isfinite(value)
                or (last_at is not None and value < last_at)):
            timing_complete = False
            raise _Stop("invalid_timing", "coding_transaction_monotonic_invalid")
        last_at = float(value)
        return last_at

    def remaining(end):
        value = end - now()
        if value <= 0:
            raise _Stop("timeout", "coding_transaction_deadline_exhausted")
        return value

    def record(method, *args, **kwargs):
        try:
            return getattr(journal, method)(*args, **kwargs)
        except KeyboardInterrupt:
            raise
        except Exception:
            raise _Stop("storage_failed", "transaction_journal_" + method + "_failed") from None

    def relative(at): return at - start

    def open_connection(index, end):
        nonlocal attempts, opened, connection_uncertain, conn_index
        conn_index = index
        def attempted():
            record("connection_attempted", index, relative(now()))
        def connecting():
            nonlocal attempts, connection_uncertain
            attempts += 1
            connection_uncertain = True
        def accepted():
            nonlocal opened, connection_uncertain
            opened += 1
            connection_uncertain = False
            record("opened", index, relative(now()))
        return factory.open(inputs.network, end, attempted, accepted, connecting)

    def close_connection():
        nonlocal conn, close_uncertain
        if conn is None:
            return None
        try:
            conn.close()
        except (Exception, KeyboardInterrupt):
            close_uncertain = True
            record("closed", conn_index, True, None)
            raise _Stop("close_uncertain", "coding_transaction_socket_close_failed") from None
        finally:
            conn = None
        at = now()
        record("closed", conn_index, False, relative(at))
        return at

    try:
        if type(selection) is not TransactionSelection:
            raise PolicyViolation("coding_transaction_selection_invalid")
        selection.validate()
        if type(inputs) is not TransactionInputs:
            raise PolicyViolation("coding_transaction_inputs_invalid")
        inputs.validate()
        module = inputs.edit.module; spec = contract(module)
        code_stages, post_stages = transaction_stages(module); stages = code_stages + post_stages
        initial = initial_read_frames(module)
        group_count = len(spec.groups); extended = code_stages.index('extended_session'); key_index = code_stages.index('security_key')
        write_start = key_index + 1; finalize = write_start + group_count; post = len(code_stages)
        chunk_cap = transaction_bounds(module)[2]
        if ((not synthetic and inputs.original.provenance == "synthetic_fixture")
                or (synthetic and isinstance(factory, NativeCodingConnector))):
            raise PolicyViolation("synthetic_inputs_or_injected_clock_not_native_authority")
        if not _ncds_matches(ncds_provider, module) or not _provider_matches(as_provider, unused_required=True, module=module):
            raise _Stop("provider_invalid", "normal_ncds_and_as_providers_required")
        start = now()
        global_end = start + 90.0
        connection_end = start + 30.0
        conn = open_connection(1, connection_end)
        policy = CodingTransportPolicy(selection, module=module)
        connection_received = connection_chunks = 0
        originals, returned = [], []

        def exchange(index, frame, parser):
            nonlocal app_attempts, sent, confirmed, transmission_uncertain, received_bytes, received_chunks
            nonlocal connection_received, connection_chunks, writes, reset_attempted
            stage = stages[index]
            remaining(connection_end)
            conn.assert_bound(inputs.network, connection_end)
            policy.validate(frame, index=index, completed=len(completed),
                            destination=(inputs.network.gateway_address, 6801), network=inputs.network)
            at = now()
            request_end = min(connection_end, at + 6.0)
            token = record("before_attempt", stage, frame, connection_index=conn_index, at=relative(at))
            remaining(request_end)
            conn.settimeout(min(3.0, remaining(request_end)))
            # Fsync/clock/timeout work can consume the earlier preflight. Repeat
            # binding and exact candidate authorization at the final boundary.
            conn.assert_bound(inputs.network, request_end)
            policy.validate(frame, index=index, completed=len(completed),
                            destination=(inputs.network.gateway_address, 6801), network=inputs.network)
            remaining(request_end)
            app_attempts += 1
            if write_start <= index < finalize: writes += 1
            if index == finalize + 3 and module == 'HU': reset_attempted = True
            transmission_uncertain = True
            try:
                count = conn.send(frame)
            except BaseException:
                record("after_attempt", token, None, True, None)
                raise
            if type(count) is not int or not 0 <= count <= len(frame):
                record("after_attempt", token, None, True, None)
                raise _Stop("send_failed", "coding_transaction_send_accounting_invalid")
            confirmed += count
            transmission_uncertain = count != len(frame)
            if not transmission_uncertain: sent += 1
            record("after_attempt", token, count, transmission_uncertain, None)
            sent_at = now()
            record("after_attempt_at", token, relative(sent_at))
            if transmission_uncertain:
                raise _Stop("send_failed", "coding_transaction_partial_send")
            response_end = min(request_end, sent_at + 3.0)
            stream = IncrementalParser(max_body_length=4096)
            ack = pending = 0
            value = None
            terminal = False
            target, uds = frame[7], frame[8:]
            while not terminal:
                if connection_chunks >= chunk_cap or connection_received >= 65536:
                    raise _Stop("receive_limit", "coding_transaction_connection_receive_budget")
                active_end = min(request_end, response_end)
                conn.settimeout(remaining(active_end))
                raw = conn.recv(min(4096, 65536 - connection_received))
                if type(raw) is not bytes:
                    raise _Stop("receive_failed", "coding_transaction_receive_accounting_invalid")
                if not raw:
                    stream.finish()
                    raise _Stop("eof", "coding_transaction_eof_before_positive")
                received_bytes += len(raw); received_chunks += 1
                connection_received += len(raw); connection_chunks += 1
                receipt = record("received", token, raw, None)
                received_at = now()
                record("received_at", receipt, relative(received_at))
                if len(raw) > 4096 or connection_received > 65536:
                    raise _Stop("receive_limit", "coding_transaction_received_bytes_exceed_budget")
                if received_at >= active_end:
                    raise _Stop("timeout", "coding_transaction_response_late")
                for incoming in stream.feed(raw):
                    if terminal:
                        raise _Stop("unexpected_response", "coding_transaction_extra_terminal_frame")
                    if incoming.control is Control.ACK:
                        # Explicit long-write rule: exact capped echo, never any prefix.
                        if (ack or (incoming.source, incoming.target) != (0xF4, target)
                                or incoming.diagnostic_payload != expected_ack_echo(uds)):
                            raise _Stop("unexpected_response", "coding_transaction_ack_not_exact")
                        ack = 1
                        continue
                    if incoming.control is not Control.DIAGNOSTIC or (incoming.source, incoming.target) != (target, 0xF4):
                        raise _Stop("unexpected_response", "coding_transaction_application_not_correlated")
                    pdu = incoming.diagnostic_payload
                    if pdu[:1] == b"\x7f":
                        nrc = p.negative_response(pdu, uds[0])
                        if nrc != 0x78:
                            record("completed", token, "negative_response", nrc, pending)
                            raise _Stop("negative_response", "coding_transaction_terminal_negative")
                        pending += 1
                        if pending > 4:
                            raise _Stop("receive_limit", "coding_transaction_pending_budget")
                        response_end = min(request_end, received_at + 3.0)
                        continue
                    if ack != 1:
                        raise _Stop("unexpected_response", "coding_transaction_positive_without_ack")
                    value = parser(pdu)
                    terminal = True
                if terminal:
                    stream.finish()
                    remaining(min(request_end, response_end))
            record("completed", token, "positive", None, pending)
            completed.append(stage)
            return value

        def svk_value(pdu):
            if type(pdu) is not bytes or pdu[:3] != b"\x62\xf1\x01":
                raise p.CodingProtocolError("transaction_svk_response_mismatch")
            value = pdu[3:]
            _software_tuple(parse_svk_value(value), module=module)
            if hashlib.sha256(value).hexdigest() != inputs.svk.value_sha256:
                raise p.CodingProtocolError("transaction_svk_original_changed")
            return value

        def vin_value(pdu):
            if pdu != b"\x62\xf1\x90" + inputs.identity.discovery.vin_candidate.encode("ascii"):
                raise p.CodingProtocolError("transaction_current_vin_mismatch")
        exchange(0, initial[0], vin_value)
        current_svk = exchange(1, initial[1], svk_value)
        for index, (address, _) in enumerate(spec.groups, 2):
            originals.append((address, exchange(index, initial[index],
                              lambda value, address=address: p.parse_group_read_response(value, address, module=module))))
        current = CodingSnapshot(tuple(originals), inputs.original.provenance, spec.cafd, spec.btld)
        if current.groups != inputs.original.groups:
            raise _Stop("original_changed", "coding_transaction_originals_differ_from_preserved")
        if module != 'HU':
            exchange(extended - 1, initial[extended - 1], lambda value: p.parse_cps_read_response(value, inputs.original_cps))
        prepared = ncds_provider.prepare(current, inputs.edit)
        if (type(prepared) is not PreparedCoding or prepared.original.groups != current.groups
                or prepared.edit != inputs.edit):
            raise _Stop("provider_invalid", "coding_transaction_preparation_not_bound_to_current")
        plan = CodingFramePlan(prepared, inputs.identity.discovery.vin_candidate)
        cps = inputs.identity.discovery.vin_candidate[-7:].encode("ascii")
        policy = CodingTransportPolicy(selection, plan, module)
        for index, sub in ((extended, 0x03), (extended + 1, 0x41)):
            exchange(index, plan.expected_frame("coding", index),
                     lambda value, sub=sub: p.parse_session_response(value, sub, layout="opaque_parameters"))
        seed = exchange(key_index - 1, plan.expected_frame("coding", key_index - 1), lambda value: p.parse_seed_response(value).seed)
        if len(seed) != 8:
            raise _Stop("authentication_failed", "coding_transaction_fresh_seed_width_changed")
        remaining(connection_end)
        envelope = as_provider.sign_seed(seed)
        if not _provider_matches(as_provider, module=module):
            raise _Stop("provider_invalid", "coding_transaction_as_provider_invalid_after_signing")
        plan = plan.bind_as_response(seed, envelope, as_provider.public_key)
        policy = CodingTransportPolicy(selection, plan, module)
        exchange(key_index, plan.expected_frame("coding", key_index), p.parse_key_response)
        for index, (address, _) in enumerate(spec.groups, write_start):
            exchange(index, plan.expected_frame("coding", index),
                     lambda value, address=address: p.parse_group_write_response(value, address, module=module))
        def signature_value(value):
            if p.parse_signature_check_response(value) is not True:
                raise _Stop("signature_rejected", "coding_transaction_ecu_signature_incorrect")
        exchange(finalize, plan.expected_frame("coding", finalize), signature_value)
        exchange(finalize + 1, plan.expected_frame("coding", finalize + 1), p.parse_cps_write_response)
        exchange(finalize + 2, plan.expected_frame("coding", finalize + 2), lambda value: p.parse_cps_read_response(value, cps))
        exchange(finalize + 3, plan.expected_frame("coding", finalize + 3), p.parse_reset_response if module == 'HU' else
                 lambda value: p.parse_session_response(value, 0x01, layout='opaque_parameters'))
        closed_at = close_connection()
        remaining(global_end)
        if module == 'HU': pause(max(0.0, closed_at + 30.0 - now()))
        if module == 'HU' and now() < closed_at + 30.0:
            raise _Stop("invalid_timing", "coding_transaction_reset_wait_incomplete")
        remaining(global_end)
        connection_end = min(global_end, now() + 30.0)
        conn = open_connection(2, connection_end)
        connection_received = connection_chunks = 0

        exchange(post, plan.expected_frame("verification", 0), vin_value)
        exchange(post + 1, plan.expected_frame("verification", 1), svk_value)
        def ping_value(pdu):
            parsed = p.parse_ping_response(pdu, layout="f186_state")
            if (parsed.session, parsed.state) != (0x01, 0x81):
                raise p.CodingProtocolError("transaction_post_reset_state_not_selected")
        exchange(post + 2, plan.expected_frame("verification", 2), ping_value)
        def readback_value(pdu, address, expected):
            value = p.parse_group_read_response(pdu, address, module=module)
            if not hmac.compare_digest(value, expected):
                raise p.CodingProtocolError("transaction_readback_candidate_mismatch")
            return value
        for index, (address, _) in enumerate(spec.groups, post + 3):
            expected = prepared.candidate.groups[index - post - 3][1]
            returned.append((address, exchange(index, plan.expected_frame("verification", index - post),
                             lambda value, address=address, expected=expected: readback_value(value, address, expected))))
        def cps_value(pdu):
            p.parse_cps_read_response(pdu, cps)
            return pdu[3:]
        returned_cps = exchange(len(stages) - 1, plan.expected_frame("verification", len(post_stages) - 1), cps_value)
        readback = CodingSnapshot(tuple(returned), current.provenance, spec.cafd, spec.btld)
        verify_coding_readback(prepared, readback, expected_cps=cps, returned_cps=returned_cps)
        close_connection()
        remaining(connection_end)
        outcome, reason = "candidate_readback_verified", None
    except PolicyViolation as exc:
        outcome, reason = "denied", str(exc)
    except _Stop as exc:
        outcome, reason = exc.outcome, exc.reason
        if outcome == "close_uncertain": close_uncertain = True
    except (p.CodingProtocolError, CodingFramePlanError, CodingPreparationError, EvidenceError) as exc:
        outcome, reason = "contract_failed", getattr(exc, "reason", "coding_transaction_contract_failed")
    except HSFZError:
        outcome, reason = "malformed_response", "coding_transaction_hsfz_invalid"
    except socket.timeout:
        outcome, reason = "timeout", "coding_transaction_socket_timeout"
    except KeyboardInterrupt:
        outcome, reason = "interrupted", "coding_transaction_user_interrupt"
        timing_complete = False
    except Exception:
        outcome, reason = "failed", "coding_transaction_operation_failed"
    finally:
        if conn is not None:
            try:
                close_connection()
            except (Exception, KeyboardInterrupt):
                close_uncertain = True
                outcome, reason = "close_uncertain", "coding_transaction_cleanup_incomplete"
    elapsed = None
    if start is not None:
        try:
            finished = now()
            elapsed = finished - start
            if (outcome == "candidate_readback_verified"
                    and (finished >= connection_end or finished >= global_end)):
                outcome, reason = "timeout", "coding_transaction_final_deadline_exhausted"
        except (Exception, KeyboardInterrupt):
            timing_complete = False
            outcome, reason = "invalid_timing", "coding_transaction_final_clock_incomplete"
    return CodingTransportResult("SYNTHETIC_FIXTURE" if synthetic else "LOCAL_OBSERVATION",
        inputs.original.provenance if type(inputs) is TransactionInputs and type(inputs.original) is CodingSnapshot else "unverified",
        outcome, reason, attempts, opened, connection_uncertain,
        app_attempts, sent, confirmed, transmission_uncertain, received_bytes, received_chunks, tuple(completed),
        writes, reset_attempted, close_uncertain, timing_complete, elapsed, prepared, readback, current_svk, cps, seed,
        module)
