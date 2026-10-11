"""Strict private original gates for session preparation and authentication.

Loading evidence opens no vehicle socket and loads no signing material.
The selected session schema is explicit; a six-byte reply never selects it.
An earlier seed supplies only an observed width, never a replayed challenge.
"""
from __future__ import annotations

from . import __version__

from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path

from .coding_protocol import (CodingProtocolError, negative_response,
                              parse_seed_response, parse_session_response, parse_key_response,
                              parse_ping_response)
from .coding_signature import RSA1024PublicKey, verify_security_access
from .evidence import (EvidenceError, GatewayVINReadEvidence, _hash_shape,
                       _open_directory, _read_private_file, _unique_object)
from .hsfz import Control, HSFZError, IncrementalParser, expected_ack_echo
from .svk import HeadUnitSVKEvidence, BDCSVKEvidence, VSGSVKEvidence, svk_module, svk_source_key
from .coding_contract import contract

SCHEMA = "i3enet-head-unit-auth-capture/1"
STAGES = ("extended_session", "coding_session", "security_seed")
FIXED_REQUESTS = tuple(bytes.fromhex(s) for s in (
    "000000040001f4631003", "000000040001f4631041", "000000080001f4632701ffffffff"))
MODES = {
    "observe_extended_session": ("observe-head-unit-extended-session", "extended_session_observed", 1),
    "capture_auth_seed": ("prepare-head-unit-auth", "authentication_seed_observed", 3),
    "validate_bdc_auth": ("validate-bdc-auth", "bdc_authentication_default_session_observed", 6),
    "capture_bdc_seed_and_default": ("prepare-bdc-auth", "authentication_seed_default_session_observed", 5),
    'capture_vsg_seed_and_default': ('prepare-vsg-auth','authentication_seed_default_session_observed',5),
}


def auth_stages(mode):
    suffix = {"validate_bdc_auth": ("security_key", "default_session", "session_state"),
              "capture_bdc_seed_and_default": ("default_session", "session_state"),
              'capture_vsg_seed_and_default': ('default_session','session_state')}.get(mode, ())
    return STAGES + suffix if suffix else STAGES[:MODES[mode][2]]


def auth_request(mode, module, index, key_frame=None):
    stage = auth_stages(mode)[index]
    if index < 3: return auth_requests(module)[index]
    _require(module == ('VSG01' if mode == 'capture_vsg_seed_and_default' else 'BDC'), 'auth_mode_module_mismatch')
    target = bytes((contract(module).target,))
    return {'security_key': key_frame, 'default_session': bytes.fromhex('000000040001f4') + target + b'\x10\x01',
            'session_state': bytes.fromhex('000000050001f4') + target + bytes.fromhex('22f186')}[stage]


def auth_requests(module):
    target = bytes((contract(module).target,))
    return tuple(raw[:7] + target + raw[8:] for raw in FIXED_REQUESTS)


def auth_command(mode, module):
    name = MODES[mode][0]
    return name.replace('head-unit', 'bdc' if module == 'BDC' else 'vsg') if module != 'HU' else name


@dataclass(frozen=True, slots=True)
class AuthSessionEvidence:
    manifest_sha256: str
    discovery_manifest_sha256: str
    identity_manifest_sha256: str
    svk_manifest_sha256: str
    session_layout: str
    parameter_byte_count: int
    parameter_sha256: str
    module: str = 'HU'


@dataclass(frozen=True, slots=True)
class AuthenticationSeedEvidence:
    manifest_sha256: str
    discovery_manifest_sha256: str
    identity_manifest_sha256: str
    svk_manifest_sha256: str
    session_manifest_sha256: str
    session_layout: str
    seed_byte_length: int
    seed_sha256: str
    module: str = 'HU'


@dataclass(frozen=True, slots=True)
class AuthCaptureFacts:
    session_parameters: tuple[tuple[int, bytes], ...] = field(repr=False)
    seed: bytes | None = field(repr=False)


def source_links(identity: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence) -> dict[str, object]:
    discovery = identity.discovery
    return {
        "source_discovery": {"manifest_sha256": discovery.manifest_sha256,
                             "reply_sha256": discovery.reply_sha256},
        "source_gateway_identity": {"manifest_sha256": identity.manifest_sha256,
                                    "request_sha256": identity.request_sha256},
        svk_source_key(svk_module(svk)): {"manifest_sha256": svk.manifest_sha256,
                                 "request_sha256": svk.request_sha256,
                                 "value_sha256": svk.value_sha256},
    }


def _require(condition: bool, reason: str = "invalid_auth_original") -> None:
    if not condition:
        raise EvidenceError(reason)


def _number(value: object, upper: float) -> bool:
    return type(value) in (float, int) and math.isfinite(value) and 0 <= value < upper


def validate_capture(manifest: dict[str, object], requests: tuple[bytes, ...],
                     chunks: tuple[bytes, ...], *, mode: str,
                     identity: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence,
                     session_layout: str | None = None,
                     session_evidence: AuthSessionEvidence | None = None,
                     as_public_key: RSA1024PublicKey | None = None) -> AuthCaptureFacts:
    """Independently correlate complete successful originals, including ACKs.

    Caller-supplied counters, positive values or completion labels cannot replace
    this raw-stream check. Authentication acceptance is not future permission.
    """
    _require(mode in MODES)
    command, outcome, count = MODES[mode]
    module = svk_module(svk)
    target = contract(module).target
    stages = auth_stages(mode)
    if mode == "validate_bdc_auth":
        _require(module == 'BDC' and type(as_public_key) is RSA1024PublicKey,
                 'bdc_auth_public_key_required')
    if mode == "capture_bdc_seed_and_default": _require(module == 'BDC')
    if mode == 'capture_vsg_seed_and_default': _require(module == 'VSG01')
    if module == 'VSG01': _require(mode in ('observe_extended_session','capture_vsg_seed_and_default'))
    command = auth_command(mode, module)
    _require(type(manifest) is dict and manifest.get("schema") == SCHEMA)
    _require(manifest.get("implementation_version") == __version__)
    _require(manifest.get("private_raw_originals") is True)
    for key, value in source_links(identity, svk).items():
        _require(manifest.get(key) == value, "auth_source_proof_mismatch")
    report = manifest.get("report")
    _require(type(report) is dict)
    discovery = identity.discovery
    expected = {
        "command": command, "outcome": outcome, "reason": None,
        "implementation_version": manifest["implementation_version"], "exchange_mode": mode,
        "source_interface": discovery.source_interface,
        "source_address": discovery.source_address,
        "gateway_address": discovery.gateway_address,
        "interface_index": discovery.interface_index,
        "tcp_connections_attempted": 1, "tcp_connections_opened": 1,
        "application_frames_attempted": count, "application_frames_sent": count,
        "vehicle_bytes_confirmed_sent": sum(map(len, requests)), "ack_count": count,
        "timing_complete": True, "tcp_close_uncertain": False,
        "tcp_connection_uncertain": False, "transmission_uncertain": False,
        "writes_supported": False, "nrc": None, "last_control": "0x0001",
        "coding_readiness_established": False,
        "completed_stage_names": list(stages),
        "completed_stage_count": count, "exchange_complete": True,
        "chunk_timestamp_origin": "experiment_start_before_connect",
        "request_timestamp_origin": "experiment_start_before_connect",
    }
    for key, value in expected.items():
        _require(report.get(key) == value and type(report.get(key)) is type(value))
    _require(len(requests) == count and requests[:min(count, 3)] == auth_requests(module)[:min(count, 3)])
    if mode == "validate_bdc_auth":
        _require(len(requests[3]) == 142 and requests[3][:10] == bytes.fromhex('000000880001f4402702'))
        for key in ('as_signature_verified', 'authentication_acceptance_observed', 'default_session_observed'):
            _require(report.get(key) is True)
    if mode in ('validate_bdc_auth', 'capture_bdc_seed_and_default','capture_vsg_seed_and_default'):
        _require(requests[-2:] == tuple(auth_request(mode,module,i) for i in range(count-2,count)))
        _require(report.get('default_session_observed') is True)
    _require(type(report.get("pending_count")) is int and 0 <= report["pending_count"] <= count * 4)
    rows = manifest.get("received_chunks")
    starts = manifest.get("requests")
    _require(type(rows) is list and 1 <= len(rows) == len(chunks) <= 64)
    _require(type(starts) is list and len(starts) == count)
    _require(report.get("received_chunks") == len(chunks) and type(report.get("received_chunks")) is int)
    _require(0 < sum(map(len, chunks)) <= 65536)
    _require(report.get("received_bytes") == sum(map(len, chunks)) and type(report.get("received_bytes")) is int)
    for key in ("response_elapsed_seconds", "experiment_elapsed_seconds"):
        _require(_number(report.get(key), 30))
    _require(_number(report.get("elapsed_seconds"), float("inf")))
    _require(report["response_elapsed_seconds"] <= report["experiment_elapsed_seconds"] <= report["elapsed_seconds"])
    start_times = []
    for index, (row, request) in enumerate(zip(starts, requests)):
        _require(type(row) is dict and row.get("stage") == stages[index])
        _require(row.get("file") == f"request-{index + 1:02d}.bin")
        _require(type(row.get("byte_length")) is int and row["byte_length"] == len(request))
        _require(row.get("sha256") == hashlib.sha256(request).hexdigest())
        at = row.get("started_after_seconds")
        _require(_number(at, 30) and (not start_times or at >= start_times[-1]))
        start_times.append(at)
    stage_rows: list[list[tuple[dict, bytes]]] = [[] for _ in range(count)]
    last_at = -1.0
    last_stage = -1
    for index, (row, chunk) in enumerate(zip(rows, chunks)):
        _require(type(row) is dict and row.get("stage") in stages)
        stage_index = stages.index(row["stage"])
        _require(stage_index >= last_stage)
        _require(row.get("file") == f"recv-{index + 1:02d}.bin")
        _require(type(chunk) is bytes and 0 < len(chunk) <= 4096)
        _require(type(row.get("byte_length")) is int and row["byte_length"] == len(chunk))
        _require(row.get("sha256") == hashlib.sha256(chunk).hexdigest())
        at = row.get("received_after_seconds")
        _require(_number(at, 30) and at >= last_at and start_times[stage_index] <= at < start_times[stage_index] + 6)
        _require(stage_index == count - 1 or at <= start_times[stage_index + 1])
        stage_rows[stage_index].append((row, chunk))
        last_at, last_stage = at, stage_index
    _require(last_at <= report["experiment_elapsed_seconds"])
    _require(abs((report["experiment_elapsed_seconds"] - start_times[0])
                 - report["response_elapsed_seconds"]) <= 0.000002)
    if mode == "observe_extended_session":
        _require(session_layout is None and manifest.get("selected_session_layout") is None)
    else:
        _require(session_layout in ("p2_timing", "opaque_parameters"), "auth_session_layout_not_selected")
        _require(type(session_evidence) is AuthSessionEvidence)
        _require(session_evidence.module == module, 'auth_session_module_mismatch')
        _require(session_evidence.session_layout == session_layout)
        _require((session_evidence.discovery_manifest_sha256, session_evidence.identity_manifest_sha256,
                  session_evidence.svk_manifest_sha256) ==
                 (discovery.manifest_sha256, identity.manifest_sha256, svk.manifest_sha256),
                 "auth_session_source_mismatch")
        _require(manifest.get("selected_session_layout") == session_layout)
        _require(manifest.get("source_session_probe") == {"manifest_sha256": session_evidence.manifest_sha256,
                                                       "session_layout": session_layout})
    parameters: list[tuple[int, bytes]] = []
    seed = None
    total_pending = 0
    for index, (request, stage_data) in enumerate(zip(requests, stage_rows)):
        _require(bool(stage_data))
        parser = IncrementalParser(max_body_length=4096)
        ack = 0
        positive = None
        pending = 0
        # Original timestamps bound each whole request independently. The live
        # first-response timer starts after send completion, not at this saved
        # pre-send timestamp, so do not invent an earlier receive deadline.
        receive_deadline = start_times[index] + 6
        for row, raw in stage_data:
            at = row["received_after_seconds"]
            _require(at < receive_deadline)
            for frame in parser.feed(raw):
                _require(positive is None, "auth_extra_terminal_frame")
                if frame.control is Control.ACK:
                    _require(ack == 0 and (frame.source, frame.target) == (0xF4, target)
                             and frame.diagnostic_payload == expected_ack_echo(request[8:]), "auth_ack_mismatch")
                    ack += 1
                    continue
                _require(frame.control is Control.DIAGNOSTIC and (frame.source, frame.target) == (target, 0xF4),
                         "auth_response_mismatch")
                pdu = frame.diagnostic_payload
                _require(type(pdu) is bytes and bool(pdu))
                if pdu[0] == 0x7F:
                    _require(negative_response(pdu, request[8]) == 0x78, "auth_terminal_negative")
                    pending += 1
                    _require(pending <= 4, "auth_pending_limit")
                    receive_deadline = min(start_times[index] + 6, at + 3)
                    continue
                _require(ack == 1, "auth_positive_without_ack")
                if index < 2:
                    selected_layout = "opaque_parameters" if mode == "observe_extended_session" else session_layout
                    response = parse_session_response(pdu, request[9], layout=selected_layout)
                    parameters.append((request[9], response.parameters))
                elif index == 2:
                    seed = parse_seed_response(pdu).seed
                    _require(len(seed) <= 4092)
                elif stages[index] == 'security_key':
                    _require(type(seed) is bytes and len(seed) == 8 and
                             verify_security_access(seed, request[10:], as_public_key, module='BDC'),
                             'bdc_auth_signature_mismatch')
                    parse_key_response(pdu)
                elif stages[index] == 'default_session':
                    response = parse_session_response(pdu, 0x01, layout=session_layout)
                    parameters.append((0x01, response.parameters))
                elif stages[index] == 'session_state':
                    response = parse_ping_response(pdu, layout='f186_state')
                    _require((response.session, response.state) == (1, 0x81),
                             'bdc_default_session_state_mismatch')
                positive = pdu
        parser.finish()
        _require(ack == 1 and positive is not None)
        total_pending += pending
    _require(report["pending_count"] == total_pending)
    parameter_records = report.get("session_parameter_records")
    _require(type(parameter_records) is list and len(parameter_records) == len(parameters))
    for row, (subfunction, raw) in zip(parameter_records, parameters):
        _require(type(row) is dict and set(row) == {"subfunction", "byte_length", "sha256"})
        _require(row.get("subfunction") == f"0x{subfunction:02X}")
        _require(type(row.get("byte_length")) is int and row["byte_length"] == len(raw))
        _require(row.get("sha256") == hashlib.sha256(raw).hexdigest())
    if seed is not None:
        _require(report.get("seed_byte_count") == len(seed) and type(report.get("seed_byte_count")) is int)
        _require(report.get("seed_sha256") == hashlib.sha256(seed).hexdigest())
    return AuthCaptureFacts(tuple(parameters), seed)


def _load_original(directory: Path, manifest_sha256: str, mode: str,
                   identity: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence,
                   session_layout: str | None = None,
                   session_evidence: AuthSessionEvidence | None = None,
                   as_public_key: RSA1024PublicKey | None = None) -> AuthCaptureFacts:
    _require(_hash_shape(manifest_sha256), "invalid_auth_manifest_pin")
    fd = _open_directory(directory)
    try:
        raw = _read_private_file(fd, "manifest.json", 65536)
        _require(hashlib.sha256(raw).hexdigest() == manifest_sha256, "auth_manifest_hash_mismatch")
        manifest = json.loads(raw, object_pairs_hook=_unique_object,
                              parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("invalid_auth_original")))
        _require(type(manifest) is dict)
        count = MODES[mode][2]
        rows = manifest.get("received_chunks")
        _require(type(rows) is list and 1 <= len(rows) <= 64)
        requests = tuple(_read_private_file(fd, f"request-{i:02d}.bin", 142) for i in range(1, count + 1))
        chunks = tuple(_read_private_file(fd, f"recv-{i:02d}.bin", 4096) for i in range(1, len(rows) + 1))
        expected_files = {"manifest.json", *(f"request-{i:02d}.bin" for i in range(1, count + 1)),
                          *(f"recv-{i:02d}.bin" for i in range(1, len(rows) + 1))}
        _require(set(os.listdir(fd)) == expected_files, "auth_original_file_set_mismatch")
        return validate_capture(manifest, requests, chunks, mode=mode, identity=identity, svk=svk,
                                session_layout=session_layout, session_evidence=session_evidence,
                                as_public_key=as_public_key)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError,
            OverflowError, OSError, HSFZError, CodingProtocolError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("invalid_auth_original") from None
    finally:
        os.close(fd)


def load_auth_session_evidence(directory: Path, manifest_sha256: str, *,
                               identity: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence,
                               session_layout: str) -> AuthSessionEvidence:
    _require(session_layout in ("p2_timing", "opaque_parameters"), "auth_session_layout_not_selected")
    facts = _load_original(directory, manifest_sha256, "observe_extended_session", identity, svk)
    # Explicit chosen parser, never a width heuristic. The exact probe echo was
    # already checked against raw frames by the shared original validator.
    record = facts.session_parameters[0][1]
    try:
        parse_session_response(b"\x50\x03" + record, 0x03, layout=session_layout)
    except CodingProtocolError:
        raise EvidenceError("auth_session_profile_does_not_fit_probe") from None
    return AuthSessionEvidence(manifest_sha256, identity.discovery.manifest_sha256,
                               identity.manifest_sha256, svk.manifest_sha256, session_layout,
                               len(record), hashlib.sha256(record).hexdigest(), svk_module(svk))


def load_auth_seed_evidence(directory: Path, manifest_sha256: str, *,
                            identity: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence,
                            session_evidence: AuthSessionEvidence,
                            mode: str = 'capture_auth_seed') -> AuthenticationSeedEvidence:
    _require(type(session_evidence) is AuthSessionEvidence)
    _require(mode in ('capture_auth_seed', 'capture_bdc_seed_and_default','capture_vsg_seed_and_default'))
    facts = _load_original(directory, manifest_sha256, mode, identity, svk,
                           session_evidence.session_layout, session_evidence)
    _require(facts.seed is not None)
    return AuthenticationSeedEvidence(manifest_sha256, identity.discovery.manifest_sha256,
                                      identity.manifest_sha256, svk.manifest_sha256,
                                      session_evidence.manifest_sha256, session_evidence.session_layout,
                                      len(facts.seed), hashlib.sha256(facts.seed).hexdigest(), svk_module(svk))
