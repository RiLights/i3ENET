"""Offline, private validation of the selected current-SVK acquisition.

The suffix record structure is a reference-supported interpretation, not a
self-describing coding schema. Successful loading establishes consistency with
the selected discovery/VIN originals and observed software tuple; it grants no
socket, coding interpretation or write permission. No raw data is rendered.
"""

from __future__ import annotations

from . import __version__

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path

from .evidence import (
    EvidenceError, GatewayIdentityEvidence, GatewayVINReadEvidence,
    MAX_MANIFEST_BYTES, _exact_int, _finite_nonnegative, _hash_shape,
    _invalid_constant, _open_directory, _read_private_file, _unique_object,
    _valid_discovery_evidence,
)
from .hsfz import Control, HSFZError, IncrementalParser


HEAD_UNIT_SVK_REQUEST = bytes.fromhex("000000050001f46322f101")
HEAD_UNIT_SVK_REQUEST_SHA256 = hashlib.sha256(HEAD_UNIT_SVK_REQUEST).hexdigest()
BDC_SVK_REQUEST = bytes.fromhex("000000050001f44022f101")
VSG_SVK_REQUEST = bytes.fromhex("000000050001f42d22f101")
_VIN_REQUEST_SHA256 = hashlib.sha256(bytes.fromhex("000000050001f41022f190")).hexdigest()
EXPECTED_CAFD_IDENTIFIER = "00000DED"
EXPECTED_CAFD_VERSION = "003.015.041"
EXPECTED_BTLD_IDENTIFIER = "00001ABA"
EXPECTED_BTLD_VERSION = "130.026.001"
MAX_SVK_RECORDS = 256  # Local resource bound, not a BMW protocol maximum.
MAX_FRAME_BODY_BYTES = 4096
MAX_RECEIVE_CHUNKS = 64
MAX_RECEIVE_BYTES = 64 * 1024
MAX_CHUNK_BYTES = 4096


@dataclass(frozen=True, slots=True)
class SVKRecord:
    kind: int
    identifier: int
    version: tuple[int, int, int]


@dataclass(frozen=True, slots=True)
class SVKValue:
    """Original-order records and uninterpreted header, hidden from repr."""

    record_count: int
    header: bytes = field(repr=False)
    records: tuple[SVKRecord, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class HeadUnitSVKEvidence:
    gateway_address: str
    source_interface: str
    source_address: str
    interface_index: int
    discovery_manifest_sha256: str
    identity_manifest_sha256: str
    manifest_sha256: str
    request_sha256: str
    value_sha256: str
    cafd_identifier: str = EXPECTED_CAFD_IDENTIFIER
    cafd_version: str = EXPECTED_CAFD_VERSION
    btld_identifier: str = EXPECTED_BTLD_IDENTIFIER
    btld_version: str = EXPECTED_BTLD_VERSION


@dataclass(frozen=True, slots=True)
class BDCSVKEvidence:
    """Reopened BDC software observation, deliberately distinct from HU proof."""
    gateway_address: str
    source_interface: str
    source_address: str
    interface_index: int
    discovery_manifest_sha256: str
    identity_manifest_sha256: str
    manifest_sha256: str
    request_sha256: str
    value_sha256: str
    cafd_identifier: str
    cafd_version: str
    btld_identifier: str
    btld_version: str


@dataclass(frozen=True, slots=True)
class VSGSVKEvidence(BDCSVKEvidence):
    """Separate VSG observation; never usable as a BDC or HU proof."""


_SVK_IDENTITIES = {
    'HU': (HEAD_UNIT_SVK_REQUEST, 0x63, 'head-unit', 'head_unit', HeadUnitSVKEvidence),
    'BDC': (BDC_SVK_REQUEST, 0x40, 'bdc', 'bdc', BDCSVKEvidence),
    'VSG01': (VSG_SVK_REQUEST, 0x2D, 'vsg', 'vsg', VSGSVKEvidence),
}


def svk_module(svk):
    for module, (_, _, _, _, proof_type) in _SVK_IDENTITIES.items():
        if type(svk) is proof_type: return module
    raise EvidenceError('svk_module_evidence_invalid')


def svk_source_key(module):
    return {'HU':'source_head_unit_svk','BDC':'source_bdc_svk','VSG01':'source_vsg_svk'}[module]


def parse_svk_value(value: bytes) -> SVKValue:
    """Decode only the bounded count/suffix-record contract.

    The seven-byte base header contains a BE16 count at offsets 2–3. Additional
    header bytes are opaque and are located by the exact count-times-eight
    suffix. No padding is removed, count repaired, date decoded, order reversed
    or primary-CAF priority/fallback selected.
    """
    if type(value) is not bytes or not 7 <= len(value) <= MAX_FRAME_BODY_BYTES - 5:
        raise EvidenceError("invalid_svk_value")
    count = int.from_bytes(value[2:4], "big")
    if not 1 <= count <= MAX_SVK_RECORDS:
        raise EvidenceError("invalid_svk_record_count")
    header_length = len(value) - count * 8
    if header_length < 7:
        raise EvidenceError("invalid_svk_record_layout")
    records = tuple(
        SVKRecord(value[offset], int.from_bytes(value[offset + 1:offset + 5], "big"),
                  tuple(value[offset + 5:offset + 8]))
        for offset in range(header_length, len(value), 8)
    )
    return SVKValue(count, value[:header_length], records)


def software_records(decoded: SVKValue) -> tuple[str, str, str, str]:
    """One unambiguous CAFD/BTLD pair; observes IDs without granting compatibility."""
    cafds = [record for record in decoded.records if record.kind == 0x05]
    btlds = [record for record in decoded.records if record.kind == 0x06]
    if len(cafds) != 1 or len(btlds) != 1:
        raise EvidenceError("svk_software_records_ambiguous")
    result = (f"{cafds[0].identifier:08X}", ".".join(f"{part:03d}" for part in cafds[0].version),
              f"{btlds[0].identifier:08X}", ".".join(f"{part:03d}" for part in btlds[0].version))
    return result


def _software_tuple(decoded: SVKValue, *, module='HU') -> tuple[str, str, str, str]:
    from .coding_contract import contract
    result = software_records(decoded)
    spec = contract(module)
    if result != (*spec.cafd.split('/'), *spec.btld.split('/')):
        raise EvidenceError("svk_software_tuple_not_selected")
    return result


def _valid_proofs(discovery: object, identity: object) -> bool:
    return (_valid_discovery_evidence(discovery)
            and type(identity) is GatewayVINReadEvidence
            and type(identity.discovery) is GatewayIdentityEvidence
            and identity.discovery == discovery
            and _hash_shape(identity.manifest_sha256)
            and type(identity.request_sha256) is str
            and identity.request_sha256 == _VIN_REQUEST_SHA256)


def _manifest_contract(
    manifest: object, discovery: GatewayIdentityEvidence, identity: GatewayVINReadEvidence,
    *, module: str = 'HU',
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    if module not in _SVK_IDENTITIES:
        raise EvidenceError('svk_module_not_selected')
    if (not isinstance(manifest, dict) or not _exact_int(manifest.get("schema_version"), 1)
            or manifest.get("implementation_version") != __version__
            or manifest.get("private_raw_originals") is not True
):
        raise EvidenceError("invalid_svk_evidence_manifest")
    if (manifest.get("source_discovery") != {
            "manifest_sha256": discovery.manifest_sha256, "reply_sha256": discovery.reply_sha256,
        } or manifest.get("source_gateway_identity") != {
            "manifest_sha256": identity.manifest_sha256, "request_sha256": identity.request_sha256,
        }):
        raise EvidenceError("svk_evidence_prior_proof_mismatch")
    report = manifest.get("report")
    if not isinstance(report, dict):
        raise EvidenceError("invalid_svk_evidence_report")
    request_bytes, address, command_name, mode_name, _ = _SVK_IDENTITIES[module]
    target = f'0x{address:02X}'
    expected = {
        "implementation_version": manifest["implementation_version"],
        "command": f'read-{command_name}-svk',
        "mode": f'live_{mode_name}_svk',
        "outcome": "identity_value_observed", "reason": None,
        "source_interface": discovery.source_interface, "source_address": discovery.source_address,
        "gateway_address": discovery.gateway_address, "tester_address": "0xF4",
        "candidate_diagnostic_address": target, "candidate_address": target,
        "service": "0x22", "identifier": "0xF101", "request_hex": request_bytes.hex(),
        "discovery_manifest_sha256": discovery.manifest_sha256,
        "discovery_reply_sha256": discovery.reply_sha256,
        "identity_manifest_sha256": identity.manifest_sha256,
        "identity_request_sha256": identity.request_sha256,
        "masked_discovery_vin": "*" * 13 + discovery.vin_candidate[-4:],
        "vehicle_identity_status": "prior_gateway_vin_matches_discovery",
        "transport_identity_status": "candidate_identity_response_via_previously_vin_matched_gateway",
        "candidate_address_status": "identity_response_received",
        "address_association_status": "unconfirmed", "head_unit_identity_status": "unverified",
        "head_unit_status": "unverified", "ecu_software_status": "unverified",
        "value_interpretation": "opaque_private_value_requires_review",
        "last_control": "0x0001", "nrc": None,
    }
    if any(report.get(key) != value for key, value in expected.items()):
        raise EvidenceError("svk_evidence_report_not_selected")
    for key, expected_value in {
        "route_verified": True, "prior_gateway_vin_match": True, "diagnostic_tcp_opened": True,
        "timing_complete": True, "transmission_uncertain": False, "tcp_connection_uncertain": False,
        "tcp_close_uncertain": False, "tcp_control_traffic_counted": False, "writes_supported": False,
    }.items():
        if report.get(key) is not expected_value:
            raise EvidenceError("svk_evidence_report_not_complete")
    if (report.get("vehicle_contacted", False) is not None
            or ("stop_before_further_vehicle_traffic" in report
                and report["stop_before_further_vehicle_traffic"] is not False)):
        raise EvidenceError("svk_evidence_report_not_complete")
    for key, expected_value in {
        "schema_version": 1, "interface_index": discovery.interface_index, "destination_port": 6801,
        "maximum_application_frames": 1, "tcp_connections_attempted": 1, "tcp_connections_opened": 1,
        "application_frames_attempted": 1, "application_frames_sent": 1,
        "vehicle_bytes_confirmed_sent": 11, "ack_count": 1, "pending_count": 0,
        "receive_byte_limit": MAX_RECEIVE_BYTES, "receive_chunk_limit": MAX_RECEIVE_CHUNKS,
        "receive_frame_body_limit": MAX_FRAME_BODY_BYTES,
    }.items():
        if not _exact_int(report.get(key), expected_value):
            raise EvidenceError("svk_evidence_report_not_complete")
    for key, expected_value in {
        "connect_timeout_seconds": 3, "first_response_window_seconds": 3,
        "pending_response_window_seconds": 3, "overall_request_window_seconds": 6,
        "experiment_overall_window_seconds": 10,
    }.items():
        if type(report.get(key)) not in (int, float) or report[key] != expected_value:
            raise EvidenceError("svk_evidence_timing_invalid")
    response_time = report.get("response_elapsed_seconds")
    experiment_time = report.get("experiment_elapsed_seconds")
    elapsed = report.get("elapsed_seconds")
    if (not all(_finite_nonnegative(value) for value in (response_time, experiment_time, elapsed))
            or not response_time < 6 or not experiment_time < 10
            or not response_time <= experiment_time <= elapsed):
        raise EvidenceError("svk_evidence_timing_invalid")
    if not _hash_shape(report.get("value_sha256")):
        raise EvidenceError("svk_evidence_value_metadata_invalid")
    value_size = report.get("value_byte_count")
    if type(value_size) is not int or not 7 <= value_size <= MAX_FRAME_BODY_BYTES - 5:
        raise EvidenceError("svk_evidence_value_metadata_invalid")
    request = manifest.get("request")
    if (not isinstance(request, dict) or request.get("file") != "request.bin"
            or request.get("sha256") != hashlib.sha256(request_bytes).hexdigest()
            or not _exact_int(request.get("byte_length"), 11)
            or not _exact_int(request.get("application_frames_attempted"), 1)
            or not _exact_int(request.get("application_frames_sent"), 1)
            or not _exact_int(request.get("confirmed_bytes"), 11)
            or request.get("transmission_uncertain") is not False):
        raise EvidenceError("invalid_svk_evidence_request")
    records = manifest.get("received_chunks")
    if (not isinstance(records, list) or not 1 <= len(records) <= MAX_RECEIVE_CHUNKS
            or not _exact_int(report.get("received_chunks"), len(records))):
        raise EvidenceError("invalid_svk_evidence_chunks")
    total = 0
    previous_time = 0.0
    for index, record in enumerate(records, 1):
        if (not isinstance(record, dict) or record.get("file") != f"recv-{index:02d}.bin"
                or not _hash_shape(record.get("sha256"))):
            raise EvidenceError("invalid_svk_evidence_chunk_record")
        size, received_time = record.get("byte_length"), record.get("received_after_seconds")
        if (type(size) is not int or not 0 < size <= MAX_CHUNK_BYTES
                or not _finite_nonnegative(received_time)
                or not previous_time <= received_time <= response_time or not received_time < 6):
            raise EvidenceError("invalid_svk_evidence_chunk_record")
        previous_time = received_time
        total += size
    if total > MAX_RECEIVE_BYTES or not _exact_int(report.get("received_bytes"), total):
        raise EvidenceError("svk_evidence_receive_length_invalid")
    return report, request, records


def load_head_unit_svk_evidence(
    directory: Path, *, manifest_sha256: str, discovery: GatewayIdentityEvidence,
    identity: GatewayVINReadEvidence,
) -> HeadUnitSVKEvidence:
    """Reparse one hash-pinned, private, successful F101 exchange offline.

    This gate deliberately requires the reviewed full ACK and no pending frame.
    Original bytes, successful accounting and an exact software tuple must all
    agree. It does not authenticate the peer or establish coding compatibility.
    """
    return _load_svk_evidence(directory, manifest_sha256=manifest_sha256, discovery=discovery, identity=identity, module='HU')


def load_bdc_svk_evidence(directory: Path, *, manifest_sha256: str,
                          discovery: GatewayIdentityEvidence, identity: GatewayVINReadEvidence) -> BDCSVKEvidence:
    """Strict BDC F101 stream validation; no selected software/coding claim."""
    return _load_svk_evidence(directory, manifest_sha256=manifest_sha256, discovery=discovery, identity=identity, module='BDC')


def load_vsg_svk_evidence(directory: Path, *, manifest_sha256: str,
                          discovery: GatewayIdentityEvidence, identity: GatewayVINReadEvidence) -> VSGSVKEvidence:
    return _load_svk_evidence(directory, manifest_sha256=manifest_sha256, discovery=discovery, identity=identity, module='VSG01')


def _load_svk_evidence(directory, *, manifest_sha256, discovery, identity, module):
    if module not in _SVK_IDENTITIES:
        raise EvidenceError('svk_module_not_selected')
    request_bytes, target, _, _, evidence_type = _SVK_IDENTITIES[module]
    if not _hash_shape(manifest_sha256):
        raise EvidenceError("invalid_svk_evidence_manifest_hash")
    if not _valid_proofs(discovery, identity):
        raise EvidenceError("invalid_svk_evidence_prior_proofs")
    directory_fd = _open_directory(directory)
    try:
        encoded = _read_private_file(directory_fd, "manifest.json", MAX_MANIFEST_BYTES)
        if hashlib.sha256(encoded).hexdigest() != manifest_sha256:
            raise EvidenceError("svk_evidence_manifest_hash_mismatch")
        try:
            manifest = json.loads(encoded, object_pairs_hook=_unique_object,
                                  parse_constant=_invalid_constant)
        except (UnicodeError, ValueError, RecursionError):
            raise EvidenceError("invalid_svk_evidence_manifest") from None
        report, request_record, records = _manifest_contract(manifest, discovery, identity, module=module)
        request = _read_private_file(directory_fd, "request.bin", 11)
        if (request != request_bytes
                or hashlib.sha256(request).hexdigest() != request_record["sha256"]):
            raise EvidenceError("svk_evidence_request_mismatch")
        expected_files = {"manifest.json", "request.bin", *(record["file"] for record in records)}
        try:
            seen: set[str] = set()
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if entry.name not in expected_files or entry.name in seen:
                        raise EvidenceError("svk_evidence_unlisted_files")
                    seen.add(entry.name)
            if seen != expected_files:
                raise EvidenceError("svk_evidence_unlisted_files")
        except OSError:
            raise EvidenceError("svk_evidence_directory_unavailable") from None
        parser = IncrementalParser(max_body_length=MAX_FRAME_BODY_BYTES)
        ack_count = 0
        value: bytes | None = None
        for record in records:
            raw = _read_private_file(directory_fd, record["file"], MAX_CHUNK_BYTES)
            if (len(raw) != record["byte_length"]
                    or hashlib.sha256(raw).hexdigest() != record["sha256"]):
                raise EvidenceError("svk_evidence_chunk_hash_or_length_mismatch")
            if value is not None:
                raise EvidenceError("svk_evidence_extra_response")
            try:
                frames = parser.feed(raw)
            except HSFZError:
                raise EvidenceError("invalid_svk_evidence_stream") from None
            for incoming in frames:
                if value is not None:
                    raise EvidenceError("svk_evidence_extra_response")
                if incoming.control is Control.ACK:
                    if (ack_count or (incoming.source, incoming.target) != (0xF4, target)
                            or incoming.diagnostic_payload != bytes.fromhex("22f101")):
                        raise EvidenceError("svk_evidence_ack_not_correlated")
                    ack_count += 1
                elif (incoming.control is Control.DIAGNOSTIC
                      and (incoming.source, incoming.target) == (target, 0xF4)
                      and incoming.diagnostic_payload[:3] == bytes.fromhex("62f101")):
                    if ack_count != 1:
                        raise EvidenceError("svk_evidence_ack_missing_or_out_of_order")
                    value = incoming.diagnostic_payload[3:]
                else:
                    raise EvidenceError("svk_evidence_response_not_correlated")
        try:
            parser.finish()
        except HSFZError:
            raise EvidenceError("invalid_svk_evidence_stream") from None
        if ack_count != 1 or value is None:
            raise EvidenceError("svk_evidence_response_counts_mismatch")
        value_hash = hashlib.sha256(value).hexdigest()
        if (len(value) != report["value_byte_count"] or value_hash != report["value_sha256"]):
            raise EvidenceError("svk_evidence_value_metadata_mismatch")
        software = (_software_tuple if module == 'HU' else software_records)(parse_svk_value(value))
        return evidence_type(
            discovery.gateway_address, discovery.source_interface, discovery.source_address,
            discovery.interface_index, discovery.manifest_sha256, identity.manifest_sha256,
            manifest_sha256, hashlib.sha256(request_bytes).hexdigest(), value_hash, *software,
        )
    finally:
        os.close(directory_fd)
