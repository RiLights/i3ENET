"""Private, offline validation of one explicitly selected discovery artifact.

This does not open sockets, establish owner confirmation or identify a head
unit. The caller must separately review/select the experiment and its hash.
Identifying bytes are kept out of exceptions and object representations.
"""

from __future__ import annotations

from . import __version__

from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat

from .discovery import DISCOVERY_PORT, DiscoveryError, parse_discovery_response
from .hsfz import Control, HSFZError, IncrementalParser
from .uds import NegativeResponse, ReadDataByIdentifierRequest, UDSError, parse_read_data_response


MAX_MANIFEST_BYTES = 64 * 1024
MAX_REPLY_BYTES = 65535
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_INTERFACE = re.compile(r"en[0-9]+\Z")
_VIN = re.compile(r"[A-Z0-9]{17}\Z")
_LINK_LOCAL = ipaddress.IPv4Network("169.254.0.0/16")
_VIN_READ_REQUEST = bytes.fromhex("000000050001f41022f190")
_MAX_VIN_CHUNKS = 64
_MAX_VIN_RECEIVE_BYTES = 64 * 1024
_MAX_VIN_CHUNK_BYTES = 4096


class EvidenceError(ValueError):
    """Evidence validation failed; reason contains no original artifact data."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class GatewayIdentityEvidence:
    """Selected gateway candidate; stored VIN supports a later local comparison.

    Successful loading verifies file/protocol consistency, not authenticity,
    owner confirmation, default-session support or live diagnostic permission.
    """

    gateway_address: str
    source_interface: str
    source_address: str
    interface_index: int
    vin_candidate: str = field(repr=False)
    manifest_sha256: str
    reply_sha256: str
    diagnostic_address: int = 0x10


@dataclass(frozen=True, slots=True)
class GatewayVINReadEvidence:
    """Pinned successful VIN exchange, with its already selected discovery.

    This verifies original application bytes, not authentication or permission
    for another operation. The nested discovery representation hides its VIN.
    """

    discovery: GatewayIdentityEvidence
    manifest_sha256: str
    request_sha256: str


def _hash_shape(value: object) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _selected_endpoint(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return (str(address) == value and address in _LINK_LOCAL
            and address not in (_LINK_LOCAL.network_address, _LINK_LOCAL.broadcast_address))


def _open_directory(directory: Path) -> int:
    """Traverse every component with NOFOLLOW; never resolve away a symlink."""
    if not isinstance(directory, Path) or ".." in directory.parts:
        raise EvidenceError("invalid_evidence_directory")
    absolute = directory if directory.is_absolute() else Path.cwd() / directory
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(absolute.anchor, flags)
        for part in absolute.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise EvidenceError("evidence_directory_not_private")
        result, descriptor = descriptor, None
        return result
    except (OSError, AttributeError):
        raise EvidenceError("evidence_directory_unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_private_file(directory_fd: int, filename: str, maximum: int) -> bytes:
    descriptor: int | None = None
    try:
        # NONBLOCK prevents a substituted FIFO from blocking before fstat.
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
            raise EvidenceError("evidence_file_not_private")
        if not 0 < before.st_size <= maximum:
            raise EvidenceError("evidence_file_size_invalid")
        chunks: list[bytes] = []
        count = 0
        while count <= maximum:
            chunk = os.read(descriptor, min(8192, maximum + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        after = os.fstat(descriptor)
        if (count != before.st_size or count > maximum
                or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                != (before.st_size, before.st_mtime_ns, before.st_ctime_ns)):
            raise EvidenceError("evidence_file_changed")
        return b"".join(chunks)
    except OSError:
        raise EvidenceError("evidence_file_unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("invalid_evidence_manifest")
        result[key] = value
    return result


def _invalid_constant(value: str) -> object:
    raise EvidenceError("invalid_evidence_manifest")


def _exact_int(value: object, expected: int) -> bool:
    return type(value) is int and value == expected


def _manifest_selection(
    manifest: object, *, gateway_address: str, source_interface: str, source_address: str
) -> tuple[int, dict[str, object], dict[str, object]]:
    if (not isinstance(manifest, dict)
            or not _exact_int(manifest.get("schema_version"), 1)
            or manifest.get("implementation_version") != __version__
            or manifest.get("private_raw_originals") is not True):
        raise EvidenceError("invalid_evidence_manifest")
    report = manifest.get("report")
    if not isinstance(report, dict):
        raise EvidenceError("invalid_evidence_report")
    expected_values = {
        "implementation_version": manifest["implementation_version"],
        "command": "discover", "mode": "live_discovery", "outcome": "gateway_found",
        "source_interface": source_interface, "source_address": source_address,
        "broadcast_address": "169.254.255.255", "discovery_request_hex": "000000000011",
    }
    if (any(report.get(key) != value for key, value in expected_values.items())
            or report.get("route_verified") is not True
            or report.get("transmission_uncertain") is not False
            or report.get("diagnostic_tcp_opened") is not False
            or report.get("writes_supported") is not False
            or report.get("reason") is not None):
        raise EvidenceError("evidence_report_not_selected")
    for key, value in {"timing_complete": True, "socket_close_uncertain": False}.items():
        if report.get(key) is not value:
            raise EvidenceError("evidence_report_not_complete")
    counts = {"schema_version": 1, "vehicle_packets_attempted": 1,
              "vehicle_packets_sent": 1, "vehicle_bytes_confirmed_sent": 6,
              "destination_port": DISCOVERY_PORT, "received_datagrams": 1,
              "truncated_datagrams": 0, "rejected_datagrams": 0}
    if any(not _exact_int(report.get(key), value) for key, value in counts.items()):
        raise EvidenceError("evidence_report_not_complete")
    index = report.get("interface_index")
    if type(index) is not int or not 0 < index <= 0x7fffffff:
        raise EvidenceError("invalid_evidence_interface_index")
    candidates = report.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 1:
        raise EvidenceError("ambiguous_evidence_candidates")
    candidate = candidates[0]
    if (not isinstance(candidate, dict) or candidate.get("address") != gateway_address
            or not _exact_int(candidate.get("port"), DISCOVERY_PORT)
            or not _exact_int(candidate.get("reply_count"), 1)
            or candidate.get("identity_conflict") is not False
            or candidate.get("layouts") != ["marker_identity"]):
        raise EvidenceError("evidence_candidate_not_selected")
    datagrams = manifest.get("datagrams")
    if not isinstance(datagrams, list) or len(datagrams) != 1:
        raise EvidenceError("ambiguous_evidence_datagrams")
    record = datagrams[0]
    if (not isinstance(record, dict) or record.get("file") != "reply-01.bin"
            or record.get("peer_address") != gateway_address
            or not _exact_int(record.get("peer_port"), DISCOVERY_PORT)
            or record.get("truncated") is not False
            or record.get("disposition") != "candidate"
            or record.get("reason") is not None or not _hash_shape(record.get("sha256"))):
        raise EvidenceError("evidence_datagram_not_selected")
    length = record.get("byte_length")
    if (type(length) is not int or not 0 < length <= MAX_REPLY_BYTES
            or not _exact_int(report.get("captured_bytes"), length)):
        raise EvidenceError("evidence_datagram_length_invalid")
    return index, candidate, record


def load_gateway_identity_evidence(
    directory: Path, *, manifest_sha256: str, gateway_address: str,
    source_interface: str, source_address: str,
) -> GatewayIdentityEvidence:
    """Load exactly one pinned, private, consistent gateway identity reply.

    Hash verification precedes JSON decoding. The gateway, source/interface and
    manifest hash are explicit caller selections, never automatically chosen.
    Extra/ambiguous replies are rejected rather than selecting a convenient one.
    """
    if not _hash_shape(manifest_sha256):
        raise EvidenceError("invalid_evidence_manifest_hash")
    if (not _selected_endpoint(gateway_address) or not _selected_endpoint(source_address)
            or gateway_address == source_address or not isinstance(source_interface, str)
            or _INTERFACE.fullmatch(source_interface) is None):
        raise EvidenceError("invalid_evidence_selection")
    directory_fd = _open_directory(directory)
    try:
        encoded = _read_private_file(directory_fd, "manifest.json", MAX_MANIFEST_BYTES)
        if hashlib.sha256(encoded).hexdigest() != manifest_sha256:
            raise EvidenceError("evidence_manifest_hash_mismatch")
        try:
            manifest = json.loads(encoded, object_pairs_hook=_unique_object,
                                  parse_constant=_invalid_constant)
        except (UnicodeError, ValueError, RecursionError):
            raise EvidenceError("invalid_evidence_manifest") from None
        index, candidate, record = _manifest_selection(
            manifest, gateway_address=gateway_address, source_interface=source_interface,
            source_address=source_address,
        )
        raw = _read_private_file(directory_fd, "reply-01.bin", MAX_REPLY_BYTES)
        reply_hash = hashlib.sha256(raw).hexdigest()
        if len(raw) != record["byte_length"] or reply_hash != record["sha256"]:
            raise EvidenceError("evidence_reply_hash_or_length_mismatch")
        try:
            response = parse_discovery_response(raw)
        except DiscoveryError:
            raise EvidenceError("invalid_evidence_discovery_reply") from None
        if (response.layout != "marker_identity"
                or not response.identification.startswith(b"DIAGADR10")
                or response.identification.count(b"DIAGADR10") != 1
                or response.vin_candidate is None
                or _VIN.fullmatch(response.vin_candidate) is None):
            raise EvidenceError("unsupported_evidence_identity")
        if ("masked_vin_candidates" in candidate
                and candidate["masked_vin_candidates"] != [response.masked_vin]):
            raise EvidenceError("evidence_masked_identity_mismatch")
        return GatewayIdentityEvidence(
            gateway_address, source_interface, source_address, index,
            response.vin_candidate, manifest_sha256, reply_hash,
        )
    finally:
        os.close(directory_fd)


def _finite_nonnegative(value: object) -> bool:
    if type(value) not in (int, float) or value < 0:
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError):
        return False


def _valid_discovery_evidence(discovery: object) -> bool:
    return (type(discovery) is GatewayIdentityEvidence
            and _selected_endpoint(discovery.gateway_address)
            and _selected_endpoint(discovery.source_address)
            and discovery.gateway_address != discovery.source_address
            and type(discovery.source_interface) is str
            and _INTERFACE.fullmatch(discovery.source_interface) is not None
            and type(discovery.interface_index) is int
            and 0 < discovery.interface_index <= 0x7fffffff
            and type(discovery.diagnostic_address) is int and discovery.diagnostic_address == 0x10
            and type(discovery.vin_candidate) is str and _VIN.fullmatch(discovery.vin_candidate) is not None
            and _hash_shape(discovery.manifest_sha256) and _hash_shape(discovery.reply_sha256))


def _vin_manifest_contract(
    manifest: object, discovery: GatewayIdentityEvidence
) -> tuple[dict[str, object], dict[str, object], list[dict[str, object]]]:
    if (not isinstance(manifest, dict) or not _exact_int(manifest.get("schema_version"), 1)
            or manifest.get("implementation_version") != __version__
            or manifest.get("private_raw_originals") is not True):
        raise EvidenceError("invalid_vin_evidence_manifest")
    if manifest.get("source_discovery") != {
        "manifest_sha256": discovery.manifest_sha256, "reply_sha256": discovery.reply_sha256,
    }:
        raise EvidenceError("vin_evidence_discovery_mismatch")
    report = manifest.get("report")
    if not isinstance(report, dict):
        raise EvidenceError("invalid_vin_evidence_report")
    expected_values = {
        "implementation_version": manifest["implementation_version"], "command": "identify-gateway",
        "mode": "live_gateway_identity", "outcome": "vin_match", "reason": None,
        "source_interface": discovery.source_interface, "source_address": discovery.source_address,
        "gateway_address": discovery.gateway_address, "tester_address": "0xF4",
        "gateway_diagnostic_address": "0x10", "service": "0x22", "identifier": "0xF190",
        "request_hex": _VIN_READ_REQUEST.hex(),
        "discovery_manifest_sha256": discovery.manifest_sha256,
        "discovery_reply_sha256": discovery.reply_sha256,
        "masked_discovery_vin": "*" * 13 + discovery.vin_candidate[-4:],
        "masked_vin_candidate": "*" * 13 + discovery.vin_candidate[-4:],
        "vehicle_identity_status": "gateway_vin_matches_discovery",
        "transport_identity_status": "gateway_vin_response_matches_discovery",
    }
    if any(report.get(key) != value for key, value in expected_values.items()):
        raise EvidenceError("vin_evidence_report_not_selected")
    for key, value in {"route_verified": True, "diagnostic_tcp_opened": True,
                       "vin_matches_discovery": True, "writes_supported": False,
                       "transmission_uncertain": False, "tcp_connection_uncertain": False,
                       "tcp_control_traffic_counted": False}.items():
        if report.get(key) is not value:
            raise EvidenceError("vin_evidence_report_not_complete")
    for key, value in {"timing_complete": True, "tcp_close_uncertain": False}.items():
        if report.get(key) is not value:
            raise EvidenceError("vin_evidence_report_not_complete")
    for key, value in {"schema_version": 1, "interface_index": discovery.interface_index,
                       "destination_port": 6801, "tcp_connections_attempted": 1,
                       "tcp_connections_opened": 1, "application_frames_attempted": 1,
                       "application_frames_sent": 1, "vehicle_bytes_confirmed_sent": 11,
                       "ack_count": 1}.items():
        if not _exact_int(report.get(key), value):
            raise EvidenceError("vin_evidence_report_not_complete")
    timing_limits = {"connect_timeout_seconds": 3, "first_response_window_seconds": 3,
                     "pending_response_window_seconds": 3, "overall_request_window_seconds": 6,
                     "experiment_overall_window_seconds": 10}
    if any(type(report.get(key)) not in (int, float) or report[key] != value
           for key, value in timing_limits.items()):
        raise EvidenceError("vin_evidence_timing_invalid")
    response_elapsed = report.get("response_elapsed_seconds")
    experiment_elapsed = report.get("experiment_elapsed_seconds")
    elapsed = report.get("elapsed_seconds")
    if (not all(_finite_nonnegative(value) for value in (response_elapsed, experiment_elapsed, elapsed))
            or not response_elapsed < 6 or not experiment_elapsed < 10
            or not response_elapsed <= experiment_elapsed <= elapsed):
        raise EvidenceError("vin_evidence_timing_invalid")
    request = manifest.get("request")
    if (not isinstance(request, dict) or request.get("file") != "request.bin"
            or not _hash_shape(request.get("sha256"))
            or not _exact_int(request.get("byte_length"), 11)
            or not _exact_int(request.get("application_frames_attempted"), 1)
            or not _exact_int(request.get("application_frames_sent"), 1)
            or not _exact_int(request.get("confirmed_bytes"), 11)
            or request.get("transmission_uncertain") is not False):
        raise EvidenceError("invalid_vin_evidence_request")
    records = manifest.get("received_chunks")
    if (not isinstance(records, list) or not 1 <= len(records) <= _MAX_VIN_CHUNKS
            or not _exact_int(report.get("received_chunks"), len(records))):
        raise EvidenceError("invalid_vin_evidence_chunks")
    total = 0
    previous_time = 0.0
    for index, record in enumerate(records, 1):
        if (not isinstance(record, dict) or record.get("file") != f"recv-{index:02d}.bin"
                or not _hash_shape(record.get("sha256"))):
            raise EvidenceError("invalid_vin_evidence_chunk_record")
        size = record.get("byte_length")
        received_at = record.get("received_after_seconds")
        if (type(size) is not int or not 0 < size <= _MAX_VIN_CHUNK_BYTES
                or not _finite_nonnegative(received_at)
                or not previous_time <= received_at <= response_elapsed
                or not received_at < 6):
            raise EvidenceError("invalid_vin_evidence_chunk_record")
        previous_time = received_at
        total += size
    if total > _MAX_VIN_RECEIVE_BYTES or not _exact_int(report.get("received_bytes"), total):
        raise EvidenceError("vin_evidence_receive_length_invalid")
    return report, request, records


def load_gateway_vin_read_evidence(
    directory: Path, *, manifest_sha256: str, discovery: GatewayIdentityEvidence,
) -> GatewayVINReadEvidence:
    """Reparse an explicitly pinned, reviewed v0.3/v0.4 VIN exchange.

    Exactly one correlated ACK is required for this reviewed capture shape.
    The full short-request echo is required for every original.
    A valid full VIN must match discovery. Report labels cannot substitute for
    original bytes. Timing metadata is checked for consistency with fixed bounds;
    it cannot independently establish an authenticated acquisition time.
    """
    if not _hash_shape(manifest_sha256):
        raise EvidenceError("invalid_vin_evidence_manifest_hash")
    if not _valid_discovery_evidence(discovery):
        raise EvidenceError("invalid_vin_evidence_discovery")
    directory_fd = _open_directory(directory)
    try:
        encoded = _read_private_file(directory_fd, "manifest.json", MAX_MANIFEST_BYTES)
        if hashlib.sha256(encoded).hexdigest() != manifest_sha256:
            raise EvidenceError("vin_evidence_manifest_hash_mismatch")
        try:
            manifest = json.loads(encoded, object_pairs_hook=_unique_object,
                                  parse_constant=_invalid_constant)
        except (UnicodeError, ValueError, RecursionError):
            raise EvidenceError("invalid_vin_evidence_manifest") from None
        report, request_record, records = _vin_manifest_contract(manifest, discovery)
        request = _read_private_file(directory_fd, "request.bin", 11)
        request_hash = hashlib.sha256(request).hexdigest()
        if request != _VIN_READ_REQUEST or request_hash != request_record["sha256"]:
            raise EvidenceError("vin_evidence_request_mismatch")
        parser = IncrementalParser(max_body_length=4096)
        ack_count = pending_count = positive_count = 0
        response_deadline = 6.0  # Send-completion time is absent from saved v0.3 metadata.
        for record in records:
            if record["received_after_seconds"] >= response_deadline:
                raise EvidenceError("vin_evidence_timing_invalid")
            raw = _read_private_file(directory_fd, record["file"], _MAX_VIN_CHUNK_BYTES)
            if len(raw) != record["byte_length"] or hashlib.sha256(raw).hexdigest() != record["sha256"]:
                raise EvidenceError("vin_evidence_chunk_hash_or_length_mismatch")
            if positive_count:
                raise EvidenceError("vin_evidence_extra_response")
            try:
                frames = parser.feed(raw)
            except HSFZError:
                raise EvidenceError("invalid_vin_evidence_stream") from None
            for incoming in frames:
                if positive_count:
                    raise EvidenceError("vin_evidence_extra_response")
                if incoming.control is Control.ACK:
                    if (ack_count or (incoming.source, incoming.target) != (0xF4, 0x10)
                            or incoming.diagnostic_payload != bytes.fromhex("22f190")):
                        raise EvidenceError("vin_evidence_ack_not_correlated")
                    ack_count += 1
                    continue
                if (incoming.control is not Control.DIAGNOSTIC
                        or (incoming.source, incoming.target) != (0x10, 0xF4)):
                    raise EvidenceError("vin_evidence_response_not_correlated")
                try:
                    response = parse_read_data_response(
                        incoming.diagnostic_payload, ReadDataByIdentifierRequest(0xF190),
                        expected_value_length=17,
                    )
                except UDSError:
                    raise EvidenceError("invalid_vin_evidence_uds_response") from None
                if isinstance(response, NegativeResponse):
                    if not response.pending:
                        raise EvidenceError("vin_evidence_terminal_negative")
                    pending_count += 1
                    response_deadline = min(6.0, record["received_after_seconds"] + 3.0)
                    continue
                try:
                    vin = response.value.decode("ascii")
                except UnicodeError:
                    raise EvidenceError("invalid_vin_evidence_vin") from None
                if _VIN.fullmatch(vin) is None or vin != discovery.vin_candidate:
                    raise EvidenceError("vin_evidence_vin_mismatch")
                positive_count += 1
        try:
            parser.finish()
        except HSFZError:
            raise EvidenceError("invalid_vin_evidence_stream") from None
        if (ack_count != 1 or positive_count != 1
                or not _exact_int(report.get("pending_count"), pending_count)
                or report.get("nrc") != ("0x78" if pending_count else None)
                or report.get("last_control") != "0x0001"):
            raise EvidenceError("vin_evidence_response_counts_mismatch")
        return GatewayVINReadEvidence(discovery, manifest_sha256, request_hash)
    finally:
        os.close(directory_fd)
