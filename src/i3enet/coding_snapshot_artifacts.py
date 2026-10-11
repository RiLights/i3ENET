"""Private original retention for the prepared fixed snapshot acquisition.

Create the context before any traffic. This module opens no socket, imports no
key and grants no send permission. A neutral offline import is produced only
after complete client accounting and an independent raw-stream correlation.
Its provenance remains ``unverified_import``; retention does not establish
signature validity, atomic currentness, ECU acceptance or recovery.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import stat

from . import REPORT_SCHEMA_VERSION, __version__
from .artifacts import ArtifactError, DiscoveryArtifactStore
from .coding_preparation import BTLD, CAFD
from .coding_snapshot import SCHEMA
from .evidence import (GatewayIdentityEvidence, GatewayVINReadEvidence, _open_directory,
                       _read_private_file, _unique_object, _invalid_constant)
from .coding_snapshot import load_coding_snapshot
from .hsfz import Control, HSFZError, IncrementalParser
from .live_coding_snapshot import (
    CodingSnapshotResult, GROUP_LENGTHS, HEAD_UNIT_ADDRESS,
    MAX_RAW_RECEIVE_BYTES, MAX_RECEIVE_CHUNKS, MAX_FRAME_BODY_BYTES,
    RECEIVE_CHUNK_BYTES, SNAPSHOT_REQUESTS, SNAPSHOT_WINDOW_SECONDS,
)
from .live_block import _exbox_svk_evidence_matches, _bdc_svk_evidence_matches, _exbox_vin_evidence_matches
from .live_identity import ReceivedTCPChunk, TESTER_ADDRESS
from .network import GatewayNetwork
from .svk import HeadUnitSVKEvidence, BDCSVKEvidence, VSGSVKEvidence, svk_module, svk_source_key
from .live_block import _block_svk_matches
from .coding_contract import contract
from .uds import (
    MalformedResponseError, NegativeResponse, ReadDataByIdentifierRequest,
    UnexpectedResponseError, parse_read_data_response,
)


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hash_pin(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _number(value: object) -> bool:
    # Bound before float conversion so hostile giant JSON-style integers cannot
    # raise OverflowError or make serialization unbounded. Real complete reads
    # have the much narrower 30-second cap; this also retains failed timings.
    return (type(value) in (int, float) and 0 <= value <= 1_000_000_000
            and math.isfinite(value))


def _same_json(actual: object, expected: object) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return (actual.keys() == expected.keys()
                and all(_same_json(actual[key], value) for key, value in expected.items()))
    if type(expected) is list:
        return len(actual) == len(expected) and all(_same_json(a, b) for a, b in zip(actual, expected))
    return actual == expected


def _validate_input(result: CodingSnapshotResult, report: dict[str, object], network: GatewayNetwork,
                    evidence: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence) -> bool:
    """Bound private inputs before serialization; return only proof agreement."""
    if type(result) is not CodingSnapshotResult:
        raise ArtifactError("snapshot_artifact_types_invalid")
    spec = contract(result.module)
    if (type(result) is not CodingSnapshotResult or type(report) is not dict
            or type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence
            or type(evidence.discovery) is not GatewayIdentityEvidence
            or type(svk) is not {'HU':HeadUnitSVKEvidence,'BDC':BDCSVKEvidence,'VSG01':VSGSVKEvidence}[result.module]):
        raise ArtifactError("snapshot_artifact_types_invalid")
    GatewayNetwork.__post_init__(network)
    pins = (evidence.discovery.manifest_sha256, evidence.discovery.reply_sha256,
            evidence.manifest_sha256, evidence.request_sha256, svk.manifest_sha256,
            svk.request_sha256, svk.value_sha256, svk.discovery_manifest_sha256,
            svk.identity_manifest_sha256)
    if not all(_hash_pin(pin) for pin in pins):
        raise ArtifactError("snapshot_artifact_proof_hash_invalid")
    integers = (result.tcp_connections_attempted, result.tcp_connections_opened,
                result.application_frames_attempted, result.application_frames_sent,
                result.vehicle_bytes_confirmed_sent, result.ack_count, result.pending_count)
    flags = (result.tcp_connection_uncertain, result.transmission_uncertain,
             result.tcp_close_uncertain, result.timing_complete)
    if (any(type(value) is not int or value < 0 for value in integers)
            or any(type(flag) is not bool for flag in flags)
            or not result.tcp_connections_opened <= result.tcp_connections_attempted <= 1
            or not result.application_frames_sent <= result.application_frames_attempted <= len(spec.groups)
            or result.vehicle_bytes_confirmed_sent > result.application_frames_attempted * 11
            or result.ack_count > len(spec.groups) or result.pending_count > MAX_RAW_RECEIVE_BYTES // 11
            or type(result.request_bytes) is not tuple
            or result.request_bytes != spec.requests[:result.application_frames_attempted]
            or type(result.recv_chunks) is not tuple or len(result.recv_chunks) > spec.receive_chunks
            or type(result.chunk_group_addresses) is not tuple
            or len(result.chunk_group_addresses) != len(result.recv_chunks)
            or type(result.groups) is not tuple or len(result.groups) > result.application_frames_sent
            or type(result.outcome) is not str or len(result.outcome) > 64
            or (result.reason is not None and (type(result.reason) is not str or len(result.reason) > 128))
            or any(value is not None and not _number(value)
                   for value in (result.elapsed_seconds, result.experiment_elapsed_seconds))
            or (result.nrc is not None and (type(result.nrc) is not int or not 0 <= result.nrc <= 255))
            or (result.last_control is not None and (type(result.last_control) is not int
                                                    or not 0 <= result.last_control <= 65535))):
        raise ArtifactError("snapshot_artifact_accounting_invalid")
    for item, (address, length) in zip(result.groups, spec.groups):
        if (type(item) is not tuple or len(item) != 2 or type(item[0]) is not int
                or item[0] != address or type(item[1]) is not bytes or len(item[1]) != length):
            raise ArtifactError("snapshot_artifact_group_shape_invalid")
    permitted_addresses = {address for address, _length in spec.groups[:result.application_frames_attempted]}
    received_bytes = 0
    prior_address = 0
    for chunk, address in zip(result.recv_chunks, result.chunk_group_addresses):
        if (type(chunk) is not ReceivedTCPChunk or type(chunk.data) is not bytes
                or not 0 < len(chunk.data) <= RECEIVE_CHUNK_BYTES
                or type(address) is not int or address not in permitted_addresses or address < prior_address
                or (chunk.received_after_seconds is not None and not _number(chunk.received_after_seconds))):
            raise ArtifactError("snapshot_artifact_chunk_shape_invalid")
        received_bytes += len(chunk.data)
        prior_address = address
    if received_bytes > MAX_RAW_RECEIVE_BYTES:
        raise ArtifactError("snapshot_artifact_receive_budget_invalid")
    native_report = result.public_report()
    if any(key not in report or not _same_json(report[key], value) for key, value in native_report.items()):
        raise ArtifactError("snapshot_artifact_report_mismatch")
    return (_exbox_vin_evidence_matches(network, evidence)
            and _block_svk_matches(network, evidence, svk, module=result.module))


def _complete_stream_agrees(result: CodingSnapshotResult, proofs_match: bool) -> bool:
    """Do not promote a claimed complete result without its actual originals."""
    spec = contract(result.module)
    if (not proofs_match or result.public_report()["snapshot_complete"] is not True
            or not _number(result.elapsed_seconds) or result.elapsed_seconds > SNAPSHOT_WINDOW_SECONDS
            or result.experiment_elapsed_seconds != result.elapsed_seconds):
        return False
    chunks_by_group = {address: [] for address, _length in spec.groups}
    previous_time = 0.0
    for chunk, address in zip(result.recv_chunks, result.chunk_group_addresses):
        when = chunk.received_after_seconds
        if not _number(when) or not previous_time <= when <= result.elapsed_seconds:
            return False
        previous_time = when
        chunks_by_group[address].append(chunk.data)
    pending_total = 0
    try:
        for index, ((address, length), (_group_address, expected_value)) in enumerate(zip(spec.groups, result.groups)):
            parser = IncrementalParser(max_body_length=MAX_FRAME_BODY_BYTES)
            request = ReadDataByIdentifierRequest(address)
            ack_count = 0
            value = None
            for chunk in chunks_by_group[address]:
                for incoming in parser.feed(chunk):
                    if value is not None:
                        return False
                    if incoming.control is Control.ACK:
                        if (ack_count or (incoming.source, incoming.target) != (TESTER_ADDRESS, spec.target)
                                or incoming.diagnostic_payload != spec.requests[index][8:]):
                            return False
                        ack_count = 1
                    elif incoming.control is Control.DIAGNOSTIC:
                        if (incoming.source, incoming.target) != (spec.target, TESTER_ADDRESS):
                            return False
                        response = parse_read_data_response(incoming.diagnostic_payload, request)
                        if isinstance(response, NegativeResponse):
                            if not response.pending:
                                return False
                            pending_total += 1
                        else:
                            if ack_count != 1 or len(response.value) != length or response.value != expected_value:
                                return False
                            value = response.value
                    else:
                        return False
            parser.finish()
            if value is None:
                return False
    except (HSFZError, UnexpectedResponseError, MalformedResponseError):
        return False
    return pending_total == result.pending_count


class CodingSnapshotArtifactStore(DiscoveryArtifactStore):
    """Pre-traffic private storage context, with immutable neutral file names."""

    _category = "coding-snapshot"

    def __init__(self, project_directory: Path) -> None:
        super().__init__(project_directory)
        info = os.fstat(self._directory_fd)
        if stat.S_IMODE(info.st_mode) != 0o700 or os.listdir(self._directory_fd):
            self.close()
            raise ArtifactError("snapshot_artifact_directory_not_fresh_private")

    @staticmethod
    def _write_at(directory_fd: int, name: str, raw: bytes) -> None:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)

    def _write(self, name: str, data: bytes) -> None:
        if self._directory_fd is None:
            raise ArtifactError("snapshot_artifact_store_closed")
        self._write_at(self._directory_fd, name, data)

    def save_snapshot(self, result: CodingSnapshotResult, report: dict[str, object],
                      evidence: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence,
                      network: GatewayNetwork) -> dict[str, object]:
        """Save complete attempted frames and original chunks, never raw exports.

        Counter metadata distinguishes a planned complete attempt from a short
        or uncertain send. Partial valid groups are retained but have no import
        manifest. The public caller report is checked, then replaced by the
        canonical value-free client report rather than arbitrary extra fields.
        """
        if self._directory_fd is None:
            raise ArtifactError("snapshot_artifact_store_closed")
        group_fd = None
        try:
            spec = contract(result.module)
            if self._category != {'HU':'coding-snapshot','BDC':'bdc-snapshot','VSG01':'vsg-snapshot'}[result.module]:
                raise ArtifactError("snapshot_store_module_mismatch")
            proofs_match = _validate_input(result, report, network, evidence, svk)
            complete = _complete_stream_agrees(result, proofs_match)
            requests, chunks, groups = [], [], []
            for index, request in enumerate(result.request_bytes, start=1):
                name = f"request-{index:02d}.bin"
                self._write(name, request)
                requests.append({"file": name, "byte_length": len(request), "sha256": _hash(request),
                                 "group_address": f"{spec.groups[index - 1][0]:04X}",
                                 "meaning": "complete attempted frame; aggregate counters establish accepted bytes"})
            for index, (chunk, address) in enumerate(zip(result.recv_chunks, result.chunk_group_addresses), start=1):
                name = f"recv-{index:02d}.bin"
                self._write(name, chunk.data)
                chunks.append({"file": name, "byte_length": len(chunk.data), "sha256": _hash(chunk.data),
                               "group_address": f"{address:04X}",
                               "received_after_seconds": chunk.received_after_seconds})
            if result.groups:
                os.mkdir("original-snapshot", 0o700, dir_fd=self._directory_fd)
                group_fd = os.open("original-snapshot", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=self._directory_fd)
                os.fchmod(group_fd, 0o700)
                for address, value in result.groups:
                    name = f"group-{address:04x}.bin"
                    self._write_at(group_fd, name, value)
                    groups.append({"address": f"{address:04X}", "file": name,
                                   "byte_length": len(value), "sha256": _hash(value)})
            manifest = {
                "schema_version": REPORT_SCHEMA_VERSION, "implementation_version": __version__,
                "timestamp_utc": self.timestamp_utc,
                "acquisition_method": f"one source/interface-bound TCP connection; {len(spec.groups)} fixed sequential coding reads",
                "network": {"source_interface": network.interface, "source_address": network.source_address,
                            "gateway_address": network.gateway_address, "interface_index": network.interface_index,
                            "route_verified": network.route_verified},
                "source_discovery": {"manifest_sha256": evidence.discovery.manifest_sha256,
                                     "reply_sha256": evidence.discovery.reply_sha256},
                "source_gateway_identity": {"manifest_sha256": evidence.manifest_sha256,
                                            "request_sha256": evidence.request_sha256},
                svk_source_key(result.module): {"manifest_sha256": svk.manifest_sha256,
                                         "request_sha256": svk.request_sha256, "value_sha256": svk.value_sha256,
                                         "discovery_manifest_sha256": svk.discovery_manifest_sha256,
                                         "identity_manifest_sha256": svk.identity_manifest_sha256},
                "source_proofs_match_network": proofs_match,
                "cafd": spec.cafd, "btld": spec.btld,
                "report": result.public_report(), "requests": requests, "received_chunks": chunks,
                "retained_group_directory": "original-snapshot" if groups else None,
                "retained_groups": groups,
                "complete_stream_correlated": complete,
                "neutral_snapshot_manifest_eligible": complete,
                "neutral_snapshot_provenance": "unverified_import" if complete else None,
                "original_signature_status": "not_checked",
            }
            encoded = (json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
            self._write("manifest.json", encoded)
            manifest_hash = _hash(encoded)
            original_snapshot = None
            if complete:
                neutral = {"schema": SCHEMA, "cafd": spec.cafd, "btld": spec.btld,
                           "provenance": "unverified_import", "source_sha256": manifest_hash,
                           "groups": groups}
                neutral_raw = (json.dumps(neutral, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
                self._write_at(group_fd, "manifest.json", neutral_raw)
                original_snapshot = {"directory": str(self.directory / "original-snapshot"),
                                     "manifest_sha256": _hash(neutral_raw), "provenance": "unverified_import"}
            if group_fd is not None:
                os.fsync(group_fd)
            os.fsync(self._directory_fd)
            return {"directory": str(self.directory), "manifest_sha256": manifest_hash,
                    "requests_saved": len(requests), "received_chunks_saved": len(chunks),
                    "received_bytes_saved": sum(row["byte_length"] for row in chunks),
                    "all_received_bytes_saved": True, "retained_group_count": len(groups),
                    "complete_snapshot_saved": complete, "original_snapshot": original_snapshot,
                    "requests": [{key: row[key] for key in ("file", "byte_length", "sha256")} for row in requests],
                    "received_chunks": [{key: row[key] for key in ("file", "byte_length", "sha256")} for row in chunks]}
        except ArtifactError:
            raise
        except (OSError, ValueError, TypeError, AttributeError) as error:
            raise ArtifactError("coding_snapshot_storage_failed; stop before further traffic") from error
        finally:
            if group_fd is not None:
                os.close(group_fd)


class BDCSnapshotArtifactStore(CodingSnapshotArtifactStore):
    _category = "bdc-snapshot"


class VSGSnapshotArtifactStore(CodingSnapshotArtifactStore):
    _category = 'vsg-snapshot'


def load_acquired_snapshot(directory: Path, pin: str, *, network: GatewayNetwork,
                           identity: GatewayVINReadEvidence, svk) -> object:
    """Reopen both neutral groups and their complete, proof-bound acquisition."""
    snapshot = load_coding_snapshot(directory, pin)
    spec = contract(svk_module(svk))
    if (snapshot.cafd, snapshot.btld) != (spec.cafd, spec.btld):
        raise ArtifactError('snapshot_acquisition_software_mismatch')
    if directory.name != 'original-snapshot':
        raise ArtifactError('snapshot_acquisition_directory_invalid')
    fd = _open_directory(directory)
    try:
        neutral_raw = _read_private_file(fd, 'manifest.json', 65536)
        if _hash(neutral_raw) != pin: raise ArtifactError('snapshot_neutral_pin_mismatch')
        neutral = json.loads(neutral_raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if set(os.listdir(fd)) != {'manifest.json', *(f'group-{a:04x}.bin' for a,_ in spec.groups)}:
            raise ArtifactError('snapshot_neutral_file_set_mismatch')
    finally:
        os.close(fd)
    fd = _open_directory(directory.parent)
    try:
        raw = _read_private_file(fd, 'manifest.json', 262144)
        if _hash(raw) != neutral['source_sha256']: raise ArtifactError('snapshot_acquisition_pin_mismatch')
        saved = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        expected = dict(cafd=spec.cafd, btld=spec.btld, complete_stream_correlated=True,
            neutral_snapshot_manifest_eligible=True, source_proofs_match_network=True,
            retained_group_directory='original-snapshot', retained_groups=neutral['groups'],
            source_discovery=dict(manifest_sha256=identity.discovery.manifest_sha256, reply_sha256=identity.discovery.reply_sha256),
            source_gateway_identity=dict(manifest_sha256=identity.manifest_sha256, request_sha256=identity.request_sha256),
            network=dict(source_interface=network.interface, source_address=network.source_address,
                         gateway_address=network.gateway_address, interface_index=network.interface_index, route_verified=True))
        expected[svk_source_key(spec.module)] = dict(
            manifest_sha256=svk.manifest_sha256, request_sha256=svk.request_sha256, value_sha256=svk.value_sha256,
            discovery_manifest_sha256=svk.discovery_manifest_sha256, identity_manifest_sha256=svk.identity_manifest_sha256)
        if any(not _same_json(saved.get(k),v) for k,v in expected.items()):
            raise ArtifactError('snapshot_acquisition_proofs_mismatch')
        requests = saved['requests']; rows = saved['received_chunks']
        if len(requests) != len(spec.groups) or not 1 <= len(rows) <= spec.receive_chunks:
            raise ArtifactError('snapshot_acquisition_count_invalid')
        request_bytes = []; chunks = []; addresses = []
        for index, row in enumerate(requests, 1):
            name = f'request-{index:02d}.bin'; value = _read_private_file(fd, name, 11)
            if (row.get('file') != name or row.get('byte_length') != 11 or row.get('sha256') != _hash(value)
                    or row.get('group_address') != f'{spec.groups[index-1][0]:04X}'):
                raise ArtifactError('snapshot_acquisition_request_mismatch')
            request_bytes.append(value)
        for index, row in enumerate(rows, 1):
            name = f'recv-{index:02d}.bin'; value = _read_private_file(fd, name, 4096)
            if row.get('file') != name or row.get('byte_length') != len(value) or row.get('sha256') != _hash(value):
                raise ArtifactError('snapshot_acquisition_chunk_mismatch')
            chunks.append(ReceivedTCPChunk(value, row['received_after_seconds'])); addresses.append(int(row['group_address'],16))
        if set(os.listdir(fd)) != {'manifest.json', 'original-snapshot',
                *(f'request-{i:02d}.bin' for i in range(1,len(requests)+1)),
                *(f'recv-{i:02d}.bin' for i in range(1,len(rows)+1))}:
            raise ArtifactError('snapshot_acquisition_file_set_mismatch')
        report = saved['report']
        values = {name: report[name] for name in CodingSnapshotResult.__dataclass_fields__
                  if name not in ('request_bytes','recv_chunks','chunk_group_addresses','groups','module')}
        for name in ('nrc','last_control'):
            values[name] = None if values[name] is None else int(values[name],16)
        result = CodingSnapshotResult(**values, request_bytes=tuple(request_bytes), recv_chunks=tuple(chunks),
                    chunk_group_addresses=tuple(addresses), groups=snapshot.groups, module=spec.module)
        if not _complete_stream_agrees(result, _validate_input(result,report,network,identity,svk)):
            raise ArtifactError('snapshot_acquisition_stream_mismatch')
        return snapshot
    finally:
        os.close(fd)
