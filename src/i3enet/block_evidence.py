"""Independent retained HU EXBOX / BDC PfFesMaster stream validation."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re

from . import __version__
from .evidence import (EvidenceError, _invalid_constant, _open_directory,
                       _read_private_file, _unique_object,
                       load_gateway_identity_evidence, load_gateway_vin_read_evidence)
from .hsfz import Control, HSFZError, IncrementalParser
from .svk import BDCSVKEvidence, VSGSVKEvidence, load_head_unit_svk_evidence, load_bdc_svk_evidence, load_vsg_svk_evidence
from .profiles import BDC_SOFTWARE, VSG_SOFTWARE
from .policy import BDC_METADATA, VSG_METADATA
from .uds import ReadDataByIdentifierRequest, UDSError, parse_read_data_response

_REQUEST = bytes.fromhex("000000050001f463223001")


def _require(condition: bool) -> None:
    if not condition:
        raise EvidenceError("retained_block_validation_failed")


def _json(raw: str | bytes) -> dict:
    value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    _require(type(value) is dict)
    return value


def load_exbox_value(report: dict, *, root: Path, network: tuple, proofs: tuple) -> bytes:
    return _load_block_value(report, root=root, network=network, proofs=proofs, module='HU')


def load_bdc_pffes_value(report: dict, *, root: Path, network: tuple, proofs: tuple) -> bytes:
    return _load_block_value(report, root=root, network=network, proofs=proofs, module='BDC')


def load_vsg_config_value(report: dict, *, root: Path, network: tuple, proofs: tuple) -> bytes:
    return _load_block_value(report, root=root, network=network, proofs=proofs, module='VSG01')


def load_bdc_metadata_value(kind: str, report: dict, *, root: Path, network: tuple, proofs: tuple) -> bytes:
    _require(type(kind) is str and kind in BDC_METADATA)
    return _load_block_value(report, root=root, network=network, proofs=proofs, module='BDC', kind=kind)


def load_vsg_metadata_value(kind: str, report: dict, *, root: Path, network: tuple, proofs: tuple) -> bytes:
    _require(type(kind) is str and kind in VSG_METADATA)
    return _load_block_value(report, root=root, network=network, proofs=proofs, module='VSG01', kind=kind)


def load_bdc_cps_original(directory: Path, pin: str, *, network: tuple, proofs: tuple) -> bytes:
    return _load_cps_original(directory,pin,network=network,proofs=proofs,module='BDC')


def load_vsg_cps_original(directory: Path, pin: str, *, network: tuple, proofs: tuple) -> bytes:
    return _load_cps_original(directory,pin,network=network,proofs=proofs,module='VSG01')


def _load_cps_original(directory: Path, pin: str, *, network: tuple, proofs: tuple, module) -> bytes:
    """Reopen a pinned CPS acquisition and independently correlate its stream."""
    fd = _open_directory(directory)
    try:
        raw = _read_private_file(fd, 'manifest.json', 65536)
        _require(hashlib.sha256(raw).hexdigest() == pin)
        manifest = _json(raw)
        report = manifest['report'].copy(); rows = manifest['received_chunks']; request = manifest['request']
        report['raw_artifacts'] = dict(directory=str(directory), manifest_sha256=pin,
            all_received_bytes_saved=True, received_chunks_saved=len(rows), received_chunks=rows,
            received_bytes_saved=sum(row['byte_length'] for row in rows),
            request={k: request[k] for k in ('file','byte_length','sha256')})
    finally:
        os.close(fd)
    return (load_bdc_metadata_value if module == 'BDC' else load_vsg_metadata_value)(
        'bdc_cps' if module == 'BDC' else 'vsg_cps',report,root=directory.parents[2],network=network,proofs=proofs)


def _load_block_value(report: dict, *, root: Path, network: tuple, proofs: tuple, module: str, kind=None) -> bytes:
    """Recheck only the new capture returned by this invocation, never latest."""
    target, did, length, block_kind, category, loader = {
        'HU': (0x63,0x3001,151,'exbox','head-unit-exbox',load_head_unit_svk_evidence),
        'BDC': (0x40,0x3221,17,'bdc_pffes','bdc-pffes',load_bdc_svk_evidence),
        'VSG01': (0x2D,0x3000,8,'vsg_config','vsg-config',load_vsg_svk_evidence),
    }[module]
    request_bytes = bytes.fromhex('000000050001f4') + bytes((target,0x22)) + did.to_bytes(2,'big')
    if kind is not None:
        metadata = BDC_METADATA if module == 'BDC' else VSG_METADATA if module == 'VSG01' else {}
        _require(kind in metadata)
        did, length, _ = metadata[kind]
        request_bytes = bytes.fromhex('000000050001f4') + bytes((target,0x22)) + did.to_bytes(2, "big")
        if length is None:
            length = report.get("value_byte_count")
            _require(type(length) is int and 1 <= length <= 32)
    version = report.get('implementation_version')
    _require(version == __version__)
    expected = {
        "command": 'read-' + block_kind.replace('_','-'), "mode": 'live_' + block_kind, "outcome": "coding_value_observed",
        "reason": None, "implementation_version": version, "route_verified": True,
        "source_interface": network[0], "source_address": network[1],
        "gateway_address": network[2], "interface_index": network[3],
        "tcp_connections_attempted": 1, "tcp_connections_opened": 1,
        "application_frames_attempted": 1, "application_frames_sent": 1,
        "vehicle_bytes_confirmed_sent": 11, "transmission_uncertain": False,
        "tcp_connection_uncertain": False, "tcp_close_uncertain": False,
        "timing_complete": True, "ack_count": 1,
        "last_control": "0x0001", "value_byte_count": length, "writes_supported": False,
        "candidate_address": f"0x{target:02X}", "identifier": f"0x{did:04X}",
    }
    if kind is not None:
        expected.update(command="read-" + kind.replace("_", "-"), mode="live_" + kind)
    for key, value in expected.items():
        _require(type(report.get(key)) is type(value) and report.get(key) == value)
    for key, bound in (("elapsed_seconds", float("inf")), ("response_elapsed_seconds", 6),
                       ("experiment_elapsed_seconds", 10)):
        value = report.get(key)
        _require(type(value) in (int, float) and math.isfinite(value) and 0 <= value < bound)
    _require(report["response_elapsed_seconds"] <= report["experiment_elapsed_seconds"] <= report["elapsed_seconds"])
    _require(type(report.get("pending_count")) is int and 0 <= report["pending_count"] <= 64)
    _require(report.get("nrc") == ("0x78" if report["pending_count"] else None))

    discovery = load_gateway_identity_evidence(
        root / proofs[0][1], manifest_sha256=proofs[0][2],
        gateway_address=network[2], source_interface=network[0], source_address=network[1])
    identity = load_gateway_vin_read_evidence(
        root / proofs[1][1], manifest_sha256=proofs[1][2], discovery=discovery)
    svk = loader(
        root / proofs[2][1], manifest_sha256=proofs[2][2], discovery=discovery, identity=identity)
    if module != 'HU':
        _require(type(svk) is (BDCSVKEvidence if module == 'BDC' else VSGSVKEvidence))
        _require((svk.cafd_identifier, svk.cafd_version, svk.btld_identifier, svk.btld_version) == (BDC_SOFTWARE if module == 'BDC' else VSG_SOFTWARE))
    _require(discovery.interface_index == network[3])
    proof_fields = {
        "discovery_manifest_sha256": discovery.manifest_sha256,
        "discovery_reply_sha256": discovery.reply_sha256,
        "identity_manifest_sha256": identity.manifest_sha256,
        "identity_request_sha256": identity.request_sha256,
        "svk_manifest_sha256": svk.manifest_sha256, "svk_request_sha256": svk.request_sha256,
        "prior_svk_value_sha256": svk.value_sha256,
        "observed_cafd_identifier": svk.cafd_identifier, "observed_cafd_version": svk.cafd_version,
        "observed_btld_identifier": svk.btld_identifier, "observed_btld_version": svk.btld_version,
        "prior_gateway_vin_match": True, "prior_svk_match": True,
    }
    for key, expected_value in proof_fields.items():
        _require(type(report.get(key)) is type(expected_value) and report.get(key) == expected_value)
    artifacts = report.get("raw_artifacts")
    _require(type(artifacts) is dict and artifacts.get("all_received_bytes_saved") is True)
    directory = Path(artifacts["directory"])
    _require(directory.parent == root / ('private/' + ('bdc-metadata' if module == 'BDC' else 'vsg-metadata') if kind is not None else 'private/' + category)
             and re.fullmatch(r"\d{8}T\d{6}_[0-9a-f]{12}", directory.name) is not None)
    pin = artifacts.get("manifest_sha256")
    _require(type(pin) is str and re.fullmatch(r"[0-9a-f]{64}", pin) is not None)
    fd = _open_directory(directory)
    try:
        raw = _read_private_file(fd, "manifest.json", 65536)
        _require(hashlib.sha256(raw).hexdigest() == pin)
        manifest = _json(raw)
        _require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1
                 and manifest.get("private_raw_originals") is True
                 and manifest.get("implementation_version") == version)
        _require(manifest.get("report") == {key: value for key, value in report.items() if key != "raw_artifacts"})
        links = {
            "source_discovery": {"manifest_sha256": discovery.manifest_sha256, "reply_sha256": discovery.reply_sha256},
            "source_gateway_identity": {"manifest_sha256": identity.manifest_sha256, "request_sha256": identity.request_sha256},
            {'HU':'source_head_unit_svk','BDC':'source_bdc_svk','VSG01':'source_vsg_svk'}[module]: {"manifest_sha256": svk.manifest_sha256, "request_sha256": svk.request_sha256,
                                     "value_sha256": svk.value_sha256},
        }
        for key, value in links.items():
            _require(manifest.get(key) == value)
        request = _read_private_file(fd, "request.bin", 11)
        _require(request == request_bytes)
        row = manifest["request"]
        request_fields = {"file": "request.bin", "byte_length": 11,
                          "sha256": hashlib.sha256(request).hexdigest(),
                          "application_frames_attempted": 1, "application_frames_sent": 1,
                          "confirmed_bytes": 11, "transmission_uncertain": False}
        for key, expected_value in request_fields.items():
            _require(type(row.get(key)) is type(expected_value) and row.get(key) == expected_value)
        _require(artifacts.get("request") == {key: row[key] for key in ("file", "byte_length", "sha256")})
        rows = manifest.get("received_chunks")
        _require(type(rows) is list and 1 <= len(rows) <= 64)
        _require(type(report.get("received_chunks")) is int and report["received_chunks"] == len(rows))
        _require(type(artifacts.get("received_chunks_saved")) is int
                 and artifacts["received_chunks_saved"] == len(rows) and artifacts.get("received_chunks") == rows)
        _require(set(os.listdir(fd)) == {"manifest.json", "request.bin", *(f"recv-{i:02d}.bin" for i in range(1, len(rows) + 1))})
        parser = IncrementalParser(max_body_length=4096)
        total = pending = ack = 0
        last_at = -1.0
        # These originals timestamp the request before send, but start
        # the first-response window after send returns. Send completion is not
        # retained, so reconstruct only the six-second overall and any known
        # pending+three-second deadlines; never invent an earlier first window.
        receive_deadline = 6.0
        value = None
        for index, row in enumerate(rows, 1):
            name = f"recv-{index:02d}.bin"
            _require(type(row) is dict and row.get("file") == name)
            chunk = _read_private_file(fd, name, 4096)
            _require(0 < len(chunk) <= 4096 and type(row.get("byte_length")) is int
                     and row["byte_length"] == len(chunk) and row.get("sha256") == hashlib.sha256(chunk).hexdigest())
            total += len(chunk)
            _require(total <= 65536)
            at = row.get("received_after_seconds")
            _require(type(at) in (float, int) and math.isfinite(at)
                     and 0 <= at < receive_deadline and at >= last_at)
            last_at = at
            for frame in parser.feed(chunk):
                _require(value is None)
                if frame.control is Control.ACK:
                    _require(ack == 0 and (frame.source, frame.target, frame.diagnostic_payload) == (0xF4, target, request_bytes[8:]))
                    ack += 1
                else:
                    _require(frame.control is Control.DIAGNOSTIC and (frame.source, frame.target) == (target, 0xF4))
                    if frame.diagnostic_payload == b"\x7f\x22\x78":
                        pending += 1
                        receive_deadline = min(6.0, at + 3.0)
                    else:
                        _require(ack == 1)
                        _require(frame.diagnostic_payload[:1] == b"\x62")
                        value = parse_read_data_response(frame.diagnostic_payload,
                                                         ReadDataByIdentifierRequest(did), expected_value_length=length).value
        parser.finish()
        _require(ack == 1 and value is not None and pending == report["pending_count"])
        _require(type(report.get("received_bytes")) is int and total == report["received_bytes"])
        _require(type(artifacts.get("received_bytes_saved")) is int and artifacts["received_bytes_saved"] == total)
        _require(last_at <= report["response_elapsed_seconds"])
        _require(hashlib.sha256(value).hexdigest() == report.get("value_sha256"))
        return value
    except (HSFZError, UDSError):
        raise EvidenceError("retained_block_validation_failed") from None
    finally:
        os.close(fd)
