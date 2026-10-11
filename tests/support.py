"""Shared synthetic fixtures and explicit assertions; no owner material."""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from i3enet.coding_preparation import CodingEdit

DEFAULT_EDIT = CodingEdit(0x3001, 58, b"\x00", b"\xff", b"\xff")

NETWORK_IO = ("socket.socket", "socket.getaddrinfo", "socket.gethostbyname", "subprocess.run")

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def frame(body, control=1):
    return struct.pack(">IH", len(body), control) + body

def write_private(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)

def write_json(path, value):
    raw = json.dumps(value, sort_keys=True).encode()
    write_private(path, raw)
    return digest(raw)

def proofs(index=19, gateway="169.254.0.2", source="169.254.20.3", vin="SYNTHETIC00000001"):
    from i3enet.evidence import GatewayIdentityEvidence, GatewayVINReadEvidence
    from i3enet.network import GatewayNetwork
    from i3enet.svk import HeadUnitSVKEvidence
    network = GatewayNetwork("en9", source, gateway, index, "255.255.0.0", "Synthetic Ethernet")
    discovery = GatewayIdentityEvidence(gateway, "en9", source, index, vin, "a" * 64, "b" * 64)
    identity = GatewayVINReadEvidence(discovery, "c" * 64, digest(bytes.fromhex("000000050001f41022f190")))
    svk = HeadUnitSVKEvidence(gateway, "en9", source, index, "a" * 64, "c" * 64, "d" * 64,
                            digest(bytes.fromhex("000000050001f46322f101")), "e" * 64)
    return network, discovery, identity, svk


def bdc_svk(svk):
    from dataclasses import asdict
    from i3enet.svk import BDCSVKEvidence
    values = asdict(svk)
    values.update(request_sha256=digest(bytes.fromhex('000000050001f44022f101')),
        cafd_identifier='000017BE', cafd_version='085.010.012', btld_identifier='00002418', btld_version='085.010.060')
    return BDCSVKEvidence(**values)

def vsg_svk(svk):
    from dataclasses import asdict
    from i3enet.svk import VSGSVKEvidence
    values = asdict(svk)
    values.update(request_sha256=digest(bytes.fromhex('000000050001f42d22f101')),
        cafd_identifier='00001A79',cafd_version='001.003.001',btld_identifier='00001A77',btld_version='001.001.002')
    return VSGSVKEvidence(**values)

@contextmanager
def mocked(values=(), *, forbidden=NETWORK_IO, cwd=None):
    with ExitStack() as stack:
        mocks = {name: stack.enter_context(patch(name, return_value=value)) for name, value in values}
        for name in forbidden:
            stack.enter_context(patch(name, side_effect=AssertionError("unexpected external I/O: " + name)))
        if cwd is not None:
            stack.enter_context(patch("pathlib.Path.cwd", return_value=Path(cwd)))
        yield stack, mocks

class OfflineCase(unittest.TestCase):
    def temporary(self):
        temporary = tempfile.TemporaryDirectory(dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def forbid(self, *names):
        for name in names or NETWORK_IO:
            guard = patch(name, side_effect=AssertionError("unexpected external I/O: " + name))
            guard.start()
            self.addCleanup(guard.stop)

    def fields(self, value, **expected):
        actual = {key: value[key] if isinstance(value, dict) else getattr(value, key) for key in expected}
        self.assertEqual(actual, expected)

    def redacted(self, value, *secrets):
        for secret in secrets:
            self.assertNotIn(secret, str(value) + repr(value))

    def private(self, directory):
        for path in (directory, *directory.rglob("*")):
            info = path.lstat()
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
            if path.is_file(): self.assertEqual(info.st_nlink, 1)

    def rejects(self, error, operation, cases):
        for name, args, kwargs in cases:
            with self.subTest(case=name), self.assertRaises(error):
                operation(*args, **kwargs)

    def mutate(self, original, cases, persist, reject):
        for path, value in cases:
            with self.subTest(path=path, value=value):
                changed = deepcopy(original)
                target = changed
                for key in path[:-1]: target = target[key]
                target[path[-1]] = value
                persist(changed)
                reject()


class StreamEvidenceCase(OfflineCase):
    def write_private(self, name, raw):
        write_private(self.directory / name, raw)

    def persist(self, encoded=None):
        if encoded is None: encoded = json.dumps(self.manifest, sort_keys=True).encode()
        self.manifest_hash = digest(encoded)
        self.write_private("manifest.json", encoded)

    def persist_chunks(self, times=None):
        for path in self.directory.glob("recv-*.bin"): path.unlink()
        rows = []
        for index, raw in enumerate(self.chunks):
            name = f"recv-{index + 1:02d}.bin"
            self.write_private(name, raw)
            rows.append(dict(file=name, byte_length=len(raw), sha256=digest(raw),
                             received_after_seconds=.01 * (index + 1) if times is None else times[index]))
        self.manifest["received_chunks"] = rows
        self.manifest["report"].update(received_chunks=len(rows), received_bytes=sum(map(len, self.chunks)))
        self.write_private("request.bin", self.request)
        self.persist()


def stream_manifest(discovery, request, command, mode, outcome, version, **extra_report):
    """Independent expected report schema for saved fixed-read original streams."""
    report = dict(schema_version=1, implementation_version=version, command=command, mode=mode,
        outcome=outcome, reason=None, timing_complete=True, tcp_close_uncertain=False, source_interface=discovery.source_interface,
        source_address=discovery.source_address, gateway_address=discovery.gateway_address,
        interface_index=discovery.interface_index, destination_port=6801, tester_address="0xF4",
        service="0x22", identifier=f"0x{request[9:].hex().upper()}", request_hex=request.hex(),
        discovery_manifest_sha256=discovery.manifest_sha256, discovery_reply_sha256=discovery.reply_sha256,
        masked_discovery_vin="*" * 13 + discovery.vin_candidate[-4:], route_verified=True,
        diagnostic_tcp_opened=True, writes_supported=False, transmission_uncertain=False,
        tcp_connection_uncertain=False, tcp_control_traffic_counted=False, tcp_connections_attempted=1,
        tcp_connections_opened=1, application_frames_attempted=1, application_frames_sent=1,
        vehicle_bytes_confirmed_sent=11, ack_count=1, pending_count=0, nrc=None, last_control="0x0001",
        connect_timeout_seconds=3.0, first_response_window_seconds=3.0, pending_response_window_seconds=3.0,
        overall_request_window_seconds=6.0, experiment_overall_window_seconds=10.0,
        response_elapsed_seconds=.1, experiment_elapsed_seconds=.2, elapsed_seconds=.3)
    report.update(extra_report)
    return dict(schema_version=1, implementation_version=version, private_raw_originals=True,
        source_discovery=dict(manifest_sha256=discovery.manifest_sha256, reply_sha256=discovery.reply_sha256),
        request=dict(file="request.bin", byte_length=11, sha256=digest(request),
                     application_frames_attempted=1, application_frames_sent=1,
                     confirmed_bytes=11, transmission_uncertain=False), received_chunks=[], report=report)
