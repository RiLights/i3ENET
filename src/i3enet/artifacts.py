"""Private acquisition evidence storage, without sockets or raw exports."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import TYPE_CHECKING
from uuid import uuid4

from . import REPORT_SCHEMA_VERSION, __version__

if TYPE_CHECKING:
    from .evidence import GatewayIdentityEvidence, GatewayVINReadEvidence
    from .live_identity import GatewayIdentityResult
    from .live_discovery import LiveDiscoveryResult
    from .live_svk import ModuleSVKResult
    from .live_block import ModuleBlockResult
    from .svk import HeadUnitSVKEvidence, BDCSVKEvidence


class ArtifactError(OSError):
    """Private evidence could not be prepared or retained; never retry discovery."""


def _private_directory(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    info = os.fstat(descriptor)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(descriptor)
        raise ArtifactError("private artifact directory must be owned by this user and mode 0700")
    return descriptor


class DiscoveryArtifactStore:
    """Prepare private storage before traffic; write originals after socket close.

    All child traversal is relative to open directories, with symlinks refused.
    Existing evidence is never replaced. Names contain no vehicle identifiers.
    """

    _category = "discovery"

    def __init__(self, project_directory: Path) -> None:
        self._directory_fd: int | None = None
        self.timestamp_utc = datetime.now(timezone.utc).isoformat()
        name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "_" + uuid4().hex[:12]
        self.directory = project_directory.resolve() / "private" / self._category / name
        descriptors: list[int] = []
        try:
            descriptors.append(os.open(project_directory.resolve(), os.O_RDONLY | os.O_DIRECTORY))
            descriptors.append(_private_directory(descriptors[-1], "private"))
            descriptors.append(_private_directory(descriptors[-1], self._category))
            self._directory_fd = _private_directory(descriptors[-1], name)
            self._write("storage-check", b"")
            os.unlink("storage-check", dir_fd=self._directory_fd)
        except (OSError, KeyboardInterrupt) as exc:
            self.close()
            raise ArtifactError("could not prepare private discovery evidence; no packet permitted") from exc
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _write(self, name: str, data: bytes) -> None:
        if self._directory_fd is None:
            raise ArtifactError("artifact store is closed")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(name, flags, 0o600, dir_fd=self._directory_fd)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)

    def save(self, result: LiveDiscoveryResult, report: dict[str, object]) -> dict[str, object]:
        """Original binary datagrams and a private manifest; public summary has hashes only."""
        records = []
        try:
            for index, datagram in enumerate(result.datagrams, start=1):
                filename = f"reply-{index:02d}.bin"
                self._write(filename, datagram.data)
                records.append({
                    "file": filename, "sha256": hashlib.sha256(datagram.data).hexdigest(),
                    "byte_length": len(datagram.data), "peer_address": datagram.peer_address,
                    "peer_port": datagram.peer_port, "truncated": datagram.truncated,
                    "disposition": datagram.disposition, "reason": datagram.reason,
                    "received_after_seconds": datagram.received_after_seconds,
                })
            manifest = {
                "schema_version": REPORT_SCHEMA_VERSION, "implementation_version": __version__,
                "timestamp_utc": self.timestamp_utc,
                "acquisition_method": "one interface-bound HSFZ UDP discovery datagram; no TCP",
                "private_raw_originals": not any(item["truncated"] for item in records),
                "report": report, "datagrams": records,
            }
            encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
            self._write("manifest.json", encoded)
            return {"directory": str(self.directory), "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                    "datagrams_saved": len(records), "received_bytes_saved": sum(item["byte_length"] for item in records),
                    "all_datagrams_complete": not any(item["truncated"] for item in records),
                    "datagrams": [{key: item[key] for key in ("file", "sha256", "byte_length", "truncated")}
                                  for item in records]}
        except OSError as exc:
            raise ArtifactError("discovery evidence storage failed; stop before further traffic") from exc

    def close(self) -> None:
        if self._directory_fd is not None:
            os.close(self._directory_fd)
            self._directory_fd = None

    def __enter__(self) -> DiscoveryArtifactStore:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class GatewayIdentityArtifactStore(DiscoveryArtifactStore):
    """Retain a planned request and original received stream chunks privately."""

    _category = "gateway-identity"

    def save_identity(
        self,
        result: GatewayIdentityResult,
        report: dict[str, object],
        evidence: GatewayIdentityEvidence,
    ) -> dict[str, object]:
        return self._save_exchange(
            result, report,
            {"manifest_sha256": evidence.manifest_sha256, "reply_sha256": evidence.reply_sha256},
            "one source/interface-bound gateway VIN read on TCP; no session changes",
        )

    def _save_exchange(
        self,
        result: GatewayIdentityResult | ModuleSVKResult | ModuleBlockResult,
        report: dict[str, object],
        source_discovery: dict[str, str],
        acquisition_method: str,
        source_gateway_identity: dict[str, str] | None = None,
        source_head_unit_svk: dict[str, str] | None = None,
        svk_source_key: str = "source_head_unit_svk",
    ) -> dict[str, object]:
        records = []
        try:
            self._write("request.bin", result.request_bytes)
            request = {
                "file": "request.bin", "byte_length": len(result.request_bytes),
                "sha256": hashlib.sha256(result.request_bytes).hexdigest(),
                "meaning": "complete planned application frame; counters establish what send accepted",
                "application_frames_attempted": result.application_frames_attempted,
                "application_frames_sent": result.application_frames_sent,
                "confirmed_bytes": result.vehicle_bytes_confirmed_sent,
                "transmission_uncertain": result.transmission_uncertain,
            }
            for index, chunk in enumerate(result.recv_chunks, start=1):
                filename = f"recv-{index:02d}.bin"
                self._write(filename, chunk.data)
                records.append({
                    "file": filename, "byte_length": len(chunk.data),
                    "sha256": hashlib.sha256(chunk.data).hexdigest(),
                    "received_after_seconds": chunk.received_after_seconds,
                })
            manifest = {
                "schema_version": REPORT_SCHEMA_VERSION, "implementation_version": __version__,
                "timestamp_utc": self.timestamp_utc,
                "acquisition_method": acquisition_method,
                "source_discovery": source_discovery,
                "request": request, "received_chunks": records, "report": report,
                "private_raw_originals": True,
                "capture_scope": "application stream reads only; not a link-layer capture",
            }
            if source_gateway_identity is not None:
                manifest["source_gateway_identity"] = source_gateway_identity
            if source_head_unit_svk is not None:
                manifest[svk_source_key] = source_head_unit_svk
            encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
            self._write("manifest.json", encoded)
            return {
                "directory": str(self.directory),
                "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                "request": {key: request[key] for key in ("file", "byte_length", "sha256")},
                "received_chunks_saved": len(records),
                "received_bytes_saved": sum(item["byte_length"] for item in records),
                "all_received_bytes_saved": True,
                "received_chunks": records,
            }
        except OSError as exc:
            raise ArtifactError("gateway exchange evidence storage failed; stop before further traffic") from exc


class HeadUnitSVKArtifactStore(GatewayIdentityArtifactStore):
    """Private original stream bytes for one candidate current SVK query."""

    _category = "head-unit-svk"

    def save_svk(
        self,
        result: ModuleSVKResult,
        report: dict[str, object],
        evidence: GatewayVINReadEvidence,
    ) -> dict[str, object]:
        return self._save_exchange(
            result, report,
            {"manifest_sha256": evidence.discovery.manifest_sha256,
             "reply_sha256": evidence.discovery.reply_sha256},
            f"one source/interface-bound candidate address 0x{result.diagnostic_address:02X} current SVK read on TCP; no session changes",
            {"manifest_sha256": evidence.manifest_sha256, "request_sha256": evidence.request_sha256},
        )


class BDCSVKArtifactStore(HeadUnitSVKArtifactStore):
    _category = "bdc-svk"


class VSGSVKArtifactStore(HeadUnitSVKArtifactStore):
    _category = "vsg-svk"


class ExboxArtifactStore(GatewayIdentityArtifactStore):
    """Private original chunks for one selected EXBOX coding-group read."""

    _category = "head-unit-exbox"

    def save_block(
        self,
        result: ModuleBlockResult,
        report: dict[str, object],
        evidence: GatewayVINReadEvidence,
        svk: HeadUnitSVKEvidence | BDCSVKEvidence,
    ) -> dict[str, object]:
        return self._save_exchange(
            result, report,
            {"manifest_sha256": evidence.discovery.manifest_sha256,
             "reply_sha256": evidence.discovery.reply_sha256},
            f"one source/interface-bound address 0x{result.diagnostic_address:02X} group 0x{result.identifier:04X} read on TCP; no session changes",
            {"manifest_sha256": evidence.manifest_sha256, "request_sha256": evidence.request_sha256},
            {"manifest_sha256": svk.manifest_sha256, "request_sha256": svk.request_sha256,
             "value_sha256": svk.value_sha256},
            svk_source_key={0x40:'source_bdc_svk',0x2D:'source_vsg_svk',0x63:'source_head_unit_svk'}[result.diagnostic_address],
        )


class BDCPfFesArtifactStore(ExboxArtifactStore):
    _category = "bdc-pffes"


class VSGConfigArtifactStore(ExboxArtifactStore):
    _category = 'vsg-config'


class BDCMetadataArtifactStore(ExboxArtifactStore):
    _category = "bdc-metadata"


class VSGMetadataArtifactStore(ExboxArtifactStore):
    _category = 'vsg-metadata'
