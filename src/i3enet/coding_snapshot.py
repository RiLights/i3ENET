"""Hash-pinned private offline snapshot import; never imports a key or socket."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .coding_preparation import BTLD, CAFD, GROUP_LENGTHS, CodingPreparationError, CodingSnapshot
from .coding_contract import software_contract

SCHEMA = "i3enet-coding-snapshot/1"


class CodingSnapshotError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _digest(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise CodingSnapshotError("invalid_hash_pin")
    return value


def _private_read(directory_fd: int, name: str, length: int, digest: str) -> bytes:
    # Nonblocking open lets fstat reject a FIFO/device before any read blocks.
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size != length):
            raise CodingSnapshotError("private_file_shape_or_mode")
        chunks = []; remaining = length
        while remaining:
            block = os.read(fd, min(remaining, 65536))
            if not block:
                raise CodingSnapshotError("short_read")
            chunks.append(block); remaining -= len(block)
        if os.read(fd, 1):
            raise CodingSnapshotError("file_grew")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise CodingSnapshotError("file_changed_during_read")
        raw = b"".join(chunks)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise CodingSnapshotError("file_hash_mismatch")
        return raw
    finally:
        os.close(fd)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise CodingSnapshotError("duplicate_json_key")
        result[name] = value
    return result


def load_coding_snapshot(directory: Path, manifest_sha256: str) -> CodingSnapshot:
    """Accept fixed neutral names/geometry only; metadata cannot claim freshness.

    Hashes bind the imported bytes. They do not authenticate their origin,
    confirm the signature, or establish that they are current on the ECU.
    """
    pin = _digest(manifest_sha256)
    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise CodingSnapshotError("private_directory_mode")
        info = os.stat("manifest.json", dir_fd=fd, follow_symlinks=False)
        if not 0 < info.st_size <= 65536:
            raise CodingSnapshotError("manifest_size_limit")
        raw = _private_read(fd, "manifest.json", info.st_size, pin)
        manifest = json.loads(raw, object_pairs_hook=_unique_object)
        if type(manifest) is not dict or set(manifest) != {"schema", "cafd", "btld", "provenance", "source_sha256", "groups"}:
            raise CodingSnapshotError("manifest_schema")
        if manifest["schema"] != SCHEMA:
            raise CodingSnapshotError("unsupported_software_tuple")
        spec = software_contract(manifest['cafd'], manifest['btld'])
        _digest(manifest["source_sha256"])
        rows = manifest["groups"]
        if type(rows) is not list or len(rows) != len(spec.groups):
            raise CodingSnapshotError("incomplete_group_set")
        groups = []
        for row, (address, length) in zip(rows, spec.groups):
            expected_name = f"group-{address:04x}.bin"
            if (type(row) is not dict or set(row) != {"address", "file", "byte_length", "sha256"} or
                    row["address"] != f"{address:04X}" or row["file"] != expected_name or
                    type(row["byte_length"]) is not int or row["byte_length"] != length):
                raise CodingSnapshotError("group_manifest_shape")
            groups.append((address, _private_read(fd, expected_name, length, _digest(row["sha256"]))))
        return CodingSnapshot(tuple(groups), manifest["provenance"], spec.cafd, spec.btld)
    except CodingSnapshotError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, CodingPreparationError):
        raise CodingSnapshotError("snapshot_import_failed") from None
    finally:
        if fd is not None:
            os.close(fd)
