"""Explicit, profile-bound loading of bundled or local RSA signing keys.

Configuration validation hashes files but does not construct a private key.
Protected loading is a separate operation, after transaction approval. No key
extraction, vendor resource loading or import-time file access occurs here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat

from .coding_contract import contract
from .coding_signature import RSA1024PrivateKey


_BUNDLE = Path(__file__).resolve().with_name('data')
_BUNDLE_PINS = {'HU': 'cbccdab2459cc69760ddb115a0feb91757a582f94ca3bda449ca4923ec7c75fe', 'BDC': 'afcfe54292c2772a1190355f21ef0680de6b9b1855a148239adf2445407b1a16', 'VSG01': '7659fe303e31922256abd3f53bbb1e61cef90e67e997ccf3e0ce34613aba4521'}


def bundled_configuration(module: str) -> Path:
    require(module in _BUNDLE_PINS, 'bundled_signing_profile_unavailable')
    return _BUNDLE / (module + '.json')


def _bundled(path: Path, pin: str, module: str) -> bool:
    return path == bundled_configuration(module) and pin == _BUNDLE_PINS[module]


class SigningKeyError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def require(condition, reason):
    if not condition:
        raise SigningKeyError(reason)


def is_pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _stamp(item):
    return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
            item.st_ctime_ns, item.st_mode, item.st_uid, item.st_nlink)


def _read(path: Path, maximum: int = 16384, *, private: bool = True) -> bytes:
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        require(not stat.S_ISLNK(item.lstat().st_mode), 'signing_path_link')
    parent = path.parent.stat()
    require(not private or (parent.st_uid == os.getuid() and stat.S_IMODE(parent.st_mode) == 0o700),
            'signing_directory_requires_0700')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and (not private or before.st_uid == os.getuid()) and 0 < before.st_size <= maximum,
                'signing_file_invalid')
        require(not private or stat.S_IMODE(before.st_mode) == 0o600, 'signing_file_requires_0600')
        blocks, remaining = [], before.st_size
        while remaining:
            block = os.read(fd, remaining)
            require(bool(block), 'signing_file_short')
            blocks.append(block)
            remaining -= len(block)
        require(os.read(fd, 1) == b'', 'signing_file_grew')
        require(_stamp(before) == _stamp(os.fstat(fd)) == _stamp(path.lstat()),
                'signing_file_changed')
        require(_stamp(parent) == _stamp(path.parent.stat()), 'signing_directory_changed')
        return b''.join(blocks)
    finally:
        os.close(fd)


def configuration_pin(path: Path) -> str:
    try:
        path = path.absolute()
        expected = next((pin for module, pin in _BUNDLE_PINS.items() if path == bundled_configuration(module)), None)
        actual = hashlib.sha256(_read(path, private=expected is None)).hexdigest()
        require(expected is None or actual == expected, 'bundled_configuration_changed')
        return actual
    except SigningKeyError:
        raise
    except (OSError, ValueError):
        raise SigningKeyError('signing_configuration_unavailable') from None


@dataclass(frozen=True, slots=True)
class SigningKeyReference:
    configuration: Path = field(repr=False)
    configuration_sha256: str
    module: str
    role: str
    key_path: Path = field(repr=False)
    key_sha256: str

    def public_report(self):
        spec = contract(self.module)
        return dict(provider_kind='supplied_key_' + self.role.lower(), role=self.role,
                    module=self.module, cafd=spec.cafd, btld_identifier=spec.btld.split('/')[0],
                    configuration_sha256=self.configuration_sha256,
                    key_file_sha256=self.key_sha256, protected_material_loaded=False,
                    key_source='bundled' if _bundled(self.configuration, self.configuration_sha256, self.module) else 'local',
                    key_eligibility='original_signature_and_ecu_acceptance_checks_required')


def validate_key_reference(path: Path, pin: str, *, module: str, role: str) -> SigningKeyReference:
    """Bind one declared role to an exact software profile and immutable file."""
    try:
        require(is_pin(pin) and role in ('AS', 'NCDS'), 'signing_selection_invalid')
        path = Path(os.path.abspath(path))
        bundled = _bundled(path, pin, module)
        raw = _read(path, private=not bundled)
        require(hashlib.sha256(raw).hexdigest() == pin, 'signing_configuration_changed')
        def pairs(items):
            result = {}
            for key, value in items:
                require(key not in result, 'signing_configuration_duplicate')
                result[key] = value
            return result
        data = json.loads(raw, object_pairs_hook=pairs)
        spec = contract(module)
        require(type(data) is dict and set(data) == {'schema', 'module', 'cafd', 'btld', 'keys'}
                and data['schema'] == 'i3enet-signing-keys/1', 'signing_configuration_invalid')
        require((data['module'], data['cafd'], data['btld']) == (module, spec.cafd, spec.btld),
                'signing_software_profile_mismatch')
        require(type(data['keys']) is dict and set(data['keys']) == {'AS', 'NCDS'},
                'signing_roles_required')
        for record in data['keys'].values():
            require(type(record) is dict and set(record) == {'file', 'sha256'}
                    and type(record['file']) is str and 0 < len(record['file']) <= 1024
                    and is_pin(record['sha256']), 'signing_key_record_invalid')
        record = data['keys'][role]
        key_path = Path(record['file'])
        if not key_path.is_absolute():
            key_path = path.parent / key_path
        key_path = Path(os.path.abspath(key_path))
        require(not bundled or key_path == _BUNDLE / (module + '-' + role + '.pem'), 'bundled_key_path_invalid')
        require(hashlib.sha256(_read(key_path, private=not bundled)).hexdigest() == record['sha256'], 'signing_key_hash_mismatch')
        require(hashlib.sha256(_read(path, private=not bundled)).hexdigest() == pin, 'signing_configuration_changed')
        return SigningKeyReference(path, pin, module, role, key_path, record['sha256'])
    except SigningKeyError:
        raise
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        raise SigningKeyError('signing_configuration_invalid') from None


class _DER:
    def __init__(self, raw):
        self.raw, self.offset = raw, 0

    def take(self, tag):
        require(self.offset + 2 <= len(self.raw) and self.raw[self.offset] == tag, 'signing_key_der_invalid')
        self.offset += 1
        size = self.raw[self.offset]; self.offset += 1
        if size & 0x80:
            count = size & 0x7f
            require(1 <= count <= 2 and self.offset + count <= len(self.raw), 'signing_key_der_invalid')
            encoded = self.raw[self.offset:self.offset + count]; self.offset += count
            require(encoded[0] != 0, 'signing_key_der_invalid')
            size = int.from_bytes(encoded, 'big')
            require(size >= 128 and (count == 1 or size >= 256), 'signing_key_der_invalid')
        require(self.offset + size <= len(self.raw), 'signing_key_der_invalid')
        result = self.raw[self.offset:self.offset + size]; self.offset += size
        return result

    def integer(self):
        raw = self.take(2)
        require(0 < len(raw) <= 129 and raw[0] < 128
                and (len(raw) == 1 or raw[0] != 0 or raw[1] >= 128), 'signing_key_integer_invalid')
        return int.from_bytes(raw, 'big')

    def end(self):
        require(self.offset == len(self.raw), 'signing_key_der_trailing_bytes')


def _parse_pem(raw):
    match = re.fullmatch(rb'\s*-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY)-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END \1-----\s*', raw)
    require(match is not None, 'signing_key_requires_unencrypted_rsa_pem')
    der = base64.b64decode(re.sub(rb'\s', b'', match[2]), validate=True)
    outer = _DER(der); body = _DER(outer.take(0x30)); outer.end()
    if match[1] == b'PRIVATE KEY':
        require(body.integer() == 0, 'signing_key_version_invalid')
        # rsaEncryption OID and explicit NULL; reject other algorithms.
        require(body.take(0x30) == bytes.fromhex('06092a864886f70d0101010500'), 'signing_key_algorithm_invalid')
        inner = _DER(body.take(4)); body.end()
        body = _DER(inner.take(0x30)); inner.end()
    require(body.integer() == 0, 'signing_key_version_invalid')
    values = {name: body.integer() for name in ('n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi')}
    body.end()
    try:
        return RSA1024PrivateKey.from_components(**values)
    finally:
        values.clear()


def load_key(reference: SigningKeyReference, role: str) -> RSA1024PrivateKey:
    """Disable core dumps, repeat all pins and validate RSA geometry in RAM."""
    try:
        require(type(reference) is SigningKeyReference and reference.role == role,
                'signing_reference_role_invalid')
        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
        require(resource.getrlimit(resource.RLIMIT_CORE)[0] == 0, 'core_dump_disable_failed')
        checked = validate_key_reference(reference.configuration, reference.configuration_sha256,
                                         module=reference.module, role=role)
        require(checked == reference, 'signing_reference_changed')
        raw = _read(reference.key_path, private=not _bundled(reference.configuration, reference.configuration_sha256, reference.module))
        require(hashlib.sha256(raw).hexdigest() == reference.key_sha256, 'signing_key_hash_mismatch')
        key = _parse_pem(raw)
        require(validate_key_reference(reference.configuration, reference.configuration_sha256,
                                       module=reference.module, role=role) == reference, 'signing_reference_changed')
        return key
    except SigningKeyError:
        raise
    except (OSError, ValueError, TypeError, RecursionError):
        raise SigningKeyError('signing_key_load_failed') from None
    finally:
        raw = key = None
