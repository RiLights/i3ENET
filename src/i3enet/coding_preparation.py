"""Offline bounded field edits for the verified head-unit profile; no transport.

Descriptor geometry comes from authenticated CAFD 00000DED/003.015.041.
Private arrays never appear in repr or the public summary. An imported backup
is a preserved reference, not a current ECU snapshot or a live permission.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
from .coding_contract import software_contract, contract, HU

CAFD, BTLD, TARGET, GROUP_LENGTHS = HU.cafd, HU.btld, HU.target, HU.groups
SIGNING_INPUT_LENGTH = HU.signing_bytes


class CodingPreparationError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True, repr=False)
class CodingEdit:
    """One explicit byte region; values are encoded bits, not inferred meanings."""
    group: int
    offset: int
    value: bytes = field(repr=False)
    mask: bytes = field(repr=False)
    expected: bytes | None = field(default=None, repr=False)
    module: str = "HU"
    expected_masked: bool = False

    def __post_init__(self):
        try:
            lengths = dict(contract(self.module).groups[:-2])
        except ValueError:
            raise CodingPreparationError('invalid_coding_edit_module') from None
        if (type(self.group) is not int or self.group not in lengths
                or type(self.offset) is not int or self.offset < 0
                or type(self.value) is not bytes or not 1 <= len(self.value) <= 32
                or self.offset + len(self.value) > lengths[self.group]
                or type(self.mask) is not bytes or len(self.mask) != len(self.value)
                or not any(self.mask) or any(v & ~m for v, m in zip(self.value, self.mask))
                or (self.expected is not None and
                    (type(self.expected) is not bytes or len(self.expected) != len(self.value)))
                or type(self.expected_masked) is not bool
                or (self.expected_masked and self.expected is not None and
                    any(v & ~m for v,m in zip(self.expected, self.mask)))):
            raise CodingPreparationError('invalid_coding_edit')

    def __repr__(self):
        return f'CodingEdit(group=0x{self.group:04X}, offset={self.offset}, bytes={len(self.value)}, values=<private>)'

    def summary(self):
        result = {'group': f'{self.group:04X}', 'offset': self.offset,
                'value': self.value.hex().upper(), 'mask': self.mask.hex().upper(),
                'expected': None if self.expected is None else self.expected.hex().upper()}
        if self.expected_masked: result['expected_scope'] = 'masked_selected_bits'
        return result

    def data_groups(self, snapshot):
        if type(snapshot) is not CodingSnapshot:
            raise CodingPreparationError('invalid_snapshot_type')
        CodingSnapshot.__post_init__(snapshot); self.__post_init__()
        if (snapshot.cafd, snapshot.btld) != (contract(self.module).cafd, contract(self.module).btld):
            raise CodingPreparationError('coding_edit_software_mismatch')
        raw = dict(snapshot.groups)[self.group]
        old = raw[self.offset:self.offset + len(self.value)]
        compared = bytes(b & m for b,m in zip(old,self.mask)) if self.expected_masked else old
        if self.expected is not None and not hmac.compare_digest(compared, self.expected):
            raise CodingPreparationError('coding_expected_value_mismatch')
        new = bytes((b & (0xFF ^ m)) | v for b, m, v in zip(old, self.mask, self.value))
        if old == new:
            raise CodingPreparationError('coding_value_already_set')
        changed = raw[:self.offset] + new + raw[self.offset + len(new):]
        return tuple((a, changed if a == self.group else value) for a, value in snapshot.groups[:-1])

    def signing_input(self, snapshot):
        return b''.join(raw for _, raw in self.data_groups(snapshot))


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, repr=False)
class CodingSnapshot:
    """Ordered original bytes with deliberately limited provenance labels."""
    groups: tuple[tuple[int, bytes], ...] = field(repr=False)
    provenance: str = "unverified_import"
    cafd: str = CAFD
    btld: str = BTLD

    def __post_init__(self) -> None:
        try:
            spec = software_contract(self.cafd, self.btld)
        except ValueError:
            raise CodingPreparationError("unsupported_software_tuple")
        if self.provenance not in ("unverified_import", "preserved_backup", "synthetic_fixture"):
            raise CodingPreparationError("unsupported_provenance")
        if type(self.groups) is not tuple or len(self.groups) != len(spec.groups):
            raise CodingPreparationError("incomplete_group_set")
        for item, (address, length) in zip(self.groups, spec.groups):
            if (type(item) is not tuple or len(item) != 2 or
                    type(item[0]) is not int or item[0] != address or
                    type(item[1]) is not bytes or len(item[1]) != length):
                raise CodingPreparationError("group_order_type_or_length")

    def __repr__(self) -> str:
        return f"CodingSnapshot(cafd={self.cafd!r}, group_count={len(self.groups)}, values=<private>)"

    @property
    def signing_input(self) -> bytes:
        return b"".join(raw for _, raw in self.groups[:-1])

    @property
    def signature(self) -> bytes:
        return self.groups[-1][1]

    def summary(self) -> dict[str, object]:
        return {
            "cafd": self.cafd, "btld": self.btld, "target_address": f"0x{software_contract(self.cafd, self.btld).target:02X}",
            "provenance": self.provenance, "group_count": len(self.groups),
            "groups": [{"address": f"0x{a:04X}", "byte_length": len(raw), "sha256": _hash(raw)}
                       for a, raw in self.groups],
            "signing_input_byte_length": len(self.signing_input),
            "signing_input_sha256": _hash(self.signing_input),
            "tlid_replacement": False,
            "current_complete_ecu_snapshot": False,
            "live_ready": False,
        }


@dataclass(frozen=True, repr=False)
class PreparedCoding:
    original: CodingSnapshot = field(repr=False)
    candidate: CodingSnapshot = field(repr=False)
    _verification_key: object = field(repr=False)
    edit: CodingEdit = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.original) is not CodingSnapshot or type(self.candidate) is not CodingSnapshot:
            raise CodingPreparationError("invalid_snapshot_type")
        CodingSnapshot.__post_init__(self.original)
        CodingSnapshot.__post_init__(self.candidate)
        _require_only_selected_change(self.original, self.candidate, self.edit)
        from .coding_signature import RSA1024PublicKey, verify_coding1
        if type(self._verification_key) is not RSA1024PublicKey:
            raise CodingPreparationError("invalid_verification_key")
        if not verify_coding1(self.original.signing_input, self.original.signature, self._verification_key, module=self.edit.module):
            raise CodingPreparationError("original_signature_mismatch")
        if not verify_coding1(self.candidate.signing_input, self.candidate.signature, self._verification_key, module=self.edit.module):
            raise CodingPreparationError("candidate_signature_mismatch")

    def __repr__(self) -> str:
        return f"PreparedCoding(group=0x{self.edit.group:04X}, offset={self.edit.offset}, values=<private>)"

    def summary(self) -> dict[str, object]:
        return {
            "outcome": "offline_candidate_verified",
            "cafd": self.original.cafd, "btld": self.original.btld, "target_address": f"0x{contract(self.edit.module).target:02X}",
            "original": self.original.summary(), "candidate": self.candidate.summary(),
            "logical_change": self.edit.summary(),
            "changed_data_byte_count": sum(b != a for (_, old), (_, new) in
                zip(self.original.groups[:-1], self.candidate.groups[:-1]) for b, a in zip(old, new)),
            "signature_group_regenerated": True,
            "original_signature_verified": True, "candidate_signature_verified": True,
            "effect_verified_on_car": False,
            "tlid_replacement": False, "vehicle_contacted": False,
            "vehicle_bytes_confirmed_sent": 0, "writes_supported": False, "live_ready": False,
        }


def _require_only_selected_change(original: CodingSnapshot, candidate: CodingSnapshot, edit: CodingEdit) -> None:
    if (original.provenance, original.cafd, original.btld) != (candidate.provenance, candidate.cafd, candidate.btld):
        raise CodingPreparationError("provenance_changed")
    if type(edit) is not CodingEdit or candidate.groups[:-1] != edit.data_groups(original):
        raise CodingPreparationError("unexpected_data_diff")
    if original.signature == candidate.signature:
        raise CodingPreparationError("signature_not_regenerated")


def prepare_coding(snapshot: CodingSnapshot, key: object, edit: CodingEdit) -> PreparedCoding:
    """Verify originals, apply exactly the selected bits and sign all data groups."""
    from .coding_signature import RSA1024PrivateKey, sign_coding1, verify_coding1
    if type(snapshot) is not CodingSnapshot or type(key) is not RSA1024PrivateKey:
        raise CodingPreparationError("invalid_snapshot_or_key_type")
    if type(edit) is not CodingEdit:
        raise CodingPreparationError('invalid_coding_edit')
    if not verify_coding1(snapshot.signing_input, snapshot.signature, key.public_key, module=edit.module):
        raise CodingPreparationError("original_signature_mismatch")
    data = edit.data_groups(snapshot)
    changed_input = b''.join(raw for _, raw in data)
    signature = sign_coding1(changed_input, key, module=edit.module)
    if not verify_coding1(changed_input, signature, key.public_key, module=edit.module):
        raise CodingPreparationError("candidate_signature_mismatch")
    candidate = CodingSnapshot(data + ((snapshot.groups[-1][0], signature),), snapshot.provenance, snapshot.cafd, snapshot.btld)
    return PreparedCoding(snapshot, candidate, key.public_key, edit)


def verify_coding_readback(prepared: PreparedCoding, readback: CodingSnapshot, *,
                            expected_cps: bytes, returned_cps: bytes) -> dict[str, object]:
    """Check caller-supplied complete bytes using the prepared public key.

    This performs no acquisition or key loading. Equality and independent
    returned-signature verification establish byte-level consistency only,
    without acquisition freshness, activation, persistence or recovery claims.
    """
    from .coding_signature import verify_coding1
    if type(prepared) is not PreparedCoding or type(readback) is not CodingSnapshot:
        raise CodingPreparationError("invalid_readback_type")
    if any(type(value) is not bytes or len(value) != 7 for value in (expected_cps, returned_cps)):
        raise CodingPreparationError("readback_cps_shape")
    if (readback.cafd, readback.btld) != (prepared.candidate.cafd, prepared.candidate.btld):
        raise CodingPreparationError("readback_software_mismatch")
    if any(address != expected_address or not hmac.compare_digest(value, expected_value)
           for (address, value), (expected_address, expected_value)
           in zip(readback.groups, prepared.candidate.groups)):
        raise CodingPreparationError("readback_candidate_mismatch")
    if not verify_coding1(readback.signing_input, readback.signature, prepared._verification_key, module=prepared.edit.module):
        raise CodingPreparationError("readback_signature_mismatch")
    if not hmac.compare_digest(returned_cps, expected_cps):
        raise CodingPreparationError("readback_cps_mismatch")
    return {"outcome": "offline_readback_verified", "complete_group_count": len(readback.groups),
            "all_groups_match_candidate": True, "returned_signature_verified": True,
            "cps_readback_matches": True, "currentness_established": False,
            "activation_verified": False, "persistence_verified": False,
            "recovery_established": False, "effect_verified_on_car": False,
            "vehicle_traffic_performed": False, "writes_supported": False, "live_ready": False}
