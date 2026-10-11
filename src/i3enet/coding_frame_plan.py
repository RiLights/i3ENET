"""Pure candidate-bound frames for a proposed head-unit field transaction.

This is neither a sender nor a state machine. Frame equality cannot establish
live permission, fresh originals/authentication, accepted responses or suitable
power/recovery. No socket, provider, file, wait or reconnect operation is here.
The fixed accounting excludes any readiness waits; activation bounds remain
unresolved. Private values never appear in repr or the public summary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import re

from . import coding_protocol as p
from .coding_preparation import CodingSnapshot, PreparedCoding
from .coding_contract import contract, transaction_stages
from .coding_signature import RSA1024PublicKey, SignatureError, verify_security_access
from .hsfz import Control, HSFZFrame, encode_frame


class CodingFramePlanError(ValueError):
    """A fixed reason without VIN, candidate, seed or signature bytes."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _frame(pdu: bytes, *, target: int = 0x63) -> bytes:
    return encode_frame(HSFZFrame(Control.DIAGNOSTIC, bytes((0xF4, target)) + pdu),
                        max_body_length=4096)


@dataclass(frozen=True, slots=True, repr=False, init=False)
class CodingFramePlan:
    """Exact offline frames, with a deliberately unresolved AS response slot.

    Indices describe order only; this object never observes completion or
    permits an outbound operation. The sender must enforce the actual
    response/proof/authentication/authorization gates separately.
    """

    _coding: tuple[bytes | None, ...] = field(repr=False)
    _verification: tuple[bytes, ...] = field(repr=False)
    _provenance: str
    module: str

    @property
    def key_index(self): return transaction_stages(self.module)[0].index('security_key')

    @property
    def coding_count(self): return len(self._coding)

    @property
    def frame_count(self): return len(self._coding) + len(self._verification)

    def __init__(self, prepared: PreparedCoding, vin: str):
        if (type(prepared) is not PreparedCoding
                or type(prepared.original) is not CodingSnapshot
                or type(prepared.candidate) is not CodingSnapshot):
            raise CodingFramePlanError("verified_preparation_required")
        # Do not replace the preparation's actual signature checks with a flag.
        CodingSnapshot.__post_init__(prepared.original)
        CodingSnapshot.__post_init__(prepared.candidate)
        PreparedCoding.__post_init__(prepared)
        module = prepared.edit.module
        spec = contract(module)
        def frame(pdu, *, target=None): return _frame(pdu, target=spec.target if target is None else target)
        if type(vin) is not str or re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin) is None:
            raise CodingFramePlanError("complete_vin_required_for_cps")
        cps = vin[-7:].encode("ascii")
        reads = tuple(frame(p.group_read_request(address, module=module))
                      for address, _ in prepared.original.groups)
        coding = (
            frame(b"\x22\xf1\x90", target=0x10), frame(b"\x22\xf1\x01"), *reads,
            *((frame(p.cps_read_request()),) if module != 'HU' else ()),
            frame(p.session_request(0x03)), frame(p.session_request(0x41)),
            frame(p.seed_request()), None,
            *(frame(p.group_write_request(address, raw, module=module))
              for address, raw in prepared.candidate.groups),
            frame(p.signature_check_request()), frame(p.cps_write_request(cps)),
            frame(p.cps_read_request()), frame(p.reset_request() if module == "HU" else p.session_request(0x01)),
        )
        verification = (
            frame(b"\x22\xf1\x90", target=0x10), frame(b"\x22\xf1\x01"),
            frame(p.ping_request(layout="f186_state")), *reads,
            frame(p.cps_read_request()),
        )
        object.__setattr__(self, "_coding", coding)
        object.__setattr__(self, "_verification", verification)
        object.__setattr__(self, "_provenance", prepared.original.provenance)
        object.__setattr__(self, "module", module)

    def __repr__(self) -> str:
        return f"CodingFramePlan(module={self.module}, fixed_frames={self.frame_count}, values=<private>, live_ready=False)"

    def bind_as_response(self, seed: bytes, envelope: bytes,
                         public_key: RSA1024PublicKey) -> CodingFramePlan:
        """Bind supplied AS bytes after public verification; acquire nothing.

        This cannot prove AS key role, challenge freshness or that the seed was
        received on the writing connection. Saved seed replay stays outside
        live authority even when its signature is mathematically consistent.
        """
        slot = self.key_index
        if self._coding[slot] is not None:
            raise CodingFramePlanError("offline_as_slot_already_bound")
        if type(seed) is not bytes or len(seed) != 8 or not any(seed):
            raise CodingFramePlanError("reviewed_eight_byte_nonzero_seed_required")
        if type(public_key) is not RSA1024PublicKey:
            raise CodingFramePlanError("as_public_key_required")
        try:
            valid = verify_security_access(seed, envelope, public_key, module=self.module)
        except (SignatureError, TypeError, ValueError):
            valid = False
        if valid is not True:
            raise CodingFramePlanError("as_signature_consistency_failed")
        frame = _frame(p.key_request(envelope), target=contract(self.module).target)
        result = object.__new__(type(self))
        object.__setattr__(result, "_coding", self._coding[:slot] + (frame,) + self._coding[slot + 1:])
        object.__setattr__(result, "_verification", self._verification)
        object.__setattr__(result, "_provenance", self._provenance)
        object.__setattr__(result, "module", self.module)
        return result

    def expected_frame(self, phase: str, index: int) -> bytes:
        """Return one exact private frame, without observing or authorizing it."""
        if type(phase) is not str or phase not in ("coding", "verification"):
            raise CodingFramePlanError("offline_frame_phase_invalid")
        frames = self._coding if phase == "coding" else self._verification
        if type(index) is not int or not 0 <= index < len(frames):
            raise CodingFramePlanError("offline_frame_index_invalid")
        frame = frames[index]
        if frame is None:
            raise CodingFramePlanError("offline_as_response_unresolved")
        return frame

    def validate_frame(self, phase: str, index: int, frame: bytes) -> None:
        """Check exact equality only; never replace a live final-send policy."""
        expected = self.expected_frame(phase, index)
        if type(frame) is not bytes or not hmac.compare_digest(frame, expected):
            raise CodingFramePlanError("offline_frame_not_exact")

    def summary(self) -> dict[str, object]:
        bound = self._coding[self.key_index] is not None
        return {
            "scope": "pure_offline_frame_contract", "provenance": self._provenance,
            "coding_fixed_frame_count": len(self._coding),
            "coding_nominal_application_bytes": sum(len(raw) if raw is not None else 142
                                                     for raw in self._coding),
            "verification_fixed_frame_count": len(self._verification),
            "verification_nominal_application_bytes": sum(map(len, self._verification)),
            "total_fixed_frame_count": len(self._coding) + len(self._verification),
            "total_nominal_application_bytes": sum(len(raw) if raw is not None else 142
                                                    for raw in self._coding)
                                               + sum(map(len, self._verification)),
            "as_response_bound": bound, "as_signature_consistency_checked": bound,
            "authentication_freshness_established": False,
            "as_key_role_established": False, "same_writing_connection_established": False,
            "readiness_waits_excluded": True, "activation_bounds_established": False,
            "response_acceptance_established": False, "returned_signature_check_required": True,
            "complete_candidate_and_cps_readback_required": True,
            "original_currentness_established": False, "activation_verified": False,
            "persistence_verified": False, "recovery_established": False,
            "vehicle_traffic_performed": False, "writes_supported": False, "live_ready": False,
        }
