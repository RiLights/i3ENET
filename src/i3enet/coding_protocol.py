"""Strict offline UDS codecs for the selected coding reference.

These functions do not open a socket or confer send permission. Session reply
layout must be selected explicitly: the supplied ODX declares two variants.
Size caps below are project resource choices, not measured ECU capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hmac

from .coding_contract import contract

SESSION_SEQUENCE = (0x01, 0x03, 0x41)
MAX_SESSION_PARAMETERS = 32
MAX_SEED_BYTES = 4096


class CodingProtocolError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _bytes(value: bytes) -> None:
    if type(value) is not bytes:
        raise CodingProtocolError("immutable_bytes_required")


def _group(address: int, module: str) -> int:
    lengths = dict(contract(module).groups)
    if type(address) is not int or address not in lengths:
        raise CodingProtocolError("unsupported_group")
    return lengths[address]


def session_request(subfunction: int) -> bytes:
    if type(subfunction) is not int or subfunction not in SESSION_SEQUENCE:
        raise CodingProtocolError("unsupported_session")
    return bytes((0x10, subfunction))


@dataclass(frozen=True)
class SessionResponse:
    subfunction: int
    layout: str
    parameters: bytes = field(repr=False)
    p2_max_milliseconds: int | None = None
    p2_star_milliseconds: int | None = None


def parse_session_response(pdu: bytes, subfunction: int, *, layout: str) -> SessionResponse:
    expected = session_request(subfunction)
    _bytes(pdu)
    if len(pdu) < 2 or pdu[:2] != bytes((0x50, expected[1])):
        raise CodingProtocolError("session_response_mismatch")
    if layout == "p2_timing":
        if len(pdu) != 6:
            raise CodingProtocolError("session_timing_length")
        return SessionResponse(subfunction, layout, pdu[2:],
                               int.from_bytes(pdu[2:4], "big"), int.from_bytes(pdu[4:6], "big") * 10)
    if layout == "opaque_parameters":
        if len(pdu) > 2 + MAX_SESSION_PARAMETERS:
            raise CodingProtocolError("session_parameter_limit")
        return SessionResponse(subfunction, layout, pdu[2:])
    raise CodingProtocolError("session_layout_not_selected")


def seed_request() -> bytes:
    return b"\x27\x01\xff\xff\xff\xff"


@dataclass(frozen=True)
class SeedResponse:
    seed: bytes = field(repr=False)


def parse_seed_response(pdu: bytes) -> SeedResponse:
    _bytes(pdu)
    if len(pdu) < 2 or pdu[:2] != b"\x67\x01":
        raise CodingProtocolError("seed_response_mismatch")
    seed = pdu[2:]
    if not 1 <= len(seed) <= MAX_SEED_BYTES:
        raise CodingProtocolError("seed_length_requires_review")
    if not any(seed):
        raise CodingProtocolError("zero_seed_requires_review")
    return SeedResponse(seed)


def key_request(envelope: bytes) -> bytes:
    _bytes(envelope)
    if len(envelope) != 132 or envelope[:4] != (32).to_bytes(4, "big"):
        raise CodingProtocolError("authentication_envelope_shape")
    return b"\x27\x02" + envelope


def parse_key_response(pdu: bytes) -> None:
    _bytes(pdu)
    if pdu != b"\x67\x02":
        raise CodingProtocolError("key_response_mismatch")


def group_write_request(address: int, value: bytes, *, module: str = "HU") -> bytes:
    length = _group(address, module); _bytes(value)
    if len(value) != length:
        raise CodingProtocolError("group_value_length")
    return b"\x2e" + address.to_bytes(2, "big") + value


def parse_group_write_response(pdu: bytes, address: int, *, module: str = "HU") -> None:
    _group(address, module); _bytes(pdu)
    if pdu != b"\x6e" + address.to_bytes(2, "big"):
        raise CodingProtocolError("group_write_response_mismatch")


def group_read_request(address: int, *, module: str = "HU") -> bytes:
    _group(address, module)
    return b"\x22" + address.to_bytes(2, "big")


def parse_group_read_response(pdu: bytes, address: int, *, module: str = "HU") -> bytes:
    length = _group(address, module); _bytes(pdu)
    if len(pdu) != 3 + length or pdu[:3] != b"\x62" + address.to_bytes(2, "big"):
        raise CodingProtocolError("group_read_response_mismatch")
    return pdu[3:]


def signature_check_request() -> bytes:
    return b"\x31\x01\x0f\x01"


def parse_signature_check_response(pdu: bytes) -> bool:
    _bytes(pdu)
    if len(pdu) != 5 or pdu[:4] != b"\x71\x01\x0f\x01" or pdu[4] not in (0, 1):
        raise CodingProtocolError("signature_check_response_mismatch")
    return pdu[4] == 0


def _cps(value: bytes) -> None:
    _bytes(value)
    if len(value) != 7:
        raise CodingProtocolError("cps_value_length")


def cps_write_request(value: bytes) -> bytes:
    _cps(value)
    return b"\x2e\x37\xfe" + value


def parse_cps_write_response(pdu: bytes) -> None:
    _bytes(pdu)
    if pdu != b"\x6e\x37\xfe":
        raise CodingProtocolError("cps_write_response_mismatch")


def cps_read_request() -> bytes:
    return b"\x22\x37\xfe"


def parse_cps_read_response(pdu: bytes, expected: bytes) -> None:
    _cps(expected); _bytes(pdu)
    if len(pdu) != 10 or pdu[:3] != b"\x62\x37\xfe":
        raise CodingProtocolError("cps_read_response_mismatch")
    if not hmac.compare_digest(pdu[3:], expected):
        raise CodingProtocolError("cps_readback_mismatch")


def reset_request() -> bytes:
    return b"\x11\x01"


def parse_reset_response(pdu: bytes) -> None:
    _bytes(pdu)
    if pdu != b"\x51\x01":
        raise CodingProtocolError("reset_response_mismatch")


def negative_response(pdu: bytes, expected_service: int) -> int:
    """Return only a correlated NRC. 0x78 waits; it never requests a resend."""
    _bytes(pdu)
    if type(expected_service) is not int or expected_service not in (0x10, 0x11, 0x22, 0x27, 0x2E, 0x31):
        raise CodingProtocolError("unsupported_response_service")
    if len(pdu) != 3 or pdu[:2] != bytes((0x7F, expected_service)):
        raise CodingProtocolError("negative_response_mismatch")
    return pdu[2]


@dataclass(frozen=True)
class PingResponse:
    layout: str
    session: int
    state: int
    proves_coding_persistence: bool = field(default=False, init=False)


def ping_request(*, layout: str) -> bytes:
    if layout == "f186_state":
        return b"\x22\xf1\x86"
    raise CodingProtocolError("ping_layout_not_selected")


def parse_ping_response(pdu: bytes, *, layout: str) -> PingResponse:
    request = ping_request(layout=layout); _bytes(pdu)
    if len(pdu) != 5 or pdu[:3] != b"\x62" + request[1:]:
        raise CodingProtocolError("ping_response_mismatch")
    session = pdu[3]
    # Known fixed-width mux cases only; source fallback EOP stays unselected.
    if session not in (0x01, 0x02, 0x03, 0x41, 0x43):
        raise CodingProtocolError("ping_session_requires_review")
    # The selected generic mux declares coding state 00 reserved and 03..FF
    # not valid. Other sessions have different state tables; do not impose
    # this coding-only rule on their opaque observations.
    if session == 0x41 and pdu[4] not in (0x01, 0x02):
        raise CodingProtocolError("ping_coding_state_requires_review")
    return PingResponse(layout, session, pdu[4])
