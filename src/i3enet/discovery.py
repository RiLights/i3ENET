"""Offline discovery datagram parsing with private, unverified identity bytes.

No socket access exists here. Identity markers are source-confirmed layouts,
not evidence about the equipment fitted to a particular car.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .hsfz import Control, HSFZError, decode_frame


DISCOVERY_PORT = 6811
DISCOVERY_REQUEST = bytes.fromhex("000000000011")
DEFAULT_MAX_DISCOVERY_BODY_LENGTH = 4096  # Project resource limit, not a protocol maximum.


class DiscoveryError(ValueError):
    """Invalid discovery reply; raw input should be retained privately by its caller."""


@dataclass(frozen=True, slots=True)
class DiscoveryResponse:
    raw: bytes = field(repr=False)
    identification: bytes = field(repr=False)
    layout: str
    vin_candidate: str | None = field(repr=False)
    mac_candidate: str | None = field(repr=False)
    warnings: tuple[str, ...]
    decoder_evidence_status: str = "SOURCE_CONFIRMED"
    response_evidence_status: str = "UNVERIFIED"
    vehicle_verification: str = "UNVERIFIED"

    @property
    def masked_vin(self) -> str | None:
        if self.vin_candidate is None:
            return None
        return "*" * 13 + self.vin_candidate[-4:]


def _marker_candidate(body: bytes, marker: bytes, size: int, alphabet: bytes) -> tuple[str | None, str | None]:
    count = body.count(marker)
    name = marker.decode("ascii")
    if not count:
        return None, f"{name} marker absent; field unknown"
    if count != 1:
        raise DiscoveryError(f"duplicate {name} markers make the identity ambiguous")
    start = body.index(marker) + len(marker)
    end = start + size
    if end > len(body):
        raise DiscoveryError(f"{name} marker has a truncated {size}-byte value")
    value = body[start:end]
    if any(byte not in alphabet for byte in value):
        raise DiscoveryError(f"{name} value does not match the supported ASCII candidate shape")
    return value.decode("ascii"), None


def parse_discovery_response(
    raw: bytes, *, max_body_length: int = DEFAULT_MAX_DISCOVERY_BODY_LENGTH
) -> DiscoveryResponse:
    """Validate one datagram; preserve unknown layouts without guessed offsets.

    Recognized markers yield candidates only. Vehicle identity still needs
    local confirmation, and this reply cannot establish the head-unit family.
    """
    try:
        frame = decode_frame(raw, max_body_length=max_body_length)
    except HSFZError as exc:
        raise DiscoveryError(str(exc)) from exc
    if frame.control is not Control.VEHICLE_IDENTIFICATION:
        raise DiscoveryError("discovery reply must use vehicle-identification control 0x0011")
    body = frame.payload
    if not body:
        raise DiscoveryError("zero-length identification is a discovery request, not a reply")
    warnings = ["identity candidates are unverified on this vehicle; head-unit type remains unknown"]
    if not body.startswith(b"DIAGADR10"):
        warnings.append("unrecognized identification layout; bytes preserved without field decoding")
        return DiscoveryResponse(raw, body, "unknown", None, None, tuple(warnings))
    if body.count(b"DIAGADR10") != 1:
        raise DiscoveryError("duplicate identification layout markers are ambiguous")
    # A marker embedded within another candidate is not an independent field.
    ranges = []
    for marker, size in ((b"BMWVIN", 17), (b"BMWMAC", 12)):
        if body.count(marker) == 1:
            start = body.index(marker)
            ranges.append((start, start + len(marker) + size))
    if len(ranges) == 2:
        first, second = sorted(ranges)
        if second[0] < first[1]:
            raise DiscoveryError("overlapping identity markers are ambiguous")
    vin, warning = _marker_candidate(
        body, b"BMWVIN", 17, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    )
    if warning:
        warnings.append(warning)
    mac, warning = _marker_candidate(body, b"BMWMAC", 12, b"0123456789abcdefABCDEF")
    if warning:
        warnings.append(warning)
    return DiscoveryResponse(raw, body, "marker_identity", vin, mac, tuple(warnings))
