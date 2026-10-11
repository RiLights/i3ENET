"""Small offline UDS codecs. These functions cannot transmit messages.

No BMW-specific DID decoding is implemented. See docs/protocol.md.
"""

from dataclasses import dataclass, field


READ_DATA_BY_IDENTIFIER = 0x22
POSITIVE_READ_DATA_BY_IDENTIFIER = 0x62
NEGATIVE_RESPONSE = 0x7F
RESPONSE_PENDING = 0x78


class UDSError(ValueError):
    """Base error for an invalid or unexpected UDS response."""


class MalformedResponseError(UDSError):
    """The response cannot represent the supported service."""


class UnexpectedResponseError(UDSError):
    """The response does not match the outstanding request."""


@dataclass(frozen=True, slots=True)
class ReadDataByIdentifierRequest:
    """One DID only; construction is not permission to send it."""

    did: int

    def __post_init__(self) -> None:
        if type(self.did) is not int or not 0 <= self.did <= 0xFFFF:
            raise ValueError("DID must be an integer in 0..65535")

    @property
    def payload(self) -> bytes:
        return bytes((READ_DATA_BY_IDENTIFIER,)) + self.did.to_bytes(2, "big")


@dataclass(frozen=True, slots=True)
class ReadDataByIdentifierResponse:
    did: int
    value: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class NegativeResponse:
    service: int
    code: int

    @property
    def pending(self) -> bool:
        return self.code == RESPONSE_PENDING


def parse_read_data_response(
    payload: bytes,
    request: ReadDataByIdentifierRequest,
    *,
    expected_value_length: int | None = None,
) -> ReadDataByIdentifierResponse | NegativeResponse:
    """Validate SID/DID echoes and preserve the single DID's opaque value.

    This does not infer a coding layout or a VIN format. A caller with a known
    offline fixture length can require that length; otherwise value bytes stay
    opaque. There is no padding repair, fallback service, or automatic retry.
    """
    if type(payload) is not bytes:
        raise TypeError("UDS payload must be immutable bytes")
    if type(request) is not ReadDataByIdentifierRequest:
        raise TypeError("request must be a ReadDataByIdentifierRequest")
    if expected_value_length is not None and (
        type(expected_value_length) is not int or expected_value_length < 1
    ):
        raise ValueError("expected value length must be a positive integer")
    if not payload:
        raise MalformedResponseError("empty UDS response")
    if payload[0] == NEGATIVE_RESPONSE:
        if len(payload) != 3:
            raise MalformedResponseError("negative response must contain exactly 3 bytes")
        if payload[1] != READ_DATA_BY_IDENTIFIER:
            raise UnexpectedResponseError("negative response service does not match request")
        if payload[2] == 0:
            raise MalformedResponseError("a negative response cannot use positive NRC 0x00")
        return NegativeResponse(payload[1], payload[2])
    if payload[0] != POSITIVE_READ_DATA_BY_IDENTIFIER:
        raise UnexpectedResponseError("positive response service does not match request")
    if len(payload) < 4:
        raise MalformedResponseError("RDBI response requires SID, DID, and value bytes")
    did = int.from_bytes(payload[1:3], "big")
    if did != request.did:
        raise UnexpectedResponseError("positive response DID does not match request")
    value = payload[3:]
    if expected_value_length is not None and len(value) != expected_value_length:
        raise MalformedResponseError("RDBI value length does not match offline fixture")
    return ReadDataByIdentifierResponse(did, value)
