"""Offline HSFZ framing; this module neither imports nor opens sockets.

Protocol evidence and deliberate restrictions are recorded in
``docs/protocol.md``. A decoded frame is never permission to send it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import struct


HEADER = struct.Struct(">IH")
HEADER_SIZE = HEADER.size
DEFAULT_MAX_BODY_LENGTH = 64 * 1024  # Local resource limit, not a BMW maximum.
DIAGNOSTIC_PORT = 6801
MAX_ACK_DIAGNOSTIC_BYTES = 5  # 13-byte source cap minus header and addresses.


def expected_ack_echo(request_uds: bytes) -> bytes:
    """Return the exact capped echo used by the selected authentication gate.

    Short requests retain their full UDS echo; longer requests echo five bytes.
    This pure helper grants no send permission or arbitrary-prefix acceptance.
    """
    if type(request_uds) is not bytes or not request_uds:
        raise ValueError("ACK correlation requires a nonempty immutable UDS request")
    return request_uds[:MAX_ACK_DIAGNOSTIC_BYTES]


class Control(IntEnum):
    DIAGNOSTIC = 0x0001
    ACK = 0x0002
    TERMINAL15 = 0x0010
    VEHICLE_IDENTIFICATION = 0x0011
    ALIVE_CHECK = 0x0012
    STATUS_DATA_INQUIRY = 0x0013
    INCORRECT_TESTER_ADDRESS = 0x0040
    INCORRECT_CONTROL_WORD = 0x0041
    INCORRECT_FORMAT = 0x0042
    INCORRECT_DESTINATION_ADDRESS = 0x0043
    MESSAGE_TOO_LARGE = 0x0044
    DIAGNOSTIC_APPLICATION_NOT_READY = 0x0045
    OUT_OF_MEMORY = 0x00FF


class HSFZError(ValueError):
    """An unsupported or malformed HSFZ message."""


class UnknownControlError(HSFZError):
    """A control word absent from the inspected source register."""


class MalformedFrameError(HSFZError):
    """A frame violates an evidenced or deliberately restricted layout."""


class TruncatedFrameError(HSFZError):
    """End of input occurred inside a header or declared body."""


class FrameTooLargeError(HSFZError):
    """A declared body exceeds the configured offline resource limit."""


class ParserStateError(HSFZError):
    """A finished or failed parser cannot consume more input."""


def _control(value: Control | int) -> Control:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("control must be an integer control word")
    try:
        return Control(value)
    except ValueError as exc:
        raise UnknownControlError(f"unknown HSFZ control word: {value:#x}") from exc


def _limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("body limit must be an integer")
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("body limit must fit the unsigned 32-bit length field")
    return value


def _check_layout(control: Control, length: int) -> None:
    if control is Control.DIAGNOSTIC and length < 3:
        raise MalformedFrameError("diagnostic body needs two addresses and UDS data")
    if control is Control.ACK and length < 2:
        raise MalformedFrameError("ACK body needs the echoed source/target addresses")
    if control is Control.INCORRECT_TESTER_ADDRESS and length != 2:
        raise MalformedFrameError("incorrect-tester body must contain expected/received bytes")
    if control is Control.ALIVE_CHECK and length == 1:
        raise MalformedFrameError("one-byte alive body has no inspected layout")


def _header(data: bytes | bytearray, max_body_length: int) -> tuple[int, Control]:
    length, control_word = HEADER.unpack_from(data)
    control = _control(control_word)
    if length > max_body_length:
        raise FrameTooLargeError(f"HSFZ body length {length} exceeds limit {max_body_length}")
    _check_layout(control, length)
    return length, control


@dataclass(frozen=True, slots=True)
class HSFZFrame:
    """A control word and complete body following the six-byte base header.

    ``payload`` includes source/target bytes for diagnostic and ACK frames.
    Identity, alive, terminal, and other opaque bodies retain their exact bytes.
    """

    control: Control | int
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        control = _control(self.control)
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be immutable bytes")
        _check_layout(control, len(self.payload))
        object.__setattr__(self, "control", control)

    @property
    def source(self) -> int | None:
        return self.payload[0] if self.control in (Control.DIAGNOSTIC, Control.ACK) else None

    @property
    def target(self) -> int | None:
        return self.payload[1] if self.control in (Control.DIAGNOSTIC, Control.ACK) else None

    @property
    def diagnostic_payload(self) -> bytes:
        if self.control not in (Control.DIAGNOSTIC, Control.ACK):
            raise MalformedFrameError("this control has no evidenced diagnostic payload")
        return self.payload[2:]


def encode_frame(frame: HSFZFrame, *, max_body_length: int = DEFAULT_MAX_BODY_LENGTH) -> bytes:
    """Encode offline, without granting any outbound permission."""
    if not isinstance(frame, HSFZFrame):
        raise TypeError("frame must be an HSFZFrame")
    maximum = _limit(max_body_length)
    length = len(frame.payload)
    if length > maximum:
        raise FrameTooLargeError(f"HSFZ body length {length} exceeds limit {maximum}")
    return HEADER.pack(length, frame.control) + frame.payload


def decode_frame(data: bytes, *, max_body_length: int = DEFAULT_MAX_BODY_LENGTH) -> HSFZFrame:
    """Decode exactly one complete frame, rejecting trailing or missing bytes."""
    if not isinstance(data, bytes):
        raise TypeError("frame data must be immutable bytes")
    maximum = _limit(max_body_length)
    if len(data) < HEADER_SIZE:
        raise TruncatedFrameError(f"HSFZ header needs {HEADER_SIZE} bytes; got {len(data)}")
    length, control = _header(data, maximum)
    expected = HEADER_SIZE + length
    if len(data) < expected:
        raise TruncatedFrameError(f"HSFZ frame needs {expected} bytes; got {len(data)}")
    if len(data) != expected:
        raise MalformedFrameError("single HSFZ frame contains trailing bytes")
    return HSFZFrame(control, data[HEADER_SIZE:])


class IncrementalParser:
    """Consume fragmented/coalesced input with at most one bounded retained frame.

    This object consumes bytes only. The transport must impose its own
    deadlines and call ``finish`` when the peer disconnects. A parse failure
    closes the parser; it never searches ahead for a plausible new header.
    """

    def __init__(self, *, max_body_length: int = DEFAULT_MAX_BODY_LENGTH) -> None:
        self.max_body_length = _limit(max_body_length)
        self._buffer = bytearray()
        self._closed = False

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> list[HSFZFrame]:
        if self._closed:
            raise ParserStateError("HSFZ parser is closed")
        if not isinstance(data, bytes):
            raise TypeError("parser input must be immutable bytes")
        frames: list[HSFZFrame] = []
        position = 0
        try:
            while position < len(data):
                if len(self._buffer) < HEADER_SIZE:
                    take = min(HEADER_SIZE - len(self._buffer), len(data) - position)
                    self._buffer.extend(data[position:position + take])
                    position += take
                    if len(self._buffer) < HEADER_SIZE:
                        break
                length, control = _header(self._buffer, self.max_body_length)
                total = HEADER_SIZE + length
                take = min(total - len(self._buffer), len(data) - position)
                self._buffer.extend(data[position:position + take])
                position += take
                if len(self._buffer) < total:
                    break
                frames.append(HSFZFrame(control, bytes(self._buffer[HEADER_SIZE:])))
                self._buffer.clear()
        except HSFZError:
            self._buffer.clear()
            self._closed = True
            raise
        return frames

    def finish(self) -> None:
        """Close input; distinguish a clean end from a truncated final frame."""
        if self._closed:
            raise ParserStateError("HSFZ parser is already closed")
        self._closed = True
        size = len(self._buffer)
        self._buffer.clear()
        if size:
            raise TruncatedFrameError(f"input ended with {size} incomplete HSFZ bytes")
