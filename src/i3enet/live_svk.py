"""Fixed HU/BDC current-SVK reads and their private result.

Requires the original gateway VIN proof. The bounded exchange in live_identity
uses this reader's exact frame, final policy and complete short-ACK rule.
The value remains opaque here; svk independently validates its software tuple."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from .evidence import GatewayVINReadEvidence
from .network import GatewayNetwork, identity_preflight
from .policy import LiveHeadUnitSVKPolicy, LiveBDCSVKPolicy, LiveVSGSVKPolicy
from .live_identity import ReceivedTCPChunk, _read_once, _tcp_read_report


HEAD_UNIT_SVK_REQUEST = bytes.fromhex("000000050001f46322f101")
BDC_SVK_REQUEST = bytes.fromhex("000000050001f44022f101")
VSG_SVK_REQUEST = bytes.fromhex("000000050001f42d22f101")


@dataclass(frozen=True, slots=True)
class ModuleSVKResult:
    outcome: str
    reason: str | None
    tcp_connections_attempted: int
    tcp_connections_opened: int
    tcp_connection_uncertain: bool
    application_frames_attempted: int
    application_frames_sent: int
    vehicle_bytes_confirmed_sent: int
    transmission_uncertain: bool
    request_bytes: bytes = field(repr=False)
    recv_chunks: tuple[ReceivedTCPChunk, ...] = field(repr=False)
    value: bytes | None = field(repr=False)
    ack_count: int
    pending_count: int
    nrc: int | None
    last_control: int | None
    elapsed_seconds: float | None
    response_elapsed_seconds: float | None
    experiment_elapsed_seconds: float | None = 0.0
    timing_complete: bool = True
    tcp_close_uncertain: bool = False
    diagnostic_address: int = 0x63

    def public_report(self) -> dict[str, object]:
        value = self.value if self.outcome == "identity_value_observed" else None
        return {
            **_tcp_read_report(self),
            "value_byte_count": None if value is None else len(value),
            "value_sha256": None if value is None else hashlib.sha256(value).hexdigest(),
            "candidate_address": f"0x{self.diagnostic_address:02X}",
            "candidate_address_status": "identity_response_received" if value is not None else "unverified",
            "address_association_status": "unconfirmed",
            "identifier": "0xF101",
            "identifier_name": "SVKCurrent",
            "identifier_evidence_status": "SOURCE_CONFIRMED",
            "identifier_evidence_origin": "inspected_local_odx" if self.diagnostic_address in (0x40, 0x2D) else "inspected_local_app_bytecode",
            "vehicle_support_status": "UNVERIFIED",
            "warnings": [
                "candidate address association remains unconfirmed",
                "opaque SVK value supplies no confirmed module or software mapping",
                "ECU software, coding definitions and writing remain unverified",
            ],
            "head_unit_status": "unverified",
            "ecu_software_status": "unverified",
        }


def read_head_unit_svk_once(network: GatewayNetwork, evidence: GatewayVINReadEvidence) -> ModuleSVKResult:
    """One fixed SVK read, requiring the original VIN proof."""
    if type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence:
        raise TypeError("candidate SVK query requires exact frozen network and verified VIN evidence types")
    return _read_once("svk", network, evidence)


def read_bdc_svk_once(network: GatewayNetwork, evidence: GatewayVINReadEvidence) -> ModuleSVKResult:
    """One fixed BDC_BODY F101 read at source-confirmed address 40.

    This observes software only. It supplies no parameter or coding profile.
    """
    if type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence:
        raise TypeError("BDC SVK query requires exact frozen network and verified VIN evidence types")
    return _read_once("bdc_svk", network, evidence)


def read_vsg_svk_once(network: GatewayNetwork, evidence: GatewayVINReadEvidence) -> ModuleSVKResult:
    """One fixed VSG F101 observation at I001's candidate address 2D."""
    if type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence:
        raise TypeError("VSG SVK query requires exact frozen network and verified VIN evidence types")
    return _read_once("vsg_svk", network, evidence)
