"""Fixed HU EXBOX / BDC PfFesMaster reads and their private result.

Requires original VIN and exact software proofs. The bounded exchange in
live_identity uses this reader's exact frame, final policy and full short ACK.
Reading one group supplies neither a complete coding backup nor write authority."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from .evidence import GatewayVINReadEvidence
from .svk import HeadUnitSVKEvidence, BDCSVKEvidence, VSGSVKEvidence
from .profiles import BDC_SOFTWARE, VSG_SOFTWARE
from .network import GatewayNetwork, identity_preflight
from .policy import (LiveHeadUnitEXBOXPolicy, LiveBDCPfFesPolicy, LiveVSGConfigPolicy,
    LiveBDCMetadataPolicy, LiveVSGMetadataPolicy, BDC_METADATA, VSG_METADATA)
from .live_identity import ReceivedTCPChunk, _read_once, _tcp_read_report, _verified_vin_matches


EXBOX_REQUEST = bytes.fromhex("000000050001f463223001")
BDC_PFFES_REQUEST = bytes.fromhex("000000050001f440223221")
VSG_CONFIG_REQUEST = bytes.fromhex("000000050001f42d223000")
METADATA = BDC_METADATA | VSG_METADATA


@dataclass(frozen=True, slots=True)
class ModuleBlockResult:
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
    identifier: int = 0x3001

    def public_report(self) -> dict[str, object]:
        value = self.value if self.outcome == "coding_value_observed" else None
        report = {
            **_tcp_read_report(self),
            "value_byte_count": None if value is None else len(value),
            "value_sha256": None if value is None else hashlib.sha256(value).hexdigest(),
            "candidate_address": f"0x{self.diagnostic_address:02X}",
            "candidate_address_status": "coding_response_received" if value is not None else "unverified",
            "address_association_status": "coding_identity_previously_observed",
            "compatibility_status": "unverified",
            "field_mapping_status": "unverified",
            "coding_backup_status": "single_group_only_not_full_backup",
            "identifier": f"0x{self.identifier:04X}",
            "identifier_name": next((n for did, _, n in METADATA.values() if did == self.identifier),
                                    "VSG Configuration" if self.diagnostic_address == 0x2D else "PfFesMaster" if self.diagnostic_address == 0x40 else "EXBOX"),
            "identifier_evidence_status": "SOURCE_CONFIRMED",
            "identifier_evidence_origin": "authenticated_exact_cafd_and_named_patch_comparison" if self.diagnostic_address in (0x40,0x2D) else "inspected_local_app_bytecode",
            "vehicle_support_status": "UNVERIFIED",
            "warnings": [
                "raw coding value requires separate definition and version review",
                "one group is not a full coding backup",
                "field meaning requires separate validation; reading grants no write support",
            ],
            "head_unit_status": "not_targeted" if self.diagnostic_address in (0x40,0x2D) else "physical_identity_unverified",
            "ecu_software_status": "prior_svk_observed",
        }
        if self.identifier in {did for did, _, _ in METADATA.values()}:
            report.update(coding_backup_status="metadata_original_not_group_backup",
                          identifier_evidence_origin="inspected_local_odx",
                          warnings=["metadata decoding and transaction compatibility require separate review"])
        return report


_exbox_vin_evidence_matches = _verified_vin_matches


def _exbox_svk_evidence_matches(network: GatewayNetwork, evidence: GatewayVINReadEvidence,
                                svk: HeadUnitSVKEvidence) -> bool:
    return _block_svk_matches(network, evidence, svk, module='HU')


def _bdc_svk_evidence_matches(network: GatewayNetwork, evidence: GatewayVINReadEvidence,
                              svk: BDCSVKEvidence) -> bool:
    return _block_svk_matches(network, evidence, svk, module='BDC')


def _vsg_svk_evidence_matches(network, evidence, svk):
    return _block_svk_matches(network, evidence, svk, module='VSG01')


def _block_svk_matches(network, evidence, svk, *, module):
    proof_type, target, software = {
        'HU': (HeadUnitSVKEvidence, 0x63, ('00000DED','003.015.041','00001ABA','130.026.001')),
        'BDC': (BDCSVKEvidence, 0x40, BDC_SOFTWARE), 'VSG01': (VSGSVKEvidence, 0x2D, VSG_SOFTWARE),
    }[module]
    def valid_hash(value: object) -> bool:
        return (type(value) is str and len(value) == 64
                and all(character in "0123456789abcdef" for character in value))

    return (
        type(svk) is proof_type
        and type(svk.interface_index) is int
        and (svk.gateway_address, svk.source_interface, svk.source_address, svk.interface_index)
        == (network.gateway_address, network.interface, network.source_address, network.interface_index)
        and svk.discovery_manifest_sha256 == evidence.discovery.manifest_sha256
        and svk.identity_manifest_sha256 == evidence.manifest_sha256
        and valid_hash(svk.manifest_sha256)
        and valid_hash(svk.value_sha256)
        and svk.request_sha256 == hashlib.sha256(bytes.fromhex("000000050001f4") + bytes((target,0x22,0xF1,0x01))).hexdigest()
        and (svk.cafd_identifier, svk.cafd_version, svk.btld_identifier, svk.btld_version)
        == software
    )


def read_exbox_once(network: GatewayNetwork, evidence: GatewayVINReadEvidence, svk: HeadUnitSVKEvidence) -> ModuleBlockResult:
    """One fixed EXBOX read, requiring original VIN and software proofs."""
    if (type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence
            or type(svk) is not HeadUnitSVKEvidence):
        raise TypeError("EXBOX read requires exact frozen network, VIN and SVK evidence types")
    return _read_once("exbox", network, evidence, svk)


def read_bdc_pffes_once(network: GatewayNetwork, evidence: GatewayVINReadEvidence, svk: BDCSVKEvidence) -> ModuleBlockResult:
    """One fixed 17-byte 3221 read; requires the exact BDC software proof."""
    if (type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence
            or type(svk) is not BDCSVKEvidence):
        raise TypeError("BDC group read requires exact frozen network, VIN and BDC SVK evidence types")
    return _read_once("bdc_pffes", network, evidence, svk)


def read_bdc_metadata_once(kind: str, network: GatewayNetwork, evidence: GatewayVINReadEvidence, svk: BDCSVKEvidence) -> ModuleBlockResult:
    """One selected timing/state/CPS read; no numeric or arbitrary identifier."""
    if (type(kind) is not str or kind not in BDC_METADATA or type(network) is not GatewayNetwork
            or type(evidence) is not GatewayVINReadEvidence or type(svk) is not BDCSVKEvidence):
        raise TypeError("BDC metadata requires a closed selection and exact proof types")
    return _read_once(kind, network, evidence, svk)


def read_vsg_config_once(network: GatewayNetwork, evidence: GatewayVINReadEvidence, svk: VSGSVKEvidence) -> ModuleBlockResult:
    if (type(network) is not GatewayNetwork or type(evidence) is not GatewayVINReadEvidence
            or type(svk) is not VSGSVKEvidence):
        raise TypeError('VSG read requires exact network, VIN and VSG SVK proof types')
    return _read_once('vsg_config', network, evidence, svk)


def read_vsg_metadata_once(kind: str, network: GatewayNetwork, evidence: GatewayVINReadEvidence, svk: VSGSVKEvidence) -> ModuleBlockResult:
    if (type(kind) is not str or kind not in VSG_METADATA or type(network) is not GatewayNetwork
            or type(evidence) is not GatewayVINReadEvidence or type(svk) is not VSGSVKEvidence):
        raise TypeError('VSG metadata requires a closed selection and exact proof types')
    return _read_once(kind, network, evidence, svk)
