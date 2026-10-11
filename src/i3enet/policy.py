"""Default-deny final policies for the fixed discovery and identity/coding reads."""

from dataclasses import dataclass
from enum import Enum
import ipaddress
import re

from .discovery import DISCOVERY_PORT, DISCOVERY_REQUEST
from .hsfz import DIAGNOSTIC_PORT
from .network import DiscoveryNetwork, GatewayNetwork, NetworkPreflightError


DISCOVERY_DATAGRAM = DISCOVERY_REQUEST
GATEWAY_VIN_FRAME = bytes.fromhex("000000050001f41022f190")
HEAD_UNIT_SVK_FRAME = bytes.fromhex("000000050001f46322f101")
BDC_SVK_FRAME = bytes.fromhex("000000050001f44022f101")
VSG_SVK_FRAME = bytes.fromhex("000000050001f42d22f101")
VSG_CONFIG_FRAME = bytes.fromhex("000000050001f42d223000")
EXBOX_REQUEST_FRAME = bytes.fromhex("000000050001f463223001")
BDC_PFFES_FRAME = bytes.fromhex("000000050001f440223221")


class Phase(Enum):
    DENY = "deny"
    LIVE_DISCOVERY = "live-discovery"
    LIVE_GATEWAY_IDENTITY = "live-gateway-identity"
    LIVE_HEAD_UNIT_SVK = "live-head-unit-svk"
    LIVE_BDC_SVK = "live-bdc-svk"
    LIVE_VSG_SVK = "live-vsg-svk"
    LIVE_VSG_CONFIG = "live-vsg-config"
    LIVE_VSG_METADATA = 'live-vsg-metadata'
    LIVE_HEAD_UNIT_EXBOX = "live-head-unit-exbox"
    LIVE_BDC_PFFES = "live-bdc-pffes"
    LIVE_BDC_METADATA = "live-bdc-metadata"


class PolicyViolation(ValueError):
    """The final boundary rejected a message before retaining any bytes."""


@dataclass(frozen=True, slots=True)
class LiveDiscoveryPolicy:
    """No general live sender: only the single approved discovery datagram.

    The sender additionally verifies fresh preflight, bound source and bound
    interface immediately before calling this policy at its final send boundary.
    """

    network: DiscoveryNetwork
    phase: Phase = Phase.DENY

    def validate(self, payload: bytes, destination: tuple[str, int], *, sent_count: int = 0) -> None:
        if type(self.phase) is not Phase or self.phase is not Phase.LIVE_DISCOVERY:
            raise PolicyViolation("live discovery is denied outside its explicit phase")
        if type(self.network) is not DiscoveryNetwork or self.network.route_verified is not True:
            raise PolicyViolation("live discovery requires a validated immutable local network")
        if type(sent_count) is not int or sent_count != 0:
            raise PolicyViolation("live discovery permits one attempt; no retries")
        if type(payload) is not bytes or payload != DISCOVERY_DATAGRAM:
            raise PolicyViolation("only the exact six-byte discovery datagram is permitted")
        if (type(destination) is not tuple or len(destination) != 2 or
                type(destination[0]) is not str or type(destination[1]) is not int or
                destination != (self.network.broadcast_address, DISCOVERY_PORT)):
            raise PolicyViolation("destination must be the validated interface broadcast and UDP/6811")
        if (not re.fullmatch(r"en[0-9]+", self.network.interface) or
                type(self.network.interface_index) is not int or self.network.interface_index <= 0):
            raise PolicyViolation("discovery requires an explicitly selected macOS Ethernet interface")
        try:
            source = ipaddress.IPv4Address(self.network.source_address)
            subnet = ipaddress.IPv4Network(f"{source}/{self.network.netmask}", strict=False)
        except ValueError as exc:
            raise PolicyViolation("invalid discovery source network") from exc
        if (subnet != ipaddress.IPv4Network("169.254.0.0/16") or
                not source.is_link_local or source in (subnet.network_address, subnet.broadcast_address) or
                self.network.broadcast_address != str(subnet.broadcast_address)):
            raise PolicyViolation("initial discovery supports only the validated direct link-local /16")


@dataclass(frozen=True, slots=True)
class LiveGatewayIdentityPolicy:
    """Only one exact gateway VIN frame, with no helper or retry privilege.

    A separate sender must check the reviewed discovery evidence, current local
    preflight and actual socket bindings before invoking this final boundary.
    """

    network: GatewayNetwork
    phase: Phase = Phase.DENY

    def validate(self, payload: bytes, destination: tuple[str, int], *, sent_count: int = 0) -> None:
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                 required_phase=Phase.LIVE_GATEWAY_IDENTITY, frame=GATEWAY_VIN_FRAME)


@dataclass(frozen=True, slots=True)
class LiveHeadUnitSVKPolicy:
    """One fixed current SVK hypothesis test, with no fallback privilege.

    Candidate 63 is not yet associated with HU-B. The distinct sender checks
    both pinned gateway proofs and fresh network/socket bindings separately.
    """

    network: GatewayNetwork
    phase: Phase = Phase.DENY

    def validate(self, payload: bytes, destination: tuple[str, int], *, sent_count: int = 0) -> None:
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                 required_phase=Phase.LIVE_HEAD_UNIT_SVK, frame=HEAD_UNIT_SVK_FRAME)


@dataclass(frozen=True, slots=True)
class LiveHeadUnitEXBOXPolicy:
    """One fixed EXBOX group read, with no helper or retry privilege.

    The distinct sender checks all three pinned discovery/VIN/SVK proofs
    and fresh network/socket bindings separately. This permits no writer.
    """

    network: GatewayNetwork
    phase: Phase = Phase.DENY

    def validate(self, payload: bytes, destination: tuple[str, int], *, sent_count: int = 0) -> None:
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                 required_phase=Phase.LIVE_HEAD_UNIT_EXBOX, frame=EXBOX_REQUEST_FRAME)


@dataclass(frozen=True, slots=True)
class LiveBDCSVKPolicy:
    """One source-confirmed BDC_BODY address/SVK read; no coding privilege."""

    network: GatewayNetwork
    phase: Phase = Phase.DENY

    def validate(self, payload: bytes, destination: tuple[str, int], *, sent_count: int = 0) -> None:
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                 required_phase=Phase.LIVE_BDC_SVK, frame=BDC_SVK_FRAME)


@dataclass(frozen=True, slots=True)
class LiveVSGSVKPolicy:
    """Only VSG candidate 2D / current SVK, with no session/write privilege."""
    network: GatewayNetwork
    phase: Phase = Phase.DENY

    def validate(self, payload, destination, *, sent_count=0):
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                required_phase=Phase.LIVE_VSG_SVK, frame=VSG_SVK_FRAME)


@dataclass(frozen=True, slots=True)
class LiveBDCPfFesPolicy:
    """One exact BDC 3221 read; no other group, retries or session changes."""

    network: GatewayNetwork
    phase: Phase = Phase.DENY

    def validate(self, payload: bytes, destination: tuple[str, int], *, sent_count: int = 0) -> None:
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                 required_phase=Phase.LIVE_BDC_PFFES, frame=BDC_PFFES_FRAME)


@dataclass(frozen=True, slots=True)
class LiveVSGConfigPolicy:
    """Only the exact eight-byte 3000 configuration read; no mutations."""
    network: GatewayNetwork
    phase: Phase = Phase.DENY

    def validate(self, payload, destination, *, sent_count=0):
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                required_phase=Phase.LIVE_VSG_CONFIG, frame=VSG_CONFIG_FRAME)


BDC_METADATA = {"bdc_timing": (0x2504, None, "diagnostic_timing"),
                "bdc_state": (0xF186, None, "diagnostic_session_state"),
                "bdc_cps": (0x37FE, 7, "coding_proof_stamp")}
VSG_METADATA = {k.replace('bdc_','vsg_'):v for k,v in BDC_METADATA.items()}


@dataclass(frozen=True, slots=True)
class LiveBDCMetadataPolicy:
    network: GatewayNetwork
    phase: Phase = Phase.DENY
    kind: str = ""

    def validate(self, payload, destination, *, sent_count=0):
        if type(self.kind) is not str or self.kind not in BDC_METADATA:
            raise PolicyViolation("bdc_metadata_not_selected")
        did = BDC_METADATA[self.kind][0]
        frame = bytes.fromhex("000000050001f44022") + did.to_bytes(2, "big")
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                 required_phase=Phase.LIVE_BDC_METADATA, frame=frame)


@dataclass(frozen=True, slots=True)
class LiveVSGMetadataPolicy:
    network: GatewayNetwork
    phase: Phase = Phase.DENY
    kind: str = ''

    def validate(self, payload, destination, *, sent_count=0):
        if type(self.kind) is not str or self.kind not in VSG_METADATA:
            raise PolicyViolation('vsg_metadata_not_selected')
        frame = bytes.fromhex('000000050001f42d22') + VSG_METADATA[self.kind][0].to_bytes(2,'big')
        _validate_fixed_tcp_read(self.network, self.phase, payload, destination, sent_count,
                                required_phase=Phase.LIVE_VSG_METADATA, frame=frame)


def _validate_fixed_tcp_read(network, phase, payload, destination, sent_count, *, required_phase, frame) -> None:
    """Shared boundary mechanics; callers supply only their fixed phase/frame."""
    if type(phase) is not Phase or phase is not required_phase:
        raise PolicyViolation("fixed read is denied outside its explicit phase")
    if type(network) is not GatewayNetwork:
        raise PolicyViolation("fixed read requires a validated immutable local network")
    try:
        GatewayNetwork.__post_init__(network)
    except (NetworkPreflightError, TypeError, ValueError, AttributeError):
        raise PolicyViolation("invalid fixed-read network snapshot") from None
    if type(sent_count) is not int or sent_count != 0:
        raise PolicyViolation("fixed read permits one attempt; no retries")
    if type(payload) is not bytes or payload != frame:
        raise PolicyViolation("only the exact selected read frame is permitted")
    if (type(destination) is not tuple or len(destination) != 2
            or type(destination[0]) is not str or type(destination[1]) is not int
            or destination != (network.gateway_address, DIAGNOSTIC_PORT)):
        raise PolicyViolation("destination must be the selected gateway and TCP/6801")
