"""Internal fixed readers with private retention; no public command parser."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import REPORT_SCHEMA_VERSION, __version__
from .network import NetworkPreflightError, discovery_preflight


@dataclass(frozen=True)
class ReadRequest:
    interface: str
    source_address: str
    gateway: str | None = None
    live: bool = False
    discovery_directory: Path | None = None
    discovery_manifest_sha256: str | None = None
    identity_directory: Path | None = None
    identity_manifest_sha256: str | None = None
    svk_directory: Path | None = None
    svk_manifest_sha256: str | None = None


def discover(args: ReadRequest) -> dict:
    from .artifacts import ArtifactError, DiscoveryArtifactStore
    from .discovery import DISCOVERY_PORT, DISCOVERY_REQUEST
    from .live_discovery import discover_once

    report: dict[str, object] = {
        "schema_version": REPORT_SCHEMA_VERSION, "implementation_version": __version__,
        "command": "discover", "mode": "live_discovery" if args.live else "discovery_plan",
        "evidence_status": "LOCAL_OBSERVATION", "vehicle_contacted": False,
        "vehicle_packets_attempted": 0, "vehicle_packets_sent": 0,
        "vehicle_bytes_confirmed_sent": 0, "transmission_uncertain": False,
        "writes_supported": False, "diagnostic_tcp_opened": False,
        "vehicle_identity_status": "unknown", "head_unit_identity_status": "unknown",
        "transport_identity_status": "not_tested", "route_verified": False,
        "source_interface": args.interface, "source_address": args.source_address,
    }
    try:
        network = discovery_preflight(args.interface, args.source_address)
    except NetworkPreflightError as exc:
        report.update(outcome="preflight_failed", reason=exc.reason)
        return report
    report.update(route_verified=True, broadcast_address=network.broadcast_address,
                  destination_port=DISCOVERY_PORT, interface_index=network.interface_index,
                  hardware_port=network.hardware_port, maximum_udp_packets=1,
                  receive_window_seconds=3.0, discovery_request_hex=DISCOVERY_REQUEST.hex())
    if not args.live:
        report.update(outcome="plan_only", reason="--live is required to send the reviewed datagram")
        return report
    store = None
    try:
        with DiscoveryArtifactStore(Path.cwd()) as store:
            result = discover_once(network)
            report.update(result.public_report())
            report["mode"] = "live_discovery"
            # A local UDP send cannot prove that it reached the intended car.
            report["vehicle_contacted"] = None if result.vehicle_packets_attempted else False
            report["gateway_response_received"] = bool(result.candidates)
            report["transport_identity_status"] = "unverified_gateway_candidate" if result.candidates else "no_gateway_confirmed"
            if result.outcome == "network_changed":
                report["route_verified"] = False
            try:
                report["raw_artifacts"] = store.save(result, report.copy())
            except KeyboardInterrupt:
                report.update(outcome="artifact_storage_interrupted", reason="private evidence persistence interrupted",
                              private_artifact_directory=str(store.directory),
                              stop_before_further_vehicle_traffic=True)
            except ArtifactError:
                report.update(outcome="artifact_storage_failed", reason="private evidence could not be fully retained",
                              private_artifact_directory=str(store.directory),
                              stop_before_further_vehicle_traffic=True)
    except ArtifactError:
        report.update(outcome="artifact_prepare_failed", reason="private evidence directory could not be prepared; no packet sent")
    except KeyboardInterrupt:
        # Store cleanup can be interrupted after the sender has returned. Keep
        # the existing traffic/receive report and never retry to recreate it.
        report.update(outcome="interrupted", reason="user_interrupt",
                      stop_before_further_vehicle_traffic=True)
        if store is not None:
            report["private_artifact_directory"] = str(store.directory)
    except OSError:
        report.update(outcome="artifact_storage_failed", reason="private evidence directory cleanup failed",
                      stop_before_further_vehicle_traffic=True)
        if store is not None:
            report["private_artifact_directory"] = str(store.directory)
    return report


def read_vin(args: ReadRequest) -> dict:
    return _diagnostic_read(args, "vin")


def read_svk(args: ReadRequest) -> dict:
    return _diagnostic_read(args, "svk")


def read_bdc_svk(args: ReadRequest) -> dict:
    """Internal bounded BDC software observation; selects no coding."""
    return _diagnostic_read(args, "bdc_svk")


def read_vsg_svk(args: ReadRequest) -> dict:
    return _diagnostic_read(args, 'vsg_svk')


def read_vsg_config(args: ReadRequest) -> dict:
    return _diagnostic_read(args, 'vsg_config')


def read_vsg_metadata(args: ReadRequest, kind: str) -> dict:
    from .policy import VSG_METADATA
    if type(kind) is not str or kind not in VSG_METADATA: raise ValueError('unsupported_vsg_metadata')
    return _diagnostic_read(args, kind)


def read_bdc_pffes(args: ReadRequest) -> dict:
    return _diagnostic_read(args, "bdc_pffes")


def read_bdc_metadata(args: ReadRequest, kind: str) -> dict:
    from .policy import BDC_METADATA
    if type(kind) is not str or kind not in BDC_METADATA:
        raise ValueError("unsupported_bdc_metadata")
    return _diagnostic_read(args, kind)


def read_exbox(args: ReadRequest) -> dict:
    return _diagnostic_read(args, "exbox")


def read_snapshot(args: ReadRequest, *, module: str = 'HU') -> dict:
    return _diagnostic_read(args, "snapshot", module=module)


def _diagnostic_read(args: ReadRequest, kind: str, *, module: str = 'HU') -> dict:
    """Fixed proof-gated readers with shared reporting and private retention."""
    from . import live_identity as bounds, live_svk, live_block, live_coding_snapshot
    from .artifacts import ArtifactError, GatewayIdentityArtifactStore, HeadUnitSVKArtifactStore, BDCSVKArtifactStore, ExboxArtifactStore, BDCPfFesArtifactStore, BDCMetadataArtifactStore
    from .artifacts import VSGSVKArtifactStore, VSGConfigArtifactStore, VSGMetadataArtifactStore
    from .coding_snapshot_artifacts import CodingSnapshotArtifactStore, BDCSnapshotArtifactStore, VSGSnapshotArtifactStore
    from .coding_contract import contract
    from .evidence import EvidenceError, load_gateway_identity_evidence, load_gateway_vin_read_evidence
    from .network import identity_preflight
    from .svk import load_head_unit_svk_evidence, load_bdc_svk_evidence, load_vsg_svk_evidence

    snapshot_spec = contract(module)
    specs = {
        "vin": ("identify-gateway", "gateway_identity", bounds.GATEWAY_VIN_REQUEST, GatewayIdentityArtifactStore),
        "svk": ("read-head-unit-svk", "head_unit_svk", live_svk.HEAD_UNIT_SVK_REQUEST, HeadUnitSVKArtifactStore),
        "bdc_svk": ("read-bdc-svk", "bdc_svk", live_svk.BDC_SVK_REQUEST, BDCSVKArtifactStore),
        "vsg_svk": ("read-vsg-svk", "vsg_svk", live_svk.VSG_SVK_REQUEST, VSGSVKArtifactStore),
        "vsg_config": ("read-vsg-config", "vsg_config", live_block.VSG_CONFIG_REQUEST, VSGConfigArtifactStore),
        "exbox": ("read-exbox", "exbox", live_block.EXBOX_REQUEST, ExboxArtifactStore),
        "bdc_pffes": ("read-bdc-pffes", "bdc_pffes", live_block.BDC_PFFES_REQUEST, BDCPfFesArtifactStore),
        "snapshot": ("read-coding-snapshot", "coding_snapshot", snapshot_spec.requests,
                     {'HU':CodingSnapshotArtifactStore,'BDC':BDCSnapshotArtifactStore,'VSG01':VSGSnapshotArtifactStore}[module]),
    }
    specs.update({k: ("read-" + k.replace("_", "-"), k, bytes.fromhex("000000050001f44022") + d.to_bytes(2, "big"), BDCMetadataArtifactStore)
                  for k, (d, _, _) in live_block.BDC_METADATA.items()})
    specs.update({k: ('read-' + k.replace('_','-'), k, bytes.fromhex('000000050001f42d22') + d.to_bytes(2,'big'), VSGMetadataArtifactStore)
                  for k,(d,_,_) in live_block.VSG_METADATA.items()})
    bdc_group = kind == "bdc_pffes" or kind in live_block.BDC_METADATA
    vsg_group = kind == 'vsg_config' or kind in live_block.VSG_METADATA
    command, mode, request, store_type = specs[kind]
    report = {
        "schema_version": REPORT_SCHEMA_VERSION, "implementation_version": __version__,
        "command": command, "mode": "live_" + mode if args.live else mode + "_plan",
        "evidence_status": "LOCAL_OBSERVATION", "vehicle_contacted": False,
        "tcp_connections_attempted": 0, "tcp_connections_opened": 0,
        "tcp_connection_uncertain": False, "tcp_control_traffic_counted": False,
        "application_frames_attempted": 0, "application_frames_sent": 0,
        "vehicle_bytes_confirmed_sent": 0, "transmission_uncertain": False,
        "diagnostic_tcp_opened": False, "writes_supported": False,
        "vehicle_identity_status": "unknown", "head_unit_identity_status": "unverified",
        "transport_identity_status": "not_tested", "route_verified": False,
        "source_interface": args.interface, "source_address": args.source_address,
        "gateway_address": args.gateway, "destination_port": 6801,
    }
    if kind == "vin":
        report.update(vehicle_identity_status="not_tested", head_unit_identity_status="unknown", vin_matches_discovery=None)
    else:
        report.update(candidate_address_status="unverified", address_association_status="unconfirmed")
        if kind == "snapshot":
            report.update(snapshot_complete=False, completed_group_count=0, groups=[],
                value_interpretation="opaque_private_original_groups_require_review", original_signature_status="not_checked",
                snapshot_coherence_status="not_acquired", compatibility_status="unverified", field_mapping_status="unverified",
                coding_backup_status="no_current_snapshot")
        else:
            report.update(value_byte_count=None, value_sha256=None, value_interpretation=(
                "opaque_private_value_requires_review" if kind in ("svk", "bdc_svk", "vsg_svk") else "opaque_private_coding_value_requires_review"))
            if kind in ("exbox", "bdc_pffes", "vsg_config"):
                report.update(compatibility_status="unverified", field_mapping_status="unverified",
                              coding_backup_status="single_group_only_not_full_backup")
    identity = svk = None
    try:
        discovery = load_gateway_identity_evidence(args.discovery_directory,
            manifest_sha256=args.discovery_manifest_sha256, gateway_address=args.gateway,
            source_interface=args.interface, source_address=args.source_address)
        if kind != "vin":
            identity = load_gateway_vin_read_evidence(args.identity_directory,
                manifest_sha256=args.identity_manifest_sha256, discovery=discovery)
        if kind in ("exbox", "snapshot"):
            svk = ({'HU':load_head_unit_svk_evidence,'BDC':load_bdc_svk_evidence,'VSG01':load_vsg_svk_evidence}[module] if kind == 'snapshot' else load_head_unit_svk_evidence)(args.svk_directory,
                manifest_sha256=args.svk_manifest_sha256, discovery=discovery, identity=identity)
        elif bdc_group:
            svk = load_bdc_svk_evidence(args.svk_directory,
                manifest_sha256=args.svk_manifest_sha256, discovery=discovery, identity=identity)
            from .profiles import BDC_SOFTWARE
            if (svk.cafd_identifier, svk.cafd_version, svk.btld_identifier, svk.btld_version) != BDC_SOFTWARE:
                raise EvidenceError("bdc_software_tuple_not_selected")
        elif vsg_group:
            from .profiles import VSG_SOFTWARE
            svk = load_vsg_svk_evidence(args.svk_directory, manifest_sha256=args.svk_manifest_sha256,
                discovery=discovery, identity=identity)
            if (svk.cafd_identifier, svk.cafd_version, svk.btld_identifier, svk.btld_version) != VSG_SOFTWARE:
                raise EvidenceError('vsg_software_tuple_not_selected')
    except EvidenceError as exc:
        report.update(outcome="evidence_failed", reason=exc.reason)
        return report
    report.update(discovery_manifest_sha256=discovery.manifest_sha256, discovery_reply_sha256=discovery.reply_sha256,
                  masked_discovery_vin="*"*13+discovery.vin_candidate[-4:])
    if identity is not None:
        report.update(identity_manifest_sha256=identity.manifest_sha256, identity_request_sha256=identity.request_sha256,
                      prior_gateway_vin_match=True, vehicle_identity_status="prior_gateway_vin_matches_discovery")
    if svk is not None:
        report.update(svk_manifest_sha256=svk.manifest_sha256, svk_request_sha256=svk.request_sha256,
            prior_svk_value_sha256=svk.value_sha256, observed_cafd_identifier=svk.cafd_identifier,
            observed_cafd_version=svk.cafd_version, observed_btld_identifier=svk.btld_identifier,
            observed_btld_version=svk.btld_version, prior_svk_match=True)
    try:
        network = identity_preflight(args.interface, args.source_address, args.gateway)
        if network.interface_index != discovery.interface_index:
            raise NetworkPreflightError("discovery_interface_index_changed")
    except NetworkPreflightError as exc:
        report.update(outcome="preflight_failed", reason=exc.reason)
        return report
    report.update(route_verified=True, interface_index=network.interface_index, hardware_port=network.hardware_port,
        maximum_application_frames=len(snapshot_spec.groups) if kind == "snapshot" else 1, tester_address="0xF4", service="0x22",
        request_hex=[raw.hex() for raw in request] if kind == "snapshot" else request.hex(),
        connect_timeout_seconds=bounds.CONNECT_TIMEOUT_SECONDS, first_response_window_seconds=bounds.FIRST_RESPONSE_WINDOW_SECONDS,
        pending_response_window_seconds=bounds.PENDING_RESPONSE_WINDOW_SECONDS, overall_request_window_seconds=bounds.OVERALL_REQUEST_WINDOW_SECONDS,
        experiment_overall_window_seconds=live_coding_snapshot.SNAPSHOT_WINDOW_SECONDS if kind == "snapshot" else bounds.EXPERIMENT_WINDOW_SECONDS,
        receive_byte_limit=bounds.MAX_RAW_RECEIVE_BYTES, receive_chunk_limit=snapshot_spec.receive_chunks if kind == 'snapshot' else bounds.MAX_RECEIVE_CHUNKS,
        receive_frame_body_limit=bounds.MAX_FRAME_BODY_BYTES, timing_source="project_bounds_not_ecu_reported_timings")
    if kind == "vin":
        report.update(gateway_diagnostic_address="0x10", identifier="0xF190")
    else:
        meaning = {"svk": "SVKCurrent", "bdc_svk": "SVKCurrent", "vsg_svk": "SVKCurrent", "vsg_config": "VSG Configuration", "exbox": "EXBOX", "bdc_pffes": "PfFesMaster", "snapshot": "fixed_exact_cafd_coding_groups", **{k: n for k, (_, _, n) in live_block.METADATA.items()}}[kind]
        report.update(candidate_diagnostic_address=f'0x{snapshot_spec.target:02X}' if kind == 'snapshot' else "0x2D" if kind == "vsg_svk" or vsg_group else "0x40" if (kind == "bdc_svk" or bdc_group) else "0x63", identifier_meaning=meaning, identifier_evidence_status="SOURCE_CONFIRMED",
            identifier_evidence_origin="inspected_local_odx" if kind in ("bdc_svk", "vsg_svk") else ("authenticated_exact_cafd_and_inspected_read_contract" if kind == "snapshot" else "inspected_local_app_bytecode"),
            target_evidence_status="SOURCE_CONFIRMED", vehicle_support_status="UNVERIFIED")
        if kind == "snapshot":
            report.update(maximum_application_bytes=11*len(snapshot_spec.groups), planned_groups=[
                {"identifier": f"0x{address:04X}", "expected_value_byte_length": size}
                for address, size in snapshot_spec.groups])
        else:
            report["identifier"] = "0xF101" if kind in ("svk", "bdc_svk", "vsg_svk") else "0x3000" if kind == "vsg_config" else "0x3221" if kind == "bdc_pffes" else f"0x{live_block.METADATA[kind][0]:04X}" if kind in live_block.METADATA else "0x3001"
    if not args.live:
        report.update(outcome="plan_only", reason={
            "vin": "--live is required for the reviewed gateway VIN read",
            "svk": "--live is required for the reviewed candidate identity read",
            "bdc_svk": "--live is required for the reviewed BDC current software read",
            "vsg_svk": "--live is required for the fixed VSG current software read",
            "vsg_config": "--live is required for the exact VSG configuration read",
            "exbox": "--live is required for the reviewed EXBOX coding-group read",
            "bdc_pffes": "--live is required for the reviewed BDC PfFesMaster group read",
            "snapshot": "--live is required for the separately selected complete fixed group acquisition",
            **{k: '--live is required for the fixed selected module metadata read' for k in live_block.METADATA},
        }[kind])
        return report
    store = None
    try:
        with store_type(Path.cwd()) as store:
            if kind == "vin":
                result = bounds.identify_gateway_once(network, discovery)
            elif kind == "svk":
                result = live_svk.read_head_unit_svk_once(network, identity)
            elif kind == "bdc_svk":
                result = live_svk.read_bdc_svk_once(network, identity)
            elif kind == "vsg_svk":
                result = live_svk.read_vsg_svk_once(network, identity)
            elif kind == "exbox":
                result = live_block.read_exbox_once(network, identity, svk)
            elif vsg_group:
                result = (live_block.read_vsg_config_once(network, identity, svk) if kind == 'vsg_config' else
                          live_block.read_vsg_metadata_once(kind, network, identity, svk))
            elif bdc_group:
                result = (live_block.read_bdc_pffes_once(network, identity, svk) if kind == "bdc_pffes" else
                          live_block.read_bdc_metadata_once(kind, network, identity, svk))
            else:
                result = {'HU':live_coding_snapshot.read_current_coding_snapshot,'BDC':live_coding_snapshot.read_bdc_coding_snapshot,
                          'VSG01':live_coding_snapshot.read_vsg_coding_snapshot}[module](network, identity, svk)
            report.update(result.public_report())
            report.update(vehicle_contacted=None if result.tcp_connections_attempted else False,
                          diagnostic_tcp_opened=bool(result.tcp_connections_opened))
            success = {"vin": "vin_match", "svk": "identity_value_observed", "bdc_svk": "identity_value_observed", "vsg_svk": "identity_value_observed", "vsg_config": "coding_value_observed", "exbox": "coding_value_observed", "bdc_pffes": "coding_value_observed", "snapshot": "snapshot_observed", **{k: "coding_value_observed" for k in live_block.METADATA}}[kind]
            success_status = {"vin": "gateway_vin_response_matches_discovery",
                "svk": "candidate_identity_response_via_previously_vin_matched_gateway",
                "bdc_svk": "candidate_identity_response_via_previously_vin_matched_gateway",
                "vsg_svk": "candidate_identity_response_via_previously_vin_matched_gateway",
                "exbox": "coding_response_via_previously_vin_and_svk_observed_gateway",
                "bdc_pffes": "coding_response_via_previously_vin_and_svk_observed_gateway",
                "vsg_config": "coding_response_via_previously_vin_and_svk_observed_gateway",
                "snapshot": "original_groups_via_previously_vin_and_svk_observed_gateway",
                **{k: "metadata_response_via_previously_vin_and_svk_observed_gateway" for k in live_block.METADATA}}[kind]
            if result.outcome == success and (kind != "snapshot" or report.get("snapshot_complete")):
                report["transport_identity_status"] = success_status
            elif result.tcp_connections_opened:
                report["transport_identity_status"] = {
                    "vin": "tcp_connected_no_identity_confirmed",
                    "svk": "tcp_connected_no_candidate_identity_value",
                    "bdc_svk": "tcp_connected_no_candidate_identity_value",
                    "vsg_svk": "tcp_connected_no_candidate_identity_value",
                }.get(kind, "tcp_connected_no_coding_value")
            else:
                report["transport_identity_status"] = (
                    "connection_not_confirmed" if result.tcp_connections_attempted else "not_tested")
            if kind == "snapshot":
                report["coding_backup_status"] = ("acquired_original_groups_not_yet_retained" if report.get("snapshot_complete") else "incomplete_original_groups")
            if result.outcome == "network_changed":
                report["route_verified"] = False
            try:
                if kind == "vin":
                    receipt = store.save_identity(result, report.copy(), discovery)
                elif kind in ("svk", "bdc_svk", "vsg_svk"):
                    receipt = store.save_svk(result, report.copy(), identity)
                elif kind == 'exbox' or vsg_group or bdc_group:
                    receipt = store.save_block(result, report.copy(), identity, svk)
                else:
                    receipt = store.save_snapshot(result, report.copy(), identity, svk, network)
                report["raw_artifacts"] = receipt
                if kind == "snapshot":
                    if receipt.get("complete_snapshot_saved") is True:
                        report["coding_backup_status"] = "complete_original_groups_retained_signature_not_checked"
                    if report.get("snapshot_complete") and receipt.get("complete_snapshot_saved") is not True:
                        report.update(outcome="snapshot_artifact_validation_failed", reason="retained original stream did not establish a complete snapshot",
                            snapshot_complete=False, groups=[], coding_backup_status="retained_stream_validation_failed", stop_before_further_vehicle_traffic=True)
            except (KeyboardInterrupt, ArtifactError) as exc:
                report.update(outcome="artifact_storage_interrupted" if isinstance(exc, KeyboardInterrupt) else "artifact_storage_failed",
                              reason="private evidence could not be fully retained", private_artifact_directory=str(store.directory), stop_before_further_vehicle_traffic=True)
                if kind == "snapshot":
                    report["coding_backup_status"] = "private_retention_unconfirmed"
    except ArtifactError:
        report.update(outcome="artifact_prepare_failed", reason="private evidence directory could not be prepared; no connection attempted")
    except (OSError, KeyboardInterrupt) as exc:
        report.update(outcome="interrupted" if isinstance(exc, KeyboardInterrupt) else "artifact_storage_failed",
                      reason="private evidence cleanup failed", stop_before_further_vehicle_traffic=True)
        if store is not None:
            report["private_artifact_directory"] = str(store.directory)
        if kind == "snapshot":
            report["coding_backup_status"] = "private_retention_unconfirmed"
    return report
