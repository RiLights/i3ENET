"""Fresh discovery/VIN/SVK chain; no saved-proof rebinding."""
from __future__ import annotations

from dataclasses import replace
import ipaddress
from pathlib import Path

from . import REPORT_SCHEMA_VERSION, __version__, reads
from .evidence import EvidenceError, load_gateway_identity_evidence, load_gateway_vin_read_evidence
from .network import NetworkPreflightError, doctor
from .svk import load_head_unit_svk_evidence, load_bdc_svk_evidence, load_vsg_svk_evidence
from .coding_preparation import CodingPreparationError
from .block_evidence import load_exbox_value, load_bdc_pffes_value, load_vsg_config_value
from .profiles import resolve_parameter, BDC_SOFTWARE, VSG_SOFTWARE

_COUNTERS = ("vehicle_packets_attempted", "vehicle_packets_sent", "tcp_connections_attempted",
             "tcp_connections_opened", "application_frames_attempted", "application_frames_sent",
             "vehicle_bytes_confirmed_sent")
_UNCERTAINTIES = ("transmission_uncertain", "socket_close_uncertain", "tcp_connection_uncertain",
                  "tcp_close_uncertain")
_STEPS = ("discover", "read-vin", "read-head-unit-svk", "read-block")


def _interface(source: str) -> str:
    observation = doctor()
    if observation["local_inspection_status"] != "complete":
        raise NetworkPreflightError("local_interface_inspection_incomplete")
    matches = [item["name"] for item in observation["interfaces"] if source in item["ipv4"]]
    if len(matches) != 1:
        raise NetworkPreflightError("source_address_requires_one_local_interface")
    # Existing discovery preflight verifies Ethernet, link, subnet and route.
    return matches[0]


def _retained(args: reads.ReadRequest, report: dict, category: str) -> reads.ReadRequest:
    artifacts = report.get("raw_artifacts", {})
    directory, pin = artifacts.get("directory"), artifacts.get("manifest_sha256")
    if not isinstance(directory, str) or not isinstance(pin, str):
        raise EvidenceError("fresh_originals_unavailable")
    return replace(args, **{category + "_directory": Path(directory), category + "_manifest_sha256": pin})


def _successful(report: dict, outcome: str) -> bool:
    return (report.get("outcome") == outcome and not report.get("stop_before_further_vehicle_traffic")
            and report.get("timing_complete") is True
            and not any(report.get(key, False) for key in _UNCERTAINTIES))


def read(command: str, source: str, *, live: bool = False, ecu: str | None = None,
         parameter: str | None = None) -> dict:
    """Read one selected value using only this invocation's immutable captures."""
    if command not in ("read-vin", "read-block"):
        raise ValueError("unsupported read command")
    steps = _STEPS[:2] if command == "read-vin" else _STEPS
    bdc = command == 'read-block' and ecu == 'BDC'
    if bdc:
        steps = (*_STEPS[:2], 'read-bdc-svk', 'read-block')
    if command == 'read-block' and ecu == 'VSG01':
        steps = (*_STEPS[:2], 'read-vsg-svk', 'read-block')
    report = dict(schema_version=REPORT_SCHEMA_VERSION, implementation_version=__version__,
        command=command, mode="live_read" if live else "read_plan", source_address=source,
        planned_steps=list(steps), maximum_udp_packets=1, maximum_application_frames=len(steps)-1,
        maximum_application_bytes=6+11*(len(steps)-1), maximum_tcp_connections=len(steps)-1, writes_supported=False,
        diagnostic_tcp_opened=False, vehicle_contacted=False, steps=[])
    report.update({key: 0 for key in _COUNTERS})
    report.update({key: False for key in _UNCERTAINTIES})
    stage = "connection"
    try:
        field = None
        if command == 'read-block':
            stage = 'selection'
            field = resolve_parameter(ecu, parameter, reading=True)
            report.update(ecu=ecu, parameter=parameter, block=f'{field.group:04X}', block_name=field.group_name)
        stage = 'connection'
        address = ipaddress.IPv4Address(source)
        if (str(address) != source or not address.is_link_local
                or int(address) & 0xFFFF in (0, 0xFFFF)):
            raise NetworkPreflightError("link_local_mac_ip_required")
        if not live:
            report.update(outcome="plan_only", reason="Add --live to perform the bounded read sequence")
            return report
        args = reads.ReadRequest(_interface(source), source, live=True)
        report["source_interface"] = args.interface

        def execute(name, reader, expected):
            nonlocal stage
            stage = name
            step = reader(args)
            report["steps"].append(step)
            for key in _COUNTERS:
                report[key] += step.get(key, 0)
            for key in _UNCERTAINTIES:
                report[key] |= step.get(key, False)
            report["diagnostic_tcp_opened"] |= step.get("diagnostic_tcp_opened", False)
            report["vehicle_contacted"] = None if report["vehicle_packets_attempted"] else False
            if not _successful(step, expected):
                raise EvidenceError(step.get("reason") or step.get("outcome") or "read_failed")
            return step

        found = execute("discover", reads.discover, "gateway_found")
        candidates = found.get("candidates", [])
        if len(candidates) != 1 or candidates[0].get("identity_conflict") is not False:
            raise EvidenceError("one_unambiguous_gateway_required")
        args = replace(args, gateway=candidates[0]["address"])
        args = _retained(args, found, "discovery")
        discovery = load_gateway_identity_evidence(args.discovery_directory,
            manifest_sha256=args.discovery_manifest_sha256, gateway_address=args.gateway,
            source_interface=args.interface, source_address=source)
        report.update(gateway_address=args.gateway, interface_index=discovery.interface_index,
                      gateway_selection_status="unique_discovery_candidate")
        vin = execute("read-vin", reads.read_vin, "vin_match")
        args = _retained(args, vin, "identity")
        identity = load_gateway_vin_read_evidence(args.identity_directory,
            manifest_sha256=args.identity_manifest_sha256, discovery=discovery)
        report["masked_vin"] = "*" * 13 + discovery.vin_candidate[-4:]
        if command == "read-block":
            svk_reader, svk_loader, block_reader, block_loader, software = {
                'HU': (reads.read_svk,load_head_unit_svk_evidence,reads.read_exbox,load_exbox_value,None),
                'BDC': (reads.read_bdc_svk,load_bdc_svk_evidence,reads.read_bdc_pffes,load_bdc_pffes_value,BDC_SOFTWARE),
                'VSG01': (reads.read_vsg_svk,load_vsg_svk_evidence,reads.read_vsg_config,load_vsg_config_value,VSG_SOFTWARE),
            }[ecu]
            svk_report = execute(steps[2], svk_reader, "identity_value_observed")
            args = _retained(args, svk_report, "svk")
            svk = svk_loader(args.svk_directory,
                manifest_sha256=args.svk_manifest_sha256, discovery=discovery, identity=identity)
            if software is not None and (svk.cafd_identifier, svk.cafd_version, svk.btld_identifier, svk.btld_version) != software:
                raise EvidenceError(('bdc' if bdc else 'vsg') + '_software_tuple_not_selected')
            report.update(observed_cafd_identifier=svk.cafd_identifier, observed_cafd_version=svk.cafd_version,
                          observed_btld_identifier=svk.btld_identifier, observed_btld_version=svk.btld_version)
            block = execute("read-block", block_reader, "coding_value_observed")
            pins = tuple((name, getattr(args, name+"_directory"), getattr(args, name+"_manifest_sha256"))
                         for name in ("discovery", "identity", "svk"))
            value = block_loader(block, root=Path.cwd(),
                network=(args.interface, source, args.gateway, discovery.interface_index), proofs=pins)
            report.update(value_byte_count=len(value), value_sha256=block["value_sha256"],
                          parameter_value_evidence_status="CAPTURE_CONFIRMED", **field.decode(value))
        report.update(outcome="block_read" if command == "read-block" else "vin_read", raw_artifacts=report["steps"][-1]["raw_artifacts"])
    except (EvidenceError, NetworkPreflightError, CodingPreparationError) as exc:
        report.update(outcome="read_stopped", failed_step=stage, reason=exc.reason,
                      stop_before_further_vehicle_traffic=True)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError, KeyboardInterrupt):
        report.update(outcome="read_stopped", failed_step=stage, reason="read_or_original_validation_failed",
                      stop_before_further_vehicle_traffic=True)
    return report
