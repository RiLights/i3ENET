"""Named parameter coding within exact selected-module software contracts.

CLI creation/tests select no traffic. A live invocation captures fresh originals,
then asks approval before sessions, signing loads or the mutation transaction.
"""
from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path
import sys

from . import REPORT_SCHEMA_VERSION, __version__, reads, read_workflow
from .auth_artifacts import HeadUnitAuthenticationArtifactStore, BDCAuthenticationArtifactStore, VSGAuthenticationArtifactStore
from .auth_evidence import MODES, load_auth_session_evidence, load_auth_seed_evidence, svk_module, auth_command
from .coding_preparation import CodingPreparationError
from .coding_contract import contract, transaction_bounds
from .coding_snapshot import load_coding_snapshot
from .coding_snapshot_artifacts import load_acquired_snapshot
from .block_evidence import load_bdc_cps_original, load_vsg_cps_original
from .coding_transport import TransactionPhase, TransactionSelection
from .signing_keys import SigningKeyError, configuration_pin, bundled_configuration
from .evidence import EvidenceError, load_gateway_identity_evidence, load_gateway_vin_read_evidence
from .live_head_unit_auth import AuthProfile, observe_extended_session_once, capture_auth_seed_once, capture_bdc_seed_once, capture_vsg_seed_once
from .network import identity_preflight
from .profiles import MODULES, CODING_MODULES, resolve_parameter, module_identity
from .coding_transaction import PinnedOriginal, CodingProofs, run_coding_transaction
from .svk import load_head_unit_svk_evidence, load_bdc_svk_evidence, load_vsg_svk_evidence

_COUNTERS = ('vehicle_bytes_confirmed_sent', 'application_frames_attempted', 'application_frames_sent',
             'tcp_connections_attempted', 'tcp_connections_opened', 'vehicle_packets_attempted', 'vehicle_packets_sent')


def add_arguments(parser):
    parser.add_argument('--ip', help='Mac ENET IPv4 address')
    parser.add_argument('--ecu', choices=MODULES, help='Module: HU, BDC or VSG01')
    parser.add_argument('--parm', dest='parameter', metavar='GROUP/PARAMETER', help='Verified parameter path within the module')
    parser.add_argument('--value', help='Parameter value in hexadecimal, for example 00 or 01')
    parser.add_argument('--keys', type=Path, metavar='CONFIG', help='Optional local signing-key configuration; defaults to bundled profile keys')
    parser.add_argument('--expect', help='Optional original parameter value; a mismatch stops')
    parser.add_argument('--live', action='store_true', help='Capture fresh originals, review, and explicitly approve coding')
    parser.add_argument('--json', action='store_true', help='Print safe plan/result and artifact references')


def _hex(text):
    if type(text) is not str:
        raise CodingPreparationError('hex_bytes_required')
    if text[:2].lower() == '0x':
        text = text[2:]
    if not text or any(c not in '0123456789abcdefABCDEF' for c in text) or len(text) % 2:
        raise CodingPreparationError('hex_bytes_required')
    return bytes.fromhex(text)


def selected_edit(args):
    try:
        address = ipaddress.IPv4Address(args.ip)
    except ipaddress.AddressValueError:
        raise CodingPreparationError('link_local_mac_ip_required') from None
    if (str(address) != args.ip or not address.is_link_local
            or int(address) & 0xFFFF in (0, 0xFFFF)):
        raise CodingPreparationError('link_local_mac_ip_required')
    parameter = resolve_parameter(args.ecu, args.parameter)
    value = _hex(args.value)
    expected = None if args.expect is None else _hex(args.expect)
    return parameter.edit(value, expected)


def _auth_capture(reader, network, identity, svk, session=None):
    module = svk_module(svk)
    with {'HU':HeadUnitAuthenticationArtifactStore, 'BDC':BDCAuthenticationArtifactStore,
          'VSG01':VSGAuthenticationArtifactStore}[module](Path.cwd()) as store:
        result = (reader(network, identity, svk) if session is None else
                  reader(network, identity, svk, AuthProfile('opaque_parameters')))
        report = result.public_report()
        report.update(command=auth_command(result.mode, module), implementation_version=__version__, exchange_mode=result.mode,
            source_interface=network.interface, source_address=network.source_address,
            gateway_address=network.gateway_address, interface_index=network.interface_index,
            selected_session_layout=None if session is None else 'opaque_parameters')
        report['raw_artifacts'] = store.save_auth(result, report, identity, svk, session_evidence=session)
    if report['raw_artifacts'].get('complete_original_stream_validated') is not True:
        raise EvidenceError('authentication_originals_incomplete')
    return report


def run(args):
    supported = args.ecu in CODING_MODULES
    frames, byte_cap, _ = transaction_bounds(args.ecu) if supported else (0,0,0)
    spec = contract(args.ecu) if supported else None
    report = dict(command='code', schema_version=REPORT_SCHEMA_VERSION, implementation_version=__version__,
        mode='live_coding' if args.live else 'coding_plan', outcome='plan_only', source_address=args.ip, ecu=args.ecu,
        **module_identity(args.ecu),
        steps=[], transaction_complete=False,
        maximum_application_frames={'HU':53,'BDC':353,'VSG01':37}.get(args.ecu,0) if supported else 0,
        maximum_application_bytes={'HU':1771,'BDC':10880,'VSG01':699}.get(args.ecu,0) if supported else 0,
        maximum_tcp_connections=8 if args.ecu == 'HU' else 9 if supported else 0, maximum_udp_packets=1 if supported else 0,
        transaction_maximum_application_frames=frames, transaction_maximum_application_bytes=byte_cap,
        coding_write_performed=False, transmission_uncertain=False, traffic_accounting_uncertain=False)
    report.update({key: 0 for key in _COUNTERS})
    in_flight = False
    stage = 'selection'
    try:
        edit = selected_edit(args)
        report.update(logical_change=edit.summary(), parameter=args.parameter,
                      parameter_value_hex='0x' + _hex(args.value).hex().upper(),
                      meaning_evidence_status='SOURCE_SUPPORTED', planned_whole_group_count=len(spec.groups),
                      activation='reset' if args.ecu == 'HU' else 'default_session')
        if not args.live:
            return report
        if not sys.stdin.isatty():
            raise EvidenceError('live_approval_requires_a_terminal')
        stage = 'signing_configuration'
        key_configuration = bundled_configuration(args.ecu) if args.keys is None else args.keys.absolute()
        key_pin = configuration_pin(key_configuration)
        from .auth_provider import validate_auth_reference
        from .coding_provider import validate_coding_reference
        validate_auth_reference(key_configuration, key_pin, module=args.ecu)
        validate_coding_reference(key_configuration, key_pin, module=args.ecu)

        def perform(name, callback, expected):
            nonlocal stage, in_flight
            stage = name; in_flight = True
            step = callback()
            if expected == 'block_read':
                step = dict(step, timing_complete=len(step.get('steps', [])) == 4 and
                            all(s.get('timing_complete') is True for s in step['steps']))
            report['steps'].append(step)
            for key in read_workflow._UNCERTAINTIES:
                report[key] = bool(report.get(key, False) or step.get(key, False))
            for key in _COUNTERS:
                amount = step.get(key, 0)
                if amount is None or report[key] is None:
                    report[key] = None
                    report['traffic_accounting_uncertain'] = True
                else:
                    report[key] += amount
            in_flight = False
            if not read_workflow._successful(step, expected):
                raise EvidenceError('coding_prerequisite_failed')
            return step

        observed = perform('fresh_identity_software', lambda: read_workflow.read('read-block', args.ip, live=True,
                           ecu=args.ecu, parameter=args.parameter), 'block_read')
        request = reads.ReadRequest(observed['source_interface'], args.ip, observed['gateway_address'], live=True)
        pins = {}
        for name, step in zip(('discovery', 'identity', 'svk'), observed['steps'][:3]):
            request = read_workflow._retained(request, step, name)
            pins[name] = PinnedOriginal(getattr(request, name + '_directory'), getattr(request, name + '_manifest_sha256'))
        discovery = load_gateway_identity_evidence(pins['discovery'].directory, manifest_sha256=pins['discovery'].manifest_sha256,
            gateway_address=request.gateway, source_interface=request.interface, source_address=args.ip)
        identity = load_gateway_vin_read_evidence(pins['identity'].directory, manifest_sha256=pins['identity'].manifest_sha256,
            discovery=discovery)
        svk = {'HU':load_head_unit_svk_evidence,'BDC':load_bdc_svk_evidence,'VSG01':load_vsg_svk_evidence}[args.ecu](pins['svk'].directory, manifest_sha256=pins['svk'].manifest_sha256,
                                        discovery=discovery, identity=identity)
        snapshot_report = perform('fresh_complete_originals', lambda: reads.read_snapshot(request, module=args.ecu), 'snapshot_observed')
        original = snapshot_report['raw_artifacts']['original_snapshot']
        pins['snapshot'] = PinnedOriginal(Path(original['directory']), original['manifest_sha256'])
        network = identity_preflight(request.interface, args.ip, request.gateway)
        if network.interface_index != discovery.interface_index:
            raise EvidenceError('current_interface_index_changed')
        snapshot = (load_acquired_snapshot(pins['snapshot'].directory, pins['snapshot'].manifest_sha256,
                    network=network, identity=identity, svk=svk) if args.ecu != 'HU' else
                    load_coding_snapshot(pins['snapshot'].directory, pins['snapshot'].manifest_sha256))
        if args.ecu != 'HU':
            cps_reader, cps_kind, cps_loader = {'BDC':(reads.read_bdc_metadata,'bdc_cps',load_bdc_cps_original),
                'VSG01':(reads.read_vsg_metadata,'vsg_cps',load_vsg_cps_original)}[args.ecu]
            cps_report = perform('fresh_original_cps', lambda: cps_reader(request, cps_kind), 'coding_value_observed')
            artifact = cps_report['raw_artifacts']
            pins['cps'] = PinnedOriginal(Path(artifact['directory']), artifact['manifest_sha256'])
            cps = cps_loader(pins['cps'].directory, pins['cps'].manifest_sha256,
                network=(network.interface, network.source_address, network.gateway_address, network.interface_index),
                proofs=tuple((name, pins[name].directory, pins[name].manifest_sha256) for name in ('discovery','identity','svk')))
            if cps != discovery.vin_candidate[-7:].encode('ascii'):
                raise EvidenceError('original_cps_mismatch')
        stage = 'review_selected_edit'
        selected = dict(snapshot.groups)[edit.group][edit.offset:edit.offset + len(edit.value)]
        parameter = resolve_parameter(args.ecu, args.parameter)
        decoded = parameter.decode(dict(snapshot.groups)[edit.group])
        if _hex(decoded['parameter_value_hex']) not in dict(parameter.meanings):
            raise CodingPreparationError('named_parameter_original_not_supported')
        edit.signing_input(snapshot)  # Enforce expected bytes and reject no-op before sessions/signing.
        report['selected_original_sha256'] = hashlib.sha256(selected).hexdigest()
        print(f"Car gateway: {request.gateway}; VIN: {'*' * 13 + discovery.vin_candidate[-4:]}", file=sys.stderr)
        print(f"ECU {args.ecu} (0x{spec.target:02X}) / {spec.cafd}; {args.parameter}: "
              f"{decoded['parameter_value_hex']} -> {report['parameter_value_hex']}.", file=sys.stderr)
        print(f'Parameter: {args.parameter}; selected original bytes are retained privately.', file=sys.stderr)
        print(f"Approve {len(spec.groups)} whole groups/signature, coding metadata, {report['activation']} and complete readback; no automatic retry/restore.", file=sys.stderr)
        print('Use at your own risk. No warranties or guarantees of compatibility, successful coding or recovery.', file=sys.stderr)
        print('Coding tested on a 2017 BMW i3 with the supported software profiles.', file=sys.stderr)
        print('Approval acknowledges these risks and confirms a parked/awake car, exclusive diagnostics and your recovery fallback for this module.', file=sys.stderr)
        approval = 'CODE HEADUNIT' if args.ecu == 'HU' else f'CODE {args.ecu}'
        print(f'Type {approval} to approve: ', end='', flush=True, file=sys.stderr)
        if input() != approval:
            report.update(outcome='cancelled', reason='change_not_approved')
            return report
        network = identity_preflight(request.interface, args.ip, request.gateway)
        if network.interface_index != discovery.interface_index:
            raise EvidenceError('current_interface_index_changed')
        probe_report = perform('session_probe', lambda: _auth_capture(observe_extended_session_once, network, identity, svk), 'extended_session_observed')
        probe_artifact = probe_report['raw_artifacts']
        pins['session'] = PinnedOriginal(Path(probe_artifact['directory']), probe_artifact['manifest_sha256'])
        probe = load_auth_session_evidence(pins['session'].directory, pins['session'].manifest_sha256,
            identity=identity, svk=svk, session_layout='opaque_parameters')
        seed_mode, seed_reader = {'HU':('capture_auth_seed',capture_auth_seed_once),
            'BDC':('capture_bdc_seed_and_default',capture_bdc_seed_once),
            'VSG01':('capture_vsg_seed_and_default',capture_vsg_seed_once)}[args.ecu]
        seed_report = perform('session_seed_prerequisite', lambda: _auth_capture(
            seed_reader, network, identity, svk, probe), MODES[seed_mode][1])
        seed_artifact = seed_report['raw_artifacts']
        pins['seed'] = PinnedOriginal(Path(seed_artifact['directory']), seed_artifact['manifest_sha256'])
        seed = load_auth_seed_evidence(pins['seed'].directory, pins['seed'].manifest_sha256,
            identity=identity, svk=svk, session_evidence=probe, mode=seed_mode)
        if seed.seed_byte_length != 8:
            raise EvidenceError('unsupported_seed_width')
        stage = 'coding_transaction'; in_flight = True
        transaction = run_coding_transaction(network, CodingProofs(**pins), key_configuration, key_pin,
            project_directory=Path.cwd(), edit=edit,
            selection=TransactionSelection(phase=TransactionPhase.CODING, change_approved=True,
                risk_acknowledged=True, recovery_confirmed=True,
                exclusive_diagnostics_confirmed=True, parked_awake_confirmed=True))
        for key in _COUNTERS:
            amount = transaction.get(key, 0)
            report[key] = None if amount is None or report[key] is None else report[key] + amount
        in_flight = False
        attempts = transaction.get('coding_group_write_attempts')
        report.update(transaction=transaction, outcome=transaction.get('outcome', 'coding_stopped'),
            reason=transaction.get('reason'), transaction_complete=transaction.get('transaction_complete') is True,
            coding_write_performed=(attempts > 0 if type(attempts) is int else
                                    False if transaction.get('vehicle_traffic_performed') is False else None),
            traffic_accounting_uncertain=any(report[key] is None for key in _COUNTERS),
            transmission_uncertain=report['transmission_uncertain'] or transaction.get('transmission_uncertain', False),
            raw_artifacts=transaction.get('raw_artifacts'))
        for key in read_workflow._UNCERTAINTIES:
            report[key] = bool(report.get(key, False) or transaction.get(key, False))
    except CodingPreparationError as exc:
        report.update(outcome='already_set' if exc.reason == 'coding_value_already_set' else 'coding_stopped', reason=exc.reason, failed_step=stage)
        if exc.reason == 'unsupported_ecu_profile':
            report['message'] = f"{report['ecu']} coding is not supported yet; its parameter mappings and native transaction must be validated first."
    except (Exception, KeyboardInterrupt) as exc:
        report.update(outcome='coding_stopped', reason=exc.reason if type(exc) in (EvidenceError, SigningKeyError) else
                      'coding_or_original_validation_failed', failed_step=stage)
        if in_flight:
            report.update({key: None for key in _COUNTERS})
            report.update(traffic_accounting_uncertain=True, transmission_uncertain=True, coding_write_performed=None)
    return report


def display(report):
    target = report['ecu'] + (f" ({report['diagnostic_address']})" if report['diagnostic_address'] else '')
    print(f"Coding: {report['outcome']}; Mac IP: {report['source_address']}; ECU: {target}")
    change = report.get('logical_change')
    if change:
        print(f"{report['parameter']}: {report['parameter_value_hex']}")
    if report['outcome'] == 'plan_only':
        print('Offline plan: fresh originals -> review/approval -> authentication/signing -> whole groups/activation/readback.')
        print('Add --live to capture and review the selected software profile.')
    else:
        print(f"Confirmed application bytes sent: {report['vehicle_bytes_confirmed_sent']}")
        artifact = report.get('raw_artifacts') or {}
        if artifact.get('directory'):
            print(f"Private journal: {artifact['directory']}")
        if report.get('transaction_complete'):
            print('Complete coding/signature/metadata readback verified; observe the intended behavior separately.')
        elif report['outcome'] == 'already_set':
            print('Selected bytes already match; no session change, protected loading or coding write.')
        else:
            print(f"Stopped at {report.get('failed_step', 'transaction')}: {report.get('reason')}")
            print(report.get('message') or 'Review retained artifacts before further action. No automatic retry or restore.')
