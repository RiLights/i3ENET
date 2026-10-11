"""Profile-bound native field transaction orchestration; no implicit live call.

Execution defaults to DENY, opens private storage before loading two distinct
configured signing roles, and always closes their handles. Tests mock all protected
loading and native operations. A successful offline test grants no live approval.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from .auth_evidence import load_auth_session_evidence, load_auth_seed_evidence
from .auth_provider import validate_auth_reference, load_auth_provider
from .coding_journal import CodingJournal
from .coding_preparation import CodingEdit
from .coding_provider import validate_coding_reference, load_coding_provider
from .coding_snapshot import load_coding_snapshot
from .coding_snapshot_artifacts import load_acquired_snapshot
from .coding_transport import TransactionInputs, TransactionSelection, execute_coding_transaction
from .evidence import load_gateway_identity_evidence, load_gateway_vin_read_evidence
from .live_head_unit_auth import AuthProfile
from .network import GatewayNetwork, identity_preflight
from .policy import PolicyViolation
from .svk import load_head_unit_svk_evidence, load_bdc_svk_evidence, load_vsg_svk_evidence
from .block_evidence import load_bdc_cps_original, load_vsg_cps_original


@dataclass(frozen=True, slots=True)
class PinnedOriginal:
    directory: Path = field(repr=False)
    manifest_sha256: str

    def __post_init__(self):
        if (not isinstance(self.directory, Path) or type(self.manifest_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}', self.manifest_sha256) is None):
            raise PolicyViolation('coding_original_selection_invalid')


@dataclass(frozen=True, slots=True)
class CodingProofs:
    discovery: PinnedOriginal
    identity: PinnedOriginal
    svk: PinnedOriginal
    session: PinnedOriginal
    seed: PinnedOriginal
    snapshot: PinnedOriginal
    cps: PinnedOriginal | None = None

    def validate(self):
        for name in self.__dataclass_fields__:
            item = getattr(self, name)
            if name == 'cps' and item is None: continue
            if type(item) is not PinnedOriginal:
                raise PolicyViolation('coding_proof_selection_invalid')
            PinnedOriginal.__post_init__(item)

    def pins(self) -> dict[str, str]:
        self.validate()
        return {name: getattr(self, name).manifest_sha256 for name in self.__dataclass_fields__ if getattr(self,name) is not None}


def load_transaction_inputs(network: GatewayNetwork, proofs: CodingProofs,
                            edit: CodingEdit) -> TransactionInputs:
    """Reopen original bytes under their pins; acquire no new vehicle evidence."""
    if type(network) is not GatewayNetwork or type(proofs) is not CodingProofs:
        raise PolicyViolation('coding_input_selection_invalid')
    GatewayNetwork.__post_init__(network)
    proofs.validate()
    if type(edit) is not CodingEdit:
        raise PolicyViolation('coding_edit_invalid')
    edit.__post_init__()
    discovery = load_gateway_identity_evidence(
        proofs.discovery.directory, manifest_sha256=proofs.discovery.manifest_sha256,
        gateway_address=network.gateway_address, source_interface=network.interface,
        source_address=network.source_address)
    identity = load_gateway_vin_read_evidence(
        proofs.identity.directory, manifest_sha256=proofs.identity.manifest_sha256, discovery=discovery)
    svk = {'HU':load_head_unit_svk_evidence, 'BDC':load_bdc_svk_evidence, 'VSG01':load_vsg_svk_evidence}[edit.module](
        proofs.svk.directory, manifest_sha256=proofs.svk.manifest_sha256,
        discovery=discovery, identity=identity)
    probe = load_auth_session_evidence(
        proofs.session.directory, proofs.session.manifest_sha256,
        identity=identity, svk=svk, session_layout='opaque_parameters')
    seed = load_auth_seed_evidence(
        proofs.seed.directory, proofs.seed.manifest_sha256, identity=identity,
        svk=svk, session_evidence=probe, mode={'HU':'capture_auth_seed',
            'BDC':'capture_bdc_seed_and_default', 'VSG01':'capture_vsg_seed_and_default'}[edit.module])
    original = (load_acquired_snapshot(proofs.snapshot.directory, proofs.snapshot.manifest_sha256,
                  network=network, identity=identity, svk=svk) if edit.module != 'HU' else
                load_coding_snapshot(proofs.snapshot.directory, proofs.snapshot.manifest_sha256))
    # Validate the selected region and expected bytes before signing or traffic.
    edit.signing_input(original)
    cps = None
    if edit.module != 'HU':
        if proofs.cps is None: raise PolicyViolation('original_cps_required')
        cps = {'BDC':load_bdc_cps_original, 'VSG01':load_vsg_cps_original}[edit.module](proofs.cps.directory, proofs.cps.manifest_sha256,
            network=(network.interface, network.source_address, network.gateway_address, network.interface_index),
            proofs=tuple((name, getattr(proofs,name).directory, getattr(proofs,name).manifest_sha256)
                         for name in ('discovery','identity','svk')))
    elif proofs.cps is not None: raise PolicyViolation('hu_cps_proof_not_selected')
    result = TransactionInputs(network, identity, svk, original, probe, seed, edit, cps,
                               None if proofs.cps is None else proofs.cps.manifest_sha256)
    result.validate()
    return result


def run_coding_transaction(network: GatewayNetwork, proofs: CodingProofs,
                            signing_configuration: Path, configuration_sha256: str, *,
                            project_directory: Path,
                            selection: TransactionSelection = TransactionSelection(),
                            edit: CodingEdit) -> dict:
    """Native library entry for an explicitly selected complete operation.

    No injection or arbitrary request parameters are exposed here. Selection
    records approval and risk acknowledgement and attests recovery/operating
    conditions; it measures none of them. DENY happens before original loading,
    storage, keys or sockets.
    Caller must review this exact operation and its private mutation journal.
    """
    if type(selection) is not TransactionSelection:
        raise PolicyViolation('coding_transaction_selection_invalid')
    selection.validate()
    inputs = load_transaction_inputs(network, proofs, edit)
    if inputs.original.provenance == 'synthetic_fixture':
        raise PolicyViolation('synthetic_originals_not_native_authority')
    as_reference = validate_auth_reference(signing_configuration, configuration_sha256, module=edit.module)
    ncds_reference = validate_coding_reference(signing_configuration, configuration_sha256, module=edit.module)
    if identity_preflight(network.interface, network.source_address, network.gateway_address) != network:
        raise PolicyViolation('coding_current_network_changed')

    binding = (network.interface, network.source_address, network.gateway_address,
               network.interface_index, network.netmask, network.hardware_port)
    journal = CodingJournal(project_directory, binding=binding,
                            source_pins=dict(proofs.pins(), signing_configuration=configuration_sha256),
                            evidence_status='LOCAL_OBSERVATION', edit=edit)
    as_provider = ncds_provider = result = None
    engine_started = False
    integration_failed = False
    report = {'outcome': 'provider_preparation_failed', 'reason': 'signing_providers_unavailable',
              'application_frames_attempted': 0, 'application_frames_sent': 0,
              'vehicle_bytes_confirmed_sent': 0, 'tcp_connections_attempted': 0,
              'tcp_connections_opened': 0, 'transaction_complete': False,
              'originals_complete': False, 'vehicle_traffic_performed': False}
    try:
        as_provider = load_auth_provider(as_reference)
        ncds_provider = load_coding_provider(ncds_reference)
        engine_started = True
        result = execute_coding_transaction(inputs, selection, ncds_provider, as_provider, journal)
        # A returned result can precede a reporting failure. Discard the
        # pre-engine zero counters before calling any report method.
        report.update(outcome='integration_failed', reason='transaction_report_unavailable',
                      vehicle_traffic_performed=None, transmission_uncertain=True,
                      application_frames_attempted=None, application_frames_sent=None,
                      vehicle_bytes_confirmed_sent=None, tcp_connections_attempted=None,
                      tcp_connections_opened=None)
        report = dict(result.public_report(), transaction_complete=False, originals_complete=False)
        report['signing_providers'] = {
            'AS': as_provider.safe_summary(), 'NCDS': ncds_provider.safe_summary()}
    except (Exception, KeyboardInterrupt):
        # Providers fail before a socket; the engine itself retains all partial
        # attempt facts. Never turn an unexpected integration failure into a
        # zero-traffic assertion after it was invoked.
        integration_failed = True
        if result is None and engine_started:
            report.update(outcome='integration_failed', reason='transaction_result_unavailable',
                          vehicle_traffic_performed=None, transmission_uncertain=True,
                          application_frames_attempted=None, application_frames_sent=None,
                          vehicle_bytes_confirmed_sent=None, tcp_connections_attempted=None,
                          tcp_connections_opened=None)
        elif result is not None:
            report.update(outcome='integration_failed', reason='transaction_report_unavailable')
    finally:
        try:
            vin = inputs.identity.discovery.vin_candidate
            artifacts = journal.finish(
                prepared=None if result is None else result.prepared,
                as_public_key=None if as_provider is None else as_provider.public_key,
                expected_vin=vin, expected_svk=b'' if result is None or result.current_svk is None else result.current_svk,
                expected_cps=vin[-7:].encode('ascii'), profile=AuthProfile('opaque_parameters', 8),
                result_report=report)
            report.update(raw_artifacts=artifacts, originals_complete=True)
            report['transaction_complete'] = (
                not integration_failed
                and report.get('complete_candidate_signature_cps_readback_verified') is True
                and artifacts.get('complete_data_verified') is True)
        except (Exception, KeyboardInterrupt):
            report.update(originals_complete=False, transaction_complete=False,
                          raw_artifacts={'directory': str(journal.directory), 'complete': False})
        for provider in (as_provider, ncds_provider):
            if provider is not None:
                try:
                    provider.close()
                except (Exception, KeyboardInterrupt):
                    report.update(provider_cleanup_uncertain=True, transaction_complete=False)
        try:
            journal.close()
        except (Exception, KeyboardInterrupt):
            report.update(storage_close_uncertain=True, originals_complete=False, transaction_complete=False)
    return report
