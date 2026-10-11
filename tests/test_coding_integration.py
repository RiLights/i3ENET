"""Native facade and durable journal tested against synthetic transport originals."""
from support import DEFAULT_EDIT
from contextlib import contextmanager, ExitStack
import json
import os
from unittest.mock import patch, Mock
from i3enet import coding_transport as transport, coding_transaction as s
from i3enet.auth_provider import ASAuthProvider
from i3enet.coding_provider import NCDSCodingProvider
from i3enet.coding_journal import CodingJournal, JournalError, validate_journal
from i3enet.live_head_unit_auth import AuthProfile
from coding_synthetic_fixture import synthetic_private_key
from support import OfflineCase, mocked
from test_coding_transport import Clock, Connector, synthetic_inputs
from dataclasses import replace
from pathlib import Path
from i3enet.coding_transport import TransactionPhase, TransactionSelection
from i3enet.policy import PolicyViolation


class CodingJournalTests(OfflineCase):
    def setUp(self):
        self.root = self.temporary()
        self.forbid("socket.socket", "socket.getaddrinfo", "subprocess.run", "subprocess.Popen")
        self.inputs = synthetic_inputs()
        network = self.inputs.network
        self.binding = (network.interface, network.source_address, network.gateway_address,
                        network.interface_index, network.netmask, network.hardware_port)
        self.pins = dict(discovery=self.inputs.identity.discovery.manifest_sha256,
                         identity=self.inputs.identity.manifest_sha256, svk=self.inputs.svk.manifest_sha256)
        self.vin = self.inputs.identity.discovery.vin_candidate

    def journal(self):
        return CodingJournal(self.root, binding=self.binding, source_pins=self.pins,
                             evidence_status="SYNTHETIC_FIXTURE", edit=self.inputs.edit if self.inputs.edit.module != "HU" else None)

    @contextmanager
    def transaction(self, *, failure=None, configure=lambda journal: None):

        ncds = NCDSCodingProvider._from_key(synthetic_private_key(), "f" * 64, "a" * 64, module=self.inputs.edit.module)
        auth = ASAuthProvider._from_key(synthetic_private_key(True), "f" * 64, "a" * 64, module=self.inputs.edit.module)
        self.addCleanup(ncds.close); self.addCleanup(auth.close)
        clock = Clock(); connector = Connector(self.inputs, clock)
        if failure: connector.failure_at, connector.failure_kind = failure
        with self.journal() as journal:
            configure(journal)
            selection = transport.TransactionSelection(transport.TransactionPhase.CODING,
                                                       True, True, True, True, True)
            result = transport.execute_coding_transaction(self.inputs, selection, ncds, auth, journal,
                                             connector=connector, clock=clock.now, wait=clock.wait)
            facts = dict(prepared=result.prepared, as_public_key=auth.public_key, expected_vin=self.vin,
                         expected_svk=result.current_svk, expected_cps=result.expected_cps,
                         profile=AuthProfile("opaque_parameters", 8))
            yield journal, result, facts, connector, clock

    def finish(self, journal, result, facts):
        return journal.finish(**facts, result_report=result.public_report())

    def begin(self, journal):
        journal.connection_attempted(1, 0.0); journal.opened(1, 0.01)
        raw = bytes.fromhex("000000050001f41022f190")
        return raw, journal.before_attempt("current_vin", raw, connection_index=1, at=0.02)

    def test_module_full_journal_seal_reopen_and_raw_request_corruption(self):
        for module,frames,byte_cap,count,request in (('BDC',261,9863,82,'request-090.bin'),('VSG01',24,551,3,'request-012.bin')):
            self.inputs=synthetic_inputs(module=module)
            with self.transaction() as (journal, result, facts, connector, clock):
                summary = self.finish(journal, result, facts)
                self.fields(summary,complete_data_verified=True,request_intents=frames,confirmed_application_bytes=byte_cap,
                            complete_readback_group_count=count,AS_signature_verified=True)
                self.assertFalse(result.reset_attempted); self.assertEqual(clock.waits,[])
                checked=validate_journal(journal.directory,expected_context=journal._context,
                                         manifest_sha256=summary['manifest_sha256'],**facts)
                self.assertTrue(checked['complete_data_verified'])
                with self.assertRaises(JournalError):
                    validate_journal(journal.directory,expected_context=dict(journal._context,module='HU'),
                                     manifest_sha256=summary['manifest_sha256'],**facts)
                path=journal.directory/request; raw=path.read_bytes(); path.write_bytes(raw[:-1]+bytes((raw[-1]^1,)))
                with self.assertRaises(JournalError):
                    validate_journal(journal.directory,expected_context=journal._context,
                                     manifest_sha256=summary['manifest_sha256'],**facts)

    def test_engine_journal_seals_complete_pending_and_partial_originals(self):
        for failure in (None, (22, "pending_once"), (14, "partial"), (0, "wrong_positive")):
            with self.subTest(failure=failure), self.transaction(failure=failure) as (journal, result, facts, connector, clock):
                failed = failure not in (None, (22, "pending_once")); partial = failure == (14, "partial")
                summary = self.finish(journal, result, facts)
                self.fields(summary, complete_data_verified=not failed, transmission_uncertain=partial,
                            request_intents=15 if partial else 1 if failed else 38,
                            confirmed_application_bytes=sum(map(len, connector.frames)) - int(partial))
                self.assertTrue(all(connection.closed for connection in connector.connections))
                self.assertEqual(clock.waits, [] if failed else [30.0])
                reread = validate_journal(journal.directory, expected_context=journal._context,
                                          manifest_sha256=summary["manifest_sha256"], **facts)
                self.assertEqual(reread["complete_data_verified"], not failed)
                if not failed:
                    self.fields(reread, ACK_count=38, complete_readback_group_count=8, AS_signature_verified=True,
                                returned_signature_verified=True, pending_count=int(failure is not None),
                                persistence_established=False, storage_is_send_authority=False)
                    self.redacted(json.dumps(summary) + repr(journal), self.vin, result.prepared.candidate.signature.hex())
                    self.private(journal.directory)
                    with self.assertRaises(JournalError): validate_journal(journal.directory, expected_context=journal._context, **facts)
                    with self.assertRaises(JournalError): journal.connection_attempted(1, 0.0)

    def test_wrong_saved_ack_identity_candidate_cps_and_signature_never_promote(self):
        # The engine sees valid replies. Only the journal's originals are changed,
        # proving that storage performs its own protocol and signature validation.
        for stage in ("current_vin", "security_key", "write_3001", "check_signature", "post_vin",
                      "readback_3001", "post_cps", "post_ping", "security_seed"):
            def configure(journal):
                original = journal.received
                def received(token, raw, at=None):
                    if journal._intents[token - 1]["stage"] == stage:
                        offset = 12 if stage == "security_key" else len(raw) - 1
                        raw = raw[:offset] + bytes((raw[offset] ^ 1,)) + raw[offset + 1:]
                    return original(token, raw, at)
                journal.received = received
            with self.subTest(stage=stage), self.transaction(configure=configure) as (journal, result, facts, _, _):
                self.assertEqual(result.outcome, "candidate_readback_verified")
                self.assertFalse(self.finish(journal, result, facts)["complete_data_verified"])

    def test_incomplete_storage_preserves_raw_bytes_and_honest_counts(self):
        for accepted in (4, None):
            with self.subTest(accepted=accepted), self.journal() as journal:
                raw, token = self.begin(journal)
                if accepted is not None: journal.after_attempt(token, accepted, True, None)
                journal.closed(1, False, 0.03)
                with patch("i3enet.coding_journal.verify_coding1", side_effect=AssertionError("no crypto")):
                    summary = journal.finish(prepared=None, as_public_key=None, expected_vin=self.vin,
                        expected_svk=b"", expected_cps=b"", profile=None, result_report={})
                self.fields(summary, complete_data_verified=False, confirmed_application_bytes=accepted or 0,
                            transmission_uncertain=True, recorded_attempt_results=int(accepted is not None))
        with self.journal() as journal:
            raw, token = self.begin(journal); journal.after_attempt(token, len(raw), False, None)
            with patch.object(journal, "_append", side_effect=OSError("synthetic storage failure")), self.assertRaises(OSError):
                journal.received(token, b"SYNTHETIC-RECEIVED")
            self.assertEqual((journal.directory / "recv-001.bin").read_bytes(), b"SYNTHETIC-RECEIVED")

    def test_replay_enforces_response_connection_and_global_deadlines(self):
        for boundary in ("missing_receipt_time", "response", "connection", "reconnect", "global"):
            def configure(journal):
                receive, closed, connected = journal.received_at, journal.closed, journal.connection_attempted
                def receipt(number, at):
                    if boundary == "missing_receipt_time" and len(journal._intents) == 38: return
                    return receive(number, journal._intents[-1]["send_at"] + 3
                                   if boundary == "response" and len(journal._intents) == 38 else at)
                journal.received_at = receipt
                journal.closed = lambda index, uncertain, at: closed(index, uncertain,
                    30.0 if boundary == "connection" and index == 1 else
                    90.0 if boundary == "global" and index == 2 else at)
                journal.connection_attempted = lambda index, at: connected(index,
                    at - 1 if boundary == "reconnect" and index == 2 else at)
            with self.subTest(boundary=boundary), self.transaction(configure=configure) as (journal, result, facts, _, _):
                summary = self.finish(journal, result, facts)
                self.fields(summary, complete_data_verified=False, full_requests_confirmed=38)
                self.assertGreater(summary["received_bytes"], 0)

    def test_unsafe_intents_files_and_hash_chain_cannot_be_sealed(self):
        for attack in ("raw", "chain", "mode", "link"):
            with self.subTest(attack=attack), self.transaction() as (journal, result, facts, _, _):
                path = journal.directory / "recv-001.bin"
                if attack == "raw": path.write_bytes(path.read_bytes()[:-1] + b"X")
                elif attack == "chain":
                    events = journal.directory / "events.jsonl"; events.write_bytes(events.read_bytes()[:-1])
                elif attack == "mode": path.chmod(0o644)
                else: os.link(path, journal.directory / "alias.bin")
                with self.assertRaises((JournalError, OSError)): self.finish(journal, result, facts)
                self.assertFalse((journal.directory / "manifest.json").exists())
        with self.journal() as journal:
            raw, token = self.begin(journal)
            self.assertEqual((journal.directory / "request-001.bin").read_bytes(), raw)
        for stage, request, conn in (("write_3001", raw, 1), ("current_vin", bytearray(raw), 1),
                                     ("current_vin", raw, 2), ("current_vin", raw + b"\0", 1)):
            with self.subTest(stage=stage), self.journal() as journal:
                journal.connection_attempted(1, 0.0); journal.opened(1, 0.01)
                with self.assertRaises(JournalError):
                    journal.before_attempt(stage, request, connection_index=conn, at=0.02)
        with self.assertRaises(JournalError):
            CodingJournal(self.root, binding=self.binding, source_pins={"discovery": "NOT-A-PIN"},
                          evidence_status="SYNTHETIC_FIXTURE")

class CodingTransactionTests(OfflineCase):
    def setUp(self):
        self.forbid('socket.socket', 'socket.getaddrinfo', 'subprocess.Popen')
        self.inputs = synthetic_inputs()
        self.network = self.inputs.network
        pins = (self.inputs.identity.discovery.manifest_sha256, self.inputs.identity.manifest_sha256,
                self.inputs.svk.manifest_sha256, self.inputs.probe.manifest_sha256,
                self.inputs.seed.manifest_sha256, "5" * 64)
        self.proofs = s.CodingProofs(*(s.PinnedOriginal(Path('/synthetic') / name, pin)
            for name, pin in zip(('discovery', 'identity', 'svk', 'session', 'seed', 'snapshot'),
                                 pins)))
        self.selected = TransactionSelection(TransactionPhase.CODING, True, True, True, True, True)
        self.reference = Path('/synthetic/reference'); self.ref_pin = 'f' * 64

    @contextmanager
    def facade(self, inputs, *, network=None):
        """Fresh mocks isolate each integration failure; no real loader runs."""
        reference = Mock(); reference.public_report.return_value = {"validated": True}
        auth, ncds, journal, result = (Mock() for _ in range(4))
        auth.safe_summary.return_value = {"role": "AS"}
        ncds.safe_summary.return_value = {"role": "NCDS"}
        journal.directory = Path("/synthetic/journal")
        journal.finish.return_value = {"complete_data_verified": True}
        result.public_report.return_value = {
            "complete_candidate_signature_cps_readback_verified": True,
            "outcome": "candidate_readback_verified"}
        result.current_svk = b"SYNTHETIC-SVK"
        returns = {"load_transaction_inputs": inputs, "validate_auth_reference": reference,
                   "validate_coding_reference": reference, "identity_preflight": network or self.network,
                   "CodingJournal": journal, "load_auth_provider": auth,
                   "load_coding_provider": ncds, "execute_coding_transaction": result}
        with ExitStack() as stack:
            operations = {name: stack.enter_context(patch.object(s, name, return_value=value))
                          for name, value in returns.items()}
            yield operations, auth, ncds, journal, result

    def run_selected(self, selection):
        return s.run_coding_transaction(self.network, self.proofs, self.reference, self.ref_pin,
                                        project_directory=Path("/synthetic"), selection=selection, edit=DEFAULT_EDIT)

    def test_native_selection_originals_and_binding_gate_all_io(self):
        native = replace(self.inputs, original=replace(self.inputs.original, provenance="unverified_import"))
        cases = [("not_selected", native, selection, self.network, set()) for selection in (
            TransactionSelection(), replace(self.selected, risk_acknowledged=False),
            replace(self.selected, recovery_confirmed=False))]
        cases += [("synthetic_originals_not_native_authority", self.inputs, self.selected, self.network,
                   {"load_transaction_inputs"}),
                  ("coding_current_network_changed", native, self.selected,
                   replace(self.network, interface_index=28),
                   {"load_transaction_inputs", "validate_auth_reference", "validate_coding_reference", "identity_preflight"})]
        for reason, inputs, selection, network, allowed in cases:
            with self.subTest(gate=reason), self.facade(inputs, network=network) as (ops, *_):
                with self.assertRaisesRegex(PolicyViolation, reason):
                    self.run_selected(selection)
                for name, operation in ops.items():
                    if name not in allowed: operation.assert_not_called()

    def test_pinned_chain_preserves_identity_without_live_loading(self):
        i = self.inputs
        values = (("load_gateway_identity_evidence", i.identity.discovery), ("load_gateway_vin_read_evidence", i.identity),
                  ("load_head_unit_svk_evidence", i.svk), ("load_auth_session_evidence", i.probe),
                  ("load_auth_seed_evidence", i.seed), ("load_coding_snapshot", i.original))
        with mocked([(s.__name__ + "." + name, value) for name, value in values]) as (_, ops):
            self.assertEqual(s.load_transaction_inputs(self.network, self.proofs, DEFAULT_EDIT), i)
            self.assertEqual(ops[s.__name__ + ".load_auth_session_evidence"].call_args.kwargs["session_layout"], "opaque_parameters")
            self.assertIs(ops[s.__name__ + ".load_auth_seed_evidence"].call_args.kwargs["session_evidence"], i.probe)
            with self.assertRaises(PolicyViolation):
                s.load_transaction_inputs(replace(self.network, source_address="169.254.20.99"), self.proofs, DEFAULT_EDIT)
    def test_selected_facade_requires_engine_and_seal_and_closes_both_roles(self):
        # Re-labelled synthetic data stays behind the fully mocked engine.
        inputs = replace(self.inputs, original=replace(self.inputs.original, provenance="unverified_import"))
        for failure in ("none", "ncds", "engine", "public_report", "summary", "seal", "provider_close", "storage_close"):
            with self.subTest(failure=failure), self.facade(inputs) as (ops, auth, ncds, journal, result):
                faults = {"ncds": ops["load_coding_provider"], "engine": ops["execute_coding_transaction"],
                          "public_report": result.public_report, "summary": auth.safe_summary,
                          "seal": journal.finish, "provider_close": auth.close, "storage_close": journal.close}
                if failure != "none": faults[failure].side_effect = OSError("PRIVATE")
                order = Mock()
                for label, name in (("storage", "CodingJournal"), ("AS", "load_auth_provider"),
                                    ("NCDS", "load_coding_provider"), ("engine", "execute_coding_transaction")):
                    order.attach_mock(ops[name], label)
                report = self.run_selected(self.selected)
                self.assertEqual([call[0] for call in order.mock_calls if "." not in call[0]][:3],
                                 ["storage", "AS", "NCDS"])
                auth.close.assert_called_once(); journal.close.assert_called_once()
                self.assertEqual(report["transaction_complete"], failure == "none")
                self.assertNotIn("PRIVATE", repr(report))
                if failure == "ncds":
                    ops["execute_coding_transaction"].assert_not_called(); ncds.close.assert_not_called()
                    self.assertEqual(report["vehicle_bytes_confirmed_sent"], 0)
                else: ncds.close.assert_called_once()
                if failure in ("engine", "public_report"):
                    for name in ("vehicle_bytes_confirmed_sent", "application_frames_attempted", "vehicle_traffic_performed"):
                        self.assertIsNone(report[name])
                    self.assertTrue(report["transmission_uncertain"])
                if failure == "summary":
                    self.assertEqual((report["outcome"], report["reason"]),
                                     ("integration_failed", "transaction_report_unavailable"))
