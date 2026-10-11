"""Fixed native transaction tested with synthetic keys and virtual transport."""
from support import DEFAULT_EDIT, bdc_svk, vsg_svk
from dataclasses import replace
import hashlib
import json
import socket
import struct
import unittest
from unittest.mock import patch

from i3enet import coding_transport as t
from i3enet.auth_evidence import AuthSessionEvidence, AuthenticationSeedEvidence
from i3enet.auth_provider import ASAuthProvider
from i3enet.coding_provider import NCDSCodingProvider
from i3enet.coding_signature import verify_security_access
from coding_synthetic_fixture import synthetic_private_key
from i3enet.policy import PolicyViolation
from test_coding_preparation import fixture_snapshot
from test_live_head_unit_auth import make_proofs
from test_live_identity import FakeClock, FakeTCPSocket


def wire(body, control=1):
    return struct.pack(">IH", len(body), control) + body


def synthetic_inputs(snapshot=None, module="HU"):
    """One shared native target/proof fixture for transport, journal and facade."""
    network, identity, svk = make_proofs()
    identity = replace(identity, discovery=replace(identity.discovery, vin_candidate="WBYTEST000TEST123"))
    value = bytes.fromhex("000000020000000500000ded030f290600001aba821a01")
    if module != 'HU':
        from i3enet.coding_contract import contract
        from i3enet.coding_preparation import CodingSnapshot, CodingEdit
        from i3enet.coding_signature import sign_coding1
        spec = contract(module)
        value = bytes.fromhex({'BDC':'0000000200000005000017be550a0c0600002418550a3c',
                              'VSG01':'000000020000000500001a790103010600001a77010102'}[module])
        svk = {'BDC':bdc_svk,'VSG01':vsg_svk}[module](svk)
        groups = tuple((a, bytes((i & 0xF7 for i in range(n))) if module == 'BDC' else
                       bytes((0xA0,))*n) for a,n in spec.groups[:-1])
        signature = sign_coding1(b"".join(raw for _,raw in groups), synthetic_private_key(), module=module)
        snapshot = CodingSnapshot(groups + ((spec.groups[-1][0],signature),), "synthetic_fixture", spec.cafd, spec.btld)
        edit = CodingEdit(0x3221,11,b"\x08",b"\x08",module=module) if module == 'BDC' else CodingEdit(0x3000,7,b'\x01',b'\x0f',module=module)
    else: edit = DEFAULT_EDIT
    svk = replace(svk, value_sha256=hashlib.sha256(value).hexdigest())
    pins = (identity.discovery.manifest_sha256, identity.manifest_sha256, svk.manifest_sha256)
    probe = AuthSessionEvidence("1" * 64, *pins, "opaque_parameters", 4, "2" * 64, module)
    seed = AuthenticationSeedEvidence("3" * 64, *pins, probe.manifest_sha256, "opaque_parameters", 8, "4" * 64, module)
    return t.TransactionInputs(network, identity, svk, fixture_snapshot()[0] if snapshot is None else snapshot, probe, seed, edit,
        identity.discovery.vin_candidate[-7:].encode() if module != 'HU' else None, "5"*64 if module != 'HU' else None)


class Journal:
    """RAM event fixture; production fsync storage is tested separately."""
    def __init__(self):
        self.events = []; self.raw = []; self.fail = None; self.hook = None
    def _event(self, method, *args, **kwargs):
        self.events.append((method, args, kwargs))
        if self.hook: self.hook(method, args)
        if self.fail == method: raise OSError("PRIVATE SYNTHETIC JOURNAL FAILURE")
        return len(self.events)
    def received(self, token, raw, at=None):
        self.raw.append(raw)
        return self._event("received", token, raw, at)
    def __getattr__(self, method):
        return lambda *args, **kwargs: self._event(method, *args, **kwargs)


class Clock:
    def __init__(self): self.value = 100.0; self.waits = []; self.sample_hook = None
    def now(self): return self.sample_hook(self.value) if self.sample_hook else self.value
    def wait(self, duration): self.waits.append(duration); self.value += duration


class Connector:
    """Stateful synthetic ECU: every successful full-group write changes RAM."""
    def __init__(self, inputs, clock):
        self.inputs = inputs; self.clock = clock; self.connections = []; self.frames = []
        self.groups = dict(inputs.original.groups); self.cps = inputs.original_cps; self.queue = []; self.receive_delays = []
        self.failure_at = None; self.failure_kind = None; self.close_fail_at = None
        self.open_failure_at = None; self.binding_failure_at = None; self.delay_at = None
        self.svk = bytes.fromhex({'HU':'000000020000000500000ded030f290600001aba821a01',
            'BDC':'0000000200000005000017be550a0c0600002418550a3c',
            'VSG01':'000000020000000500001a790103010600001a77010102'}[inputs.edit.module])
    def open(self, network, deadline, attempted, opened, connecting):
        index = len(self.connections) + 1
        attempted()
        connecting()
        if self.open_failure_at == index: raise OSError("PRIVATE SYNTHETIC CONNECT ERROR")
        opened()
        conn = Connection(self, index); self.connections.append(conn)
        return conn


class Connection:
    def __init__(self, owner, index): self.owner = owner; self.index = index; self.closed = False; self.timeout = None
    def assert_bound(self, network, deadline):
        if self.owner.binding_failure_at == len(self.owner.frames):
            raise OSError("PRIVATE SYNTHETIC BINDING ERROR")
    def settimeout(self, value): self.timeout = value
    def send(self, frame):
        o = self.owner; index = len(o.frames); o.frames.append(frame)
        if o.failure_at == index and o.failure_kind == "send":
            raise OSError("PRIVATE SYNTHETIC SEND FAILURE")
        if o.failure_at == index and o.failure_kind == "partial":
            return len(frame) - 1
        target, pdu = frame[7], frame[8:]
        did = int.from_bytes(pdu[1:3], "big")
        if pdu[:1] == b"\x22":
            value = (o.svk if did == 0xF101 else o.inputs.identity.discovery.vin_candidate.encode()
                     if did == 0xF190 else b"\x01\x81" if did == 0xF186 else o.cps if did == 0x37FE else o.groups[did])
            positive = b"\x62" + pdu[1:3] + value
        elif pdu[:1] == b"\x10": positive = b"\x50" + pdu[1:2] + b"\x00\x01\x00\x02"
        elif pdu[:2] == b"\x27\x01": positive = b"\x67\x01" + bytes(range(1, 9))
        elif pdu[:2] == b"\x27\x02":
            assert verify_security_access(bytes(range(1, 9)), pdu[2:], synthetic_private_key(True).public_key, module=o.inputs.edit.module)
            positive = b"\x67\x02"
        elif pdu[:1] == b"\x2e":
            if did == 0x37FE: o.cps = pdu[3:]
            else: o.groups[did] = pdu[3:]
            positive = b"\x6e" + pdu[1:3]
        elif pdu[:1] == b"\x31": positive = b"\x71\x01\x0f\x01\x00"
        elif pdu == b"\x11\x01": positive = b"\x51\x01"
        else: raise AssertionError("unexpected synthetic request")
        ack = wire(bytes((0xF4, target)) + pdu[:5], 2)
        response = wire(bytes((target, 0xF4)) + positive)
        if o.failure_at == index:
            kind = o.failure_kind
            if kind == "negative": response = wire(bytes((target, 0xF4, 0x7F, pdu[0], 0x31)))
            elif kind == "ack": ack = ack[:-1] + bytes((ack[-1] ^ 1,))
            elif kind == "short_ack": ack = wire(bytes((0xF4, target)) + pdu[:4], 2)
            elif kind == "long_ack": ack = wire(bytes((0xF4, target)) + pdu, 2)
            elif kind == "address": response = wire(bytes((0xF4, target)) + positive)
            elif kind == "duplicate": ack += ack
            elif kind == "trailing": response += b"x"
            elif kind == "extra": response += response
            elif kind == "missing_ack": ack = b""
            elif kind == "wrong_positive": response = wire(bytes((target, 0xF4)) + positive[:-1] + bytes((positive[-1] ^ 1,)))
            elif kind == "incorrect_signature": response = wire(bytes((target, 0xF4)) + b"\x71\x01\x0f\x01\x01")
            elif kind == "pending_limit": response = wire(bytes((target, 0xF4, 0x7F, pdu[0], 0x78))) * 5
            elif kind in ("pending_once", "pending_overall"):
                pending = wire(bytes((target, 0xF4, 0x7F, pdu[0], 0x78)))
                o.queue = [ack + pending, response] if kind == "pending_once" else [ack + pending, pending, response]
                o.receive_delays = [0.001, 0.001] if kind == "pending_once" else [2.9, 2.9, 0.3]
                return len(frame)
            elif kind == "eof": o.queue = [b""]; return len(frame)
            elif kind == "fragmented": o.queue = [bytes((byte,)) for byte in ack + response]; return len(frame)
        o.queue = [ack + response]
        return len(frame)
    def recv(self, size):
        o = self.owner
        o.clock.value += o.receive_delays.pop(0) if o.receive_delays else 0.001
        if o.delay_at == len(o.frames) - 1: o.clock.value += 4
        if not o.queue: raise socket.timeout()
        return o.queue.pop(0)
    def close(self):
        self.closed = True
        if self.owner.close_fail_at == self.index: raise OSError("PRIVATE SYNTHETIC CLOSE FAILURE")


class CodingTransportTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen",
                     "i3enet.auth_provider.load_auth_provider", "i3enet.coding_provider.load_coding_provider"):
            guard = patch(name, side_effect=AssertionError("real transport/material operation forbidden"))
            guard.start(); self.addCleanup(guard.stop)
        self.snapshot, self.key = fixture_snapshot()
        self.inputs = synthetic_inputs(self.snapshot)
        self.selected = t.TransactionSelection(t.TransactionPhase.CODING, True, True, True, True, True)

    def run_case(self, *, selection=None, inputs=None, failure=None, journal_failure=None, close=None, opened=None,
                 binding=None, delay=None, wait=None, ncds=None, as_provider=None, journal_hook=None):
        selected_inputs = self.inputs if inputs is None else inputs
        clock = Clock(); journal = Journal(); journal.fail = journal_failure
        connector = Connector(selected_inputs, clock)
        if failure: connector.failure_at, connector.failure_kind = failure
        connector.close_fail_at = close; connector.open_failure_at = opened
        connector.binding_failure_at = binding; connector.delay_at = delay
        if journal_hook: journal.hook = lambda method, args: journal_hook(method, args, connector, clock)

        ncds = NCDSCodingProvider._from_key(self.key, "f" * 64, "a" * 64, module=selected_inputs.edit.module) if ncds is None else ncds
        as_provider = ASAuthProvider._from_key(synthetic_private_key(True), "f" * 64, "a" * 64, module=selected_inputs.edit.module) if as_provider is None else as_provider
        try:
            result = t.execute_coding_transaction(selected_inputs, self.selected if selection is None else selection,
                ncds, as_provider, journal, connector=connector, clock=clock.now,
                wait=clock.wait if wait is None else wait)
        finally:
            ncds.close(); as_provider.close()
        return result, connector, journal, clock

    def test_module_complete_edit_default_activation_and_failure_boundaries(self):
        for module,frames,byte_cap,groups,finalize,group,offset,diff in (
            ('BDC',261,9863,82,174,0x3221,11,8),('VSG01',24,551,3,16,0x3000,7,1)):
            inputs=synthetic_inputs(module=module);stages=sum(t.transaction_stages(module),())
            result, conn, _, clock = self.run_case(inputs=inputs)
            self.assertEqual(result.outcome, "candidate_readback_verified")
            self.assertEqual((len(conn.frames), result.application_bytes_sent, result.write_attempts), (frames,byte_cap,groups))
            self.assertEqual(result.completed_stages, stages); self.assertEqual(clock.waits, [])
            self.assertTrue(result.public_report()["complete_candidate_signature_cps_readback_verified"])
            self.assertFalse(result.reset_attempted); self.assertEqual(conn.frames[finalize][8:], b"\x10\x01")
            self.assertEqual(dict(result.prepared.candidate.groups)[group][offset] ^ dict(inputs.original.groups)[group][offset], diff)
            faults = ((i,'negative') for i in range(frames)) if module=='VSG01' else (
                (84,'wrong_positive'),(88,'short_ack'),(89,'negative'),(170,'partial'),(171,'incorrect_signature'),
                (172,'negative'),(173,'wrong_positive'),(174,'negative'),(177,'wrong_positive'),(259,'wrong_positive'),(260,'wrong_positive'))
            for index, kind in faults:
                with self.subTest(module=module,stage=stages[index],kind=kind):
                    failed, conn, _, _ = self.run_case(inputs=inputs,failure=(index,kind))
                    self.assertEqual(len(conn.frames), index+1); self.assertEqual(failed.completed_stages, stages[:index])
                    self.assertFalse(failed.public_report()["complete_candidate_signature_cps_readback_verified"])
                    self.assertTrue(all(c.closed for c in conn.connections))
            for wrong in (replace(inputs, original_cps=None),replace(inputs,probe=replace(inputs.probe,module="HU")),
                          replace(inputs,edit=DEFAULT_EDIT)):
                denied, conn, _, _ = self.run_case(inputs=wrong)
                self.assertEqual(denied.application_attempts,0); self.assertEqual(conn.frames,[])

    def assert_stopped(self, result, connector, stage, *, outcome=None):
        self.assertNotEqual(result.outcome, "candidate_readback_verified")
        self.assertEqual(len(connector.frames), stage + 1)
        self.assertEqual(result.completed_stages, t.STAGES[:stage])
        self.assertTrue(all(conn.closed for conn in connector.connections))
        self.assertFalse(result.public_report()["complete_candidate_signature_cps_readback_verified"])
        if outcome is not None:
            self.assertEqual(result.outcome, outcome)

    def test_complete_candidate_with_coalesced_fragmented_and_pending_replies(self):
        for failure in (None, (14, "fragmented"), (14, "pending_once")):
            with self.subTest(reply=failure):
                result, connector, journal, clock = self.run_case(failure=failure)
                report = result.public_report()
                self.assertEqual(result.outcome, "candidate_readback_verified")
                self.assertEqual((report["application_frames_attempted"], report["vehicle_bytes_confirmed_sent"],
                                  report["coding_group_write_attempts"], report["tcp_connections_opened"]), (38, 1600, 8, 2))
                self.assertEqual(tuple(report["completed_stage_names"]), t.STAGES)
                self.assertEqual(result.readback.groups, result.prepared.candidate.groups)
                self.assertEqual(connector.groups[0x3001][58], 0)
                self.assertEqual(clock.waits, [30.0])
                self.assertTrue(all(conn.closed for conn in connector.connections))
                self.assertTrue(report["complete_candidate_signature_cps_readback_verified"])
                self.assertEqual(report["evidence_status"], "SYNTHETIC_FIXTURE")
                for field in ("writes_supported", "live_ready", "vehicle_traffic_performed", "effect_verified_on_car",
                              "authenticated_connection_available", "recovery_established", "activation_scheduling_verified_on_hardware"):
                    self.assertFalse(report[field], field)
                safe = json.dumps(report) + repr(result)
                for raw in (result.prepared.candidate.signature.hex(), result.current_svk.hex(),
                            result.expected_cps.decode(), self.inputs.identity.discovery.vin_candidate):
                    self.assertNotIn(raw, safe)
                methods = [row[0] for row in journal.events]
                for index, method in enumerate(methods):
                    if method == "received": self.assertEqual(methods[index + 1], "received_at")
                    if method == "before_attempt": self.assertEqual(methods[index + 1], "after_attempt")
                self.assertEqual(methods.count("before_attempt"), 38)

    def test_selection_proofs_and_final_policy_deny_before_transport(self):
        from i3enet.coding_preparation import CodingEdit, prepare_coding
        selected_inputs = replace(self.inputs, edit=CodingEdit(0x3002,12,b'\x01',b'\x03'))
        with patch.object(NCDSCodingProvider,'prepare',return_value=prepare_coding(self.snapshot,self.key, DEFAULT_EDIT)):
            result, connector, _, _ = self.run_case(inputs=selected_inputs)
            self.assertEqual(result.outcome,'provider_invalid')
            self.assertEqual(len(connector.frames),10); self.assertEqual(result.write_attempts,0)
        cases = [t.TransactionSelection()]
        for field in ("change_approved", "risk_acknowledged", "recovery_confirmed",
                      "exclusive_diagnostics_confirmed", "parked_awake_confirmed"):
            cases += [replace(self.selected, **{field: False}), replace(self.selected, **{field: 1})]
        for selection in cases:
            with self.subTest(selection=selection):
                result, connector, journal, _ = self.run_case(selection=selection)
                self.assertEqual(result.outcome, "denied")
                self.assertEqual((result.application_attempts, result.connection_attempts, len(connector.frames), len(journal.events)), (0, 0, 0, 0))
        for inputs in (replace(self.inputs, probe=replace(self.inputs.probe, session_layout="p2_timing")),
                       replace(self.inputs, seed=replace(self.inputs.seed, seed_byte_length=16)),
                       replace(self.inputs, seed=replace(self.inputs.seed, session_manifest_sha256="e" * 64)),
                       replace(self.inputs, network=replace(self.inputs.network, source_address="169.254.20.4"))):
            result, connector, _, _ = self.run_case(inputs=inputs)
            self.assertEqual(result.outcome, "denied"); self.assertFalse(connector.frames)

        with self.assertRaises(PolicyViolation):
            t.CodingTransportPolicy().validate(t._INITIAL[0], index=0, completed=0,
                destination=(self.inputs.network.gateway_address, 6801), network=self.inputs.network)
        policy = t.CodingTransportPolicy(self.selected)
        for index, completed, destination, frame in ((0, 1, (self.inputs.network.gateway_address, 6801), t._INITIAL[0]),
                (0, 0, (self.inputs.network.gateway_address, 6802), t._INITIAL[0]),
                (0, 0, (self.inputs.network.gateway_address, 6801), bytearray(t._INITIAL[0])),
                (10, 10, (self.inputs.network.gateway_address, 6801), b"arbitrary")):
            with self.assertRaises(PolicyViolation):
                policy.validate(frame, index=index, completed=completed, destination=destination, network=self.inputs.network)

    def test_correlated_terminal_and_malformed_replies_stop_at_the_failed_stage(self):
        cases = [(stage, "negative") for stage in range(38)]
        cases += [(stage, kind) for stage in (13, 14, 21, 23)
                  for kind in ("ack", "short_ack", "long_ack", "duplicate", "address", "missing_ack",
                               "trailing", "extra", "wrong_positive", "pending_limit", "eof")]
        for stage, kind in cases:
            with self.subTest(stage=t.STAGES[stage], reply=kind):
                result, connector, _, _ = self.run_case(failure=(stage, kind))
                self.assert_stopped(result, connector, stage,
                                    outcome="negative_response" if kind == "negative" else None)
                self.assertEqual(result.application_attempts, stage + 1)
        result, connector, _, _ = self.run_case(failure=(14, "pending_overall"))
        self.assert_stopped(result, connector, 14, outcome="timeout")

    def test_send_storage_and_intent_faults_preserve_counts_and_stop_mutation(self):
        for kind in ("partial", "send"):
            result, connector, journal, _ = self.run_case(failure=(14, kind))
            self.assertEqual(result.application_attempts, 15)
            self.assertEqual(result.write_attempts, 1)
            self.assertTrue(result.transmission_uncertain)
            self.assertEqual(len(connector.frames), 15)
            self.assertTrue(result.public_report()["partial_or_uncertain_coding"])
            self.assertIn("after_attempt", [row[0] for row in journal.events])
        for method in ("connection_attempted", "opened", "before_attempt", "after_attempt", "after_attempt_at",
                       "received", "received_at", "completed", "closed"):
            result, connector, _, _ = self.run_case(journal_failure=method)
            self.assertEqual(result.outcome, "storage_failed")
            self.assertLessEqual(len(connector.frames), 26 if method == "closed" else 1)
            self.assertTrue(all(conn.closed for conn in connector.connections))

        def binding_change(method, args, connector, clock):
            if method == "before_attempt" and args[0] == "write_3000":
                connector.binding_failure_at = len(connector.frames)
        result, connector, journal, _ = self.run_case(journal_hook=binding_change)
        self.assertEqual((result.application_attempts, result.write_attempts, len(connector.frames)), (14, 0, 14))
        self.assertFalse(result.public_report()["partial_or_uncertain_coding"])
        def late_intent(method, args, connector, clock):
            if method == "before_attempt" and args[0] == "write_3000": clock.value += 7
        result, connector, _, _ = self.run_case(journal_hook=late_intent)
        self.assertEqual(result.outcome, "timeout"); self.assertEqual(len(connector.frames), 14)
        def bad_receipt_clock(method, args, connector, clock):
            if method == "received": clock.value = float("nan")
        result, connector, journal, _ = self.run_case(journal_hook=bad_receipt_clock)
        self.assertFalse(result.timing_complete)
        self.assertEqual((result.received_chunks, len(journal.raw), len(connector.frames)), (1, 1, 1))

    def test_reset_post_identity_state_complete_bytes_and_cps_are_mandatory(self):
        # Fresh full VIN must stop a same-IP/SVK/group fixture before either
        # signing provider, session changes or any coding attempt.
        with patch.object(NCDSCodingProvider, "prepare", side_effect=AssertionError("no candidate before current VIN")) as preparation, \
             patch.object(ASAuthProvider, "sign_seed", side_effect=AssertionError("no AS before current VIN")) as signing:
            result, connector, _, _ = self.run_case(failure=(0, "wrong_positive"))
        preparation.assert_not_called(); signing.assert_not_called()
        self.assertEqual(result.outcome, "contract_failed")
        self.assertEqual(result.reason, "transaction_current_vin_mismatch")
        self.assertEqual((result.application_attempts, result.application_bytes_sent, result.write_attempts), (1, 11, 0))
        self.assertEqual(connector.frames, [bytes.fromhex("000000050001f41022f190")])
        self.assertEqual(result.completed_stages, ())
        for stage, kind in ((22, "incorrect_signature"), (25, "wrong_positive"), (26, "wrong_positive"),
                            (27, "wrong_positive"), (28, "wrong_positive"), (29, "wrong_positive"),
                            (36, "wrong_positive"), (37, "wrong_positive")):
            with self.subTest(stage=stage):
                result, connector, _, clock = self.run_case(failure=(stage, kind))
                self.assertNotEqual(result.outcome, "candidate_readback_verified")
                self.assertEqual(len(connector.frames), stage + 1)
                self.assertEqual(bool(clock.waits), stage > 25)
        for close in (1, 2):
            result, connector, _, _ = self.run_case(close=close)
            self.assertTrue(result.close_uncertain)
            self.assertEqual(len(connector.frames), 26 if close == 1 else 38)
            self.assertFalse(result.public_report()["complete_candidate_signature_cps_readback_verified"])
        for stage in (0, 14, 25, 28):
            result, connector, _, _ = self.run_case(delay=stage)
            self.assertEqual(result.outcome, "timeout"); self.assertEqual(len(connector.frames), stage + 1)
        result, connector, _, _ = self.run_case(wait=lambda seconds: None)
        self.assertEqual(result.outcome, "invalid_timing"); self.assertEqual(len(connector.connections), 1)
        result, connector, _, _ = self.run_case(opened=2)
        self.assertTrue(result.connection_uncertain); self.assertEqual(len(connector.frames), 26)
        def late_final_clock(method, args, connector, clock):
            if method == "closed" and args[0] == 2:
                samples = iter((clock.value, clock.value + 100.0))
                clock.sample_hook = lambda value: next(samples, value + 100.0)
        result, connector, _, _ = self.run_case(journal_hook=late_final_clock)
        self.assertEqual(result.outcome, "timeout")
        self.assertEqual(result.completed_stages, t.STAGES)
        self.assertEqual((result.application_attempts, result.application_bytes_sent), (38, 1600))
        self.assertFalse(result.public_report()["complete_candidate_signature_cps_readback_verified"])
        self.assertTrue(all(conn.closed for conn in connector.connections))

    def test_native_adapter_rechecks_after_intent_and_before_connect_without_actual_socket(self):
        network = self.inputs.network
        for change_at in (None, 2, 3):
            virtual = FakeClock(); sock = FakeTCPSocket(virtual); callbacks = []
            calls = []
            def preflight(*args, **kwargs):
                calls.append(len(calls) + 1)
                return replace(network, source_address="169.254.20.4") if change_at == len(calls) else network
            with patch.object(t.socket, "socket", return_value=sock), \
                 patch.object(t, "identity_preflight", side_effect=preflight), \
                 patch.object(t.time, "monotonic", side_effect=virtual.monotonic):
                if change_at is None:
                    conn = t.NativeCodingConnector().open(network, virtual.now + 30,
                        lambda: callbacks.append("intent"), lambda: callbacks.append("opened"),
                        lambda: callbacks.append("connect"))
                    self.assertEqual(callbacks, ["intent", "connect", "opened"])
                    self.assertEqual(len(calls), 3)
                    conn.close()
                else:
                    with self.assertRaises(t._Stop):
                        t.NativeCodingConnector().open(network, virtual.now + 30,
                            lambda: callbacks.append("intent"), lambda: callbacks.append("opened"),
                            lambda: callbacks.append("connect"))
                    self.assertEqual(callbacks, ["intent"] if change_at == 2 else ["intent", "connect", "opened"])
                self.assertTrue(sock.closed)
                self.assertFalse(sock.sent)
