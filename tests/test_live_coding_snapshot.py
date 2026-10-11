"""Synthetic eight-group acquisitions; every socket/OS query is mocked."""

from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import struct
from support import OfflineCase, proofs
from support import bdc_svk, vsg_svk
from i3enet.coding_contract import BDC, VSG
from unittest.mock import patch

from i3enet import live_coding_snapshot as live
from i3enet.policy import PolicyViolation
from test_live_identity import FakeClock, FakeTCPSocket, frame, bind_tcp

SYNTHETIC_SOURCE = "169.254.20.3"
SYNTHETIC_GATEWAY = "169.254.0.2"
SYNTHETIC_VIN = "SYNTHETIC00000001"
EXPECTED_LENGTHS = ((0x3000, 152), (0x3001, 151), (0x3002, 150),
                    (0x3003, 150), (0x3004, 150), (0x3005, 150),
                    (0x3006, 8), (0x3007, 132))
EXPECTED_REQUESTS = tuple(bytes.fromhex(text) for text in (
    "000000050001f463223000", "000000050001f463223001",
    "000000050001f463223002", "000000050001f463223003",
    "000000050001f463223004", "000000050001f463223005",
    "000000050001f463223006", "000000050001f463223007",
))

def value_for(address, length):
    # Invented bytes, with a conspicuous marker in groups large enough for it.
    raw = b"SYNTHETIC_PRIVATE_GROUP" + bytes((address & 255,)) * length
    return raw[:length]

def ack(address):
    return frame(b"\xf4\x63\x22" + address.to_bytes(2, "big"), 2)

def positive(address, value):
    return frame(b"\x63\xf4\x62" + address.to_bytes(2, "big") + value)

def negative(code=0x78, service=0x22):
    return frame(bytes((0x63, 0xF4, 0x7F, service, code)))

class SnapshotSocket(FakeTCPSocket):
    def __init__(self, clock):
        super().__init__(clock)
        self.send_counts = []

    def send(self, payload):
        if self.send_counts:
            item = self.send_counts.pop(0)
            if isinstance(item, BaseException):
                self.sent.append(payload)
                self.events.append(("send", payload))
                raise item
            self.send_count = item
        return super().send(payload)


class LiveCodingSnapshotTests(OfflineCase):
    def setUp(self):
        self.forbid("socket.getaddrinfo","socket.gethostbyname","subprocess.run",
                    "i3enet.coding_signature.sign_coding1","i3enet.coding_signature.sign_security_access")
        self.network, _, self.evidence, self.svk = proofs(12)
        self.clock=FakeClock(); self.sock=SnapshotSocket(self.clock); self.socket_calls=[]
        bind_tcp(self.enterContext(ExitStack()), self, live)

    def run_reader(self, *, network=None, evidence=None, svk=None):
        return live.read_current_coding_snapshot(
            self.network if network is None else network,
            self.evidence if evidence is None else evidence,
            self.svk if svk is None else svk,
        )

    def queue_all(self, override=None, delay=0.0):
        for address, length in EXPECTED_LENGTHS:
            raw = ack(address) + positive(address, value_for(address, length))
            self.sock.queue.append((raw if override is None else override(address, raw), delay))

    def assert_stopped_after(self, result, attempts, completed):
        self.assertEqual(result.application_frames_attempted, attempts)
        self.assertEqual(self.sock.sent, list(EXPECTED_REQUESTS[:attempts]))
        self.assertEqual(len(result.groups), completed)
        self.assertFalse(result.public_report()["snapshot_complete"])
        self.assertEqual(result.public_report()["groups"], [])
        if self.socket_calls: self.assertTrue(self.sock.closed)

    def fresh(self):
        self.clock.now = 100.0; self.sock = SnapshotSocket(self.clock); self.socket_calls.clear()
        self.preflight.reset_mock(); self.preflight.side_effect = None
        self.clock_mock.side_effect = self.clock.monotonic

    def test_complete_fragmented_and_pending_snapshots_preserve_group_originals(self):
        self.assertEqual((live.GROUP_LENGTHS, live.SNAPSHOT_REQUESTS), (EXPECTED_LENGTHS, EXPECTED_REQUESTS))
        for mode in ("complete", "fragmented", "pending"):
            with self.subTest(mode=mode):
                self.fresh(); chunks = []; attribution = []
                for address, length in EXPECTED_LENGTHS:
                    raw = ack(address) + positive(address, value_for(address, length))
                    pieces = [(raw, 0)]
                    if mode == "fragmented": pieces = [(p, .01) for p in (raw[:2], raw[2:9], raw[9:15], raw[15:])]
                    if mode == "pending" and address == 0x3000:
                        pieces = [(ack(address) + negative(), .1), (negative(), 2), (positive(address, value_for(address, length)), 2.5)]
                    self.sock.queue.extend(pieces); chunks.extend(p for p, _ in pieces); attribution.extend([address] * len(pieces))
                result = self.run_reader(); report = result.public_report()
                self.assertEqual((result.outcome, self.sock.sent, result.vehicle_bytes_confirmed_sent, result.ack_count),
                                 ("snapshot_observed", list(EXPECTED_REQUESTS), 88, 8))
                self.assertEqual((result.tcp_connections_attempted, result.tcp_connections_opened, self.preflight.call_count), (1, 1, 10))
                self.assertTrue(all(call.kwargs == {"deadline": 130.0} for call in self.preflight.call_args_list))
                self.assertEqual([c.data for c in result.recv_chunks], chunks)
                self.assertEqual(result.chunk_group_addresses, tuple(attribution))
                self.assertEqual(result.groups, tuple((a, value_for(a, n)) for a, n in EXPECTED_LENGTHS))
                self.assertEqual(result.pending_count, 2 if mode == "pending" else 0)
                self.assertTrue(self.sock.closed); self.assertTrue(report["snapshot_complete"])
                self.assertEqual(report["snapshot_coherence_status"], "sequential_bounded_reads_not_atomic")
                self.assertEqual(report["original_signature_status"], "not_checked"); self.assertFalse(report["writes_supported"])
                self.assertNotIn("SYNTHETIC_PRIVATE_GROUP", str(report))

    def test_ack_echo_geometry_correlation_trailers_and_receive_caps_stop_at_prefix(self):
        first = ack(0x3000); value = value_for(0x3000, 152); good = positive(0x3000, value)
        cases = [(name, [(raw, 0), (b"", 0)], outcome, 1, 0) for name, raw, outcome in (
            ("EOF", b"", "eof"), ("partial_EOF", b"\0", "truncated_response"), ("body_limit", struct.pack(">IH", 4097, 1), "malformed_response"),
            ("NRC_zero", negative(0), "malformed_response"), ("negative", first + negative(0x31), "negative_response"),
            ("control", first + frame(b"", 0x12), "unexpected_control"))]
        wrong = (("missing_ACK", good), ("short_ACK", frame(b"\xf4\x63\x22\x30", 2)),
            ("long_ACK", frame(b"\xf4\x63\x22\x30\x00\0", 2)), ("ACK_DID", ack(0x3001)),
            ("ACK_target", frame(b"\xf4\x10\x22\x30\x00", 2)), ("ACK_duplicate", first * 2),
            ("DID", first + positive(0x3001, b"X" * 152)), ("SID", first + frame(b"\x63\xf4\x63\x30\x00X")),
            ("source", first + frame(b"\x10\xf4\x62\x30\x00X")), ("target", first + frame(b"\x63\xf5\x62\x30\x00X")),
            ("negative_service", first + negative(service=0x23)))
        cases += [(name, [(raw, 0)], "unexpected_response", 1, 0) for name, raw in wrong]
        cases += [("trailer_" + name, [(first + good + tail, 0)], None, 1, 0) for name, tail in (
            ("partial", b"\0"), ("ACK", first), ("pending", negative()), ("positive", positive(0x3001, b"X" * 151)))]
        cases += [("previous_group_replay", [(first + good, 0), (good, 0)], "unexpected_response", 2, 1),
                  ("pending_overall_cap", [(first + negative(), 2.5), (negative(), 2.5), (good, 1.1)], "timeout", 1, 0)]
        for name, chunks, outcome, attempts, completed in cases:
            with self.subTest(fault=name):
                self.fresh(); self.sock.queue.extend(chunks); result = self.run_reader()
                self.assertIn(result.outcome, (outcome,) if outcome else ("malformed_response", "unexpected_response"))
                self.assert_stopped_after(result, attempts, completed)
                if chunks[0][0]: self.assertEqual(result.recv_chunks[0].data, chunks[0][0])
        for index, (target, length) in enumerate(EXPECTED_LENGTHS):
            for delta in (-1, 1):
                with self.subTest(group=f"0x{target:04X}", delta=delta):
                    self.fresh(); self.queue_all(lambda address, raw: ack(address) + positive(address, b"X" * (length + delta)) if address == target else raw)
                    result = self.run_reader(); self.assertEqual(result.reason, "coding_group_length_mismatch")
                    self.assert_stopped_after(result, index + 1, index)
        for constant, limit, chunks, retained in (("MAX_RECEIVE_CHUNKS", 2, [(b"\0", 0)] * 3, 2),
                                                 ("MAX_RAW_RECEIVE_BYTES", 10, [(first, 0)], 10)):
            self.fresh(); self.sock.queue.extend(chunks)
            with patch.object(live, constant, limit): result = self.run_reader()
            self.assertEqual(len(result.recv_chunks) if constant == "MAX_RECEIVE_CHUNKS" else sum(len(c.data) for c in result.recv_chunks), retained)
            self.assert_stopped_after(result, 1, 0)

    def test_proof_binding_policy_partial_send_and_uncertain_cleanup_gates(self):
        for change in ({"cafd_version":"003.015.006"},{"btld_identifier":"00000000"},
                       {"identity_manifest_sha256":"f"*64},{"source_address":"169.254.20.4"}):
            with self.subTest(proof=change):
                self.assertEqual(self.run_reader(svk=replace(self.svk,**change)).outcome,"evidence_mismatch")
                self.assertEqual(self.socket_calls,[])
        for case,attempts,completed in (("network",1,1),("peer",0,0),("partial",2,1),("send",2,1),("policy",1,1),("close",8,8)):
            with self.subTest(case=case):
                self.fresh(); self.queue_all()
                if case=="network": self.preflight.side_effect=[self.network]*3+[replace(self.network,interface_index=13)]
                elif case=="peer": self.sock.peer_override=("169.254.0.3",6801)
                elif case in ("partial","send"): self.sock.send_counts=[11,4 if case=="partial" else OSError("PRIVATE")]
                elif case=="close": self.sock.failure="close"
                original=live.LiveCodingSnapshotPolicy.validate
                def validate(policy,payload,endpoint,**kwargs):
                    if case=="policy" and kwargs["sent_count"]==1: raise PolicyViolation("denied")
                    return original(policy,payload,endpoint,**kwargs)
                with patch.object(live.LiveCodingSnapshotPolicy,"validate",validate): result=self.run_reader()
                self.assert_stopped_after(result,attempts,completed)
                if case in ("network","peer"): self.assertEqual(result.outcome,"network_changed")
                if case in ("partial","send"):
                    self.fields(result,transmission_uncertain=True,application_frames_sent=1,
                                vehicle_bytes_confirmed_sent=15 if case=="partial" else 11)
                if case=="close": self.assertTrue(result.tcp_close_uncertain)
                if case=="policy": self.assertEqual(result.outcome,"policy_denied")

    def test_selected_complete_snapshots_storage_import_and_late_failure(self):
        from i3enet.coding_snapshot_artifacts import (BDCSnapshotArtifactStore, VSGSnapshotArtifactStore,
            CodingSnapshotArtifactStore, load_acquired_snapshot)
        from i3enet.coding_snapshot import load_coding_snapshot, CodingSnapshotError
        from i3enet.artifacts import ArtifactError
        for spec,reader,svk,store_type,counts in (
            (BDC,live.read_bdc_coding_snapshot,bdc_svk(self.svk),BDCSnapshotArtifactStore,(82,6853,6721)),
            (VSG,live.read_vsg_coding_snapshot,vsg_svk(self.svk),VSGSnapshotArtifactStore,(3,148,16))):
            self.assertEqual((len(spec.groups),sum(n for _,n in spec.groups),spec.signing_bytes),counts)
            for fault in (None,'length','ack','proof'):
                with self.subTest(module=spec.module,fault=fault):
                    self.fresh()
                    for a,n in spec.groups:
                        echo=frame(bytes((0xF4,spec.target,0x22))+a.to_bytes(2,'big'),2);raw=value_for(a,n)
                        if fault=='length' and a==spec.groups[-1][0]:raw+=b'x'
                        if fault=='ack' and a==spec.groups[-1][0]:echo=frame(bytes((0xF4,spec.target,0x22,a>>8)),2)
                        self.sock.queue.extend([(echo,0),(frame(bytes((spec.target,0xF4,0x62))+a.to_bytes(2,'big')+raw),0)])
                    proof=replace(svk,cafd_version='099.099.099') if fault=='proof' else svk
                    result=reader(self.network,self.evidence,proof)
                    if fault:
                        self.assertFalse(result.public_report()['snapshot_complete'])
                        self.assertEqual((len(result.groups),result.application_frames_attempted),
                            (0,0) if fault=='proof' else (counts[0]-1,counts[0]));continue
                    self.assertEqual((result.ack_count,result.application_frames_sent,result.vehicle_bytes_confirmed_sent),
                        (counts[0],counts[0],counts[0]*11));self.assertEqual(self.sock.sent,list(spec.requests))
                    root=self.temporary()
                    with store_type(root) as store:saved=store.save_snapshot(result,result.public_report(),self.evidence,svk,self.network)
                    self.assertTrue(saved['complete_snapshot_saved']);self.private(root/'private')
                    original=saved['original_snapshot'];directory=Path(original['directory']);pin=original['manifest_sha256']
                    snapshot=load_acquired_snapshot(directory,pin,network=self.network,identity=self.evidence,svk=svk)
                    self.assertEqual((snapshot.groups,len(snapshot.signing_input),snapshot.cafd),(result.groups,counts[2],spec.cafd))
                    with CodingSnapshotArtifactStore(root) as store,self.assertRaises(ArtifactError):
                        store.save_snapshot(result,result.public_report(),self.evidence,svk,self.network)
                    (directory/f'group-{spec.groups[0][0]:04x}.bin').write_bytes(b'x'*spec.groups[0][1])
                    with self.assertRaises(CodingSnapshotError):load_coding_snapshot(directory,pin)
            self.fresh()
            with self.assertRaises(TypeError):reader(self.network,self.evidence,self.svk)
            self.assertEqual(self.socket_calls,[])
            policy=live.LiveCodingSnapshotPolicy(self.network,live.SnapshotPhase.LIVE_CURRENT_CODING_SNAPSHOT,spec.module)
            for raw in (live.SNAPSHOT_REQUESTS[0],spec.requests[0].replace(b'\x22',b'\x2e'),spec.requests[1]):
                with self.assertRaises(PolicyViolation):policy.validate(raw,(self.network.gateway_address,6801))
