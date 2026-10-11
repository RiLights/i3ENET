"""Shared contracts for the three fixed reads and their shared TCP exchange.

All I/O is synthetic. FakeClock/FakeTCPSocket/frame are also used by the
snapshot and authentication tests; they intentionally remain public fixtures.
"""
from contextlib import ExitStack
from dataclasses import replace
import json
import socket
import struct
import unittest
from support import proofs, frame, mocked, bdc_svk, vsg_svk
from unittest.mock import patch

from i3enet import live_identity, live_svk, live_block
from i3enet.policy import PolicyViolation

SYNTHETIC_VIN = b"SYNTHETIC00000001"
SYNTHETIC_GATEWAY = "169.254.0.2"
SYNTHETIC_SOURCE = "169.254.20.3"
READS = (
    (live_identity, "identify_gateway_once", "GATEWAY_VIN_REQUEST", "LiveGatewayIdentityPolicy", "vin_match"),
    (live_svk, "read_head_unit_svk_once", "HEAD_UNIT_SVK_REQUEST", "LiveHeadUnitSVKPolicy", "identity_value_observed"),
    (live_block, "read_exbox_once", "EXBOX_REQUEST", "LiveHeadUnitEXBOXPolicy", "coding_value_observed"),
    (live_svk, "read_bdc_svk_once", "BDC_SVK_REQUEST", "LiveBDCSVKPolicy", "identity_value_observed"),
    (live_block, "read_bdc_pffes_once", "BDC_PFFES_REQUEST", "LiveBDCPfFesPolicy", "coding_value_observed"),
    (live_svk, "read_vsg_svk_once", "VSG_SVK_REQUEST", "LiveVSGSVKPolicy", "identity_value_observed"),
    (live_block, "read_vsg_config_once", "VSG_CONFIG_REQUEST", "LiveVSGConfigPolicy", "coding_value_observed"),
)


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now


class FakeTCPSocket:
    """No networking: fixed queues, synthetic failures and a virtual clock."""

    def __init__(self,clock):
        self.clock=clock; self.events=[]; self.queue=[]; self.sent=[]
        self.connected=self.local=self.bound_index=self.timeout=self.failure=None
        self.readback_override=self.peer_override=self.after_connect_source=self.after_connect_index=None
        self.connect_delay=0.0
        self.closed=False; self.send_count=11

    def record(self, *event):
        self.events.append(event)
        self.fail(event[0])

    def fail(self, stage):
        if self.failure == stage:
            raise OSError("PRIVATE SYNTHETIC ERROR")

    def setsockopt(self, level, option, value):
        self.record("setsockopt", level, option, value)
        self.bound_index = value

    def bind(self, local):
        self.record("bind", local)
        if self.local is None:
            self.local = (local[0], 54321)

    def getsockopt(self, level, option):
        self.record("getsockopt", level, option)
        if self.connected is not None and self.after_connect_index is not None:
            return self.after_connect_index
        return self.bound_index if self.readback_override is None else self.readback_override

    def getsockname(self):
        self.record("getsockname",)
        if self.connected is not None:
            if self.after_connect_source is not None:
                return self.after_connect_source
        return self.local

    def getpeername(self):
        self.record("getpeername",)
        return self.connected if self.peer_override is None else self.peer_override

    def settimeout(self, timeout):
        self.record("settimeout", timeout)
        if not 0 < timeout <= 3.0:
            raise AssertionError("nonpositive or unbounded timeout")
        self.timeout = timeout

    def advance(self, delay):
        if delay >= self.timeout:
            self.clock.now += self.timeout
            raise socket.timeout()
        self.clock.now += delay

    def connect(self, endpoint):
        self.record("connect", endpoint)
        self.advance(self.connect_delay)
        self.connected = endpoint

    def send(self, payload):
        self.events.append(("send", payload))
        self.sent.append(payload)
        self.fail("send")
        return self.send_count

    def recv(self, size):
        self.record("recv", size)
        if not self.queue:
            self.clock.now += self.timeout
            raise socket.timeout()
        data, delay = self.queue.pop(0)
        self.advance(delay)
        if isinstance(data, BaseException):
            raise data
        if len(data) > size:
            self.queue.insert(0, (data[size:], 0.0))
        return data[:size]

    def close(self):
        self.events.append(("close",))
        self.closed = True
        self.fail("close")


def bind_tcp(stack, owner, module):
    """Bind a synthetic socket and virtual clock; block real DNS/OS calls."""
    def make_socket(*args):
        owner.socket_calls.append(args)
        if args != (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP):
            raise AssertionError("wrong socket kind")
        owner.sock.fail("creation")
        return owner.sock
    _, mocks = stack.enter_context(mocked(((module.__name__ + ".identity_preflight", owner.network),),
                                          forbidden=("socket.getaddrinfo", "socket.gethostbyname", "subprocess.run")))
    owner.preflight = mocks[module.__name__ + ".identity_preflight"]
    owner.clock_mock = stack.enter_context(patch("time.monotonic", side_effect=owner.clock.monotonic))
    stack.enter_context(patch("socket.socket", side_effect=make_socket))


class ReadHarness:
    """One fresh synthetic connection for an explicitly selected fixed client."""

    def __init__(self, selection):
        self.module, function, self.constant, policy, self.success = selection
        self.function = getattr(self.module, function)
        self.policy = getattr(self.module, policy)
        self.request = getattr(self.module, self.constant)
        self.target, self.did = self.request[7], self.request[9:]
        self.gateway = self.target == 0x10
        self.value = SYNTHETIC_VIN if self.gateway else b"SYNTHETIC_PRIVATE_VALUE\x00\xff"
        self.network, self.discovery, self.identity, self.svk = proofs(12)
        if self.constant == 'BDC_PFFES_REQUEST':
            self.svk = bdc_svk(self.svk)
            self.value = b'SYNTHETIC_VALUE17'
        elif self.constant == 'VSG_CONFIG_REQUEST':
            self.svk = vsg_svk(self.svk); self.value = b'SYNTHETI'
        self.clock = FakeClock()
        self.sock = FakeTCPSocket(self.clock)
        self.socket_calls = []
        self.stack = ExitStack()

    def __enter__(self):
        bind_tcp(self.stack, self, self.module)
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def ack(self, prefix=None):
        return frame(bytes((0xF4, self.target)) + (self.request[8:] if prefix is None else prefix), 2)

    def positive(self, value=None):
        return frame(bytes((self.target, 0xF4, 0x62)) + self.did + (self.value if value is None else value))

    def negative(self, code=0x78, service=0x22):
        return frame(bytes((self.target, 0xF4, 0x7F, service, code)))

    def queue(self, data, delay=0.0):
        self.sock.queue.append((data, delay))

    def run(self):
        if self.gateway:
            return self.function(self.network, self.discovery)
        if self.module is live_svk:
            return self.function(self.network, self.identity)
        return self.function(self.network, self.identity, self.svk)


class FixedReadTests(unittest.TestCase):
    def test_selected_metadata_fixed_policies_lengths_and_ack_order(self):
        from i3enet.policy import LiveBDCMetadataPolicy,LiveVSGMetadataPolicy,Phase,BDC_METADATA,VSG_METADATA
        for selection,table,reader,constructor,phase in (
            (READS[4],BDC_METADATA,live_block.read_bdc_metadata_once,LiveBDCMetadataPolicy,Phase.LIVE_BDC_METADATA),
            (READS[6],VSG_METADATA,live_block.read_vsg_metadata_once,LiveVSGMetadataPolicy,Phase.LIVE_VSG_METADATA)):
            for kind,(did,length,_) in table.items():
                for fault in (None,'short_ack','wrong_did','bad_length','software'):
                    with self.subTest(kind=kind,fault=fault),ReadHarness(selection) as h:
                        h.request=bytes.fromhex('000000050001f4')+bytes((h.target,0x22))+did.to_bytes(2,'big');h.did=h.request[9:]
                        h.function=lambda n,v,s:reader(kind,n,v,s)
                        value=bytes(length or 4) if fault!='bad_length' else bytes(8 if length else 33)
                        h.queue(h.ack(b'\x22' if fault=='short_ack' else None))
                        h.queue(h.positive(value) if fault!='wrong_did' else h.positive(value).replace(h.did,b'\0\0'))
                        if fault=='software':h.svk=replace(h.svk,cafd_version='099.099.099')
                        result=h.run()
                        if fault is None:self.assert_sent_once(h,result);self.assertEqual(result.value,value)
                        else:self.assertIsNone(result.value)
                policy=constructor(h.network,phase,kind);policy.validate(h.request,(h.network.gateway_address,6801))
                for raw in (live_block.BDC_PFFES_REQUEST,h.request[:8]+b'\x2e'+h.request[9:]):
                    with self.assertRaises(PolicyViolation):policy.validate(raw,(h.network.gateway_address,6801))
            with self.assertRaises(TypeError):reader('arbitrary',h.network,h.identity,h.svk)

    def assert_sent_once(self, h, result):
        self.assertEqual(h.sock.sent, [h.request]); self.assertEqual(result.request_bytes, h.request)
        self.assertEqual((result.tcp_connections_attempted, result.tcp_connections_opened,
            result.application_frames_attempted, result.application_frames_sent, result.vehicle_bytes_confirmed_sent), (1, 1, 1, 1, 11))
        self.assertFalse(result.tcp_connection_uncertain); self.assertFalse(result.transmission_uncertain)
        self.assertTrue(h.sock.closed)

    def assert_not_accepted(self, h, result):
        report = result.public_report()
        if h.gateway: self.assertEqual(report["vehicle_identity_status"], "unknown")
        else:
            self.assertIsNone(result.value); self.assertIsNone(report["value_byte_count"])
            self.assertIsNone(report["value_sha256"])
        self.assertFalse(report["writes_supported"])

    def wire_case(self, selection, chunks):
        with ReadHarness(selection) as h:
            for raw, delay in chunks: h.queue(raw, delay)
            result = h.run(); self.assert_sent_once(h, result)
            return h, result

    def test_fixed_success_fragmentation_values_and_private_claims(self):
        wires=("000000050001f41022f190","000000050001f46322f101","000000050001f463223001",
               "000000050001f44022f101","000000050001f440223221","000000050001f42d22f101","000000050001f42d223000")
        for selection,wire in zip(READS,wires):
            for fragmented in (False,True):
                with self.subTest(client=selection[1],fragmented=fragmented),ReadHarness(selection) as h:
                    raw=h.ack()+h.positive(); pieces=[raw[:2],raw[2:9],raw[9:]] if fragmented else [raw]
                    for piece in pieces: h.queue(piece,.01)
                    result=h.run(); self.assert_sent_once(h,result)
                    self.assertEqual((h.request.hex(),result.outcome,result.ack_count),(wire,h.success,1))
                    self.assertEqual([c.data for c in result.recv_chunks],pieces)
                    self.assertEqual((h.preflight.call_count,h.sock.bound_index,h.sock.connected),(3,12,(SYNTHETIC_GATEWAY,6801)))
                    for hidden in (SYNTHETIC_VIN.decode(),"SYNTHETIC_PRIVATE_VALUE",raw.hex()):
                        self.assertNotIn(hidden,repr(result)+json.dumps(result.public_report()))
            for value in ((b"SHORT",b"lowercase00000001",b"SYNTHETIC00000002") if selection is READS[0] else (b"\0\xff",b"X"*4091)):
                with ReadHarness(selection) as h:
                    if selection in (READS[4],READS[6]): h.queue(h.ack())
                    h.queue(h.positive(value)); result=h.run()
                    if h.gateway: self.assertNotEqual(result.outcome,h.success)
                    elif selection in (READS[4],READS[6]): self.assertEqual(result.outcome,'malformed_response')
                    else: self.assertEqual(result.value,value)

    def test_correlated_wire_faults_complete_ack_and_control_denial(self):
        for selection in READS:
            with ReadHarness(selection) as sample:
                body = bytes((sample.target, 0xF4, 0x62)) + sample.did + sample.value
                cases = [("source", frame(bytes((sample.target ^ 1,)) + body[1:]), "unexpected_response"),
                    ("target", frame(body[:1] + b"\xf5" + body[2:]), "unexpected_response"),
                    ("SID", frame(body[:2] + b"\x63" + body[3:]), "unexpected_response"),
                    ("DID", frame(body[:4] + bytes((body[4] ^ 1,)) + body[5:]), "unexpected_response"),
                    ("negative_service", sample.negative(service=0x23), "unexpected_response"),
                    ("ACK_DID", sample.ack(b"\x22\xff\xff"), "unexpected_response"),
                    ("ACK_extra", sample.ack(sample.request[8:] + b"\0"), "unexpected_response"),
                    ("ACK_reversed", frame(body[:2] + sample.request[8:], 2), "unexpected_response"),
                    ("ACK_duplicate", sample.ack() * 2, "unexpected_response"), ("empty_value", sample.positive(b""), "malformed_response"),
                    ("body_limit", struct.pack(">IH", 4097, 1), "malformed_response"), ("NRC_zero", sample.negative(0), "malformed_response"),
                    ("NRC_truncated", frame(body[:2] + b"\x7f\x22"), "malformed_response"), ("unknown_control", frame(b"\0\0\0", 0xFFFF), "malformed_response"),
                    ("terminal_before_positive", sample.negative(0x31) + sample.positive(), "negative_response")]
                cases += [(name, sample.positive() + tail, None) for name, tail in (
                    ("positive_duplicate", sample.positive()), ("trailing_ACK", sample.ack()), ("trailing_pending", sample.negative()),
                    ("partial_trailer", b"\0"), ("trailing_control", frame(b"", 0x12)))]
                cases += [("ACK_prefix_" + str(n), sample.ack(sample.request[8:8 + n]), "unexpected_response") for n in (0, 1, 2)]
                cases += [("control_" + hex(c), frame(b"\0\0" if c == 0x40 else b"", c), "unexpected_control") for c in (0x12, 0x10, 0x13, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0xFF)]
            for name, raw, outcome in cases:
                with self.subTest(client=selection[1], fault=name):
                    h, result = self.wire_case(selection, [(raw, 0)])
                    self.assertIn(result.outcome, (outcome,) if outcome else ("unexpected_response", "malformed_response"))
                    self.assertEqual(result.recv_chunks[0].data, raw); self.assert_not_accepted(h, result)
                    if name.startswith("ACK_prefix"): self.assertEqual(result.ack_count, 0)
                    if name.startswith("control_"): self.assertEqual(result.last_control, int.from_bytes(raw[4:6], "big"))

    def test_proof_types_selected_software_fresh_binding_and_final_policy(self):
        discovery_changes = {"gateway_address": "169.254.0.3", "source_interface": "en8", "source_address": "169.254.20.4",
            "interface_index": True, "diagnostic_address": 0x63, "vin_candidate": "SHORT", "manifest_sha256": "invalid", "reply_sha256": None}
        svk_changes = {"gateway_address": "169.254.0.3", "source_address": "169.254.20.4", "source_interface": "en8",
            "interface_index": True, "discovery_manifest_sha256": "f" * 64, "identity_manifest_sha256": "f" * 64,
            "manifest_sha256": None, "request_sha256": "f" * 64, "value_sha256": "E" * 64,
            "cafd_identifier": "000000F9", "cafd_version": "003.015.006", "btld_identifier": "00001ABB", "btld_version": "130.026.002"}
        for selection in READS:
            for field, value in discovery_changes.items():
                with self.subTest(client=selection[1], discovery=field), ReadHarness(selection) as h:
                    h.discovery = replace(h.discovery, **{field: value}); h.identity = replace(h.identity, discovery=h.discovery)
                    self.assertEqual(h.run().outcome, "evidence_mismatch"); self.assertEqual(h.socket_calls, [])
            if selection is not READS[0]:
                for change in ({"discovery": object()}, {"manifest_sha256": None}, {"request_sha256": "a" * 64}):
                    with ReadHarness(selection) as h:
                        h.identity = replace(h.identity, **change)
                        self.assertEqual(h.run().outcome, "evidence_mismatch"); self.assertEqual(h.socket_calls, [])
            for call in (1, 2, 3):
                with self.subTest(client=selection[1], preflight=call), ReadHarness(selection) as h:
                    h.preflight.side_effect = [h.network] * (call - 1) + [replace(h.network, interface_index=13)]
                    result = h.run()
                    self.assertEqual((result.outcome, result.tcp_connections_attempted, result.application_frames_attempted), ("network_changed", int(call == 3), 0))
                    self.assertEqual(h.sock.sent, [])
            bindings = (("readback_override", 13), ("local", ("169.254.20.4", 54321)), ("local", (SYNTHETIC_SOURCE, 0)),
                ("peer_override", ("169.254.0.3", 6801)), ("peer_override", (SYNTHETIC_GATEWAY, 6802)),
                ("after_connect_source", ("169.254.20.4", 54321)), ("after_connect_index", 13))
            for name, value in bindings:
                with ReadHarness(selection) as h:
                    setattr(h.sock, name, value); result = h.run()
                    self.assertEqual((result.outcome, result.application_frames_attempted, h.sock.sent), ("network_changed", 0, []))
                    self.assertTrue(h.sock.closed)
            for forbidden in (b"", bytes.fromhex("000000050001f4e022f190"), bytes.fromhex("000000050001f463223f07"), bytes.fromhex("000000040001f4633e80")):
                with ReadHarness(selection) as h, patch.object(h.module, h.constant, forbidden):
                    result = h.run()
                    self.assertEqual((result.outcome, h.sock.sent), ("policy_denied", []))
                    self.assert_not_accepted(h, result)
            with ReadHarness(selection) as h, patch.object(h.policy, "validate", side_effect=PolicyViolation("denied")) as check:
                self.assertEqual(h.run().outcome, "policy_denied")
                check.assert_called_once_with(h.request, (SYNTHETIC_GATEWAY, 6801), sent_count=0)
                self.assertEqual(h.sock.sent, [])
        for selection in (READS[2],READS[4],READS[6]):
            for field, value in svk_changes.items():
                with ReadHarness(selection) as h:
                    h.svk = replace(h.svk, **{field: value})
                    self.assertEqual(h.run().outcome, "evidence_mismatch"); self.assertEqual(h.socket_calls, [])
            with ReadHarness(selection) as h:
                h.svk = proofs(12)[3] if selection in (READS[4],READS[6]) else bdc_svk(h.svk)
                with self.assertRaises(TypeError): h.run()
                self.assertEqual(h.socket_calls, [])

    def test_partial_send_and_socket_failures_account_without_retry(self):
        for selection in READS:
            for count in (0, 3, 10, -1, 12, None, True):
                with self.subTest(client=selection[1], count=count), ReadHarness(selection) as h:
                    h.sock.send_count = count; result = h.run()
                    self.assertEqual((result.outcome, result.application_frames_attempted, result.application_frames_sent), ("socket_error", 1, 0))
                    self.assertTrue(result.transmission_uncertain); self.assertEqual(len(h.sock.sent), 1)
                    self.assertEqual(result.vehicle_bytes_confirmed_sent, count if type(count) is int and 0 <= count <= 11 else 0)
                    self.assertFalse(any(e[0] == "recv" for e in h.sock.events))
            for failure in ("creation", "setsockopt", "bind", "getsockopt", "getsockname", "settimeout", "connect", "getpeername", "send", "recv", "close"):
                with self.subTest(client=selection[1], failure=failure), ReadHarness(selection) as h:
                    h.sock.failure = failure; result = h.run()
                    self.assertEqual(result.outcome, "socket_error")
                    self.assertEqual((result.tcp_connections_attempted, result.tcp_connections_opened,
                        result.application_frames_attempted, result.application_frames_sent),
                        (int(failure in ("connect", "getpeername", "send", "recv", "close")),
                         int(failure in ("getpeername", "send", "recv", "close")),
                         int(failure in ("send", "recv", "close")), int(failure in ("recv", "close"))))
                    self.assertEqual(result.tcp_connection_uncertain, failure == "connect")
                    self.assertEqual(result.transmission_uncertain, failure == "send")
                    self.assertNotIn("PRIVATE SYNTHETIC ERROR", json.dumps(result.public_report()))
                    if failure != "creation": self.assertTrue(h.sock.closed)

    def test_pending_receive_caps_and_independent_connect_experiment_deadlines(self):
        for selection in READS:
            for case in ("positive","terminal","overall","first_window","chunks","bytes","eof","partial_eof","connect"):
                with self.subTest(client=selection[1],case=case),ReadHarness(selection) as h:
                    outcome="timeout"
                    if case=="positive": h.queue(h.ack()); h.queue(h.negative(),2); h.queue(h.positive(),2); outcome=h.success
                    elif case=="terminal": h.queue(h.negative(0x31)); outcome="negative_response"
                    elif case=="overall":
                        for _ in range(10): h.queue(h.negative(),2)
                    elif case=="first_window": h.queue(h.ack(),2); h.queue(h.positive()[:2],.5); h.queue(h.positive()[2:],.6)
                    elif case in ("chunks","bytes"):
                        for _ in range(100 if case=="chunks" else 1): h.queue(h.negative()*(1 if case=="chunks" else 10000))
                        outcome="receive_limit"
                    elif case in ("eof","partial_eof"):
                        if case=="partial_eof": h.queue(h.positive()[:10])
                        h.queue(b""); outcome="truncated_response" if case=="partial_eof" else "eof"
                    elif case=="connect": h.sock.connect_delay=4; outcome="connect_timeout"
                    result=h.run(); self.assertEqual(result.outcome,outcome)
                    if case=="connect": self.assertEqual((result.application_frames_attempted,h.sock.sent),(0,[])); continue
                    self.assert_sent_once(h,result)
                    if outcome!=h.success: self.assert_not_accepted(h,result)
                    if case in ("overall","first_window"): self.assertEqual(result.response_elapsed_seconds,6. if case=="overall" else 3.)
                    if case in ("chunks","bytes"): self.assertEqual(sum(len(c.data) for c in result.recv_chunks),704 if case=="chunks" else 65536)

    def test_interruptions_before_or_after_receipts_close_and_handler_clocks(self):
        for selection in READS:
            for case in ("recv_error","recv_interrupt","send_interrupt","close_error","close_interrupt","receipt_clock","final_clock"):
                with self.subTest(client=selection[1],case=case),ReadHarness(selection) as h:
                    raw=h.ack() if case.startswith("recv") else h.ack()+h.positive()
                    h.queue(raw)
                    if case.startswith("recv"): h.queue(OSError("PRIVATE") if case=="recv_error" else KeyboardInterrupt())
                    if case=="send_interrupt": h.stack.enter_context(patch.object(h.sock,"send",side_effect=KeyboardInterrupt))
                    if case.startswith("close"): h.stack.enter_context(patch.object(h.sock,"close",side_effect=OSError("PRIVATE") if case=="close_error" else KeyboardInterrupt()))
                    fired=False
                    def clock():
                        nonlocal fired
                        trigger=(case=="final_clock" and h.sock.closed) or (case=="receipt_clock" and any(e[0]=="recv" for e in h.sock.events))
                        if trigger and not fired: fired=True; raise KeyboardInterrupt()
                        return h.clock.now
                    h.stack.enter_context(patch("time.monotonic",side_effect=clock))
                    result=h.run(); sent=case!="send_interrupt"
                    self.assertEqual(result.outcome,"socket_error" if case in ("recv_error","close_error") else "interrupted")
                    self.assert_not_accepted(h,result)
                    self.assertEqual((result.application_frames_attempted,result.application_frames_sent,result.vehicle_bytes_confirmed_sent),(1,int(sent),11*int(sent)))
                    self.assertEqual([c.data for c in result.recv_chunks],[raw] if sent else [])
                    if case=="send_interrupt": self.assertTrue(result.transmission_uncertain)
                    if case.startswith("close"): self.assertTrue(result.tcp_close_uncertain)
                    if case=="receipt_clock": self.assertIsNone(result.recv_chunks[0].received_after_seconds)
                    if case=="final_clock": self.assertFalse(result.timing_complete)
