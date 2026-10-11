"""Synthetic-only live sender tests. All socket constructors are mocked."""

from dataclasses import replace
import json
import socket
import struct
from unittest.mock import patch

from i3enet import live_discovery as live
from i3enet.network import DiscoveryNetwork, IP_BOUND_IF
from i3enet.policy import PolicyViolation
from support import OfflineCase
from test_live_identity import FakeClock, FakeTCPSocket

SYNTHETIC_SOURCE = "169.254.164.147"
SYNTHETIC_GATEWAY = "169.254.0.2"
SYNTHETIC_VIN = b"SYNTHETIC00000001"
SYNTHETIC_MAC = b"001122AABBCC"

def synthetic_reply(body=b"DIAGADR10BMWVIN" + SYNTHETIC_VIN + b"BMWMAC" + SYNTHETIC_MAC):
    return struct.pack(">IH", len(body), 0x11) + body

class FakeSocket(FakeTCPSocket):
    """The shared bound-socket fixture with UDP-specific send/receive methods."""
    def __init__(self, clock, replies=()):
        super().__init__(clock)
        self.replies = list(replies); self.send_count = 6

    def sendto(self, payload, destination):
        self.events.append(("sendto", payload, destination)); self.sent.append((payload, destination))
        self.fail("sendto")
        return self.send_count

    def recvmsg(self, size):
        self.record("recvmsg", size)
        if not self.replies:
            self.clock.now += self.timeout
            raise socket.timeout()
        payload, peer, flags, delay = self.replies.pop(0)
        self.advance(delay)
        return payload[:size], [], flags | (socket.MSG_TRUNC if len(payload) > size else 0), peer

class LiveDiscoveryTests(OfflineCase):
    def setUp(self):
        self.network = DiscoveryNetwork("en9", SYNTHETIC_SOURCE, "169.254.255.255", 19,
                                        "255.255.0.0", "Apple USB Ethernet Adapter", True)
        self.clock = FakeClock(); self.sock = FakeSocket(self.clock); self.socket_calls = []
        values = (("discovery_preflight", dict(return_value=self.network)),
                  ("time.monotonic", dict(side_effect=self.clock.monotonic)),
                  ("socket.socket", dict(side_effect=self.make_socket)))
        for name, options in values:
            guard = patch("i3enet.live_discovery." + name, **options)
            patched = guard.start(); self.addCleanup(guard.stop)
            if name == "discovery_preflight": self.preflight_mock = patched

    def make_socket(self, *args):
        self.socket_calls.append(args)
        self.assertEqual(args, (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP))
        if self.sock.failure == "creation":
            raise OSError("SYNTHETIC PRIVATE ERROR")
        return self.sock

    def queue(self, payload=None, *, address=SYNTHETIC_GATEWAY, port=6811, flags=0, delay=0.0):
        self.sock.replies.append((synthetic_reply() if payload is None else payload,
                                  (address, port), flags, delay))

    def run_experiment(self):
        return live.discover_once(self.network)

    def assert_one_request(self, result):
        self.assertEqual(self.sock.sent, [(b"\0\0\0\0\0\x11", ("169.254.255.255", 6811))])
        self.assertEqual(self.socket_calls, [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)])
        self.assertEqual(result.vehicle_packets_attempted, 1)
        self.assertEqual(result.vehicle_packets_sent, 1)
        self.assertEqual(result.vehicle_bytes_confirmed_sent, 6)
        self.assertFalse(result.transmission_uncertain)
        self.assertTrue(self.sock.closed)

    def fresh(self):
        self.clock.now = 100.0; self.sock = FakeSocket(self.clock); self.socket_calls.clear()
        self.preflight_mock.reset_mock(); self.preflight_mock.side_effect = None

    def test_bounded_discovery_classifies_and_retains_all_peer_cases(self):
        valid = synthetic_reply()
        cases = (
            ("valid", [(valid, (SYNTHETIC_GATEWAY, 6811), 0, 0)], "gateway_found", 1),
            ("timeout", [], "timeout", 0),
            ("chatter", [(b"malformed", (SYNTHETIC_GATEWAY, 6811), 0, .2)] * 31, "malformed_response", 0),
            ("limit", [(b"malformed", (SYNTHETIC_GATEWAY, 6811), 0, 0)] * 100, "reply_limit", 0),
            ("truncation", [(valid, (SYNTHETIC_GATEWAY, 6811), socket.MSG_TRUNC, 0)], "malformed_response", 0),
            ("multiple", [(valid, (SYNTHETIC_GATEWAY, 6811), 0, 0),
                          (synthetic_reply(b"UNKNOWN"), ("169.254.0.3", 6811), 0, 0)], "multiple_gateways", 2),
            ("conflict", [(valid, (SYNTHETIC_GATEWAY, 6811), 0, 0),
                          (synthetic_reply(b"DIAGADR10BMWVIN" + b"SYNTHETIC00000002"), (SYNTHETIC_GATEWAY, 6811), 0, 0)], "ambiguous_gateway", 1),
            ("peers", [(valid, peer, 0, 0) for peer in ((SYNTHETIC_GATEWAY, 6801), ("10.0.0.2", 6811),
                       (SYNTHETIC_SOURCE, 6811), ("169.254.255.255", 6811), ("169.254.0.0", 6811))], "unexpected_peer_only", 0),
        )
        for name, replies, outcome, candidates in cases:
            with self.subTest(case=name):
                self.fresh(); self.sock.replies = list(replies); result = self.run_experiment()
                self.assert_one_request(result)
                self.assertEqual((result.outcome, len(result.candidates)), (outcome, candidates))
                self.assertEqual(self.preflight_mock.call_count, 2)
                self.assertEqual(self.sock.events[:3], [("setsockopt", socket.SOL_SOCKET, socket.SO_BROADCAST, 1),
                    ("setsockopt", socket.IPPROTO_IP, IP_BOUND_IF, 19), ("bind", (SYNTHETIC_SOURCE, 0))])
                self.assertLess(self.sock.events.index(("getsockname",)), next(i for i, row in enumerate(self.sock.events) if row[0] == "sendto"))
                if name in ("timeout", "chatter"): self.assertEqual(result.elapsed_seconds, 3.0)
                if name == "limit": self.assertEqual((len(result.datagrams), len(self.sock.replies)), (32, 68))
                if name == "chatter":
                    windows = [e[1] for e in self.sock.events if e[0] == "settimeout"][1:]
                    self.assertTrue(all(b < a for a, b in zip(windows, windows[1:])))
                if name == "truncation": self.assertTrue(result.datagrams[0].truncated)
                if name == "conflict": self.assertTrue(result.candidates[0].identity_conflict)
                if name == "peers": self.assertEqual([d.data for d in result.datagrams], [valid] * 5)
                self.assertNotIn(SYNTHETIC_VIN.decode(), json.dumps(result.public_report()))

    def test_rebound_source_interface_and_final_policy_deny_before_attempt(self):
        cases = ("network", "interface", "source", "policy", b"", b"\0\0\0\0\0\x12",
                 b"\0\0\0\0\0\x11\0", b"\x22\xf1\x90")
        for case in cases:
            with self.subTest(case=case):
                self.fresh()
                if case == "network": self.preflight_mock.side_effect = [self.network, replace(self.network, source_address="169.254.1.1")]
                if case == "interface": self.sock.readback_override = 20
                if case == "source": self.sock.local = ("169.254.1.1", 54321)
                target = patch.object(live, "DISCOVERY_REQUEST", case) if isinstance(case, bytes) else \
                         patch.object(live.LiveDiscoveryPolicy, "validate", side_effect=PolicyViolation("denied")) if case == "policy" else None
                if target:
                    with target as check: result = self.run_experiment()
                    if case == "policy": check.assert_called_once_with(b"\0\0\0\0\0\x11", ("169.254.255.255", 6811), sent_count=0)
                else: result = self.run_experiment()
                self.assertEqual(result.outcome, "policy_denied" if case == "policy" or isinstance(case, bytes) else "network_changed")
                self.assertEqual((self.sock.sent, result.vehicle_packets_attempted), ([], 0))
                self.assertTrue(self.sock.closed)

    def test_socket_partial_send_and_clock_interruptions_preserve_known_originals(self):
        stages = ("creation", "setsockopt", "bind", "getsockopt", "getsockname", "settimeout", "sendto", "recvmsg", "close")
        for case in (*stages, "partial", "send_interrupt", "recv_interrupt", "receipt_clock"):
            with self.subTest(case=case):
                self.fresh()
                if case in stages: self.sock.failure = case
                if case == "partial": self.sock.send_count = 3
                if case in ("close", "recv_interrupt", "receipt_clock"): self.queue()
                if case == "recv_interrupt":
                    receive = self.sock.recvmsg; calls = 0
                    def interrupted(size):
                        nonlocal calls
                        calls += 1
                        if calls > 1: raise KeyboardInterrupt()
                        return receive(size)
                    self.sock.recvmsg = interrupted
                target = patch.object(self.sock, "sendto", side_effect=KeyboardInterrupt) if case == "send_interrupt" else \
                         patch.object(live.time, "monotonic", side_effect=[100.0, 100.0, 100.0, KeyboardInterrupt(), 100.0]) if case == "receipt_clock" else None
                if target:
                    with target: result = self.run_experiment()
                else: result = self.run_experiment()
                attempted = case in ("sendto", "recvmsg", "close", "partial", "send_interrupt", "recv_interrupt", "receipt_clock")
                sent = case in ("recvmsg", "close", "recv_interrupt", "receipt_clock")
                self.assertEqual(result.outcome, "interrupted" if case.endswith("interrupt") or case == "receipt_clock" else "socket_error")
                self.assertEqual((result.vehicle_packets_attempted, result.vehicle_packets_sent,
                    result.vehicle_bytes_confirmed_sent), (int(attempted), int(sent), 3 if case == "partial" else int(sent) * 6))
                self.assertEqual(result.transmission_uncertain, case in ("sendto", "partial", "send_interrupt"))
                self.assertLessEqual(len(self.sock.sent), 1)
                if case != "creation": self.assertTrue(self.sock.closed)
                if case in ("close", "recv_interrupt", "receipt_clock"):
                    self.assertEqual(result.datagrams[0].data, synthetic_reply())
                if case == "receipt_clock":
                    self.assertIsNone(result.datagrams[0].received_after_seconds); self.assertFalse(result.timing_complete)
                    self.assertEqual(result.candidates, ())
                if case == "close": self.assertTrue(result.socket_close_uncertain)
                if case == "partial": self.assertFalse(any(e[0] == "recvmsg" for e in self.sock.events))
                self.assertNotIn("SYNTHETIC PRIVATE ERROR", json.dumps(result.public_report()))
