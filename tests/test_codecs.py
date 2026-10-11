"""Independent transport wire vectors, malformed streams and fixed coding codecs."""
import struct
import unittest
import hashlib
import json
import socket
from i3enet.hsfz import (
    FrameTooLargeError, IncrementalParser, MalformedFrameError, ParserStateError, TruncatedFrameError,
    UnknownControlError, decode_frame, encode_frame, HSFZFrame,
)
from i3enet.discovery import DiscoveryError, parse_discovery_response
from pathlib import Path
from unittest.mock import patch
from i3enet import coding_protocol as p
from i3enet.coding_preparation import GROUP_LENGTHS


WIRE = bytes.fromhex("000000050001f4a1221234")

class HSFZTests(unittest.TestCase):

    def test_malformed_geometry_resource_limits_and_terminal_parser(self):
        cases=[(300,0x1234,UnknownControlError),(0xFFFFFFFF,1,FrameTooLargeError)]
        cases += [(size,control,MalformedFrameError) for control,sizes in
                  ((1,(0,1,2)),(2,(0,1)),(0x40,(0,1,3)),(0x12,(1,))) for size in sizes]
        for length,control,error in cases:
            with self.subTest(length=length,control=control):
                parser=IncrementalParser(max_body_length=8)
                with self.assertRaises(error): parser.feed(struct.pack(">IH",length,control))
                self.assertEqual(parser.buffered_bytes,0)
                with self.assertRaises(ParserStateError): parser.feed(WIRE)
        with self.assertRaises(FrameTooLargeError): decode_frame(WIRE,max_body_length=4)
        with self.assertRaises(FrameTooLargeError): encode_frame(decode_frame(WIRE),max_body_length=4)
        for length in range(len(WIRE)):
            with self.assertRaises(TruncatedFrameError): decode_frame(WIRE[:length])
        with self.assertRaises(MalformedFrameError): decode_frame(WIRE+b"\0")

class DiscoveryTests(unittest.TestCase):
    def test_private_unique_identity_markers(self):
        vin, mac = b"SYNTHETIC00000001", b"001122AABBCC"
        body = b"DIAGADR10BMWMAC" + mac + b"BMWVIN" + vin
        for value in (body, b"DIAGADR10BMWVIN" + vin + b"BMWMAC" + mac):
            reply = parse_discovery_response(struct.pack(">IH", len(value), 0x11) + value)
            self.assertEqual((reply.vin_candidate, reply.mac_candidate), (vin.decode(), mac.decode()))
            self.assertNotIn(vin.decode(), repr(reply)); self.assertNotIn(mac.decode(), repr(reply))
        for value in (body + b"BMWVIN" + vin, body + b"BMWMAC" + mac, body + b"DIAGADR10",
                      b"DIAGADR10BMWVIN" + b"\xff" * 17, b"DIAGADR10BMWMACG01122AABBCC"):
            with self.subTest(body=value), self.assertRaises(DiscoveryError):
                parse_discovery_response(struct.pack(">IH", len(value), 0x11) + value)

class IndependentReferenceTests(unittest.TestCase):
    def test_matches_archived_independent_scapy_vectors_without_network(self):
        reference = json.loads((Path(__file__).parent / "fixtures" / "scapy-reference.json").read_text())
        self.assertEqual(reference["evidence_kind"], "SYNTHETIC_FIXTURE")
        self.assertFalse(reference["vehicle_traffic"])
        with patch.object(socket, "socket", side_effect=AssertionError("socket forbidden")), \
             patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")):
            for case in reference["cases"]:
                with self.subTest(name=case["name"]):
                    wire = bytes.fromhex(case["wire_hex"])
                    frame = HSFZFrame(int(case["control_hex"], 16), bytes.fromhex(case["body_hex"]))
                    self.assertEqual(hashlib.sha256(wire).hexdigest(), case["wire_sha256"])
                    self.assertEqual(encode_frame(frame), wire)
                    self.assertEqual(decode_frame(wire), frame)
                    parser = IncrementalParser()
                    self.assertEqual(parser.feed(wire[:3]) + parser.feed(wire[3:]), [frame])
                    parser.finish()

class CodingProtocolTests(unittest.TestCase):
    def test_fixed_requests_geometry_echoes_and_explicit_layouts(self):
        rejected = []
        for sub in p.SESSION_SEQUENCE:
            self.assertEqual(p.session_request(sub), bytes((0x10, sub)))
            reply = bytes((0x50, sub, 0, 50, 0, 100))
            timing = p.parse_session_response(reply, sub, layout="p2_timing")
            self.assertEqual((timing.p2_max_milliseconds, timing.p2_star_milliseconds), (50, 1000))
            self.assertIsNone(p.parse_session_response(reply, sub, layout="opaque_parameters").p2_max_milliseconds)
            rejected += [(p.parse_session_response, (raw, sub), {"layout":"p2_timing"})
                for raw in (reply[:-1], reply+b"x", bytes((0x50,sub^0x80))+reply[2:])]
            rejected.append((p.parse_session_response, (reply,sub), {"layout":"guess"}))
        rejected.append((p.session_request,(2,),{}))
        seed = bytes(range(16)); envelope = bytes.fromhex("00000020") + b"x" * 128
        self.assertEqual(p.seed_request(), bytes.fromhex("2701ffffffff"))
        parsed = p.parse_seed_response(b"\x67\x01" + seed)
        self.assertEqual(parsed.seed, seed); self.assertNotIn(str(seed), repr(parsed))
        self.assertEqual(p.key_request(envelope), b"\x27\x02" + envelope)
        cps = b"TEST123"
        fixed = ((p.signature_check_request, bytes.fromhex("31010f01")),
                 (p.cps_read_request, bytes.fromhex("2237fe")), (p.reset_request, b"\x11\x01"))
        for encoder, expected in fixed: self.assertEqual(encoder(), expected)
        self.assertEqual(p.cps_write_request(cps), bytes.fromhex("2e37fe") + cps)
        for parser, raw in ((p.parse_key_response,b"\x67\x02"),
                           (p.parse_cps_write_response,bytes.fromhex("6e37fe")),
                           (p.parse_reset_response,b"\x51\x01")): parser(raw)
        p.parse_cps_read_response(bytes.fromhex("6237fe") + cps,cps)
        for status in (0,1): self.assertEqual(p.parse_signature_check_response(bytes.fromhex("71010f01")+bytes((status,))),status==0)
        for address,length in GROUP_LENGTHS:
            data=b"x"*length; did=address.to_bytes(2,"big")
            self.assertEqual(p.group_write_request(address,data),b"\x2e"+did+data)
            self.assertEqual(p.group_read_request(address),b"\x22"+did)
            p.parse_group_write_response(b"\x6e"+did,address)
            self.assertEqual(p.parse_group_read_response(b"\x62"+did+data,address),data)
        self.assertEqual(p.ping_request(layout="f186_state"),bytes.fromhex("22f186"))
        for suffix in ("4102","4101","0181","01ff","0240"):
            self.assertFalse(p.parse_ping_response(bytes.fromhex("62f186"+suffix),layout="f186_state").proves_coding_persistence)
        rejected += [(p.parse_ping_response,(bytes.fromhex(raw),),{"layout":"f186_state"}) for raw in
            ("62f18601","62f1864202","62f186018100")]
        for layout in ("f186_session_only","f100_state","guess"):
            rejected += [(p.ping_request,(),{"layout":layout}),
                         (p.parse_ping_response,(bytes.fromhex("62f1860181"),),{"layout":layout})]
        for parser,args,kwargs in rejected:
            with self.subTest(parser=parser.__name__,args=args,kwargs=kwargs), self.assertRaises(p.CodingProtocolError):
                parser(*args,**kwargs)
