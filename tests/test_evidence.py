"""Independent discovery/VIN/SVK originals, proof bindings and private file validation."""
from dataclasses import FrozenInstanceError
import unittest
import os
from i3enet.evidence import (
    EvidenceError, MAX_MANIFEST_BYTES, load_gateway_identity_evidence, load_gateway_vin_read_evidence,
)
from i3enet.svk import (parse_svk_value, load_head_unit_svk_evidence, load_bdc_svk_evidence,
    load_vsg_svk_evidence, BDCSVKEvidence, VSGSVKEvidence)
from copy import deepcopy
from unittest.mock import patch
from support import StreamEvidenceCase, digest, frame, proofs, stream_manifest
from i3enet import __version__


def record(kind, identifier, version):
    return bytes([kind]) + identifier.to_bytes(4, "big") + bytes(version)

CAFD = record(5, 0xDED, (3, 15, 41))
BTLD = record(6, 0x1ABA, (130, 26, 1))
OPAQUE_RECORD = record(0xEF, 0x12345678, (10, 20, 30))

def synthetic_value(records=(BTLD, OPAQUE_RECORD, CAFD), extra=b"SYNTHETIC!"):
    # Status/date/extra bytes are arbitrary synthetic opaque data.
    return b"\xAA\xBB" + len(records).to_bytes(2, "big") + b"\x11\x22\x33" + extra + b"".join(records)

class SVKDecoderTests(unittest.TestCase):
    def test_record_order_unsigned_count_and_missing_geometry(self):
        decoded=parse_svk_value(synthetic_value())
        self.assertEqual((decoded.record_count,len(decoded.header)),(3,17))
        self.assertEqual([r.kind for r in decoded.records],[6,0xEF,5])
        self.assertEqual((decoded.records[-1].identifier,decoded.records[-1].version),(0xDED,(3,15,41)))
        self.assertNotIn("SYNTHETIC",repr(decoded))
        with self.assertRaises(FrozenInstanceError): decoded.record_count=4
        high=parse_svk_value(synthetic_value((OPAQUE_RECORD,)*256,extra=b""))
        self.assertEqual((high.record_count,len(high.records),len(high.header)),(256,256,7))
        value=synthetic_value(extra=b"")
        malformed=[value[:2]+count.to_bytes(2,"big")+value[4:] for count in (0,4,257,0xFFFF)]
        for raw in malformed+[value[:-1]]:
            with self.subTest(length=len(raw)),self.assertRaises(EvidenceError): parse_svk_value(raw)

VIN, SOURCE, GATEWAY = "SYNTHETICVIN00001", "169.254.33.44", "169.254.11.22"

class ProofFixture(StreamEvidenceCase):
    """Reusable independent original encoder; contains no discovered tests."""
    def setUp(self):
        self.root = self.temporary()
        self.forbid()

    def reset(self, kind):
        self.kind = kind
        self.directory = self.root / f"{kind}-{len(list(self.root.iterdir()))}"
        self.directory.mkdir(mode=0o700)
        _, self.discovery, self.identity, _ = proofs(27,GATEWAY,SOURCE,VIN)
        if kind == "discovery":
            body = b"DIAGADR10BMWMACAABBCCDDEEFFBMWVIN" + VIN.encode()
            self.raw = len(body).to_bytes(4,"big") + b"\0\x11" + body
            self.manifest = dict(schema_version=1,implementation_version=__version__,private_raw_originals=True,
                report=dict(schema_version=1,implementation_version=__version__,command="discover",mode="live_discovery",
                    outcome="gateway_found",reason=None,source_interface="en9",source_address=SOURCE,
                    timing_complete=True,socket_close_uncertain=False,
                    broadcast_address="169.254.255.255",destination_port=6811,discovery_request_hex="000000000011",
                    route_verified=True,interface_index=27,vehicle_packets_attempted=1,vehicle_packets_sent=1,
                    vehicle_bytes_confirmed_sent=6,transmission_uncertain=False,diagnostic_tcp_opened=False,writes_supported=False,
                    received_datagrams=1,truncated_datagrams=0,rejected_datagrams=0,captured_bytes=len(self.raw),
                    candidates=[dict(address=GATEWAY,port=6811,reply_count=1,layouts=["marker_identity"],
                                     identity_conflict=False,masked_vin_candidates=["*"*13+VIN[-4:]])]),
                datagrams=[dict(file="reply-01.bin",sha256=digest(self.raw),byte_length=len(self.raw),peer_address=GATEWAY,
                               peer_port=6811,truncated=False,disposition="candidate",reason=None,received_after_seconds=.01)])
            self.write_private("reply-01.bin",self.raw); self.persist()
            return
        self.request = bytes.fromhex("000000050001f41022f190" if kind=="vin" else
                                     "000000050001f44022f101" if kind=="bdc_svk" else
                                     "000000050001f42d22f101" if kind=="vsg_svk" else "000000050001f46322f101")
        self.value = VIN.encode() if kind=="vin" else synthetic_value()
        self.ack = frame(self.request[6:],2)
        self.positive = frame(bytes((self.request[7],0xF4,0x62))+self.request[9:]+self.value)
        self.manifest = stream_manifest(self.discovery,self.request,
            "identify-gateway" if kind=="vin" else "read-vsg-svk" if kind=="vsg_svk" else "read-bdc-svk" if kind=="bdc_svk" else "read-head-unit-svk",
            "live_gateway_identity" if kind=="vin" else "live_vsg_svk" if kind=="vsg_svk" else "live_bdc_svk" if kind=="bdc_svk" else "live_head_unit_svk",
            "vin_match" if kind=="vin" else "identity_value_observed",
            __version__)
        report = self.manifest["report"]
        if kind=="vin":
            report.update(gateway_diagnostic_address="0x10",masked_vin_candidate="*"*13+VIN[-4:],
                vehicle_identity_status="gateway_vin_matches_discovery",transport_identity_status="gateway_vin_response_matches_discovery",vin_matches_discovery=True)
        else:
            self.manifest["source_gateway_identity"] = dict(manifest_sha256="c"*64,request_sha256=self.identity.request_sha256)
            target=f"0x{self.request[7]:02X}"
            report.update(candidate_diagnostic_address=target,candidate_address=target,identity_manifest_sha256="c"*64,
                identity_request_sha256=self.identity.request_sha256,vehicle_identity_status="prior_gateway_vin_matches_discovery",
                transport_identity_status="candidate_identity_response_via_previously_vin_matched_gateway",
                candidate_address_status="identity_response_received",address_association_status="unconfirmed",
                head_unit_identity_status="unverified",head_unit_status="unverified",ecu_software_status="unverified",
                value_interpretation="opaque_private_value_requires_review",prior_gateway_vin_match=True,vehicle_contacted=None,
                timing_complete=True,tcp_close_uncertain=False,maximum_application_frames=1,receive_byte_limit=65536,
                receive_chunk_limit=64,receive_frame_body_limit=4096,value_byte_count=len(self.value),value_sha256=digest(self.value))
        self.chunks = [self.ack,self.positive]; self.persist_chunks()

    def load(self, **changes):
        options = dict(manifest_sha256=self.manifest_hash)
        if self.kind=="discovery":
            options.update(gateway_address=GATEWAY,source_interface="en9",source_address=SOURCE)
            loader=load_gateway_identity_evidence
        else:
            options["discovery"]=self.discovery
            loader={"vin":load_gateway_vin_read_evidence,"bdc_svk":load_bdc_svk_evidence,
                    "vsg_svk":load_vsg_svk_evidence,"svk":load_head_unit_svk_evidence}[self.kind]
            if self.kind != "vin": options["identity"]=self.identity
        return loader(self.directory,**(options|changes))

    def rejected(self):
        with self.assertRaises(EvidenceError) as caught: self.load()
        self.redacted(caught.exception,VIN,self.raw.hex() if self.kind=="discovery" else self.value.hex())

    def persist_changed(self, manifest):
        self.manifest=manifest; self.persist()

class EvidenceTests(ProofFixture):
    def test_independent_success_versions_and_complete_vin_ack(self):
        for kind in ("discovery","vin","svk","bdc_svk","vsg_svk"):
            with self.subTest(kind=kind):
                self.reset(kind); evidence=self.load()
                self.assertEqual(evidence.manifest_sha256,self.manifest_hash)
                self.redacted(evidence,VIN)
                self.manifest["implementation_version"]='0.0.0'
                self.persist()
                with self.assertRaises(EvidenceError):self.load()
                self.manifest["implementation_version"]=__version__
                self.manifest["report"].update(implementation_version=__version__,timing_complete=True,
                    **({"socket_close_uncertain":False} if kind=="discovery" else {"tcp_close_uncertain":False}))
                self.persist(); self.load()
                if kind=="svk": self.fields(evidence,cafd_identifier="00000DED",cafd_version="003.015.041",btld_identifier="00001ABA",btld_version="130.026.001")
                if kind=="vin":
                    self.load()
                    self.chunks=[frame(b"\xf4\x10",2),self.positive]; self.persist_chunks()
                    with self.assertRaises(EvidenceError): self.load()

    def test_bdc_observation_cannot_promote_hu_or_grant_coding_compatibility(self):
        self.reset("bdc_svk")
        value=synthetic_value((record(5,0x1234,(1,2,3)),record(6,0x17B6,(4,5,6))))
        self.manifest["report"].update(value_byte_count=len(value),value_sha256=digest(value))
        self.chunks=[self.ack,frame(b"\x40\xf4\x62\xf1\x01"+value)]; self.persist_chunks()
        evidence=self.load()
        self.assertIs(type(evidence),BDCSVKEvidence)
        self.fields(evidence,cafd_identifier="00001234",cafd_version="001.002.003",btld_identifier="000017B6",btld_version="004.005.006")
        with self.assertRaises(EvidenceError):
            load_head_unit_svk_evidence(self.directory,manifest_sha256=self.manifest_hash,discovery=self.discovery,identity=self.identity)
        original=deepcopy(self.manifest)
        for field,changed in (("command","read-head-unit-svk"),("mode","live_head_unit_svk"),("candidate_address","0x63"),("candidate_diagnostic_address","0x63")):
            self.manifest=deepcopy(original); self.manifest["report"][field]=changed; self.persist(); self.rejected()
        self.manifest=original
        for stream in (self.positive,frame(b"\xf4\x63\x22\xf1\x01",2)+self.chunks[1],
                       self.ack+frame(b"\x63\xf4\x62\xf1\x01"+value),self.ack+self.chunks[1]+b"\0"):
            self.chunks=[stream]; self.persist_chunks(); self.rejected()
        self.reset("svk")
        with self.assertRaises(EvidenceError):
            load_bdc_svk_evidence(self.directory,manifest_sha256=self.manifest_hash,discovery=self.discovery,identity=self.identity)
        self.reset("vsg_svk"); evidence=self.load()
        self.assertIs(type(evidence),VSGSVKEvidence)
        for loader in (load_bdc_svk_evidence,load_head_unit_svk_evidence):
            with self.assertRaises(EvidenceError):
                loader(self.directory,manifest_sha256=self.manifest_hash,discovery=self.discovery,identity=self.identity)
        self.chunks=[frame(b"\xf4\x40\x22\xf1\x01",2),self.positive]; self.persist_chunks(); self.rejected()

    def test_fixed_manifest_claims_links_rows_and_selection_cannot_replace_originals(self):
        common = "command mode outcome reason source_interface source_address destination_port interface_index route_verified writes_supported transmission_uncertain"
        fields = dict(discovery="broadcast_address discovery_request_hex diagnostic_tcp_opened vehicle_packets_attempted vehicle_packets_sent vehicle_bytes_confirmed_sent received_datagrams truncated_datagrams rejected_datagrams",
            vin="gateway_address identifier request_hex vin_matches_discovery masked_vin_candidate tcp_connections_opened application_frames_sent vehicle_bytes_confirmed_sent",
            svk="gateway_address identifier request_hex prior_gateway_vin_match identity_manifest_sha256 identity_request_sha256 value_sha256 value_byte_count timing_complete tcp_close_uncertain head_unit_status")
        for kind in fields:
            self.reset(kind); original=deepcopy(self.manifest); report=original["report"]
            changes=[(("report",key),True if key=="interface_index" else not value if type(value) is bool else 999 if type(value) is int else "invalid")
                for key in (common+" "+fields[kind]).split() for value in (report[key],)]
            rows="datagrams" if kind=="discovery" else "received_chunks"
            changes += [((rows,0,key),value) for key,value in (("file","../outside.bin"),("sha256","0"*64),("byte_length",True))]
            if kind=="discovery":
                changes += [(("report","candidates",0,key),value) for key,value in (("address",SOURCE),("port",6801),("identity_conflict",True),("masked_vin_candidates",[]))]
            else:
                changes += [(("request",key),value) for key,value in (("confirmed_bytes",4),("sha256","0"*64),("file","other.bin"))]
                changes += [((section,key),"0"*64) for section in original if section.startswith("source_") for key in original[section]]
            self.mutate(original,changes,self.persist_changed,self.rejected)
        for pin in (None,"INVALID","0"*64):
            self.reset("discovery")
            with self.assertRaises(EvidenceError): self.load(manifest_sha256=pin)
        for raw in (b"{",b"\xff",b"[]",b'{"x":1,"x":1}',b'{"x":NaN}'):
            self.persist(raw); self.rejected()

    def test_stream_wire_hash_correlation_pending_and_selected_software(self):
        for kind in ("vin","svk","bdc_svk","vsg_svk"):
            self.reset(kind)
            for stream in (self.positive,self.ack*2+self.positive,self.ack+self.positive+b"\0",self.ack+self.positive*2,
                    self.ack+self.positive[:-1],self.ack+frame(b"\x63\xf4\x7f\x22\x31")):
                with self.subTest(kind=kind,stream=digest(stream)):
                    self.chunks=[stream]; self.persist_chunks(); self.rejected()
            self.chunks=[self.ack,self.positive]; self.persist_chunks()
            self.write_private("recv-01.bin",b"tampered"); self.rejected()
            self.persist_chunks(); self.write_private("request.bin",self.request[:-1]); self.rejected()
        for records in ((BTLD,),(CAFD,),(CAFD,CAFD,BTLD),(CAFD,BTLD,BTLD),(record(5,0xDED,(3,15,6)),BTLD),(CAFD,record(6,0x1ABA,(130,26,2)))):
            self.reset("svk"); value=synthetic_value(records)
            self.manifest["report"].update(value_byte_count=len(value),value_sha256=digest(value))
            self.chunks=[self.ack,frame(b"\x63\xf4\x62\xf1\x01"+value)]; self.persist_chunks(); self.rejected()
        self.reset("vin"); self.chunks=[self.ack,frame(b"\x10\xf4\x7f\x22\x78"),self.positive]
        self.manifest["report"].update(pending_count=1,nrc="0x78"); self.persist_chunks(); self.load()
        self.manifest["report"]["pending_count"]=0; self.persist(); self.rejected()

    def test_private_file_types_ownership_size_and_ordered_finite_time(self):
        for attack in ("mode","directory","symlink","directory_link","hardlink","fifo","owner"):
            with self.subTest(attack=attack):
                self.reset("svk"); path=self.directory/"recv-01.bin"
                if attack=="mode": path.chmod(0o644)
                elif attack=="directory": self.directory.chmod(0o755)
                elif attack in ("symlink","directory_link"):
                    selected=self.directory if attack=="directory_link" else path
                    backup=selected.with_name(selected.name+"-original"); selected.rename(backup); selected.symlink_to(backup)
                elif attack=="hardlink": os.link(path,self.directory/"alias")
                elif attack=="fifo": path.unlink(); os.mkfifo(path,0o600)
                if attack=="owner":
                    with patch("i3enet.evidence.os.geteuid",return_value=os.geteuid()+1): self.rejected()
                else: self.rejected()
        for value in (None,True,-1,float("nan"),float("inf"),6):
            self.reset("svk"); self.persist_chunks(times=[.01,value]); self.rejected()
        self.reset("discovery"); self.write_private("manifest.json",b"x"*(MAX_MANIFEST_BYTES+1)); self.rejected()
        self.reset("discovery"); original=os.read; changed=False
        def raced(fd,amount):
            nonlocal changed
            raw=original(fd,amount)
            if not changed: changed=True; path=self.directory/"manifest.json"; path.write_bytes(path.read_bytes()[:-1]+b" ")
            return raw
        with patch("i3enet.evidence.os.read",side_effect=raced): self.rejected()
