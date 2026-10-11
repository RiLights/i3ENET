"""Independent EXBOX original validation; no actual car, keys or probes."""

from contextlib import ExitStack
import json
from pathlib import Path
import struct
from support import OfflineCase, proofs, write_json, bdc_svk, vsg_svk
from unittest.mock import patch

from i3enet import __version__
from i3enet import block_evidence as evidence
from i3enet.artifacts import (ExboxArtifactStore, BDCPfFesArtifactStore, BDCMetadataArtifactStore,
    VSGConfigArtifactStore, VSGMetadataArtifactStore)
from i3enet.evidence import EvidenceError
from i3enet.live_block import ModuleBlockResult
from i3enet.live_identity import ReceivedTCPChunk

FIXED_REQUEST = bytes.fromhex("000000050001f463223001")
SYNTHETIC_PRIVATE_MARKER = b"SYNTHETIC_PRIVATE_EXBOX_PAYLOAD"
SYNTHETIC_VIN = "SYNTHETIC00000001"

def frame(pdu: bytes, *, control=1, source=0x63, target=0xF4):
    body = bytes((source, target)) + pdu
    return struct.pack(">IH", len(body), control) + body

def ack(pdu=b"\x22\x30\x01"):
    return frame(pdu, control=2, source=0xF4, target=0x63)

def value_bytes(byte=0xFF, length=151):
    value = bytearray((SYNTHETIC_PRIVATE_MARKER + bytes(range(256)))[:length])
    if length > 58:
        value[58] = byte
    return bytes(value)

class ExboxEvidenceTests(OfflineCase):
    def setUp(self):
        self.forbid("socket.socket","socket.getaddrinfo","socket.gethostbyname","subprocess.run","i3enet.auth_provider.load_auth_provider")
        self.root=self.temporary(); self.guards=ExitStack(); self.addCleanup(self.guards.close)
        self.network=("en9","169.254.20.3","169.254.0.2",19)
        self.proof_links=tuple((name,"private/synthetic-"+name,pin) for name,pin in zip(("discovery","identity","svk"),("a"*64,"c"*64,"d"*64)))
        _,source,gateway,index=self.network
        _,self.discovery,self.identity,self.svk=proofs(index,gateway,source,SYNTHETIC_VIN)
        self.loaders=[self.guards.enter_context(patch.object(evidence,name,return_value=proof))
            for name,proof in (("load_gateway_identity_evidence",self.discovery),
                              ("load_gateway_vin_read_evidence",self.identity),("load_head_unit_svk_evidence",self.svk))]

    def capture(self, byte=0xFF, *, value=None, raws=None, times=None, pending=0, bdc=False, vsg=False, kind=None):
        target=0x2D if vsg else 0x40 if bdc else 0x63;did=0x3000 if vsg else 0x3221 if bdc else 0x3001
        svk=vsg_svk(self.svk) if vsg else bdc_svk(self.svk) if bdc else self.svk
        if kind:did=(evidence.BDC_METADATA|evidence.VSG_METADATA)[kind][0]
        request=bytes.fromhex('000000050001f4')+bytes((target,0x22))+did.to_bytes(2,'big')
        value = value_bytes(byte,length=8 if vsg else 17 if bdc else 151) if value is None else value
        raws = [frame(request[8:],control=2,source=0xF4,target=target),frame(b'\x62'+request[9:]+value,source=target)] if raws is None else raws
        times = [0.01 + i * 0.01 for i in range(len(raws))] if times is None else times
        response = max(times) + 0.01
        result = ModuleBlockResult("coding_value_observed", None, 1, 1, False, 1, 1, 11, False,
            request, tuple(ReceivedTCPChunk(raw, at) for raw, at in zip(raws, times)), value,
            1, pending, 0x78 if pending else None, 1, response + 0.1, response, response + 0.05, True, False,target,int.from_bytes(request[9:],'big'))
        report = result.public_report()
        report.update(command="read-vsg-config" if vsg else "read-bdc-pffes" if bdc else "read-exbox", mode="live_vsg_config" if vsg else "live_bdc_pffes" if bdc else "live_exbox", implementation_version=__version__,
            source_interface=self.network[0], source_address=self.network[1],
            gateway_address=self.network[2], interface_index=self.network[3], route_verified=True,
            observed_cafd_identifier=svk.cafd_identifier, observed_cafd_version=svk.cafd_version,
            observed_btld_identifier=svk.btld_identifier, observed_btld_version=svk.btld_version,
            discovery_manifest_sha256=self.discovery.manifest_sha256,
            discovery_reply_sha256=self.discovery.reply_sha256,
            identity_manifest_sha256=self.identity.manifest_sha256,
            identity_request_sha256=self.identity.request_sha256,
            svk_manifest_sha256=svk.manifest_sha256, svk_request_sha256=svk.request_sha256,
            prior_svk_value_sha256=svk.value_sha256, prior_gateway_vin_match=True, prior_svk_match=True)
        if kind: report.update(command='read-'+kind.replace('_','-'),mode='live_'+kind)
        with (VSGMetadataArtifactStore if vsg and kind else BDCMetadataArtifactStore if kind else VSGConfigArtifactStore if vsg else BDCPfFesArtifactStore if bdc else ExboxArtifactStore)(self.root) as store:
            report["raw_artifacts"] = store.save_block(result, report.copy(), self.identity, svk)
        return report

    def manifest(self, report):
        path = Path(report["raw_artifacts"]["directory"]) / "manifest.json"
        return path, json.loads(path.read_bytes())

    def rewrite(self, report, manifest):
        report["raw_artifacts"]["manifest_sha256"] = write_json(self.manifest(report)[0], manifest)


    def load(self, report):
        return evidence.load_exbox_value(report, root=self.root, network=self.network, proofs=self.proof_links)

    def assert_rejected(self, report):
        with self.assertRaises(EvidenceError): self.load(report)

    def test_proof_load_failures_stop_original_promotion(self):
        for index, loader in enumerate(self.loaders):
            with self.subTest(proof=index), patch.object(loader, "side_effect", EvidenceError("bad_proof")):
                self.assert_rejected(self.capture())

    def test_original_stream_fragmentation_pending_ack_geometry_and_trailers(self):
        good = frame(b"\x62\x30\x01" + value_bytes()); raw = ack() + good
        for name, raws, pending in (("coalesced", [raw], 0), ("fragmented", [raw[:2], raw[2:8], raw[8:12], raw[12:]], 0),
                                    ("pending", [ack(), frame(b"\x7f\x22\x78"), good], 1)):
            with self.subTest(mode=name): self.assertEqual(self.load(self.capture(raws=raws, pending=pending)), value_bytes())
        faults = (("empty_ack", ack(b"")), ("short_ack", ack(b"\x22\x30")), ("long_ack", ack(b"\x22\x30\x01\0")),
                  ("reverse_ack", frame(b"\x22\x30\x01", control=2)), ("duplicate_ack", ack() * 2), ("missing_ack", good))
        for name, bad in faults:
            with self.subTest(fault=name):
                report = self.capture(raws=[bad, good]); self.assert_rejected(report)
        for length in (0, 150, 152):
            with self.subTest(value_length=length): self.assert_rejected(self.capture(value=b"" if length == 0 else value_bytes(length=length)))
        for name, trailer in (("partial", b"\0"), ("duplicate_positive", good), ("late_ack", ack())):
            with self.subTest(trailer=name):
                report = self.capture(raws=[ack(), good + trailer]); self.assert_rejected(report)

    def test_original_hashes_complete_report_and_source_links_are_independently_reparsed(self):
        for kind in ("pin","raw","source","complete","outer"):
            with self.subTest(kind=kind):
                report=self.capture(); path,manifest=self.manifest(report)
                if kind=="pin": report["raw_artifacts"]["manifest_sha256"]="0"*64
                elif kind=="raw": (path.parent/"recv-02.bin").write_bytes(b"tampered")
                elif kind=="source": manifest["source_head_unit_svk"]["manifest_sha256"]="0"*64; self.rewrite(report,manifest)
                elif kind=="complete": manifest["report"]["timing_complete"]=report["timing_complete"]=False; self.rewrite(report,manifest)
                else: report["response_elapsed_seconds"]+=.01
                self.assert_rejected(report)

    def test_private_capture_category_is_required(self):
        report=self.capture()
        report["raw_artifacts"]["directory"]=str(self.root/"elsewhere")
        self.assert_rejected(report)

    def test_bdc_group_reopens_exact_lengths_address_proof_and_complete_ack(self):
        with patch.object(evidence,'load_vsg_svk_evidence',return_value=vsg_svk(self.svk)):
            for kind,(_,length,_) in evidence.VSG_METADATA.items():
                raw=bytes(length or 4);report=self.capture(vsg=True,kind=kind,value=raw)
                self.assertEqual(evidence.load_vsg_metadata_value(kind,report,root=self.root,network=self.network,proofs=self.proof_links),raw)
                path,manifest=self.manifest(report);manifest['source_vsg_svk']['request_sha256']='0'*64;self.rewrite(report,manifest)
                with self.assertRaises(EvidenceError):evidence.load_vsg_metadata_value(kind,report,root=self.root,network=self.network,proofs=self.proof_links)
        with patch.object(evidence,'load_bdc_svk_evidence',return_value=bdc_svk(self.svk)):
            for kind, (_, length, _) in evidence.BDC_METADATA.items():
                raw = bytes(length or 4); report = self.capture(bdc=True, kind=kind, value=raw)
                self.assertEqual(evidence.load_bdc_metadata_value(kind, report,root=self.root,network=self.network,proofs=self.proof_links), raw)
                (Path(report['raw_artifacts']['directory'])/'recv-02.bin').write_bytes(b'altered')
                with self.assertRaises(EvidenceError): evidence.load_bdc_metadata_value(kind,report,root=self.root,network=self.network,proofs=self.proof_links)
            def load(report):return evidence.load_bdc_pffes_value(report,root=self.root,network=self.network,proofs=self.proof_links)
            self.assertEqual(load(self.capture(bdc=True)),value_bytes(length=17))
            for fault in ('length','address','did','ack','source','hash'):
                report=self.capture(bdc=True)
                if fault=='length':report=self.capture(bdc=True,value=bytes(18))
                elif fault in ('address','did','ack'):
                    request=bytes.fromhex('223221');raw=frame(b'\x62'+request[1:]+value_bytes(length=17),source=0x63 if fault=='address' else 0x40)
                    if fault=='did':raw=frame(b'\x62\x32\x22'+value_bytes(length=17),source=0x40)
                    report=self.capture(bdc=True,raws=[frame(request[:-1] if fault=='ack' else request,control=2,source=0xF4,target=0x40),raw])
                else:
                    path,manifest=self.manifest(report)
                    if fault=='source':manifest['source_bdc_svk']['request_sha256']='0'*64;self.rewrite(report,manifest)
                    else:(path.parent/'recv-02.bin').write_bytes(b'changed')
                with self.subTest(fault=fault),self.assertRaises(EvidenceError):load(report)
