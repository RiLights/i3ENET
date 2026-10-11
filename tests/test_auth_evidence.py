"""Independent auth originals and private-retention contracts for fixed captures."""
from dataclasses import replace
import hashlib
import json
import struct
from pathlib import Path
from support import proofs, OfflineCase, digest, write_private, write_json, frame, bdc_svk, vsg_svk
from i3enet.auth_evidence import (
    AuthSessionEvidence, SCHEMA, FIXED_REQUESTS, load_auth_session_evidence,
    load_auth_seed_evidence, validate_capture,
)
from i3enet.coding_protocol import CodingProtocolError
from i3enet.evidence import EvidenceError
from i3enet.hsfz import HSFZError
from i3enet.live_head_unit_auth import HeadUnitAuthResult
from i3enet.live_identity import ReceivedTCPChunk
from types import SimpleNamespace
from unittest.mock import patch
from i3enet import __version__
from i3enet.artifacts import ArtifactError, DiscoveryArtifactStore, GatewayIdentityArtifactStore
from i3enet.auth_artifacts import HeadUnitAuthenticationArtifactStore
from i3enet.coding_snapshot_artifacts import CodingSnapshotArtifactStore
from i3enet.coding_snapshot import load_coding_snapshot
from i3enet.live_coding_snapshot import CodingSnapshotResult, GROUP_LENGTHS, SNAPSHOT_REQUESTS


MANUAL_REQUESTS = tuple(bytes.fromhex(raw) for raw in (
    "000000040001f4631003", "000000040001f4631041", "000000080001f4632701ffffffff"))
SYNTHETIC_PARAMETERS = bytes.fromhex("00320064")
SYNTHETIC_SEED = b"SYNTHETIC_CHALLENGE"

def hsfz(payload: bytes, control: int = 1, source: int = 0x63, target: int = 0xF4) -> bytes:
    body = bytes((source, target)) + payload
    return struct.pack(">IH", len(body), control) + body

class AuthFixture:
    """Invented source links and independently encoded original stream bytes."""

    def __init__(self, module='HU'):
        _, self.discovery, self.identity, self.svk = proofs()
        self.module = module
        if module != 'HU': self.svk = {'BDC':bdc_svk,'VSG01':vsg_svk}[module](self.svk)
        self.session = AuthSessionEvidence("f" * 64, "a" * 64, "c" * 64, "d" * 64,
            "opaque_parameters" if module != 'HU' else "p2_timing", 4, hashlib.sha256(SYNTHETIC_PARAMETERS).hexdigest(),module)


    def success(self, mode="observe_extended_session", *, parameters=SYNTHETIC_PARAMETERS,
                seed=SYNTHETIC_SEED, pending=0):
        count = {"observe_extended_session": 1, "capture_auth_seed": 3, 'capture_bdc_seed_and_default':5,'capture_vsg_seed_and_default':5}[mode]
        commands = {"observe_extended_session": "observe-head-unit-extended-session",
                    "capture_auth_seed": "prepare-head-unit-auth", 'capture_bdc_seed_and_default':'prepare-bdc-auth','capture_vsg_seed_and_default':'prepare-vsg-auth'}
        outcomes = {"observe_extended_session": "extended_session_observed",
                    "capture_auth_seed": "authentication_seed_observed",'capture_bdc_seed_and_default':'authentication_seed_default_session_observed',
                    'capture_vsg_seed_and_default':'authentication_seed_default_session_observed'}
        stages = ("extended_session", "coding_session", "security_seed", 'default_session', 'session_state')[:count]
        target = {'HU':0x63,'BDC':0x40,'VSG01':0x2D}[self.module]
        requests = tuple(r[:7]+bytes((target,))+r[8:] for r in MANUAL_REQUESTS[:min(count,3)])
        pdus = (b"\x50\x03" + parameters, b"\x50\x41" + parameters, b"\x67\x01" + seed,
                b'\x50\x01'+parameters,b'\x62\xf1\x86\x01\x81')
        if count == 5: requests += tuple(bytes.fromhex(s)+bytes((target,))+bytes.fromhex(p)
            for s,p in (('000000040001f4','1001'),('000000050001f4','22f186')))
        starts = tuple(0.2 + i for i in range(count))
        chunks, attribution = [], []
        for index, request in enumerate(requests):
            # Encode the source's 13-byte maximum independently of the project helper.
            raws = [hsfz(request[8:13], 2, 0xF4, target)]
            raws += [hsfz(bytes((0x7F, request[8], 0x78)),source=target) for _ in range(pending)]
            raws.append(hsfz(pdus[index],source=target))
            for number, raw in enumerate(raws):
                # Fragment a maximum-sized seed frame into genuine recv-sized chunks.
                for offset in range(0, len(raw), 4096):
                    at = round(starts[index] + 0.01 + number * 0.03 + offset / 1000000, 6)
                    chunks.append(ReceivedTCPChunk(raw[offset:offset + 4096], at))
                    attribution.append(stages[index])
        experiment = float(count + 1)
        result = HeadUnitAuthResult(
            mode=mode, outcome=outcomes[mode], reason=None,
            tcp_connections_attempted=1, tcp_connections_opened=1, tcp_connection_uncertain=False,
            application_frames_attempted=count, application_frames_sent=count,
            vehicle_bytes_confirmed_sent=sum(map(len, requests)), transmission_uncertain=False,
            request_bytes=requests, request_started_after_seconds=starts,
            recv_chunks=tuple(chunks), chunk_stage_names=tuple(attribution), completed_stage_names=stages,
            session_parameters=tuple((sub, parameters) for sub in ((3,0x41,1) if count == 5 else (3,0x41)[:min(count,2)])),
            seed=seed if count >= 3 else None,
            ack_count=count, pending_count=count * pending, nrc=None, last_control=1,
            elapsed_seconds=experiment + 1, response_elapsed_seconds=experiment - starts[0],
            experiment_elapsed_seconds=experiment, timing_complete=True, tcp_close_uncertain=False,module=self.module)
        report = result.public_report()
        report.update(command=commands[mode].replace('head-unit','bdc' if self.module == 'BDC' else 'vsg') if self.module != 'HU' else commands[mode], implementation_version=__version__, exchange_mode=mode,
            source_interface="en9", source_address="169.254.20.3", gateway_address="169.254.0.2",
            interface_index=19, selected_session_layout=None if count == 1 else self.session.session_layout,
            authentication_scope="not_established",
            authenticated_connection_available=False)
        manifest = {
            "schema": SCHEMA, "implementation_version": __version__, "private_raw_originals": True,
            "timestamp_utc": "SYNTHETIC_FIXTURE", "report": report,
            "selected_session_layout": report["selected_session_layout"],
            "source_discovery": {"manifest_sha256": "a" * 64, "reply_sha256": "b" * 64},
            "source_gateway_identity": {"manifest_sha256": "c" * 64, "request_sha256": self.identity.request_sha256},
            {'HU':'source_head_unit_svk','BDC':'source_bdc_svk','VSG01':'source_vsg_svk'}[self.module]: {"manifest_sha256": "d" * 64, "request_sha256": self.svk.request_sha256,
                                     "value_sha256": "e" * 64},
            "requests": [{"file": f"request-{i + 1:02d}.bin", "stage": stages[i], "byte_length": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest(), "started_after_seconds": starts[i]}
                         for i, raw in enumerate(requests)],
            "received_chunks": [{"file": f"recv-{i + 1:02d}.bin", "stage": attribution[i],
                                  "byte_length": len(chunk.data), "sha256": hashlib.sha256(chunk.data).hexdigest(),
                                  "received_after_seconds": chunk.received_after_seconds}
                                 for i, chunk in enumerate(chunks)],
        }
        if count > 1:
            manifest["source_session_probe"] = {"manifest_sha256": self.session.manifest_sha256,
                                                "session_layout": self.session.session_layout}
        return result, report, manifest

    def validate(self, result, manifest):
        return validate_capture(manifest, result.request_bytes, tuple(c.data for c in result.recv_chunks),
            mode=result.mode, identity=self.identity, svk=self.svk,
            session_layout=None if result.mode == "observe_extended_session" else self.session.session_layout,
            session_evidence=None if result.mode == "observe_extended_session" else self.session)

def write_original(directory: Path, result, manifest) -> str:
    directory.mkdir(mode=0o700)
    values = {row["file"]: raw for row, raw in zip(manifest["requests"], result.request_bytes)}
    values.update({row["file"]: chunk.data for row, chunk in zip(manifest["received_chunks"], result.recv_chunks)})
    for name, raw in values.items(): write_private(directory / name, raw)
    return write_json(directory / "manifest.json", manifest)

def change_chunk(result, manifest, index: int, raw: bytes):
    chunks = list(result.recv_chunks)
    chunks[index] = replace(chunks[index], data=raw)
    changed = replace(result, recv_chunks=tuple(chunks))
    row = manifest["received_chunks"][index]
    row.update(byte_length=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    manifest["report"]["received_bytes"] = sum(len(c.data) for c in chunks)
    return changed

class AuthEvidenceTests(OfflineCase):
    def setUp(self):
        self.forbid()
        self.fixture = AuthFixture()
        self.root = self.temporary()

    def assert_bad(self, result, manifest):
        with self.assertRaises((EvidenceError, CodingProtocolError, HSFZError)):
            self.fixture.validate(result, manifest)

    def load_probe(self,directory,pin,layout="p2_timing"):
        return load_auth_session_evidence(directory,pin,identity=self.fixture.identity,
            svk=self.fixture.svk,session_layout=layout)

    def test_explicit_probe_and_complete_seed_original_roundtrips(self):
        self.assertEqual(FIXED_REQUESTS,MANUAL_REQUESTS)
        result,report,manifest=self.fixture.success()
        self.assertEqual(self.fixture.validate(result,manifest).session_parameters,((3,SYNTHETIC_PARAMETERS),))
        for version, report_version in (('0.12.0','0.12.0'),(__version__,__version__),('0.99.0','0.99.0'),(__version__,'0.12.0')):
            with self.subTest(version=version,report_version=report_version):
                manifest['implementation_version']=version; report['implementation_version']=report_version
                if version!=__version__ or version!=report_version: self.assert_bad(result,manifest)
                else: self.fixture.validate(result,manifest)
        manifest['implementation_version']=report['implementation_version']=__version__
        self.assertIsNone(manifest["selected_session_layout"]); self.assertFalse(report["automatic_P2_deadline_selection"])
        directory=self.root/"probe"; pin=write_original(directory,result,manifest)
        for layout in ("p2_timing","opaque_parameters"):
            with self.subTest(layout=layout):
                proof=self.load_probe(directory,pin,layout)
                self.assertEqual((proof.session_layout,proof.parameter_byte_count,proof.manifest_sha256),(layout,4,pin))
        for layout in (None,"auto","p2","",1):
            with self.subTest(layout=layout), self.assertRaises(EvidenceError): self.load_probe(directory,pin,layout)
        self.fixture.session=self.load_probe(directory,pin)
        result,_,manifest=self.fixture.success("capture_auth_seed")
        self.assertEqual(self.fixture.validate(result,manifest).seed,SYNTHETIC_SEED)
        prepare=self.root/"prepare"; seed_pin=write_original(prepare,result,manifest)
        proof=load_auth_seed_evidence(prepare,seed_pin,identity=self.fixture.identity,svk=self.fixture.svk,session_evidence=self.fixture.session)
        self.assertEqual((proof.seed_byte_length,proof.session_manifest_sha256,proof.seed_sha256),
                         (len(SYNTHETIC_SEED),pin,hashlib.sha256(SYNTHETIC_SEED).hexdigest()))
        self.assertNotIn(SYNTHETIC_SEED.decode(),repr(proof))
        result,_,manifest=self.fixture.success(parameters=b"")
        opaque=self.root/"opaque"; opaque_pin=write_original(opaque,result,manifest)
        with self.assertRaises(EvidenceError): self.load_probe(opaque,opaque_pin)

    def test_proof_binding_profile_and_exact_wire_substitutions(self):
        for section in ("source_discovery","source_gateway_identity","source_head_unit_svk","source_session_probe"):
            with self.subTest(link=section):
                result,_,manifest=self.fixture.success("capture_auth_seed")
                manifest[section]["manifest_sha256"]="9"*64; self.assert_bad(result,manifest)
        result,_,manifest=self.fixture.success("capture_auth_seed"); original=self.fixture.session
        for field in ("discovery_manifest_sha256","identity_manifest_sha256","svk_manifest_sha256"):
            with self.subTest(probe_link=field):
                self.fixture.session=replace(original,**{field:"9"*64}); self.assert_bad(result,manifest)
        self.fixture.session=original
        manifest["selected_session_layout"]="opaque_parameters"; self.assert_bad(result,manifest)
        for flag in ("transmission_uncertain","tcp_close_uncertain"):
            result,_,manifest=self.fixture.success(); manifest["report"][flag]=True; self.assert_bad(result,manifest)
        wires=[(0,hsfz(b"\x10\x01",2,0xF4,0x63)),(1,hsfz(b"\x50\x41"+SYNTHETIC_PARAMETERS)),
               (5,hsfz(b"\x7f\x27\x35")),(5,hsfz(b"\x67\x01"+SYNTHETIC_SEED)+b"\0")]
        for index,wire in wires:
            with self.subTest(chunk=index):
                result,_,manifest=self.fixture.success("capture_auth_seed")
                self.assert_bad(change_chunk(result,manifest,index,wire),manifest)
        for mode,index in (("capture_auth_seed",4),):
            result,_,manifest=self.fixture.success(mode); self.fixture.validate(result,manifest)
            request=result.request_bytes[index//2][8:]; echo=request[:5]
            self.assertEqual(len(result.recv_chunks[index].data),13)
            echoes=[echo[:size] for size in range(5)]+[echo[:i]+bytes((echo[i]^1,))+echo[i+1:] for i in range(5)]+[echo+b"\0",request]
            wrong=[hsfz(value,2,0xF4,0x63) for value in echoes]+[
                   hsfz(echo,2,source,target) for source,target in ((0xF5,0x63),(0xF4,0x62),(0x63,0xF4))]+[
                   hsfz(echo,0x12,0xF4,0x63),hsfz(echo,2,0xF4,0x63)*2]
            for wire in wrong:
                with self.subTest(mode=mode,wire_hash=hashlib.sha256(wire).hexdigest()):
                    result,_,manifest=self.fixture.success(mode)
                    self.assert_bad(change_chunk(result,manifest,index,wire),manifest)

    def test_time_file_and_incomplete_promotion_rejections(self):
        changes=[("received_chunks",1,"received_after_seconds",value) for value in (None,True,-1,float("nan"),float("inf"),30,6.2)]
        changes += [("report",None,field,value) for field,value in (("experiment_elapsed_seconds",30),("elapsed_seconds",1),("response_elapsed_seconds",1.0))]
        changes += [("requests",1,"started_after_seconds",0.01)]
        for section,index,field,value in changes:
            with self.subTest(section=section,field=field,value=value):
                result,_,manifest=self.fixture.success("capture_auth_seed" if section=="requests" else "observe_extended_session")
                target=manifest[section] if index is None else manifest[section][index]
                target[field]=value; self.assert_bad(result,manifest)
        result,_,manifest=self.fixture.success(); directory=self.root/"probe"; pin=write_original(directory,result,manifest)
        for bad_pin in ("0"*64,"INVALID",None):
            with self.subTest(pin=bad_pin), self.assertRaises(EvidenceError): self.load_probe(directory,bad_pin)
        for attack in ("extra_file","raw_tamper"):
            with self.subTest(attack=attack):
                path=directory/("extra.bin" if attack=="extra_file" else "recv-02.bin"); path.write_bytes(b"SYNTHETIC_TAMPER")
                with self.assertRaises(EvidenceError): self.load_probe(directory,pin)
                if attack=="extra_file": path.unlink()
        for number,mode in enumerate(("observe_extended_session","capture_auth_seed")):
            result,_,manifest=self.fixture.success(mode)
            if mode=="capture_auth_seed": manifest["report"]["application_frames_sent"]=2
            directory=self.root/str(number); pin=write_original(directory,result,manifest)
            with self.subTest(incomplete_mode=mode), self.assertRaises(EvidenceError):
                load_auth_seed_evidence(directory,pin,identity=self.fixture.identity,svk=self.fixture.svk,session_evidence=self.fixture.session)

def snapshot_result():
    groups = tuple((address,bytes((index,))*length) for index,(address,length) in enumerate(GROUP_LENGTHS))
    chunks = tuple(ReceivedTCPChunk(frame(b"\xf4\x63\x22"+a.to_bytes(2,"big"),2)+
        frame(b"\x63\xf4\x62"+a.to_bytes(2,"big")+raw),(i+1)/10) for i,(a,raw) in enumerate(groups))
    return CodingSnapshotResult("snapshot_observed",None,1,1,False,8,8,88,False,SNAPSHOT_REQUESTS,
        chunks,tuple(a for a,_ in groups),groups,8,0,None,1,1.,1.,True,False)

class ArtifactTests(OfflineCase):
    def setUp(self):
        self.root = self.temporary()
        self.forbid()
        self.auth = AuthFixture()
        self.network, _, self.identity, self.svk = proofs(12)

    def fixtures(self):
        discovery = SimpleNamespace(datagrams=(SimpleNamespace(data=b"SYNTHETIC_PRIVATE",peer_address="169.254.0.2",
            peer_port=6811,truncated=False,disposition="malformed",reason="invented",received_after_seconds=.01),))
        identity = SimpleNamespace(request_bytes=bytes.fromhex("000000050001f41022f190"),application_frames_attempted=1,
            application_frames_sent=1,vehicle_bytes_confirmed_sent=11,transmission_uncertain=False,
            recv_chunks=(SimpleNamespace(data=b"SYNTHETIC_STREAM",received_after_seconds=.01),))
        auth,report,_ = self.auth.success("capture_auth_seed",pending=1)
        report['implementation_version']=__version__
        snapshot = snapshot_result()
        return (
            ("discovery",DiscoveryArtifactStore,lambda s:s.save(discovery,{}),{"reply-01.bin":discovery.datagrams[0].data}),
            ("identity",GatewayIdentityArtifactStore,lambda s:s.save_identity(identity,{},self.identity.discovery),
                {"request.bin":identity.request_bytes,"recv-01.bin":identity.recv_chunks[0].data}),
            ("auth",HeadUnitAuthenticationArtifactStore,lambda s:self.save_auth(s,auth,report),
                {f"request-{i+1:02d}.bin":raw for i,raw in enumerate(auth.request_bytes)}|
                {f"recv-{i+1:02d}.bin":chunk.data for i,chunk in enumerate(auth.recv_chunks)}),
            ("snapshot",CodingSnapshotArtifactStore,lambda s:self.save_snapshot(s,snapshot),
                {f"request-{i+1:02d}.bin":raw for i,raw in enumerate(snapshot.request_bytes)}|
                {f"recv-{i+1:02d}.bin":chunk.data for i,chunk in enumerate(snapshot.recv_chunks)}),
        )

    def save_auth(self,store,result,report):
        return store.save_auth(result,report,self.auth.identity,self.auth.svk,
            session_evidence=None if result.mode=="observe_extended_session" else self.auth.session)

    def save_snapshot(self,store,result):
        return store.save_snapshot(result,result.public_report(),self.identity,self.svk,self.network)

    def test_private_pinned_originals_exclusive_files_and_neutral_roundtrip(self):
        for name,store_type,save,expected in self.fixtures():
            with self.subTest(kind=name),store_type(self.root) as store:
                summary=save(store); directory=store.directory; self.private(directory)
                self.assertEqual(summary["manifest_sha256"],digest((directory/"manifest.json").read_bytes()))
                for file,raw in expected.items(): self.assertEqual((directory/file).read_bytes(),raw)
                with self.assertRaises(ArtifactError): save(store)
                self.redacted(summary,self.auth.discovery.vin_candidate,"SYNTHETIC_PRIVATE","SYNTHETIC_STREAM")
                if name=="auth": self.assertTrue(summary["complete_original_stream_validated"])
                if name=="snapshot":
                    self.assertTrue(summary["complete_snapshot_saved"])
                    neutral=summary["original_snapshot"]
                    imported=load_coding_snapshot(Path(neutral["directory"]),neutral["manifest_sha256"])
                    self.assertEqual(imported.groups,snapshot_result().groups)
                    self.assertEqual((len(imported.signing_input),imported.provenance),(911,"unverified_import"))

    def test_storage_faults_leave_raw_prefix_without_promoting_a_manifest(self):
        for name,store_type,save,expected in self.fixtures():
            for error in (OSError("private detail"),KeyboardInterrupt()):
                with self.subTest(kind=name,error=type(error).__name__),store_type(self.root) as store:
                    original=store._write
                    selected=next(file for file in expected if file.startswith(("reply-","recv-")))
                    def failed_write(file,raw):
                        original(file,raw)
                        if file==selected: raise error
                    with patch.object(store,"_write",side_effect=failed_write),self.assertRaises(
                            ArtifactError if isinstance(error,OSError) else KeyboardInterrupt): save(store)
                    self.assertEqual((store.directory/selected).read_bytes(),expected[selected])
                    self.assertFalse((store.directory/"manifest.json").exists())
        root=self.temporary(); (root/"private").mkdir(mode=0o755)
        with self.assertRaises(ArtifactError): DiscoveryArtifactStore(root)

    def test_partial_capture_preserves_honest_receipts(self):
        result,report,_=self.auth.success()
        partial=replace(result,outcome="socket_error",reason="partial_application_frame_send",application_frames_sent=0,
            vehicle_bytes_confirmed_sent=4,transmission_uncertain=True,recv_chunks=(),chunk_stage_names=(),completed_stage_names=(),session_parameters=(),ack_count=0)
        with HeadUnitAuthenticationArtifactStore(self.root) as store:
            saved=self.save_auth(store,partial,report|partial.public_report())
            self.assertFalse(saved["complete_original_stream_validated"])
            self.assertEqual(json.loads((store.directory/"manifest.json").read_bytes())["report"]["vehicle_bytes_confirmed_sent"],4)

    def test_snapshot_incomplete_uncorrelated_and_malformed_groups_do_not_promote(self):
        result=snapshot_result(); first=result.recv_chunks[0]
        cases=[replace(result,tcp_close_uncertain=True),replace(result,timing_complete=False),
            replace(result,groups=((0x3000,result.groups[0][1][:-1]+b"!"),)+result.groups[1:]),
            replace(result,recv_chunks=(replace(first,data=first.data+b"\0"),)+result.recv_chunks[1:]),
            replace(result,recv_chunks=(replace(first,data=first.data+first.data[:11]),)+result.recv_chunks[1:]),
            replace(result,groups=result.groups[:1],request_bytes=SNAPSHOT_REQUESTS[:2],recv_chunks=result.recv_chunks[:1],
                chunk_group_addresses=(0x3000,),application_frames_attempted=2,application_frames_sent=1,vehicle_bytes_confirmed_sent=15,
                transmission_uncertain=True,outcome="socket_error",reason="partial_application_frame_send",ack_count=1)]
        for index,changed in enumerate(cases):
            with self.subTest(case=index),CodingSnapshotArtifactStore(self.root) as store:
                saved=self.save_snapshot(store,changed)
                self.assertFalse(saved["complete_snapshot_saved"]); self.assertIsNone(saved["original_snapshot"])
                self.assertFalse((store.directory/"original-snapshot/manifest.json").exists())
        for changed in (replace(result,application_frames_attempted=True),replace(result,vehicle_bytes_confirmed_sent=89),
            replace(result,groups=tuple(reversed(result.groups))),replace(result,request_bytes=SNAPSHOT_REQUESTS[:-1]),
            replace(result,recv_chunks=(ReceivedTCPChunk(bytes(4097),.1),)),replace(result,elapsed_seconds=float("nan"))):
            with CodingSnapshotArtifactStore(self.root) as store,self.assertRaises(ArtifactError): self.save_snapshot(store,changed)
