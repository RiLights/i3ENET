"""Synthetic startup candidate, bounded plan and private snapshot import."""
from support import DEFAULT_EDIT
import hashlib
import os
from unittest.mock import patch
from support import OfflineCase, write_json, write_private, mocked
from i3enet.coding_preparation import (
    BTLD, CAFD, GROUP_LENGTHS, CodingPreparationError, CodingSnapshot,
    PreparedCoding, CodingEdit, prepare_coding, verify_coding_readback,
)
from i3enet.coding_snapshot import SCHEMA, CodingSnapshotError, load_coding_snapshot
from i3enet.coding_frame_plan import CodingFramePlanError, CodingFramePlan
from i3enet.coding_signature import sign_coding1, sign_security_access, verify_coding1
from coding_synthetic_fixture import synthetic_private_key

VIN, CPS, SEED = "WBYTEST000TEST123", b"TEST123", bytes(range(1, 9))

def fixture_snapshot():
    key = synthetic_private_key()
    groups = tuple((a, bytes((a + i) % 256 for i in range(n))) for a, n in GROUP_LENGTHS[:-1])
    exbox = groups[1][1]
    groups = groups[:1] + ((0x3001, exbox[:58] + b"\xff" + exbox[59:]),) + groups[2:]
    return CodingSnapshot(groups + ((0x3007, sign_coding1(b"".join(raw for _, raw in groups), key)),), "synthetic_fixture"), key

def group_changed(snapshot, index, raw):
    groups = list(snapshot.groups)
    groups[index] = (groups[index][0], raw)
    return CodingSnapshot(tuple(groups), "synthetic_fixture")

def write_fixture(directory, snapshot):
    rows = []
    for address, raw in snapshot.groups:
        name = f"group-{address:04x}.bin"
        write_private(directory / name, raw)
        rows.append(dict(address=f"{address:04X}", file=name, byte_length=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
    manifest = dict(schema=SCHEMA, cafd=CAFD, btld=BTLD, provenance=snapshot.provenance, source_sha256="1"*64, groups=rows)
    return update_manifest(directory, manifest), manifest

def update_manifest(directory, manifest):
    return write_json(directory / "manifest.json", manifest)

class PreparationTests(OfflineCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot, cls.key = fixture_snapshot()

    def test_selected_regions_preserve_other_bits_groups_and_signed_current_values(self):
        current = prepare_coding(self.snapshot, self.key, DEFAULT_EDIT).candidate
        for group, length in GROUP_LENGTHS[:6]:
            with self.subTest(group=f'{group:04X}'):
                raw = dict(current.groups)[group]; old = raw[length-2:]
                value = bytes((old[0] ^ 1, (old[1] ^ 2) & 3))
                edit = CodingEdit(group, length-2, value, b'\xff\x03', old)
                prepared = prepare_coding(current, self.key, edit)
                expected = bytes((value[0], (old[1] & 0xfc) | value[1]))
                self.assertEqual(dict(prepared.candidate.groups)[group], raw[:-2] + expected)
                self.assertEqual([(a, b) for a, b in prepared.candidate.groups[:-1] if a != group],
                                 [(a, b) for a, b in current.groups[:-1] if a != group])
                self.assertEqual(dict(prepared.candidate.groups)[0x3001][58], 0)
                self.assertEqual(prepared.edit, edit)
                self.assertTrue(verify_coding_readback(prepared, prepared.candidate,
                    expected_cps=CPS, returned_cps=CPS)['returned_signature_verified'])
        with patch('i3enet.coding_signature.sign_coding1', side_effect=AssertionError('must not sign')):
            for name, snapshot, edit, reason in (
                ('no-op', current, CodingEdit(0x3001,58,b'\x00',b'\xff'), 'coding_value_already_set'),
                ('expected', current, CodingEdit(0x3001,58,b'\x0a',b'\xff',b'\xff'), 'coding_expected_value_mismatch'),
                ('signature', group_changed(current,0,b'!'+current.groups[0][1][1:]),
                 CodingEdit(0x3001,58,b'\x0a',b'\xff'), 'original_signature_mismatch')):
                with self.subTest(case=name), self.assertRaisesRegex(CodingPreparationError,reason):
                    prepare_coding(snapshot,self.key,edit)
        self.rejects(CodingPreparationError,CodingEdit,[(str(args),args,{}) for args in (
            (0x3006,0,b'\x01',b'\xff'),(0x3007,0,b'\x01',b'\xff'),(0x3008,0,b'\x01',b'\xff'),
            (0x3002,-1,b'\x01',b'\xff'),(0x3002,149,b'\x01\x02',b'\xff\xff'),
            (0x3002,0,b'\x01',b'\x00'),(0x3002,0,b'\x04',b'\x03'),(0x3002,0,b'',b''),
            (0x3002,0,bytes(33),b'\xff'*33),(0x3002,True,b'\x01',b'\xff'),
            (0x3002,0,bytearray(b'\x01'),b'\xff'),(0x3002,0,b'\x01',b'\xff',b'xx'))])

    def test_candidate_readback_and_fixed_frame_plan(self):
        prepared = prepare_coding(self.snapshot, self.key, DEFAULT_EDIT)
        changes = [(a, i, b, c) for (a, old), (_, new) in zip(self.snapshot.groups[:-1], prepared.candidate.groups[:-1])
                   for i, (b, c) in enumerate(zip(old, new)) if b != c]
        self.assertEqual(changes, [(0x3001, 58, 255, 0)])
        self.assertTrue(verify_coding1(prepared.candidate.signing_input, prepared.candidate.signature, self.key.public_key))
        forbidden = ("socket.socket", "socket.getaddrinfo", "subprocess.Popen",
                     "i3enet.auth_provider.load_auth_provider", "i3enet.coding_signature.sign_coding1")
        with mocked(forbidden=forbidden), patch("i3enet.coding_signature.verify_coding1", wraps=verify_coding1) as verify:
            report = verify_coding_readback(prepared, prepared.candidate, expected_cps=CPS, returned_cps=CPS)
            plan = CodingFramePlan(prepared, VIN)
        self.assertGreaterEqual(verify.call_count, 1)
        self.fields(report, outcome="offline_readback_verified", complete_group_count=8, returned_signature_verified=True,
                    live_ready=False, persistence_verified=False, effect_verified_on_car=False, vehicle_traffic_performed=False)
        self.fields(plan.summary(), total_fixed_frame_count=38, total_nominal_application_bytes=1600,
                    coding_fixed_frame_count=26, verification_fixed_frame_count=12, writes_supported=False, live_ready=False)
        for i, (address, raw) in enumerate(prepared.candidate.groups):
            self.assertEqual(plan.expected_frame("coding", 14+i),
                (5+len(raw)).to_bytes(4,"big") + b"\0\1\xf4\x63\x2e" + address.to_bytes(2,"big") + raw)
        with self.assertRaisesRegex(CodingFramePlanError,"offline_as_response_unresolved"): plan.expected_frame("coding",13)
        envelope = sign_security_access(SEED, self.key)
        bound = plan.bind_as_response(SEED, envelope, self.key.public_key)
        self.assertEqual(bound.expected_frame("coding",13), bytes.fromhex("000000880001f4632702") + envelope)
        with self.assertRaises(CodingFramePlanError): bound.validate_frame("coding", 14, b"arbitrary")
        for candidate in (plan,bound): self.redacted(candidate.summary(), envelope.hex(), prepared.candidate.signature.hex(), CPS.decode())

    def test_unverified_original_shape_change_and_plan_claims_rejected(self):
        original, key = self.snapshot, self.key
        prepared = prepare_coding(original,key, DEFAULT_EDIT)
        plan = CodingFramePlan(prepared,VIN)
        with patch("i3enet.coding_signature.sign_coding1", side_effect=AssertionError("must not sign")), self.assertRaisesRegex(
                CodingPreparationError,"original_signature_mismatch"):
            prepare_coding(group_changed(original,0,b"!"+original.groups[0][1][1:]),key, DEFAULT_EDIT)
        raw = original.groups[1][1]
        for value in (0,10):
            with self.subTest(original=value), self.assertRaisesRegex(CodingPreparationError,"coding_expected_value_mismatch"):
                DEFAULT_EDIT.signing_input(group_changed(original,1,raw[:58]+bytes((value,))+raw[59:]))
        self.rejects(CodingPreparationError,CodingSnapshot,[
            (name,(groups,),{}) for name,groups in (("missing",original.groups[:-1]),("order",original.groups[::-1]),
                ("mutable",list(original.groups)),("length",original.groups[:1]+((0x3001,b"x"*150),)+original.groups[2:]),
                ("mutable value",original.groups[:1]+((0x3001,bytearray(151)),)+original.groups[2:]))] +
            [("provenance",(original.groups,"current_ecu"),{}),("software",(original.groups,),{"cafd":"00000DED/003.015.006"})])
        for name, candidate in (("unchanged", original), ("invalid signature", group_changed(prepared.candidate, 7, original.signature))):
            with self.subTest(case=name), self.assertRaises(CodingPreparationError):
                PreparedCoding(original, candidate, key.public_key, DEFAULT_EDIT)
        for index, (_,raw) in enumerate(prepared.candidate.groups):
            with self.subTest(group=index), self.assertRaisesRegex(CodingPreparationError,"readback_candidate_mismatch"):
                verify_coding_readback(prepared,group_changed(prepared.candidate,index,bytes((raw[0]^1,))+raw[1:]),expected_cps=CPS,returned_cps=CPS)
        self.rejects(CodingPreparationError,verify_coding_readback,[
            (name,(prepared,prepared.candidate),dict(expected_cps=expected,returned_cps=returned))
            for name,expected,returned in (("wrong CPS",CPS,b"TEST124"),("short CPS",CPS[:-1],CPS),("mutable CPS",CPS,bytearray(CPS)))])
        with patch("i3enet.coding_signature.verify_coding1",return_value=False), self.assertRaises(CodingPreparationError):
            verify_coding_readback(prepared,prepared.candidate,expected_cps=CPS,returned_cps=CPS)
        self.rejects(CodingFramePlanError,CodingFramePlan,[(repr(vin),(prepared,vin),{})
            for vin in ("TEST123",VIN.lower(),VIN.encode(),VIN[:-1]+"I",VIN[:-1]+"O",VIN[:-1]+"Q")])
        envelope = sign_security_access(SEED,key)
        self.rejects(CodingFramePlanError,plan.bind_as_response,[("seed",(value,envelope,key.public_key),{})
            for value in (b"",bytes(8),SEED[:-1],SEED+b"x",bytearray(SEED))] +
            [("envelope",(SEED,value,key.public_key),{}) for value in (envelope[:-1],envelope+b"x",envelope[:-1]+b"!",bytearray(envelope))] +
            [("public key",(SEED,envelope,object()),{})])
        with patch("i3enet.coding_frame_plan.verify_security_access",return_value=False), self.assertRaises(CodingFramePlanError):
            plan.bind_as_response(SEED,envelope,key.public_key)
        bound = plan.bind_as_response(SEED,envelope,key.public_key)
        with self.assertRaises(CodingFramePlanError): bound.bind_as_response(SEED,envelope,key.public_key)
        self.rejects(CodingFramePlanError,bound.expected_frame,[(repr(args),args,{})
            for args in (("write",0),(0,0),("coding",-1),("coding",26),("verification",12),("coding",True),("coding",1.0))])
        with self.assertRaises(AttributeError): bound._coding=()

class SnapshotImportTests(OfflineCase):
    @classmethod
    def setUpClass(cls): cls.snapshot, _ = fixture_snapshot()

    def reset_import(self):
        self.directory = self.temporary()
        self.pin, self.manifest = write_fixture(self.directory,self.snapshot)

    def test_private_snapshot_import_and_hostile_originals(self):
        self.reset_import()
        self.forbid()
        self.assertEqual(load_coding_snapshot(self.directory,self.pin).groups,self.snapshot.groups)
        with self.assertRaises(CodingSnapshotError): load_coding_snapshot(self.directory,"0"*64)
        edits = (lambda m:m.update(current=True),lambda m:m.update(cafd="00000DED/003.015.006"),
            lambda m:m["groups"].reverse(),lambda m:m["groups"].pop(),lambda m:m["groups"][0].update(file="../outside.bin"),
            lambda m:m["groups"][0].update(byte_length=True),lambda m:m.update(source_sha256="arbitrary text"))
        for edit in edits:
            with self.subTest(edit=edit):
                self.reset_import(); edit(self.manifest)
                with self.assertRaises(CodingSnapshotError): load_coding_snapshot(self.directory,update_manifest(self.directory,self.manifest))
        for attack in ("tamper","symlink","hardlink","file_mode","directory_mode","fifo"):
            with self.subTest(attack=attack):
                self.reset_import(); path=self.directory/"group-3000.bin"
                if attack=="tamper": path.write_bytes(b"x"*152)
                elif attack in ("symlink","hardlink"):
                    outside=self.directory/"alias.bin"; write_private(outside,path.read_bytes()); path.unlink()
                    if attack=="symlink": path.symlink_to(outside)
                    else: os.link(outside,path)
                elif attack=="file_mode": path.chmod(0o644)
                elif attack=="directory_mode": self.directory.chmod(0o755)
                else: path.unlink(); os.mkfifo(path,0o600)
                with self.assertRaises(CodingSnapshotError): load_coding_snapshot(self.directory,self.pin)
