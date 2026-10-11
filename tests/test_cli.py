"""Public CLI and internal fixed reads: private retention and failure stopping."""
from contextlib import ExitStack, redirect_stdout, redirect_stderr, nullcontext
import io
import json
import subprocess
import unittest
import tempfile
import socket
from unittest.mock import patch
from i3enet.cli import main, _parser
from i3enet import reads
from i3enet import artifacts
from dataclasses import replace
from pathlib import Path
from support import OfflineCase, digest, mocked, proofs
from i3enet.evidence import EvidenceError
from i3enet.live_identity import ReceivedTCPChunk
from i3enet.network import NetworkPreflightError, DiscoveryNetwork
from test_live_identity import READS, ReadHarness
from i3enet.artifacts import ArtifactError
from i3enet.live_discovery import LiveDiscoveryResult, ReceivedDatagram
from i3enet.live_coding_snapshot import SNAPSHOT_REQUESTS
from test_auth_evidence import snapshot_result


class CLITests(unittest.TestCase):
    def test_command_surface_requires_explicit_source_and_parameter(self):
        read=['read-block','--ecu','HU','--parm','EXBOX/LEGAL_DISCLAIMER_TIME','--ip','169.254.99.88']
        bad=[[name] for name in ('code','discover','authenticate-head-unit','apply','restore','send-hex','scan')]
        bad += [['read-vin'],['read-block','3001'],['read-block','--ip','169.254.99.88'],
                ['read-vin','--ip','169.254.99.88','--gateway','169.254.0.2']]
        bad += [['--value','00',*read], ['--ecu','HU','doctor'], ['--live','doctor']]
        with mocked(), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            for arguments,status in [([name,'--help'],0) for name in ('doctor','read-vin','read-block')]+[(['--help'],0)]+[(a,2) for a in bad]:
                with self.subTest(arguments=arguments), self.assertRaises(SystemExit) as caught: main(arguments)
                self.assertEqual(caught.exception.code,status)
            for arguments in (['read-vin','--ip','169.254.99.88'],read):
                args=_parser().parse_args(arguments); self.assertFalse(args.live)
                self.assertEqual(main(arguments),0)

    def test_doctor_partial_inspection_sends_nothing_and_fails(self):
        with patch("i3enet.network.platform.system", return_value="Darwin"), \
             patch("i3enet.network.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")), \
             patch("socket.socket", side_effect=AssertionError("socket forbidden")), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["doctor", "--json"]), 1)
        self.assertEqual(json.loads(output.getvalue())["vehicle_packets_sent"], 0)

COMMANDS = (("identify-gateway", artifacts.GatewayIdentityArtifactStore, "save_identity"),
            ("read-head-unit-svk", artifacts.HeadUnitSVKArtifactStore, "save_svk"),
            ("read-exbox", artifacts.ExboxArtifactStore, "save_block"))
RESULTS = ("GatewayIdentityResult", "ModuleSVKResult", "ModuleBlockResult")
PROOF_LOADERS = ("i3enet.evidence.load_gateway_identity_evidence", "i3enet.evidence.load_gateway_vin_read_evidence",
                 "i3enet.svk.load_head_unit_svk_evidence")

def read_request(network, links, live=False):
    values = dict(interface=network.interface, source_address=network.source_address, gateway=network.gateway_address, live=live)
    for name, proof in links:
        values[name + "_directory"] = Path("private/synthetic-" + name)
        values[name + "_manifest_sha256"] = proof.manifest_sha256
    return reads.ReadRequest(**values)

class ReadCLI:
    def __init__(self, index):
        self.index = index
        self.read = ReadHarness(READS[index])
        h = self.read
        self.command, self.store, self.save = COMMANDS[index]
        links = tuple(zip(("discovery", "identity", "svk"), (h.discovery, h.identity, h.svk)))[:index+1]
        self.arguments = read_request(h.network, links)
        self.reader = (reads.read_vin, reads.read_svk, reads.read_exbox)[index]
        self.loaders = list(zip(PROOF_LOADERS, (proof for _, proof in links)))
        self.result = getattr(h.module, RESULTS[index])(
            h.success, None, 1, 1, False, 1, 1, 11, False, h.request,
            (ReceivedTCPChunk(b"SYNTHETIC_PRIVATE_STREAM", .01),),
            h.value.decode() if h.gateway else h.value, 1, 0, None, 1, .1, .05, .08)

    def contexts(self, stack, directory):
        values = self.loaders + [("i3enet.network.identity_preflight", self.read.network),
                                 (self.read.module.__name__ + "." + READS[self.index][1], self.result)]
        _, mocks = stack.enter_context(mocked(values, cwd=directory))
        return ([mocks[name] for name, _ in self.loaders], mocks[values[-2][0]], mocks[values[-1][0]],
                stack.enter_context(redirect_stdout(io.StringIO())))

class FixedReadCLITests(OfflineCase):
    def test_internal_reads_plan_or_retain_exact_private_originals(self):
        for index in range(3):
            case=ReadCLI(index); h=case.read
            for selected in (False,True):
                with self.subTest(command=case.command,live=selected),ExitStack() as stack:
                    directory=self.temporary()
                    loaders,preflight,sender,output=case.contexts(stack,directory)
                    if not selected: stack.enter_context(patch.object(artifacts,case.store.__name__,side_effect=AssertionError("plan storage forbidden")))
                    report=case.reader(replace(case.arguments,live=selected))
                    preflight.assert_called_once_with("en9",h.network.source_address,h.network.gateway_address)
                    for loader,proof in zip(loaders,(h.discovery,h.identity,h.svk)):
                        self.assertEqual(loader.call_args.kwargs["manifest_sha256"],proof.manifest_sha256)
                    self.fields(report,command=case.command,request_hex=h.request.hex(),application_frames_attempted=int(selected),
                        vehicle_bytes_confirmed_sent=11*int(selected),writes_supported=False)
                    self.redacted(report,h.discovery.vin_candidate,"SYNTHETIC_PRIVATE")
                    if selected:
                        sender.assert_called_once()
                        original=Path(report["raw_artifacts"]["directory"]); self.private(original)
                        self.assertEqual((original/"request.bin").read_bytes(),h.request)
                        self.assertEqual((original/"recv-01.bin").read_bytes(),case.result.recv_chunks[0].data)
                        self.assertEqual(digest((original/"manifest.json").read_bytes()),report["raw_artifacts"]["manifest_sha256"])
                    else: sender.assert_not_called(); self.assertEqual(list(directory.iterdir()),[])

    def test_pretraffic_and_posttraffic_failures_stop_with_true_counts(self):
        for index in range(3):
            case=ReadCLI(index)
            for stage in (*range(len(case.loaders)),"route","index","prepare","negative","save","interrupt","exit"):
                with self.subTest(command=case.command,stage=stage),ExitStack() as stack:
                    directory=self.temporary()
                    loaders,preflight,sender,output=case.contexts(stack,directory)
                    if type(stage) is int: loaders[stage].side_effect=EvidenceError("bad_proof")
                    elif stage=="route": preflight.side_effect=NetworkPreflightError("no_route")
                    elif stage=="index": preflight.return_value=replace(case.read.network,interface_index=13)
                    elif stage=="prepare": stack.enter_context(patch.object(artifacts,case.store.__name__,side_effect=artifacts.ArtifactError("blocked")))
                    elif stage=="negative": sender.return_value=replace(case.result,outcome="negative_response",reason="negative",nrc=0x31,
                        **({"response_vin":None} if index==0 else {"value":None}))
                    else: stack.enter_context(patch.object(case.store,"__exit__" if stage=="exit" else case.save,
                        side_effect=KeyboardInterrupt() if stage=="interrupt" else OSError("PRIVATE") if stage=="exit" else artifacts.ArtifactError("PRIVATE")))
                    report=case.reader(replace(case.arguments,live=True))
                    self.assertNotEqual(report["outcome"],case.read.success)
                    posttraffic=stage in ("save","interrupt","exit","negative")
                    self.assertEqual(report["vehicle_bytes_confirmed_sent"],11 if posttraffic else 0)
                    if posttraffic: sender.assert_called_once()
                    else: sender.assert_not_called()
                    if type(stage) is int: preflight.assert_not_called()
                    if stage in ("save","interrupt","exit"): self.assertTrue(report["stop_before_further_vehicle_traffic"])
                    self.redacted(output.getvalue(),"PRIVATE")

class DiscoveryCLITests(unittest.TestCase):
    def setUp(self):
        self.network = DiscoveryNetwork("en9", "169.254.20.3", "169.254.255.255", 19,
                                        "255.255.0.0", "Synthetic USB Ethernet Adapter")
        self.arguments = reads.ReadRequest("en9", "169.254.20.3")

    def test_plan_and_private_retention_failures_keep_honest_packet_counts(self):
        datagram = ReceivedDatagram(b"SYNTHETIC PRIVATE REPLY", "169.254.30.2", 6811,
                                    False, "malformed", "invented_fixture", 0.01)
        result = LiveDiscoveryResult("malformed_response", "no_valid_gateway_reply", 1, 1, 6,
                                     False, (datagram,), (), 3.0)
        for stage in ("plan", "preflight", "prepare", "saved", "interrupt"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary, \
                 patch("i3enet.reads.discovery_preflight", return_value=self.network) as preflight, \
                 patch("pathlib.Path.cwd", return_value=Path(temporary)), \
                 patch("i3enet.live_discovery.discover_once", return_value=result) as sender, \
                 patch.object(socket, "socket", side_effect=AssertionError("real socket forbidden")), \
                 redirect_stdout(io.StringIO()) as output:
                with patch("i3enet.artifacts.DiscoveryArtifactStore.save", side_effect=KeyboardInterrupt) if stage == "interrupt" else nullcontext():
                    if stage == "preflight": preflight.side_effect = NetworkPreflightError("no_link")
                    if stage in ("plan", "prepare"):
                        with patch("i3enet.artifacts.DiscoveryArtifactStore", side_effect=ArtifactError("blocked")):
                            report = reads.discover(replace(self.arguments,live=stage != "plan"))
                    else: report = reads.discover(replace(self.arguments,live=True))
                status = 0 if report["outcome"] == "plan_only" else 1
                sent = int(stage in ("saved", "interrupt"))
                self.assertEqual((status, report["vehicle_packets_sent"], report["vehicle_bytes_confirmed_sent"]),
                                 (0 if stage == "plan" else 1, sent, sent * 6))
                self.assertNotIn("SYNTHETIC PRIVATE", output.getvalue())
                self.assertFalse(report["writes_supported"])
                if not sent:
                    sender.assert_not_called(); self.assertFalse(report["vehicle_contacted"])
                    self.assertEqual(report["outcome"], {"plan": "plan_only", "preflight": "preflight_failed", "prepare": "artifact_prepare_failed"}[stage])
                else:
                    sender.assert_called_once_with(self.network)
                    self.assertIsNone(report["vehicle_contacted"])
                    self.assertEqual(report["captured_bytes"], len(datagram.data))
                    if stage == "saved":
                        self.assertEqual((Path(report["raw_artifacts"]["directory"]) / "reply-01.bin").read_bytes(), datagram.data)
                    else:
                        self.assertEqual(report["outcome"], "artifact_storage_interrupted")
                        self.assertTrue(report["stop_before_further_vehicle_traffic"])
                        self.assertIn("private_artifact_directory", report)

class CodingSnapshotCLITests(OfflineCase):
    def test_plan_live_proofs_and_posttraffic_retention(self):
        network, discovery, identity, svk = proofs(12)
        result = snapshot_result()
        args = read_request(network, zip(("discovery", "identity", "svk"), (discovery, identity, svk)))
        values = (("i3enet.evidence.load_gateway_identity_evidence", discovery),
            ("i3enet.evidence.load_gateway_vin_read_evidence", identity), ("i3enet.svk.load_head_unit_svk_evidence", svk),
            ("i3enet.network.identity_preflight", network), ("i3enet.live_coding_snapshot.read_current_coding_snapshot", result))
        for failure in ("plan", "none", "discovery", "identity", "svk", "reparse", "save", "close"):
            with self.subTest(failure=failure), mocked(values, cwd=self.temporary()) as (stack, mocks):
                manager = stack.enter_context(patch("i3enet.coding_snapshot_artifacts.CodingSnapshotArtifactStore"))
                store = manager.return_value.__enter__.return_value; store.directory = Path("/synthetic")
                store.save_snapshot.return_value = dict(directory=str(store.directory), complete_snapshot_saved=failure != "reparse")
                if failure in ("discovery", "identity", "svk"):
                    mocks[values[("discovery", "identity", "svk").index(failure)][0]].side_effect = EvidenceError("bad_proof")
                elif failure == "save": store.save_snapshot.side_effect = KeyboardInterrupt()
                elif failure == "close": manager.return_value.__exit__.side_effect = OSError("PRIVATE")
                report = reads.read_snapshot(replace(args,live=failure != "plan"))
                status = 0 if report["outcome"] in ("plan_only", "snapshot_observed") else 1
                raw = json.dumps(report)
                sent = failure in ("none", "reparse", "save", "close")
                self.assertEqual(status, int(failure not in ("none", "plan")))
                self.fields(report, writes_supported=False, vehicle_bytes_confirmed_sent=88 if sent else 0)
                self.redacted(raw, discovery.vin_candidate, "SYNTHETIC_PRIVATE", "PRIVATE")
                sender = mocks[values[-1][0]]
                if sent:
                    sender.assert_called_once_with(network, identity, svk)
                    self.assertTrue(report["snapshot_complete"] if failure == "none" else report["stop_before_further_vehicle_traffic"])
                    if failure == "none": self.assertEqual(report["original_signature_status"], "not_checked")
                    elif failure == "reparse": self.assertFalse(report["snapshot_complete"])
                    else: self.assertEqual(report["coding_backup_status"], "private_retention_unconfirmed")
                else: sender.assert_not_called(); manager.assert_not_called()
                if failure == "plan":
                    self.assertEqual(report["request_hex"], [request.hex() for request in SNAPSHOT_REQUESTS])
                    self.fields(report, maximum_application_bytes=88, snapshot_complete=False)
                if failure in ("discovery", "identity", "svk"): mocks[values[-2][0]].assert_not_called()
