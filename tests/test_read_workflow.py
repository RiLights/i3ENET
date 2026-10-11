"""Automatic read chain with real retained synthetic proofs; external I/O blocked."""
from contextlib import redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
from unittest.mock import patch
from support import OfflineCase, frame, mocked, proofs
from i3enet import reads, read_workflow as workflow
from i3enet.discovery import parse_discovery_response
from i3enet.evidence import EvidenceError
from i3enet.live_discovery import LiveDiscoveryResult, ReceivedDatagram, GatewayCandidate
from i3enet.live_identity import GatewayIdentityResult, ReceivedTCPChunk
from i3enet.live_svk import ModuleSVKResult
from i3enet.live_block import ModuleBlockResult
from i3enet.network import DiscoveryNetwork
from test_evidence import VIN, synthetic_value, record
from test_exbox_evidence import value_bytes

class ReadWorkflowTests(OfflineCase):
    def fixtures(self, root, source="169.254.99.88", *, bdc=False, vsg=False, field_byte=0xA4):
        network, _, _, _ = proofs(12, source=source, vin=VIN)
        udp = DiscoveryNetwork("en9",source,"169.254.255.255",12,"255.255.0.0","Synthetic Ethernet")
        raw = frame(b"DIAGADR10BMWMACAABBCCDDEEFFBMWVIN"+VIN.encode(),0x11)
        discovery = LiveDiscoveryResult("gateway_found",None,1,1,6,False,
            (ReceivedDatagram(raw,network.gateway_address,6811,False,"candidate",None,.01),),
            (GatewayCandidate(network.gateway_address,6811,(parse_discovery_response(raw),)),),3.01)
        results=[]
        software = synthetic_value(records=(record(5,0x17BE,(85,10,12)),record(6,0x2418,(85,10,60)))) if bdc else synthetic_value()
        group = bytearray(value_bytes(length=17)); group[11] = field_byte
        if vsg:
            software=synthetic_value(records=(record(5,0x1A79,(1,3,1)),record(6,0x1A77,(1,1,2))))
            group=bytearray(8);group[7]=field_byte
        target=0x2D if vsg else 0x40 if bdc else 0x63;did=0x3000 if vsg else 0x3221 if bdc else 0x3001
        for cls,request,value,outcome in ((GatewayIdentityResult,bytes.fromhex("000000050001f41022f190"),VIN.encode(),"vin_match"),
            (ModuleSVKResult,bytes.fromhex('000000050001f4')+bytes((target,0x22,0xF1,0x01)),software,"identity_value_observed"),
            (ModuleBlockResult,bytes.fromhex('000000050001f4')+bytes((target,0x22))+did.to_bytes(2,'big'),bytes(group) if bdc or vsg else value_bytes(),"coding_value_observed")):
            chunks=(ReceivedTCPChunk(frame(request[6:],2),.01),
                    ReceivedTCPChunk(frame(bytes((request[7],0xF4,0x62))+request[9:]+value),.02))
            results.append(cls(outcome,None,1,1,False,1,1,11,False,request,chunks,
                value.decode() if cls is GatewayIdentityResult else value,1,0,None,1,.1,.03,.05,
                **({'diagnostic_address':target,**({'identifier':did} if cls is ModuleBlockResult else {})} if (bdc or vsg) and cls is not GatewayIdentityResult else {})))
        results[0]=replace(results[0],vin_comparison=True)
        inventory=dict(local_inspection_status="complete",interfaces=[dict(name="en9",ipv4=[source])])
        values=(("i3enet.read_workflow.doctor",inventory),
            ("i3enet.reads.discovery_preflight",udp),("i3enet.network.identity_preflight",network),
            ("i3enet.live_discovery.discover_once",discovery),("i3enet.live_identity.identify_gateway_once",results[0]),
            ("i3enet.live_svk.read_vsg_svk_once" if vsg else "i3enet.live_svk.read_bdc_svk_once" if bdc else "i3enet.live_svk.read_head_unit_svk_once",results[1]),
            ("i3enet.live_block.read_vsg_config_once" if vsg else "i3enet.live_block.read_bdc_pffes_once" if bdc else "i3enet.live_block.read_exbox_once",results[2]))
        return source, values

    def test_fresh_proof_chain_reads_changed_binding_without_relabelling_saved_proofs(self):
        from i3enet.cli import _print
        for command,total,connections in (("read-vin",17,1),("read-block",39,3)):
            with self.subTest(command=command):
                root=self.temporary(); source,values=self.fixtures(root)
                from i3enet.cli import main
                with mocked(values,cwd=root) as (stack,mocks), redirect_stdout(io.StringIO()) as output:
                    arguments=[command]+(["--ecu","HU","--parm","EXBOX/LEGAL_DISCLAIMER_TIME"] if command=="read-block" else [])+["--ip",source,"--live","--json"]
                    self.assertEqual(main(arguments),0)
                    report=json.loads(output.getvalue())
                self.fields(report,outcome="vin_read" if command=="read-vin" else "block_read",
                    source_address=source,vehicle_bytes_confirmed_sent=total,tcp_connections_opened=connections,writes_supported=False)
                self.assertEqual(len(report["steps"]),connections+1)
                for step in report["steps"]:
                    self.assertEqual(step["source_address"],source)
                    self.assertTrue(Path(step["raw_artifacts"]["directory"]).is_relative_to(root))
                self.private(root/"private")
                if command=="read-block": self.fields(report,parameter_value_hex="0xFF",parameter_meaning="permanent startup notice")
                else: mocks[values[-2][0]].assert_not_called(); mocks[values[-1][0]].assert_not_called()
                self.redacted(report,VIN,value_bytes().hex())
                with redirect_stdout(io.StringIO()) as output: _print(report,False)
                self.assertIn("Car gateway:",output.getvalue()); self.redacted(output.getvalue(),VIN)

    def test_each_failed_step_and_uncertainty_stops_without_followup_reads(self):
        for failed in range(4):
            for kind in ("negative","close_uncertain","bad_original", *(("short_ack",) if failed==1 else ())):
                with self.subTest(step=failed,failure=kind):
                    root=self.temporary(); source,values=self.fixtures(root)
                    sender=values[3+failed][0]
                    with mocked(values,cwd=root) as (stack,mocks):
                        original=mocks[sender].return_value
                        if kind=="negative": mocks[sender].return_value=replace(original,outcome="timeout" if failed==0 else "negative_response",reason="synthetic_stop")
                        elif kind=="close_uncertain": mocks[sender].return_value=replace(original,**{"socket_close_uncertain" if failed==0 else "tcp_close_uncertain":True})
                        elif kind=="short_ack": mocks[sender].return_value=replace(original,recv_chunks=(ReceivedTCPChunk(frame(b"\xf4\x10",2),.01),original.recv_chunks[1]))
                        else:
                            reader=(reads.discover,reads.read_vin,reads.read_svk,reads.read_exbox)[failed]
                            def corrupt(args):
                                result=reader(args)
                                directory=Path(result["raw_artifacts"]["directory"])
                                (directory/("reply-01.bin" if failed==0 else "recv-01.bin")).write_bytes(b"tampered")
                                return result
                            stack.enter_context(patch.object(reads,("discover","read_vin","read_svk","read_exbox")[failed],side_effect=corrupt))
                        report=workflow.read("read-block",source,live=True, ecu="HU", parameter="EXBOX/LEGAL_DISCLAIMER_TIME")
                        self.fields(report,outcome="read_stopped",stop_before_further_vehicle_traffic=True,
                            vehicle_bytes_confirmed_sent=6+11*failed)
                        for name,_ in values[4+failed:]: mocks[name].assert_not_called()
                        self.assertNotIn("parameter_value_hex",report)
                        self.redacted(report,VIN)

    def test_local_plans_invalid_ip_identity_ambiguity_and_interface_failures(self):
        with mocked(forbidden=(*reads.__dict__.get("NETWORK_IO", ()), "socket.socket", "subprocess.run", "i3enet.read_workflow.doctor")):
            for command in ("read-vin","read-block"):
                report=workflow.read(command,"169.254.99.88",ecu="HU",parameter="EXBOX/LEGAL_DISCLAIMER_TIME")
                self.fields(report,outcome="plan_only",vehicle_bytes_confirmed_sent=0)
            for source in ("10.0.0.1","bad","169.254.099.88","::1","169.254.0.0","169.254.255.255"):
                self.fields(workflow.read("read-vin",source,live=True, ecu="HU", parameter="EXBOX/LEGAL_DISCLAIMER_TIME"),outcome="read_stopped",vehicle_bytes_confirmed_sent=0)
        for failure in ("incomplete","absent","duplicate","wrong_vin","ambiguous"):
            with self.subTest(failure=failure):
                root=self.temporary();source,values=self.fixtures(root)
                with mocked(values,cwd=root) as (stack,mocks):
                    if failure=="incomplete": mocks[values[0][0]].return_value["local_inspection_status"]="partial"
                    elif failure in ("absent","duplicate"):
                        interfaces=mocks[values[0][0]].return_value["interfaces"]
                        mocks[values[0][0]].return_value["interfaces"]=[] if failure=="absent" else interfaces*2
                    elif failure=="wrong_vin":
                        mocks[values[4][0]].return_value=replace(mocks[values[4][0]].return_value,vin_comparison=False,outcome='vin_mismatch')
                    else:
                        result=mocks[values[3][0]].return_value
                        mocks[values[3][0]].return_value=replace(result,candidates=result.candidates*2)
                    report=workflow.read("read-block",source,live=True, ecu="HU", parameter="EXBOX/LEGAL_DISCLAIMER_TIME")
                    self.assertEqual(report["outcome"],"read_stopped")
                    mocks[values[5][0]].assert_not_called()
                    if failure in ("incomplete","absent","duplicate"): mocks[values[3][0]].assert_not_called()

    def test_bdc_current_bit_read_exact_software_gate_and_coding_denial(self):
        from i3enet.cli import main
        from i3enet.profiles import resolve_parameter
        from i3enet.coding_preparation import CodingPreparationError
        field=resolve_parameter('BDC','PfFesMaster/FesHasMode4',reading=True)
        for raw in range(256):
            value=bytes(11)+bytes((raw,))+bytes(5)
            self.assertEqual(field.decode(value)['parameter_value_hex'],'0x01' if raw&8 else '0x00')
        edit=field.edit(b'\x01', b'\x00')
        self.assertEqual((edit.value,edit.mask,edit.expected,edit.module,edit.expected_masked),(b'\x08',b'\x08',b'\x00','BDC',True))
        self.assertEqual(resolve_parameter('BDC','PfFesMaster/FesHasMode4'),field)
        for raw,logical,meaning in ((0xA4,'0x00','inactive'),(0xAC,'0x01','active')):
            root=self.temporary();source,values=self.fixtures(root,bdc=True,field_byte=raw)
            with mocked(values,cwd=root),redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['read-block','--ecu','BDC','--parm','PfFesMaster/FesHasMode4','--ip',source,'--live','--json']),0)
                report=json.loads(output.getvalue())
            self.fields(report,outcome='block_read',vehicle_bytes_confirmed_sent=39,tcp_connections_opened=3,
                value_byte_count=17,parameter_value_hex=logical,parameter_meaning=meaning,writes_supported=False)
            self.private(root/'private');self.redacted(report,VIN,bytes(11).hex())
        root=self.temporary();source,values=self.fixtures(root,bdc=True)
        with mocked(values,cwd=root) as (_,mocks):
            sender=mocks[values[-2][0]];original=sender.return_value
            wrong=synthetic_value(records=(record(5,0x17BE,(85,10,13)),record(6,0x2418,(85,10,60))))
            sender.return_value=replace(original,value=wrong,recv_chunks=(original.recv_chunks[0],ReceivedTCPChunk(frame(b'\x40\xf4\x62\xf1\x01'+wrong),.02)))
            report=workflow.read('read-block',source,live=True,ecu='BDC',parameter='PfFesMaster/FesHasMode4')
            self.fields(report,outcome='read_stopped',failed_step='read-bdc-svk',reason='bdc_software_tuple_not_selected',vehicle_bytes_confirmed_sent=28)
            mocks[values[-1][0]].assert_not_called()
        with mocked(forbidden=('socket.socket','subprocess.run','i3enet.read_workflow.doctor')):
            self.fields(workflow.read('read-block',source,ecu='BDC',parameter='PfFesMaster/FesHasMode4'),outcome='plan_only',vehicle_bytes_confirmed_sent=0)
            report=workflow.read('read-block',source,live=True,ecu='BDC',parameter='PfFesMaster/UNKNOWN')
            self.fields(report,outcome='read_stopped',failed_step='selection',vehicle_bytes_confirmed_sent=0)

    def test_vsg_current_nibble_read_reopened_originals_and_plan(self):
        from i3enet.cli import main
        from i3enet.profiles import resolve_parameter
        from i3enet.coding_preparation import CodingPreparationError
        path='VSG Configuration/Last user mode';field=resolve_parameter('VSG01',path,reading=True)
        for byte in range(256): self.assertEqual(field.decode(bytes(7)+bytes((byte,)))['parameter_value_hex'],f'0x{byte&15:02X}')
        edit=field.edit(b'\x01',b'\x00');self.assertTrue(edit.expected_masked);self.assertEqual(edit.mask,b'\x0f')
        with self.assertRaises(CodingPreparationError):field.edit(b'\x02')
        for fault in (None,'software','short_ack','raw'):
            root=self.temporary();source,values=self.fixtures(root,vsg=True,field_byte=0xA1)
            with mocked(values,cwd=root) as (stack,mocks),redirect_stdout(io.StringIO()) as output:
                if fault=='software':
                    original=mocks[values[-2][0]].return_value;wrong=synthetic_value(records=(record(5,0x1A79,(1,3,2)),record(6,0x1A77,(1,1,2))))
                    mocks[values[-2][0]].return_value=replace(original,value=wrong,recv_chunks=(original.recv_chunks[0],ReceivedTCPChunk(frame(b'\x2d\xf4\x62\xf1\x01'+wrong),.02)))
                elif fault=='short_ack':
                    original=mocks[values[-1][0]].return_value
                    mocks[values[-1][0]].return_value=replace(original,recv_chunks=(ReceivedTCPChunk(frame(b'\xf4\x2d\x22\x30',2),.01),original.recv_chunks[1]))
                elif fault=='raw':
                    original=reads.read_vsg_config
                    def corrupt(args):
                        report=original(args);(Path(report['raw_artifacts']['directory'])/'recv-02.bin').write_bytes(b'changed');return report
                    stack.enter_context(patch.object(reads,'read_vsg_config',side_effect=corrupt))
                self.assertEqual(main(['read-block','--ecu','VSG01','--parm',path,'--ip',source,'--live','--json']),0 if fault is None else 1)
                report=json.loads(output.getvalue())
                if fault is None:self.fields(report,outcome='block_read',value_byte_count=8,parameter_value_hex='0x01',vehicle_bytes_confirmed_sent=39,writes_supported=False)
                else:
                    self.fields(report,outcome='read_stopped');self.assertNotIn('parameter_value_hex',report)
                    if fault=='software':mocks[values[-1][0]].assert_not_called()
            self.private(root/'private');self.redacted(report,VIN)
        with mocked(),redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['--ecu','VSG01','--parm',path,'--value','01','--ip',source,'--json']),0)
            self.fields(json.loads(output.getvalue()),outcome='plan_only',vehicle_bytes_confirmed_sent=0,
                        maximum_application_bytes=699,maximum_application_frames=37,activation='default_session')
