"""Generic CLI with fresh retained synthetic proofs; no car or owner keys."""
from support import DEFAULT_EDIT
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import json
from types import SimpleNamespace
from unittest.mock import patch
from i3enet import coding_command as c, coding_transaction as s, coding_transport as t
from i3enet.cli import main
from i3enet.auth_provider import ASAuthProvider
from i3enet.coding_provider import NCDSCodingProvider
from i3enet.coding_journal import CodingJournal, validate_journal, JournalError
from i3enet.coding_preparation import prepare_coding
from i3enet.live_identity import ReceivedTCPChunk
from support import OfflineCase, mocked, frame, proofs
from coding_synthetic_fixture import synthetic_private_key
from test_coding_preparation import fixture_snapshot
from test_coding_transport import Clock, Connector
from test_auth_evidence import AuthFixture, snapshot_result
import test_read_workflow as rw
from test_evidence import synthetic_value

VIN = 'WBYTEST000TEST123'


class CodingCommandTests(OfflineCase):
    def test_canonical_selection_and_unsupported_paths_stop_without_io(self):
        canonical = ['--ecu','HU','--parm','EXBOX/LEGAL_DISCLAIMER_TIME','--value','00','--ip','169.254.99.88']
        forbidden = ('socket.socket','subprocess.run','subprocess.Popen','i3enet.coding_command.read_workflow.read',
                     'i3enet.auth_provider.validate_auth_reference','i3enet.auth_provider.load_auth_provider',
                     'i3enet.coding_provider.load_coding_provider')
        with mocked(forbidden=forbidden), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
            for value in ('00','0A','FF','0x00'):
                with self.subTest(value=value):
                    arguments=canonical.copy(); arguments[5]=value
                    out.seek(0); out.truncate(); self.assertEqual(main(arguments+['--json']),0)
                    report=json.loads(out.getvalue())
                    self.fields(report,outcome='plan_only',ecu='HU',diagnostic_address='0x63',vehicle_bytes_confirmed_sent=0)
                    self.assertEqual(report['logical_change']['group'],'3001')
            bdc=['--ecu','BDC','--parm','PfFesMaster/FesHasMode4','--value','01','--expect','00','--ip','169.254.99.88','--json']
            out.seek(0); out.truncate(); self.assertEqual(main(bdc),0)
            report=json.loads(out.getvalue())
            self.fields(report,outcome='plan_only',diagnostic_address='0x40',maximum_application_frames=353,
                        maximum_application_bytes=10880,activation='default_session',parameter_value_hex='0x01')
            self.assertEqual(report['logical_change']['value'],'08'); self.assertEqual(report['logical_change']['expected'],'00')
            for index,value,reason in ((1,'BDC','unknown_parameter_path'),(3,'EXBOX/UNKNOWN','unknown_parameter_path'),
                    (3,'LEGAL_DISCLAIMER_TIME','unknown_parameter_path'),(5,'02','parameter_value_not_supported'),
                    (5,'disabled','hex_bytes_required'),(5,'0x0X00','hex_bytes_required'),
                    (7,'10.0.0.1','link_local_mac_ip_required'),
                    (7,'169.254.0.0','link_local_mac_ip_required'),(7,'169.254.255.255','link_local_mac_ip_required')):
                for live in (False,True):
                    with self.subTest(value=value,live=live):
                        arguments=canonical.copy(); arguments[index]=value
                        out.seek(0); out.truncate(); self.assertEqual(main(arguments+(['--live'] if live else [])+['--json']),1)
                        report=json.loads(out.getvalue()); self.fields(report,reason=reason,failed_step='selection',coding_write_performed=False)
                        self.assertTrue(all(report[key]==0 for key in c._COUNTERS))
                        if value=='BDC':
                            self.fields(report,diagnostic_address='0x40',maximum_application_frames=353,steps=[])
            retired=[['code',*canonical],['--ecu','EXBOX',*canonical[2:]],['--ecu','HU_NBT',*canonical[2:]],
                canonical+['--offset','58'],canonical+['--mask','FF'],canonical+['--block','3001'],
                ['--ecu','HU','--parameter','EXBOX/LEGAL_DISCLAIMER_TIME','--value','00','--ip','169.254.99.88']]
            for arguments in retired+[canonical[:-2],canonical[:4]+canonical[6:]]:
                with self.subTest(arguments=arguments),self.assertRaises(SystemExit) as caught: main(arguments)
                self.assertEqual(caught.exception.code,2)
            with patch.object(c.sys.stdin,'isatty',return_value=False):
                self.assertEqual(main(canonical+['--live']),1)

    def test_fresh_capture_approval_exact_transaction_and_failure_stopping(self):
        snapshot, key = fixture_snapshot()
        current = prepare_coding(snapshot,key, DEFAULT_EDIT).candidate  # Previously coded startup = 00.
        result = replace(snapshot_result(),groups=current.groups,recv_chunks=tuple(
            ReceivedTCPChunk(frame(b'\xf4\x63\x22'+a.to_bytes(2,'big'),2)+
                frame(b'\x63\xf4\x62'+a.to_bytes(2,'big')+raw),(i+1)/10)
            for i,(a,raw) in enumerate(current.groups)))
        for case in ('named','cancel','eof','already','expected','probe','seed','seed_width','changed','partial','unknown'):
            with self.subTest(case=case):
                root=self.temporary()
                with patch.object(rw,'VIN',VIN): source,values=rw.ReadWorkflowTests().fixtures(root)
                network=proofs(12,source=source,vin=VIN)[0]
                auth=AuthFixture(); probe=auth.success()[0]
                seed=auth.success('capture_auth_seed',seed=bytes(range(1,9)))[0]
                extra=(('i3enet.coding_command.identity_preflight',network),('i3enet.coding_transaction.identity_preflight',network),
                    ('i3enet.live_coding_snapshot.read_current_coding_snapshot',result),
                    ('i3enet.coding_command.observe_extended_session_once',probe),
                    ('i3enet.coding_command.capture_auth_seed_once',seed))
                with mocked(values+extra,cwd=root,forbidden=('socket.socket','socket.getaddrinfo','subprocess.run','subprocess.Popen')) as (stack,mocks):
                    out=stack.enter_context(redirect_stdout(io.StringIO())); stack.enter_context(redirect_stderr(io.StringIO()))
                    stack.enter_context(patch.object(c.sys.stdin,'isatty',return_value=True))
                    answer=stack.enter_context(patch('builtins.input',return_value='no' if case=='cancel' else 'CODE HEADUNIT'))
                    if case=='eof': answer.side_effect=EOFError()
                    for name in ('auth','coding'):
                        stack.enter_context(patch(f'i3enet.{name}_provider.validate_{name}_reference'))
                        stack.enter_context(patch.object(s,f'validate_{name}_reference',return_value=SimpleNamespace(public_report=lambda:{})))

                    providers=[]; journals=[]; engines=[]
                    def provider(cls,key):
                        p=cls._from_key(key,'f'*64,'a'*64); providers.append(p); self.addCleanup(p.close); return p
                    load_as=stack.enter_context(patch.object(s,'load_auth_provider',side_effect=lambda _:provider(ASAuthProvider,synthetic_private_key(True))))
                    load_ncds=stack.enter_context(patch.object(s,'load_coding_provider',side_effect=lambda _:provider(NCDSCodingProvider,key)))
                    def journal(*args,**kwargs):
                        j=CodingJournal(*args,**dict(kwargs,evidence_status='SYNTHETIC_FIXTURE')); journals.append(j); return j
                    stack.enter_context(patch.object(s,'CodingJournal',side_effect=journal))
                    def execute(inputs,selection,ncds,as_provider,journal):
                        clock=Clock(); connector=Connector(inputs,clock); connector.svk=synthetic_value()
                        if case=='partial': connector.failure_at,connector.failure_kind=14,'partial'
                        if case=='changed': connector.groups[0x3004]=b'!'+connector.groups[0x3004][1:]
                        outcome=t.execute_coding_transaction(inputs,selection,ncds,as_provider,journal,
                            connector=connector,clock=clock.now,wait=clock.wait)
                        engines.append((outcome,connector,as_provider.public_key)); return outcome
                    engine=stack.enter_context(patch.object(s,'execute_coding_transaction',side_effect=execute))
                    if case=='unknown': stack.enter_context(patch.object(c,'run_coding_transaction',side_effect=RuntimeError('PRIVATE_ERROR')))
                    if case=='probe': mocks[extra[3][0]].return_value=replace(probe,outcome='negative_response',reason='synthetic_stop')
                    if case=='seed': mocks[extra[4][0]].return_value=replace(seed,tcp_close_uncertain=True)
                    if case=='seed_width': mocks[extra[4][0]].return_value=auth.success('capture_auth_seed',seed=bytes(range(1,17)))[0]
                    options=['--ecu','HU','--parm','EXBOX/LEGAL_DISCLAIMER_TIME','--value','00' if case=='already' else '0A']
                    if case=='expected': options+=['--expect','FF']
                    status=main(['--ip',source,*options,'--live','--json'])
                    report=json.loads(out.getvalue())
                    self.assertEqual(status,0 if case in ('named','already') else 1,
                                     (report['outcome'],report.get('reason'),report.get('failed_step')))
                    self.redacted(report,VIN,current.signature.hex(),'PRIVATE_ERROR',bytes(range(1,9)).hex())
                    if case in ('named','changed','partial'):
                        load_as.assert_called_once(); load_ncds.assert_called_once(); engine.assert_called_once()
                        outcome,connector,public=engines[0]; self.assertTrue(all(conn.closed for conn in connector.connections))
                        self.assertEqual(report['transaction_complete'],case in ('named',))
                        self.assertEqual(report['coding_write_performed'],case!='changed')
                        self.assertEqual(report['transmission_uncertain'],case=='partial')
                        if case=='changed':
                            self.assertEqual(outcome.outcome,'original_changed')
                            self.assertFalse(report['transaction']['signing_providers']['NCDS']['signing_attempted'])
                        if case in ('named',):
                            self.fields(report,vehicle_bytes_confirmed_sent=1771,application_frames_sent=53,tcp_connections_opened=8)
                            self.assertEqual(connector.groups[0x3001][58],10)
                            self.assertEqual(connector.groups[0x3002][12],0x0e)
                            j=journals[0]; facts=dict(prepared=outcome.prepared,as_public_key=public,expected_vin=VIN,
                                expected_svk=synthetic_value(),expected_cps=VIN[-7:].encode(),profile=c.AuthProfile('opaque_parameters',8))
                            self.assertTrue(validate_journal(j.directory,expected_context=j._context,
                                manifest_sha256=report['raw_artifacts']['manifest_sha256'],**facts)['complete_data_verified'])
                            wrong=replace(outcome.prepared,edit=replace(outcome.prepared.edit,
                                expected=dict(current.groups)[outcome.prepared.edit.group][outcome.prepared.edit.offset:
                                    outcome.prepared.edit.offset+len(outcome.prepared.edit.value)]))
                            with self.assertRaises(JournalError):
                                validate_journal(j.directory,expected_context=j._context,
                                    manifest_sha256=report['raw_artifacts']['manifest_sha256'],**dict(facts,prepared=wrong))
                    else:
                        load_as.assert_not_called(); load_ncds.assert_not_called(); engine.assert_not_called()
                        if case in ('cancel','eof','already','expected'):
                            mocks[extra[3][0]].assert_not_called(); mocks[extra[4][0]].assert_not_called()
                            self.assertEqual(report['vehicle_bytes_confirmed_sent'],127)
                        if case in ('already','expected'): answer.assert_not_called()
                        if case=='probe': mocks[extra[4][0]].assert_not_called()
                        if case=='unknown':
                            self.assertIsNone(report['vehicle_bytes_confirmed_sent']); self.assertIsNone(report['coding_write_performed'])
                            self.assertTrue(report['traffic_accounting_uncertain'])
                        else: self.assertFalse(report['coding_write_performed'])

    def test_module_named_field_complete_command_cps_approval_and_restoration(self):
        from pathlib import Path
        from i3enet.live_coding_snapshot import CodingSnapshotResult
        from i3enet.live_block import ModuleBlockResult
        from test_coding_transport import synthetic_inputs
        from i3enet.profiles import resolve_parameter
        key=synthetic_private_key()
        for module,path,group,offset,target,group_count,engine_frames,command_frames,byte_cap in (
            ('BDC','PfFesMaster/FesHasMode4',0x3221,11,0x40,82,261,353,10880),
            ('VSG01','VSG Configuration/Last user mode',0x3000,7,0x2D,3,24,37,699)):
            snapshot=synthetic_inputs(module=module).original;field=resolve_parameter(module,path)
            for case in ('code','restore','cancel','cps','expect','seed_default'):
                with self.subTest(module=module,case=case):
                    current=prepare_coding(snapshot,key,field.edit(b'\x01',b'\x00')).candidate if case=='restore' else snapshot
                    root=self.temporary()
                    with patch.object(rw,'VIN',VIN): source,values=rw.ReadWorkflowTests().fixtures(root,bdc=module=='BDC',vsg=module=='VSG01',field_byte=dict(current.groups)[group][offset])
                    network=proofs(12,source=source,vin=VIN)[0]
                    chunks=tuple(ReceivedTCPChunk(frame(bytes((0xF4,target,0x22))+a.to_bytes(2,'big'),2)+
                        frame(bytes((target,0xF4,0x62))+a.to_bytes(2,'big')+raw),(i+1)/100) for i,(a,raw) in enumerate(current.groups))
                    capture=CodingSnapshotResult('snapshot_observed',None,1,1,False,group_count,group_count,11*group_count,False,
                        tuple(bytes.fromhex('000000050001f4')+bytes((target,0x22))+a.to_bytes(2,'big') for a,_ in current.groups),
                        chunks,tuple(a for a,_ in current.groups),current.groups,group_count,0,None,1,1.,1.,True,False,module)
                    cps=VIN[-7:].encode(); cps_value=b'BADTEST' if case=='cps' else cps
                    req=bytes.fromhex('000000050001f4')+bytes((target,))+bytes.fromhex('2237fe')
                    meta=ModuleBlockResult('coding_value_observed',None,1,1,False,1,1,11,False,req,
                        (ReceivedTCPChunk(frame(req[6:],2)+frame(bytes((target,0xF4,0x62,0x37,0xFE))+cps_value),.01),),
                        cps_value,1,0,None,1,.1,.03,.05,diagnostic_address=target,identifier=0x37FE)
                    fixture=AuthFixture(module); probe=fixture.success()[0]
                    seed=fixture.success('capture_bdc_seed_and_default' if module=='BDC' else 'capture_vsg_seed_and_default',seed=bytes(range(1,9)))[0]
                    extra=(('i3enet.coding_command.identity_preflight',network),('i3enet.coding_transaction.identity_preflight',network),
                        ('i3enet.live_coding_snapshot.read_bdc_coding_snapshot' if module=='BDC' else 'i3enet.live_coding_snapshot.read_vsg_coding_snapshot',capture),
                        ('i3enet.live_block.read_bdc_metadata_once' if module=='BDC' else 'i3enet.live_block.read_vsg_metadata_once',meta),
                        ('i3enet.coding_command.observe_extended_session_once',probe),('i3enet.coding_command.capture_bdc_seed_once' if module=='BDC' else 'i3enet.coding_command.capture_vsg_seed_once',seed))
                    with mocked(values+extra,cwd=root,forbidden=('socket.socket','subprocess.run','subprocess.Popen')) as (stack,mocks):
                        stack.enter_context(patch.object(c.sys.stdin,'isatty',return_value=True))
                        stack.enter_context(redirect_stderr(io.StringIO())); output=stack.enter_context(redirect_stdout(io.StringIO()))
                        answer=stack.enter_context(patch('builtins.input',return_value='no' if case=='cancel' else f'CODE {module}'))
                        for name in ('auth','coding'):
                            stack.enter_context(patch(f'i3enet.{name}_provider.validate_{name}_reference'))
                            stack.enter_context(patch.object(s,f'validate_{name}_reference',return_value=SimpleNamespace(public_report=lambda:{})))
                        providers=[]; results=[]
                        def load(cls,selected_key):
                            provider=cls._from_key(selected_key,'f'*64,'a'*64,module=module); providers.append(provider); return provider
                        stack.enter_context(patch.object(s,'load_auth_provider',side_effect=lambda _:load(ASAuthProvider,synthetic_private_key(True))))
                        stack.enter_context(patch.object(s,'load_coding_provider',side_effect=lambda _:load(NCDSCodingProvider,key)))
                        stack.enter_context(patch.object(s,'CodingJournal',side_effect=lambda *a,**kw:CodingJournal(*a,**dict(kw,evidence_status='SYNTHETIC_FIXTURE'))))
                        def execute(inputs,selection,ncds,auth,journal):
                            clock=Clock(); connector=Connector(inputs,clock); connector.svk=values[5][1].value
                            result=t.execute_coding_transaction(inputs,selection,ncds,auth,journal,connector=connector,clock=clock.now,wait=clock.wait)
                            results.append((result,connector)); return result
                        engine=stack.enter_context(patch.object(s,'execute_coding_transaction',side_effect=execute))
                        if case=='seed_default': mocks[extra[-1][0]].return_value=replace(seed,outcome='negative_response',reason='default_denied')
                        status=main(['--ecu',module,'--parm',path,'--value','00' if case=='restore' else '01',
                            '--expect','01' if case in ('restore','expect') else '00','--ip',source,'--live','--json'])
                        report=json.loads(output.getvalue()); self.assertEqual(status,0 if case in ('code','restore') else 1, report.get('reason'))
                        self.redacted(report,VIN,current.signature.hex()); self.private(root/'private')
                        if case in ('code','restore'):
                            self.fields(report,transaction_complete=True,vehicle_bytes_confirmed_sent=byte_cap,application_frames_sent=command_frames,tcp_connections_opened=9)
                            engine.assert_called_once(); self.assertTrue(all(p.safe_summary()['provider_closed'] for p in providers))
                            result,connector=results[0]; self.assertEqual(field.decode(connector.groups[group])['parameter_value_hex'],'0x00' if case=='restore' else '0x01')
                            self.assertFalse(result.reset_attempted); self.assertEqual(result.application_attempts,engine_frames)
                            old=dict(current.groups)[group][offset];self.assertEqual(old ^ connector.groups[group][offset],field.edit(b'\x01').value[0])
                        else:
                            engine.assert_not_called(); self.assertEqual(providers,[]); self.assertFalse(report['coding_write_performed'])
                            if case in ('cps','expect'): answer.assert_not_called()
