"""Synthetic authentication exchanges and ordered permissions; no vehicle or owner keys."""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import unittest
from support import OfflineCase, proofs, bdc_svk, vsg_svk
from unittest.mock import patch
from i3enet import live_head_unit_auth as live
from i3enet.policy import PolicyViolation, Phase
from test_live_identity import FakeClock, FakeTCPSocket, frame, bind_tcp


SYNTHETIC_SEED = b'SYNTHETIC_CHALLENGE'
SYNTHETIC_PARAMETERS = b'SYNTHETIC_PARAMETER_RECORD'

def ack(pdu):
    # Independent synthetic wire encoder: 6-byte header + 2 addresses + <=5 UDS bytes.
    return frame(b'\xf4\x63' + pdu[:5], 2)

def positive(pdu):
    return frame(b'\x63\xf4' + pdu)

def negative(service, code):
    return positive(bytes((0x7F, service, code)))

def make_proofs():
    network, _, identity, svk = proofs(12)
    return network, identity, svk


class MultiStageSocket(FakeTCPSocket):
    def __init__(self, clock):
        super().__init__(clock)
        self.partial_at = None

    def send(self, payload):
        self.send_count = len(payload)
        if self.partial_at == len(self.sent):
            self.send_count = 4
        return super().send(payload)

class LiveHeadUnitAuthTests(OfflineCase):
    def setUp(self):
        self.network,self.identity,self.svk=make_proofs()
        self.clock=FakeClock(); self.sock=MultiStageSocket(self.clock)
        self.socket_calls=[]
        self.forbid("socket.getaddrinfo","socket.gethostbyname","subprocess.run","i3enet.coding_signature.sign_coding1","i3enet.auth_provider.ASAuthProvider.sign_seed")
        stack = self.enterContext(ExitStack())
        bind_tcp(stack, self, live)

    def queue(self, data, delay=0.0):
        self.sock.queue.append((data, delay))

    def queue_prefix(self, *, seed=SYNTHETIC_SEED, parameters=SYNTHETIC_PARAMETERS):
        for request, response in (
            (b'\x10\x03', b'\x50\x03' + parameters),
            (b'\x10\x41', b'\x50\x41' + parameters),
            (b'\x27\x01\xff\xff\xff\xff', b'\x67\x01' + seed),
        ):
            target = {'BDCSVKEvidence':0x40,'VSGSVKEvidence':0x2D}.get(type(self.svk).__name__,0x63)
            self.queue(frame(bytes((0xF4,target))+request[:5],2) + frame(bytes((target,0xF4))+response))

    def observe(self):
        return live.observe_extended_session_once(self.network, self.identity, self.svk)

    def capture(self, layout='opaque_parameters'):
        return live.capture_auth_seed_once(self.network, self.identity, self.svk, live.AuthProfile(layout))


    def assert_no_forward(self, result, count):
        self.assertEqual(len(self.sock.sent), count)
        self.assertEqual(result.application_frames_attempted, count)
        self.assertFalse(result.public_report()['authentication_acceptance_observed'])
        self.assertTrue(self.sock.closed)

    def reset_exchange(self):
        self.clock.now=100.0
        self.sock=MultiStageSocket(self.clock)
        self.socket_calls.clear()

    def queue_before(self,index):
        responses=(b"\x50\x03",b"\x50\x41",b"\x67\x01"+SYNTHETIC_SEED)
        for stage in range(index): self.queue(ack(live.AUTH_PREFIX_REQUESTS[stage][8:])+positive(responses[stage]))

    def test_same_connection_modes_profile_seed_and_signer_gates(self):
        original_svk = self.svk
        for module,mode,count,bytes_sent in ((m,mode,n,b) for m in ("HU","BDC") for mode,n,b in (("probe",1,10),("capture",3,34))):
            self.svk = bdc_svk(original_svk) if module == "BDC" else original_svk
            with self.subTest(mode=mode):
                self.reset_exchange(); self.queue_prefix()
                result={"probe":self.observe,"capture":self.capture}[mode]()
                self.fields(result,application_frames_attempted=count,ack_count=count,vehicle_bytes_confirmed_sent=bytes_sent)
                self.assertEqual(len(self.socket_calls),1)
                self.assertEqual(self.sock.sent[:min(count,3)],list(live.auth_requests(module)[:min(count,3)]))
                self.assertEqual(result.outcome,{"probe":"extended_session_observed","capture":"authentication_seed_observed"}[mode])
                self.redacted(result,SYNTHETIC_SEED.decode())
                self.assertFalse(result.public_report()["writes_supported"])
        self.svk = original_svk
        from i3enet.coding_command import _auth_capture
        from i3enet.auth_evidence import AuthSessionEvidence
        self.reset_exchange(); self.queue_prefix(seed=bytes(range(1,9)))
        links=(self.identity.discovery.manifest_sha256,self.identity.manifest_sha256,self.svk.manifest_sha256)
        probe=AuthSessionEvidence('f'*64,*links,'opaque_parameters',len(SYNTHETIC_PARAMETERS),hashlib.sha256(SYNTHETIC_PARAMETERS).hexdigest())
        with patch('pathlib.Path.cwd',return_value=self.temporary()):
            report=_auth_capture(live.capture_auth_seed_once,self.network,self.identity,self.svk,probe)
        self.fields(report,outcome='authentication_seed_observed',seed_byte_count=8,vehicle_bytes_confirmed_sent=34)
        self.assertTrue(report['raw_artifacts']['complete_original_stream_validated'])
        for defect in ("layout","empty_seed","zero_seed"):
            with self.subTest(defect=defect):
                self.reset_exchange(); self.queue_prefix(seed={"empty_seed":b"","zero_seed":bytes(16)}.get(defect,SYNTHETIC_SEED))
                result=self.capture("p2_timing") if defect=="layout" else self.capture()
                self.assert_no_forward(result,1 if defect=="layout" else 3)

    def test_exact_ack_application_echo_and_terminal_boundaries(self):
        for index in range(3):
            request=live.AUTH_PREFIX_REQUESTS[index][8:]
            response=(b"\x50\x03",b"\x50\x41",b"\x67\x01"+SYNTHETIC_SEED)[index]
            echoes=[request[:n] for n in range(min(len(request),5))]+[request[:5]+b"x",request[:4]+b"x"]
            wires=[frame(b"\xf4\x63"+value,2)+positive(response) for value in echoes]
            wires += [ack(request)+negative(request[0],code) for code in (0x31,)]
            wires += [positive(response),ack(request)*2+positive(response),ack(request)+positive(response)+b"\0"]
            for raw in wires:
                with self.subTest(stage=index,wire=hashlib.sha256(raw).hexdigest()):
                    self.reset_exchange(); self.queue_before(index); self.queue(raw)
                    result=self.capture(); self.assert_no_forward(result,index+1)
                    self.assertEqual(result.completed_stage_names,live.AUTH_STAGE_NAMES[:index])

    def test_vsg_seed_default_session_immutable_reopen_and_failures(self):
        from i3enet.coding_command import _auth_capture
        from i3enet.auth_evidence import load_auth_session_evidence,load_auth_seed_evidence
        from pathlib import Path
        from support import frame
        self.svk=vsg_svk(self.svk);root=self.temporary()
        with patch('pathlib.Path.cwd',return_value=root):
            self.queue_prefix(seed=bytes(range(1,9)))
            report=_auth_capture(live.observe_extended_session_once,self.network,self.identity,self.svk)
            artifact=report['raw_artifacts'];probe=load_auth_session_evidence(Path(artifact['directory']),artifact['manifest_sha256'],
                identity=self.identity,svk=self.svk,session_layout='opaque_parameters')
            self.reset_exchange();self.queue_prefix(seed=bytes(range(1,9)))
            for request,response in ((b'\x10\x01',b'\x50\x01'),(b'\x22\xf1\x86',b'\x62\xf1\x86\x01\x81')):
                self.queue(frame(b'\xf4\x2d'+request[:5],2)+frame(b'\x2d\xf4'+response))
            report=_auth_capture(live.capture_vsg_seed_once,self.network,self.identity,self.svk,probe)
            self.fields(report,outcome='authentication_seed_default_session_observed',vehicle_bytes_confirmed_sent=55,default_session_observed=True)
            artifact=report['raw_artifacts'];seed=load_auth_seed_evidence(Path(artifact['directory']),artifact['manifest_sha256'],
                identity=self.identity,svk=self.svk,session_evidence=probe,mode='capture_vsg_seed_and_default')
            self.assertEqual((seed.module,seed.seed_byte_length),('VSG01',8));self.private(root/'private')
            with self.assertRaises(ValueError):load_auth_seed_evidence(Path(artifact['directory']),artifact['manifest_sha256'],
                identity=self.identity,svk=self.svk,session_evidence=probe,mode='capture_bdc_seed_and_default')
        requests=tuple(live.auth_request('capture_vsg_seed_and_default','VSG01',i) for i in range(5))
        positives=(b'\x50\x03',b'\x50\x41',b'\x67\x01'+bytes(range(1,9)),b'\x50\x01',b'\x62\xf1\x86\x01\x81')
        for index in range(5):
            for fault in ('negative','short_ack','wrong_target'):
                self.reset_exchange()
                for stage in range(index+1):
                    ack=frame(requests[stage][6:13],2);response=frame(b'\x2d\xf4'+positives[stage])
                    if stage==index:
                        if fault=='negative':response=frame(bytes((0x2D,0xF4,0x7F,requests[stage][8],0x31)))
                        elif fault=='short_ack':ack=frame(requests[stage][6:7+min(len(requests[stage])-8,5)],2)
                        else:response=frame(b'\x40\xf4'+positives[stage])
                    self.queue(ack+response)
                result=live.capture_vsg_seed_once(self.network,self.identity,self.svk,live.AuthProfile('opaque_parameters'))
                self.assert_no_forward(result,index+1);self.assertEqual(len(result.completed_stage_names),index)
        self.reset_exchange();self.assertEqual(self.capture().application_frames_attempted,0)

    def test_current_proof_profile_policy_clock_and_binding_gates(self):
        for svk in (replace(self.svk,cafd_version="003.015.006"),replace(self.svk,identity_manifest_sha256="0"*64)):
            self.assertEqual(live.observe_extended_session_once(self.network,self.identity,svk).outcome,"evidence_mismatch")
        self.assertEqual(self.socket_calls,[])
        for value in (float("nan"),1e308):
            with patch.object(live.time,"monotonic",return_value=value): self.assertEqual(self.observe().application_frames_attempted,0)
        with patch.object(live.LiveHeadUnitAuthPolicy,"validate",side_effect=PolicyViolation("denied")):
            self.assertEqual(self.observe().application_frames_attempted,0)
        self.reset_exchange(); self.queue_prefix()
        self.preflight.side_effect=lambda *a,**k: replace(self.network,interface_index=13) if self.sock.sent else self.network
        result=self.capture(); self.assertEqual(result.outcome,"network_changed"); self.assert_no_forward(result,1)

    def test_deadlines_partial_send_interrupt_close_and_resource_accounting(self):
        for fault in ("pending_count","pending_deadline","partial","interrupt","close","bytes","chunks"):
            with self.subTest(fault=fault):
                self.reset_exchange(); self.queue_prefix()
                if fault=="sign_deadline": self.provider.delay=30; result=self.capture(); self.assert_no_forward(result,3)
                elif fault.startswith("pending"):
                    self.sock.queue.clear(); self.queue(ack(b"\x10\x03"))
                    for _ in range(5 if fault=="pending_count" else 2): self.queue(negative(0x10,0x78),0 if fault=="pending_count" else 2.9)
                    self.queue(positive(b"\x50\x03"),.3); result=self.observe(); self.assert_no_forward(result,1)
                elif fault=="partial":
                    self.sock.partial_at=1; result=self.capture()
                    self.fields(result,application_frames_attempted=2,application_frames_sent=1,vehicle_bytes_confirmed_sent=14,transmission_uncertain=True)
                elif fault=="interrupt":
                    with patch.object(self.sock,"send",side_effect=KeyboardInterrupt()): result=self.observe()
                    self.fields(result,outcome="interrupted",application_frames_attempted=1,vehicle_bytes_confirmed_sent=0,transmission_uncertain=True)
                elif fault=="close": self.sock.failure="close"; result=self.observe(); self.assertTrue(result.tcp_close_uncertain)
                else:
                    self.sock.queue.clear(); self.queue(ack(b"\x10\x03")+positive(b"\x50\x03"))
                    self.queue(ack(b"\x10\x41")+(positive(b"\x50\x41") if fault=="bytes" else b""))
                    if fault=="chunks": self.queue(positive(b"\x50\x41"))
                    with patch.object(live,"MAX_RAW_RECEIVE_BYTES" if fault=="bytes" else "MAX_RECEIVE_CHUNKS",39 if fault=="bytes" else 2): result=self.capture()
                    self.assertEqual(result.outcome,"receive_limit"); self.assert_no_forward(result,2)
                self.assertFalse(result.public_report()["exchange_complete"])
                self.redacted(result.public_report(),"PRIVATE")

class HeadUnitAuthPolicyTests(unittest.TestCase):
    def setUp(self):
        for target in ('socket.socket', 'socket.getaddrinfo', 'i3enet.network.subprocess.run'):
            p = patch(target, side_effect=AssertionError('network/OS forbidden'))
            p.start(); self.addCleanup(p.stop)
        self.network, _, _ = make_proofs()
        self.endpoint = (self.network.gateway_address, 6801)

    def test_static_mode_budget_endpoint_and_cross_policy_gates(self):
        for phase in (live.AuthPhase.DENY,'authenticate',Phase.LIVE_HEAD_UNIT_EXBOX,True,None):
            with self.subTest(phase=phase), self.assertRaises(PolicyViolation):
                live.LiveHeadUnitAuthPolicy(self.network,phase).validate(live.EXTENDED_SESSION_REQUEST,self.endpoint)
        for phase,maximum in ((live.AuthPhase.OBSERVE_EXTENDED_SESSION,1),
                              (live.AuthPhase.CAPTURE_AUTH_SEED,3)):
            policy=live.LiveHeadUnitAuthPolicy(self.network,phase)
            for index in range(maximum):
                policy.validate(live.AUTH_PREFIX_REQUESTS[index],self.endpoint,sent_count=index,completed_stages=index)
            for sent,completed in ((maximum,maximum),(True,0),(0,True),(1,0),(0,1)):
                with self.subTest(phase=phase,sent=sent,completed=completed), self.assertRaises(PolicyViolation):
                    policy.validate(live.EXTENDED_SESSION_REQUEST,self.endpoint,sent_count=sent,completed_stages=completed)
        for payload in (live.CODING_SESSION_REQUEST,live.SECURITY_SEED_REQUEST,bytes.fromhex('000000050001f46322f186')):
            with self.assertRaises(PolicyViolation):
                live.LiveHeadUnitAuthPolicy(self.network,live.AuthPhase.OBSERVE_EXTENDED_SESSION).validate(payload,self.endpoint)


class BDCAuthenticationValidationTests(OfflineCase):
    def test_fresh_as_default_state_originals_and_stop_boundaries(self):
        from i3enet.auth_evidence import AuthenticationSeedEvidence, AuthSessionEvidence, _load_original
        from i3enet.auth_provider import ASAuthProvider
        from i3enet.auth_artifacts import BDCAuthenticationValidationArtifactStore
        from i3enet import __version__
        from coding_synthetic_fixture import synthetic_private_key
        self.forbid('i3enet.auth_provider.load_auth_provider')
        self.network, _, self.identity, original_svk = proofs(12)
        svk = bdc_svk(original_svk)
        links = (self.identity.discovery.manifest_sha256, self.identity.manifest_sha256, svk.manifest_sha256)
        probe = AuthSessionEvidence('f'*64, *links, 'opaque_parameters', 0, hashlib.sha256(b'').hexdigest(), 'BDC')
        prerequisite = AuthenticationSeedEvidence('e'*64, *links, probe.manifest_sha256, 'opaque_parameters', 8, '9'*64, 'BDC')
        for fault, count in ((None, 6), ('ack', 4), ('key', 4), ('default', 5), ('state', 6), ('seed', 3), ('provider', 0)):
            with self.subTest(fault=fault), ExitStack() as stack:
                self.clock = FakeClock(); self.sock = MultiStageSocket(self.clock); self.socket_calls = []
                bind_tcp(stack, self, live)
                provider = ASAuthProvider._from_key(synthetic_private_key(), 'a'*64,
                           'b'*64, module='HU' if fault=='provider' else 'BDC')
                stack.callback(provider.close)
                requests = live.auth_requests('BDC') + (b'\0'*8+b'\x27\x02', b'\0'*8+b'\x10\x01', b'\0'*8+b'\x22\xf1\x86')
                responses = [b'\x50\x03', b'\x50\x41', b'\x67\x01'+bytes(range(1, 8 if fault=='seed' else 9)),
                             b'\x67\x02', b'\x50\x01', b'\x62\xf1\x86\x01\x81']
                # Long key echo includes its first three envelope bytes: fixed count 00000020.
                echoes = [p[8:13] for p in requests]; echoes[3] = b'\x27\x02\0\0\0'
                if fault=='ack': echoes[3] = echoes[3][:-1]
                if fault in ('key','default'): responses[3 if fault=='key' else 4] = b'\x7f'+bytes((0x27 if fault=='key' else 0x10, 0x31))
                if fault=='state': responses[5] = b'\x62\xf1\x86\x41\x01'
                for echo, response in zip(echoes, responses):
                    self.sock.queue.append((frame(b'\xf4\x40'+echo, 2)+frame(b'\x40\xf4'+response), 0))
                result = live.validate_bdc_auth_once(self.network, self.identity, svk, prerequisite, provider,
                         phase=live.AuthPhase.VALIDATE_BDC_AUTH)
                report = result.public_report(); self.assertEqual(result.application_frames_attempted, count)
                self.assertTrue(self.sock.closed if count else not self.socket_calls)
                self.assertEqual(report['exchange_complete'], fault is None)
                if fault is not None: continue
                self.assertEqual(result.vehicle_bytes_confirmed_sent, 197)
                self.assertEqual(result.session_parameters, ((3,b''),(0x41,b''),(1,b'')))
                report.update(command='validate-bdc-auth', implementation_version=__version__, exchange_mode=result.mode,
                    source_interface=self.network.interface, source_address=self.network.source_address,
                    gateway_address=self.network.gateway_address, interface_index=self.network.interface_index,
                    selected_session_layout='opaque_parameters')
                with BDCAuthenticationValidationArtifactStore(self.temporary()) as store:
                    artifacts = store.save_auth(result, report, self.identity, svk, session_evidence=probe, as_public_key=provider.public_key)
                    facts = _load_original(store.directory, artifacts['manifest_sha256'], result.mode,
                              self.identity, svk, 'opaque_parameters', probe, provider.public_key)
                    self.assertEqual(facts.seed, bytes(range(1,9)))
                    with self.assertRaises(ValueError):
                        _load_original(store.directory, artifacts['manifest_sha256'], result.mode,
                                       self.identity, svk, 'opaque_parameters', probe, synthetic_private_key(True).public_key)
