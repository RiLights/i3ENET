"""Final-send contracts shared by discovery and fixed-read policies."""
from dataclasses import FrozenInstanceError
from i3enet.network import DiscoveryNetwork
from i3enet.policy import (
    DISCOVERY_DATAGRAM, GATEWAY_VIN_FRAME, HEAD_UNIT_SVK_FRAME, EXBOX_REQUEST_FRAME, BDC_SVK_FRAME, BDC_PFFES_FRAME, VSG_SVK_FRAME, VSG_CONFIG_FRAME,
    LiveDiscoveryPolicy, LiveGatewayIdentityPolicy, LiveHeadUnitSVKPolicy, LiveHeadUnitEXBOXPolicy, LiveBDCSVKPolicy, LiveBDCPfFesPolicy, LiveVSGSVKPolicy, LiveVSGConfigPolicy, Phase, PolicyViolation,
)
from support import OfflineCase, proofs

READS = ((LiveGatewayIdentityPolicy,Phase.LIVE_GATEWAY_IDENTITY,GATEWAY_VIN_FRAME),
         (LiveHeadUnitSVKPolicy,Phase.LIVE_HEAD_UNIT_SVK,HEAD_UNIT_SVK_FRAME),
         (LiveHeadUnitEXBOXPolicy,Phase.LIVE_HEAD_UNIT_EXBOX,EXBOX_REQUEST_FRAME),
         (LiveBDCSVKPolicy,Phase.LIVE_BDC_SVK,BDC_SVK_FRAME),
         (LiveVSGSVKPolicy,Phase.LIVE_VSG_SVK,VSG_SVK_FRAME),
         (LiveVSGConfigPolicy,Phase.LIVE_VSG_CONFIG,VSG_CONFIG_FRAME),
         (LiveBDCPfFesPolicy,Phase.LIVE_BDC_PFFES,BDC_PFFES_FRAME))

class LivePolicyTests(OfflineCase):
    def setUp(self):
        self.forbid()
        self.network = proofs(12)[0]
        self.discovery = DiscoveryNetwork("en9","169.254.20.3","169.254.255.255",12,"255.255.0.0","Synthetic Ethernet")

    def test_exact_phase_endpoint_payload_and_single_attempt(self):
        operations = [(c,p,f,self.network,(self.network.gateway_address,6801)) for c,p,f in READS]
        operations += [(LiveDiscoveryPolicy,Phase.LIVE_DISCOVERY,DISCOVERY_DATAGRAM,self.discovery,(self.discovery.broadcast_address,6811))]
        for constructor,phase,raw,network,endpoint in operations:
            with self.subTest(policy=constructor.__name__):
                policy = constructor(network,phase)
                policy.validate(raw,endpoint)
                self.rejects(PolicyViolation,policy.validate,
                    [("payload",(value,endpoint),{}) for value in (b"",raw[:-1],raw+b"x",bytearray(raw),memoryview(raw),raw.hex())] +
                    [("byte mutation",(raw[:i]+bytes((byte^1,))+raw[i+1:],endpoint),{}) for i,byte in enumerate(raw)] +
                    [("endpoint",(raw,value),{}) for value in (None,list(endpoint),(endpoint[0],True),(endpoint[0],endpoint[1]+1),("127.0.0.1",endpoint[1]))] +
                    [("budget",(raw,endpoint),{"sent_count":value}) for value in (-1,1,True,None,"0",0.0)])
                for wrong in (None,True,phase.value,*[p for p in Phase if p!=phase]):
                    with self.subTest(phase=wrong), self.assertRaises(PolicyViolation): constructor(network,wrong).validate(raw,endpoint)
                with self.assertRaises(FrozenInstanceError): policy.phase=Phase.DENY
