"""Profile selection, immutable PEM loading and one-use signing handles."""
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import pickle
from unittest.mock import patch

from i3enet import auth_provider as ap, coding_provider as cp, signing_keys as sk
from i3enet.coding_contract import contract
from i3enet.coding_signature import verify_security_access
from coding_synthetic_fixture import synthetic_private_components, synthetic_private_key
from support import OfflineCase, DEFAULT_EDIT, mocked, write_private, write_json
from test_coding_preparation import fixture_snapshot


def tlv(tag, raw):
    size = len(raw)
    length = bytes((size,)) if size < 128 else bytes((0x80 + (size.bit_length()+7)//8,)) + size.to_bytes((size.bit_length()+7)//8, 'big')
    return bytes((tag,)) + length + raw


def integer(value):
    raw = value.to_bytes(max(1, (value.bit_length()+7)//8), 'big')
    return tlv(2, b'\0' + raw if raw[0]&0x80 else raw)


def pem(alternate=False, pkcs8=True):
    values = synthetic_private_components(alternate)
    raw = tlv(0x30, integer(0) + b''.join(integer(values[k]) for k in ('n','e','d','p','q','dp','dq','qi')))
    if pkcs8:
        raw = tlv(0x30, integer(0) + bytes.fromhex('300d06092a864886f70d0101010500') + tlv(4,raw))
    label = b'PRIVATE KEY' if pkcs8 else b'RSA PRIVATE KEY'
    return b'-----BEGIN ' + label + b'-----\n' + base64.b64encode(raw) + b'\n-----END ' + label + b'-----\n'


class ProviderTests(OfflineCase):
    def configuration(self, module='HU'):
        root=self.temporary();spec=contract(module)
        for role in ('AS','NCDS'): write_private(root/(role+'.pem'),pem(role=='AS'))
        data=dict(schema='i3enet-signing-keys/1',module=module,cafd=spec.cafd,btld=spec.btld,
                  keys={role:dict(file=role+'.pem',sha256=hashlib.sha256((root/(role+'.pem')).read_bytes()).hexdigest()) for role in ('AS','NCDS')})
        path=root/'keys.json';pin=write_json(path,data)
        return path,pin,data

    def test_validation_never_constructs_keys_and_binds_roles_profiles_and_hashes(self):
        for module in ('HU','BDC','VSG01'):
            path,pin,_=self.configuration(module)
            with mocked(),patch.object(sk,'_parse_pem',side_effect=AssertionError('private load during review')):
                for role,validator in (('AS',ap.validate_auth_reference),('NCDS',cp.validate_coding_reference)):
                    ref=validator(path,pin,module=module)
                    self.fields(ref,role=role,module=module,configuration_sha256=pin)
                    self.fields(ref.public_report(),protected_material_loaded=False,key_source='local')
                    self.redacted(ref, str(path),str(ref.key_path))
                with self.assertRaises(sk.SigningKeyError):ap.validate_auth_reference(path,pin,module='BDC' if module=='HU' else 'HU')
                with self.assertRaises(sk.SigningKeyError):ap.validate_auth_reference(path,'0'*64,module=module)

    def test_configuration_schema_duplicates_roles_and_key_pins(self):
        path,pin,data=self.configuration()
        changes=[dict(schema='other'),dict(btld='00001ABA/130.026.002'),dict(keys={'AS':data['keys']['AS']}),dict(extra=True)]
        for change in changes:
            changed=dict(data,**change);pin=write_json(path,changed)
            with self.assertRaises(sk.SigningKeyError):ap.validate_auth_reference(path,pin)
        pin=write_json(path,data)
        write_private(path.parent/'AS.pem',b'changed')
        with self.assertRaises(sk.SigningKeyError):ap.validate_auth_reference(path,pin)
        raw=b'{"schema":1,"schema":2}';write_private(path,raw)
        with self.assertRaises(sk.SigningKeyError):ap.validate_auth_reference(path,hashlib.sha256(raw).hexdigest())

    def test_permissions_links_and_errors_are_sanitized(self):
        for fault in ('file_mode','directory_mode','symlink','hardlink','missing'):
            path,pin,_=self.configuration()
            if fault=='file_mode':path.chmod(0o644)
            elif fault=='directory_mode':path.parent.chmod(0o755)
            elif fault=='symlink':
                saved=path.with_name('original.json');path.rename(saved);path.symlink_to(saved)
            elif fault=='hardlink':path.with_name('link.json').hardlink_to(path)
            else:path.unlink()
            with self.subTest(fault=fault),self.assertRaises(sk.SigningKeyError) as error:
                ap.validate_auth_reference(path,pin)
            self.redacted(error.exception,str(path))

    def test_pkcs1_pkcs8_and_malformed_der_and_key_geometry(self):
        with mocked():
            for kind in (False,True):
                self.assertEqual(sk._parse_pem(pem(pkcs8=kind)).public_key,synthetic_private_key().public_key)
            for raw in (b'',pem()+pem(),pem().replace(b'PRIVATE KEY',b'ENCRYPTED PRIVATE KEY'),
                        pem().replace(b'\n',b'\n!'),b'-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----\n'):
                with self.subTest(length=len(raw)),self.assertRaises((sk.SigningKeyError,ValueError)):
                    sk._parse_pem(raw)
            for der in (b'\x02\x01\x80',b'\x02\x02\x00\x01',b'\x02\x81\x01\x00',b'\x02\x80'):
                with self.assertRaises(sk.SigningKeyError):sk._DER(der).integer()

    def test_loading_rechecks_pins_core_disable_and_selected_role(self):
        path,pin,_=self.configuration();ref=ap.validate_auth_reference(path,pin)
        with mocked(),patch.object(sk.resource,'setrlimit') as limit,patch.object(sk.resource,'getrlimit',return_value=(0,0)):
            provider=ap.load_auth_provider(ref);self.addCleanup(provider.close)
            limit.assert_called_once();self.fields(provider.safe_summary(),signing_attempted=False,provider_closed=False)
            with self.assertRaises(sk.SigningKeyError):cp.load_coding_provider(ref)
            with patch.object(sk.resource,'getrlimit',return_value=(1,1)),self.assertRaises(sk.SigningKeyError):ap.load_auth_provider(ref)
            write_private(path.parent/'AS.pem',pem())
            with self.assertRaises(sk.SigningKeyError):ap.load_auth_provider(ref)

    def test_handles_cannot_serialize_and_one_seed_attempt_is_atomic(self):
        provider=ap.ASAuthProvider._from_key(synthetic_private_key(), 'a'*64,'b'*64)
        self.addCleanup(provider.close)
        self.assertTrue(ap._provider_matches(provider,unused_required=True))
        for operation in (pickle.dumps,copy.copy,copy.deepcopy):
            with self.assertRaises(ap.AuthProviderError):operation(provider)
        seed=bytes(range(1,9))
        def sign():
            try:return provider.sign_seed(seed)
            except ap.AuthProviderError:return None
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:sign(),range(2)))
        signature=next(r for r in results if r is not None)
        self.assertEqual(sum(r is not None for r in results),1)
        self.assertTrue(verify_security_access(seed,signature,provider.public_key))
        self.assertFalse(ap._provider_matches(provider,unused_required=True))
        provider.close();self.assertFalse(ap._provider_matches(provider))

    def test_ncds_original_verification_one_use_and_wrong_module(self):
        snapshot,key=fixture_snapshot()
        for fault in (None,'original','module'):
            provider=cp.NCDSCodingProvider._from_key(key,'a'*64,'b'*64,module='BDC' if fault=='module' else 'HU')
            self.addCleanup(provider.close)
            original=replace(snapshot,groups=snapshot.groups[:-1]+((0x3007,bytes(132)),)) if fault=='original' else snapshot
            if fault is None:self.assertEqual(dict(provider.prepare(original,DEFAULT_EDIT).candidate.groups)[0x3001][58],0)
            else:
                with self.assertRaises(cp.CodingProviderError):provider.prepare(original,DEFAULT_EDIT)
            with self.assertRaises(cp.CodingProviderError):provider.prepare(snapshot,DEFAULT_EDIT)
            self.fields(provider.safe_summary(),signing_attempted=True)
            for operation in (pickle.dumps,copy.copy,copy.deepcopy):
                with self.assertRaises(cp.CodingProviderError):operation(provider)

    def test_bundled_profiles_select_without_local_configuration_and_check_pins(self):
        with mocked():
            for module in ('HU','BDC','VSG01'):
                path=sk.bundled_configuration(module);pin=sk.configuration_pin(path)
                for role,validate,load in (('AS',ap.validate_auth_reference,ap.load_auth_provider),('NCDS',cp.validate_coding_reference,cp.load_coding_provider)):
                    ref=validate(path,pin,module=module);self.fields(ref.public_report(),key_source='bundled')
                    provider=load(ref);self.addCleanup(provider.close)
                    self.fields(provider.safe_summary(),module=module,signing_attempted=False)
                    if role=='AS':
                        seed=bytes(range(1,9));signature=provider.sign_seed(seed)
                        self.assertTrue(verify_security_access(seed,signature,provider.public_key,module=module))
                    with self.assertRaises(sk.SigningKeyError):load(replace(ref,key_sha256='0'*64))
