"""One-use SecurityAccess provider backed by an profile-selected key."""
from __future__ import annotations

import threading
from pathlib import Path

from .coding_contract import contract
from .coding_signature import RSA1024PrivateKey, RSA1024PublicKey, sign_security_access, verify_security_access
from .signing_keys import SigningKeyReference, validate_key_reference, load_key, is_pin as _pin


class AuthProviderError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _require(condition, reason):
    if not condition:
        raise AuthProviderError(reason)


def validate_auth_reference(configuration: Path, pin: str, *, module: str = "HU") -> SigningKeyReference:
    return validate_key_reference(configuration, pin, module=module, role="AS")


class ASAuthProvider:
    """Opaque, one-signing-attempt provider; no raw-key construction API."""

    __slots__ = ("__key", "__public", "__safe", "__lock", "__used", "__closed")

    def __init__(self):
        raise AuthProviderError("provider_construction_forbidden")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("AS provider cannot be subclassed")

    @classmethod
    def _from_key(cls, key, configuration_pin, key_pin, *, module="HU"):
        spec = contract(module)
        _require(type(key) is RSA1024PrivateKey and _pin(configuration_pin) and _pin(key_pin),
                 "provider_key_invalid")
        result = object.__new__(cls)
        result.__key = key
        result.__public = key.public_key
        result.__safe = {
            "provider_kind": "supplied_key_as", "role": "AS", "module": module,
            "btld_identifier": spec.btld.split('/')[0], "target_role_bound": True,
            "core_dumps_disabled": True, "key_bits": 1024, "digest": "MD5",
            "signature_scheme": "BMWSigVerify", "configuration_sha256": configuration_pin,
            "key_file_sha256": key_pin, "owner_authentication_verified": False,
        }
        result.__lock = threading.Lock()
        result.__used = result.__closed = False
        return result

    @property
    def public_key(self) -> RSA1024PublicKey:
        return self.__public

    def safe_summary(self) -> dict:
        # No mutable aliases of internal metadata escape.
        with self.__lock:
            return dict(self.__safe, signing_attempted=self.__used, provider_closed=self.__closed)

    def sign_seed(self, seed: bytes) -> bytes:
        with self.__lock:
            _require(not self.__closed, "provider_closed")
            _require(not self.__used, "provider_signing_attempt_exhausted")
            self.__used = True
            try:
                envelope = sign_security_access(seed, self.__key, module=self.__safe['module'])
                _require(verify_security_access(seed, envelope, self.__public, module=self.__safe['module']),
                         "provider_signature_postcheck_failed")
                return envelope
            except AuthProviderError:
                raise
            except KeyboardInterrupt:
                raise
            except Exception:
                raise AuthProviderError("provider_signing_failed") from None
            finally:
                self.__key = None

    def close(self) -> None:
        with self.__lock:
            self.__key = None
            self.__closed = True

    def __repr__(self) -> str:
        return "<AS provider for fixed BTLD; private material omitted>"

    def __reduce_ex__(self, protocol):
        raise AuthProviderError("provider_serialization_forbidden")

    def __getstate__(self):
        raise AuthProviderError("provider_serialization_forbidden")

    def __copy__(self):
        raise AuthProviderError("provider_serialization_forbidden")

    def __deepcopy__(self, memo):
        raise AuthProviderError("provider_serialization_forbidden")


def load_auth_provider(reference: SigningKeyReference) -> ASAuthProvider:
    key = load_key(reference, 'AS')
    try:
        return ASAuthProvider._from_key(key, reference.configuration_sha256, reference.key_sha256, module=reference.module)
    finally:
        key = None


def _provider_matches(provider: object, *, unused_required: bool = False, module: str = "HU") -> bool:
    if type(provider) is not ASAuthProvider:
        return False
    try:
        public = provider.public_key
        summary = provider.safe_summary()
        if type(public) is not RSA1024PublicKey:
            return False
        RSA1024PublicKey.__post_init__(public)
        required = {
            'provider_kind': 'supplied_key_as', 'role': 'AS', 'btld_identifier': contract(module).btld.split('/')[0],
            'module': module, 'target_role_bound': True,
            'core_dumps_disabled': True, 'key_bits': 1024, 'digest': 'MD5',
            'signature_scheme': 'BMWSigVerify', 'owner_authentication_verified': False,
        }
        return (type(summary) is dict
                and all(type(summary.get(k)) is type(v) and summary.get(k) == v for k, v in required.items())
                and summary.get('provider_closed') is False
                and type(summary.get('signing_attempted')) is bool
                and (not unused_required or summary['signing_attempted'] is False)
                and _pin(summary.get('configuration_sha256')) and _pin(summary.get('key_file_sha256')))
    except (AttributeError, TypeError, ValueError, RuntimeError, OSError):
        return False
