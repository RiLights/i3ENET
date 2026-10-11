"""One-use coding-signature provider backed by an profile-selected key."""
from __future__ import annotations

import threading
from pathlib import Path

from .coding_preparation import CodingSnapshot, PreparedCoding, CodingEdit, prepare_coding
from .coding_signature import RSA1024PrivateKey, RSA1024PublicKey
from .coding_contract import contract
from .signing_keys import SigningKeyReference, validate_key_reference, load_key, is_pin


class CodingProviderError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _require(condition, reason):
    if not condition:
        raise CodingProviderError(reason)


def validate_coding_reference(configuration: Path, pin: str, *, module: str = "HU") -> SigningKeyReference:
    return validate_key_reference(configuration, pin, module=module, role="NCDS")


class NCDSCodingProvider:
    """Opaque fixed-role provider: one original verification/candidate attempt."""
    __slots__ = ("__key", "__public", "__safe", "__lock", "__used", "__closed")

    def __init__(self):
        raise CodingProviderError("ncds_provider_construction_forbidden")

    def __init_subclass__(cls, **kwargs):
        raise TypeError("NCDS provider cannot be subclassed")

    @classmethod
    def _from_key(cls, key, configuration_pin, key_pin, *, module="HU"):
        spec = contract(module)
        _require(type(key) is RSA1024PrivateKey and is_pin(configuration_pin) and is_pin(key_pin),
                 "ncds_provider_key_invalid")
        result = object.__new__(cls)
        result.__key, result.__public = key, key.public_key
        result.__safe = {"provider_kind": "supplied_key_ncds", "role": "NCDS", "module": module,
                         "target_role_bound": True, "core_dumps_disabled": True,
                         "btld_identifier": spec.btld.split('/')[0], "cafd": spec.cafd,
                         "key_bits": 1024, "digest": "MD5", "signature_scheme": "BMWSigVerify",
                         "configuration_sha256": configuration_pin, "key_file_sha256": key_pin}
        result.__lock = threading.Lock()
        result.__used = result.__closed = False
        return result

    @property
    def public_key(self) -> RSA1024PublicKey:
        return self.__public

    def safe_summary(self) -> dict:
        with self.__lock:
            return dict(self.__safe, signing_attempted=self.__used, provider_closed=self.__closed)

    def prepare(self, snapshot: CodingSnapshot, edit: CodingEdit) -> PreparedCoding:
        with self.__lock:
            _require(not self.__closed, "ncds_provider_closed")
            _require(not self.__used, "ncds_provider_attempt_exhausted")
            self.__used = True
            try:
                _require(type(edit) is CodingEdit, 'ncds_edit_invalid')
                _require((type(snapshot) is CodingSnapshot and (snapshot.cafd, snapshot.btld) ==
                          (contract(edit.module).cafd, contract(edit.module).btld)
                          and snapshot.cafd == self.__safe['cafd']), 'ncds_software_role_mismatch')
                return prepare_coding(snapshot, self.__key, edit)
            except KeyboardInterrupt:
                raise
            except Exception:
                raise CodingProviderError("ncds_candidate_preparation_failed") from None
            finally:
                self.__key = None

    def close(self) -> None:
        with self.__lock:
            self.__key = None
            self.__closed = True

    def __repr__(self) -> str:
        return "<NCDS provider for fixed CAFD/BTLD; private material omitted>"

    def __reduce_ex__(self, protocol):
        raise CodingProviderError("ncds_provider_serialization_forbidden")

    def __getstate__(self):
        raise CodingProviderError("ncds_provider_serialization_forbidden")

    def __copy__(self):
        raise CodingProviderError("ncds_provider_serialization_forbidden")

    def __deepcopy__(self, memo):
        raise CodingProviderError("ncds_provider_serialization_forbidden")


def load_coding_provider(reference: SigningKeyReference) -> NCDSCodingProvider:
    key = load_key(reference, 'NCDS')
    try:
        return NCDSCodingProvider._from_key(key, reference.configuration_sha256, reference.key_sha256, module=reference.module)
    finally:
        key = None
