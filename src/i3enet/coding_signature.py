"""Offline primitives for the selected Coding1 NCDS and AS signatures.

The format is type 21 / MD5 / BMWSigVerify, RSA1024, 32 four-byte words
and MSB=false; see docs/protocol.md. NCDS signs the selected contract's
complete ordered coding input. SecurityAccess binds a fresh seed to that
contract's BTLD identifier. This module performs no file or network I/O.

Python integers cannot provide constant-time arithmetic or secure erasure.
The private operation uses fresh RSA blinding and public fault checks; the
opaque handle prevents incidental representation/serialization, not access
by hostile code in the same process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import math
import secrets


CODING_INPUT_BYTES = 911
RSA_BYTES = 128
SIGNATURE_WORDS = 32
SIGNATURE_BYTES = 132
SECURITY_SEED_MAX_BYTES = 4096
_PRIME_ROUNDS = 32
_BLINDING_ATTEMPTS = 128
_SMALL_PRIMES = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)


class SignatureError(ValueError):
    """A fixed safe reason; no key, signature or input bytes are included."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _require(ok: bool, reason: str) -> None:
    if not ok:
        raise SignatureError(reason)


def _public_shape(n: int, e: int) -> None:
    _require(type(n) is int and n.bit_length() == 1024 and n & 1 == 1,
             "public_modulus_invalid")
    _require(type(e) is int and 3 <= e <= 0xFFFFFFFF and e & 1 == 1,
             "public_exponent_invalid")


@dataclass(frozen=True, slots=True)
class RSA1024PublicKey:
    """Public parameters with a value-free representation."""

    n: int = field(repr=False)
    e: int = field(repr=False)

    def __post_init__(self) -> None:
        _public_shape(self.n, self.e)

    def __repr__(self) -> str:
        return "<RSA1024 public key; values omitted>"


def _probably_prime(value: int) -> bool:
    """Bounded Miller-Rabin validation with independent secure witnesses."""
    if value < 3 or value & 1 == 0:
        return False
    if any(value % prime == 0 for prime in _SMALL_PRIMES):
        return False
    odd = value - 1
    shifts = 0
    while odd & 1 == 0:
        shifts += 1
        odd >>= 1
    for _ in range(_PRIME_ROUNDS):
        witness = secrets.randbelow(value - 3) + 2
        result = pow(witness, odd, value)
        if result in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            result = result * result % value
            if result == value - 1:
                break
        else:
            return False
    return True


class RSA1024PrivateKey:
    """Immutable, repr-hidden, nonserializable in-memory RSA key handle.

    Construct only through ``from_components`` after independent provider
    identity/role validation. Components are never returned, and the full
    private exponent is discarded after consistency validation.
    """

    __slots__ = ("__public", "__p", "__q", "__dp", "__dq", "__qi")

    def __init__(self) -> None:
        raise SignatureError("private_key_construction_forbidden")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("private key handles cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> None:
        raise TypeError("private key handles are immutable")

    def __repr__(self) -> str:
        return "<opaque RSA1024 private key; values omitted>"

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("private key handles cannot be serialized")

    def __getstate__(self) -> object:
        raise TypeError("private key handles cannot be serialized")

    @classmethod
    def from_components(cls, *, n: int, e: int, d: int, p: int, q: int,
                        dp: int, dq: int, qi: int) -> RSA1024PrivateKey:
        """Validate the fixed key shape, factors and all CRT relationships."""
        _public_shape(n, e)
        values = (d, p, q, dp, dq, qi)
        _require(all(type(x) is int and 0 < x < n for x in values),
                 "private_components_invalid")
        _require(p != q and p & 1 == 1 and q & 1 == 1 and p * q == n
                 and 256 <= p.bit_length() <= 768
                 and 256 <= q.bit_length() <= 768,
                 "private_factors_invalid")
        order = math.lcm(p - 1, q - 1)
        _require(e * d % order == 1 and dp == d % (p - 1)
                 and dq == d % (q - 1) and qi * q % p == 1 and qi < p,
                 "private_crt_invalid")
        try:
            primes_ok = _probably_prime(p) and _probably_prime(q)
        except Exception:
            raise SignatureError("randomness_failed") from None
        _require(primes_ok, "private_factors_not_prime")
        handle = object.__new__(cls)
        for name, value in (("__public", RSA1024PublicKey(n, e)),
                            ("__p", p), ("__q", q), ("__dp", dp),
                            ("__dq", dq), ("__qi", qi)):
            object.__setattr__(handle, "_RSA1024PrivateKey" + name, value)
        return handle

    @property
    def public_key(self) -> RSA1024PublicKey:
        return self.__public

    def _private_operation(self, representative: int) -> int:
        """Only called by the fixed data signer; not a raw-RSA public API."""
        public = self.__public
        factor = None
        try:
            for _ in range(_BLINDING_ATTEMPTS):
                candidate = secrets.randbelow(public.n - 3) + 2
                if math.gcd(candidate, public.n) == 1:
                    factor = candidate
                    break
        except Exception:
            raise SignatureError("randomness_failed") from None
        _require(factor is not None, "blinding_unavailable")
        blinded = representative * pow(factor, public.e, public.n) % public.n
        try:
            first = pow(blinded, self.__dp, self.__p)
            second = pow(blinded, self.__dq, self.__q)
            combined = second + self.__q * ((first - second) * self.__qi % self.__p)
            _require(pow(combined, public.e, public.n) == blinded,
                     "rsa_postcheck_failed")
            signature = combined * pow(factor, -1, public.n) % public.n
            _require(pow(signature, public.e, public.n) == representative,
                     "rsa_postcheck_failed")
            return signature
        except SignatureError:
            raise
        except Exception:
            raise SignatureError("private_operation_failed") from None


def _digest_representative(data: bytes) -> bytes:
    digest = hashlib.md5(data, usedforsecurity=False).digest()
    return (digest + bytes(RSA_BYTES - len(digest)))[::-1]


def _reverse_words(value: bytes) -> bytes:
    # Reverse the sequence of four-byte words, retaining bytes within each word.
    return b"".join(value[offset:offset + 4]
                    for offset in range(RSA_BYTES - 4, -1, -4))


def _sign_input(data: bytes, key: RSA1024PrivateKey) -> bytes:
    _require(type(key) is RSA1024PrivateKey, "private_key_handle_invalid")
    representative = int.from_bytes(_digest_representative(data), "big")
    try:
        signature = key._private_operation(representative)
        # Check again at the output boundary, including a helper fault.
        public = key.public_key
        _require(type(signature) is int and 0 <= signature < public.n
                 and pow(signature, public.e, public.n) == representative,
                 "rsa_postcheck_failed")
    except SignatureError:
        raise
    except Exception:
        raise SignatureError("private_operation_failed") from None
    return SIGNATURE_WORDS.to_bytes(4, "big") + _reverse_words(
        signature.to_bytes(RSA_BYTES, "big"))


def _verify_input(data: bytes, envelope: bytes, key: RSA1024PublicKey) -> bool:
    _require(type(key) is RSA1024PublicKey, "public_key_handle_invalid")
    expected = _digest_representative(data)
    if type(envelope) is not bytes or len(envelope) != SIGNATURE_BYTES:
        return False
    if envelope[:4] != SIGNATURE_WORDS.to_bytes(4, "big"):
        return False
    value = int.from_bytes(_reverse_words(envelope[4:]), "big")
    try:
        _public_shape(key.n, key.e)
        if value >= key.n:
            return False
        recovered = pow(value, key.e, key.n).to_bytes(RSA_BYTES, "big")
    except Exception:
        raise SignatureError("public_key_handle_invalid") from None
    return hmac.compare_digest(recovered, expected)


def _coding_input(data: bytes, module: str) -> bytes:
    from .coding_contract import contract
    _require(type(data) is bytes and len(data) == contract(module).signing_bytes,
             "coding_input_invalid")
    return data


def _security_access_input(seed: bytes, module: str) -> bytes:
    # Bounds and zero-seed rejection are project choices, not source limits.
    _require(type(seed) is bytes and 1 <= len(seed) <= SECURITY_SEED_MAX_BYTES,
             "security_seed_invalid")
    _require(any(seed), "security_seed_zero")
    from .coding_contract import contract
    return bytes.fromhex('ffffffff' + contract(module).btld.split('/')[0]) + seed


def sign_coding1(data: bytes, key: RSA1024PrivateKey, *, module: str = "HU") -> bytes:
    """Produce one fixed 132-byte offline NCDS envelope from 911 bytes.

    No TLID replacement, grouping, signing-key discovery or vehicle permission
    is performed. Fresh blinding protects each private calculation while the
    source signature remains deterministic.
    """
    return _sign_input(_coding_input(data, module), key)


def verify_coding1(data: bytes, envelope: bytes,
                   key: RSA1024PublicKey, *, module: str = "HU") -> bool:
    """Verify only the exact fixed NCDS envelope; no framing fallback."""
    return _verify_input(_coding_input(data, module), envelope, key)


def sign_security_access(seed: bytes, key: RSA1024PrivateKey, *, module: str = "HU") -> bytes:
    """Sign FF4 + selected BTLD 00001ABA + seed with a separately bound AS key.

    This only calculates an offline envelope. It neither requests a seed nor
    authenticates an ECU. The provider must supply the AS key for this BTLD.
    """
    return _sign_input(_security_access_input(seed, module), key)


def verify_security_access(seed: bytes, envelope: bytes,
                           key: RSA1024PublicKey, *, module: str = "HU") -> bool:
    """Verify the selected AS input and exact envelope without a fallback."""
    return _verify_input(_security_access_input(seed, module), envelope, key)
