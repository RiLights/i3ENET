"""Synthetic RSA/NCDS/AS checks; no owner keys or coding bytes are read."""

import base64
import copy
import dataclasses
import hashlib
import math
import os
import pickle
import subprocess
import unittest
from unittest import mock

from i3enet.coding_signature import (
    CODING_INPUT_BYTES,
    RSA1024PrivateKey,
    SECURITY_SEED_MAX_BYTES,
    SIGNATURE_BYTES,
    SignatureError,
    sign_coding1,
    sign_security_access,
    verify_coding1,
    verify_security_access,
)
from coding_synthetic_fixture import (
    synthetic_private_components,
    synthetic_private_key,
)

def _components(p: int, q: int, e: int = 65537) -> dict[str, int]:
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    return {"n": p * q, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1), "qi": pow(q, -1, p)}

def _der(tag: int, raw: bytes) -> bytes:
    size = len(raw)
    length = bytes([size]) if size < 128 else (
        size.to_bytes((size.bit_length() + 7) // 8, "big"))
    if size >= 128:
        length = bytes([0x80 | len(length)]) + length
    return bytes([tag]) + length + raw

def _synthetic_pem(parts: dict[str, int]) -> bytes:
    integers = []
    for value in (0,) + tuple(parts[name] for name in
                             ("n", "e", "d", "p", "q", "dp", "dq", "qi")):
        raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        if raw[0] & 0x80:
            raw = b"\0" + raw
        integers.append(_der(2, raw))
    encoded = base64.b64encode(_der(48, b"".join(integers)))
    lines = b"\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64))
    return b"-----BEGIN RSA PRIVATE KEY-----\n" + lines + b"\n-----END RSA PRIVATE KEY-----\n"

class CodingSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Public SYNTHETIC keys are shared with offline simulations. No owner
        # key is read, and no PEM or private reference material is saved.
        cls.parts = synthetic_private_components()
        cls.key = synthetic_private_key()
        cls.as_key = synthetic_private_key(alternate=True)
        cls.data = bytes((index * 29 + 7) % 256 for index in range(CODING_INPUT_BYTES))
        cls.envelope = sign_coding1(cls.data, cls.key)

    def assert_inverse(self, envelope, data, key):
        words = [envelope[i:i + 4] for i in range(4, 132, 4)]
        recovered = pow(int.from_bytes(b"".join(reversed(words)), "big"),
                        key.public_key.e, key.public_key.n).to_bytes(128, "big")
        self.assertEqual(recovered, bytes(112) + hashlib.md5(data, usedforsecurity=False).digest()[::-1])

    def test_domains_blinding_and_independent_public_native_oracles(self):
        prefix = bytes.fromhex("ffffffff00001aba")
        cases = [("NCDS", self.parts, self.key, self.data, self.envelope)]
        for seed in (b"\x01", b"SYNTHETIC seed", bytes(range(32)), b"~" * SECURITY_SEED_MAX_BYTES):
            with self.subTest(seed_length=len(seed)):
                signed = sign_security_access(seed, self.as_key)
                self.assertEqual((len(signed), signed[:4]), (SIGNATURE_BYTES, bytes.fromhex("00000020")))
                self.assertTrue(verify_security_access(seed, signed, self.as_key.public_key))
                self.assert_inverse(signed, prefix + seed, self.as_key)
        seed = b"SYNTHETIC native AS seed"
        signed = sign_security_access(seed, self.as_key)
        cases.append(("AS", synthetic_private_components(alternate=True), self.as_key, prefix + seed, signed))
        for role, parts, key, data, signed in cases:
            with self.subTest(role=role):
                self.assert_inverse(signed, data, key)
                if os.path.isfile("/usr/bin/openssl"):
                    # Anonymous pipe contains only public test-fixture PEM.
                    read_fd, write_fd = os.pipe()
                    try:
                        os.write(write_fd, _synthetic_pem(parts)); os.close(write_fd); write_fd = -1
                        result = subprocess.run(["/usr/bin/openssl", "pkeyutl", "-sign", "-inkey",
                            f"/dev/fd/{read_fd}", "-pkeyopt", "rsa_padding_mode:none"],
                            input=bytes(112) + hashlib.md5(data, usedforsecurity=False).digest()[::-1],
                            capture_output=True, pass_fds=(read_fd,), timeout=10, check=False)
                    finally:
                        os.close(read_fd)
                        if write_fd != -1: os.close(write_fd)
                    self.assertEqual((result.returncode, len(result.stdout)), (0, 128))
                    self.assertEqual(bytes.fromhex("00000020") + b"".join(
                        reversed([result.stdout[i:i+4] for i in range(0, 128, 4)])), signed)
        for factors in ([0, 1], [self.parts["p"] - 2, 0]):
            with self.subTest(blinding=factors), mock.patch(
                    "i3enet.coding_signature.secrets.randbelow", side_effect=factors) as rng:
                first = sign_coding1(self.data, self.key)
                if factors == [0, 1]: self.assertEqual(sign_coding1(self.data, self.key), first)
                self.assertEqual(first, self.envelope)
                self.assertEqual(rng.call_count, 2)
        same_key_as = sign_security_access(self.data, self.key)
        self.assertNotEqual(same_key_as, self.envelope)
        for value, key in ((self.envelope, self.as_key), (same_key_as, self.key)):
            self.assertFalse(verify_coding1(self.data, value, key.public_key))
        self.assertFalse(verify_security_access(self.data, self.envelope, self.key.public_key))
        self.assertFalse(verify_security_access(seed + b"!", signed, self.as_key.public_key))
        self.assertFalse(verify_security_access(seed, signed, self.key.public_key))

    def test_shapes_entropy_crt_faults_and_private_handle_denial(self):
        changed = bytearray(self.data); changed[58] ^= 1
        variants = [b"", self.envelope[:-1], self.envelope + b"\0", b"\x20\0\0\0" + self.envelope[4:],
                    bytes.fromhex("00000021") + self.envelope[4:], self.envelope[:4] + self.envelope[4:][::-1],
                    self.envelope[:4] + bytes(128), bytearray(self.envelope)]
        for number in (self.parts["n"], (1 << 1024) - 1):
            raw = number.to_bytes(128, "big")
            variants.append(bytes.fromhex("00000020") + b"".join(reversed([raw[i:i+4] for i in range(0,128,4)])))
        for value in variants:
            with self.subTest(envelope_type=type(value).__name__, size=len(value)):
                self.assertFalse(verify_coding1(self.data, value, self.key.public_key))
        self.assertFalse(verify_coding1(bytes(changed), self.envelope, self.key.public_key))
        domains = ((sign_coding1, verify_coding1, self.key, (
            (b"", "coding_input_invalid"), (self.data[:-1], "coding_input_invalid"),
            (self.data + b"x", "coding_input_invalid"), (bytearray(self.data), "coding_input_invalid"),
            (memoryview(self.data), "coding_input_invalid"))),
            (sign_security_access, verify_security_access, self.as_key, (
            (b"", "security_seed_invalid"), (b"\0", "security_seed_zero"),
            (bytes(4096), "security_seed_zero"), (b"x" * 4097, "security_seed_invalid"),
            (bytearray(b"x"), "security_seed_invalid"), (memoryview(b"x"), "security_seed_invalid"),
            (None, "security_seed_invalid"))))
        for sign, verify, key, values in domains:
            for value, reason in values:
                for action in (lambda: sign(value, key), lambda: verify(value, self.envelope, key.public_key)):
                    with self.subTest(domain=sign.__name__, reason=reason), self.assertRaises(SignatureError) as caught:
                        action()
                    self.assertEqual(caught.exception.reason, reason)
        for name in ("d", "p", "q", "dp", "dq", "qi"):
            for value in (True, self.parts[name] + 2):
                with self.subTest(component=name, value_type=type(value).__name__), self.assertRaises(SignatureError):
                    RSA1024PrivateKey.from_components(**dict(self.parts, **{name:value}))
        composite = ((self.parts["p"] // 3) | 1) * 3
        with self.assertRaises(SignatureError) as caught:
            RSA1024PrivateKey.from_components(**_components(composite, self.parts["q"]))
        self.assertEqual(caught.exception.reason, "private_factors_not_prime")
        faulted = RSA1024PrivateKey.from_components(**self.parts)
        object.__setattr__(faulted, "_RSA1024PrivateKey__dp", 1)
        for key, target, effect, reason, calls in (
                (self.key, "secrets.randbelow", OSError("SYNTHETIC secret"), "randomness_failed", 1),
                (self.key, "secrets.randbelow", None, "blinding_unavailable", 128),
                (self.key, "RSA1024PrivateKey._private_operation", None, "rsa_postcheck_failed", 1)):
            result = self.parts["p"] - 2 if reason == "blinding_unavailable" else 0
            with self.subTest(fault=reason), mock.patch("i3enet.coding_signature." + target,
                    side_effect=effect, return_value=result) as patched, self.assertRaises(SignatureError) as caught:
                sign_coding1(self.data, key)
            self.assertEqual(caught.exception.reason, reason); self.assertNotIn("SYNTHETIC", str(caught.exception))
            self.assertEqual(patched.call_count, calls)
        with self.assertRaises(SignatureError) as caught: sign_coding1(self.data, faulted)
        self.assertEqual(caught.exception.reason, "rsa_postcheck_failed")
        rendered = repr(self.key) + repr(self.key.public_key)
        for name in ("d", "p"): self.assertNotIn(str(self.parts[name]), rendered)
        self.assertFalse(hasattr(self.key, "__dict__")); self.assertFalse(dataclasses.is_dataclass(self.key))
        for action in (lambda: pickle.dumps(self.key), lambda: copy.copy(self.key),
                       lambda: copy.deepcopy(self.key), lambda: RSA1024PrivateKey(),
                       lambda: setattr(self.key, "extra", "SYNTHETIC")):
            with self.assertRaises((TypeError, SignatureError)): action()
