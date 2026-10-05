"""The records parser, the rsw trapdoor checks and the decision mapping."""

import base64
import hashlib
import json
import math
import sys
import unittest

sys.path.insert(0, ".")

from tests.support import mint_v2_record, minimal_program_b64

from kiwicaptcha.decision import VerifyDecision, price_rung
from kiwicaptcha.errors import VerifyError, VerifyOutcome
from kiwicaptcha.records import (
    ChallengeRecord,
    MalformedRecordError,
    is_valid_decoy_field_name,
    is_valid_identifier,
    protocol_extension_grammar_ok,
)
from kiwicaptcha.rsw import Rsw, derive_base, proof_hex


class RecordsParserTest(unittest.TestCase):
    def test_to_array_round_trip(self):
        record = mint_v2_record(region="eu", request_binding="tx-1")
        rebuilt = ChallengeRecord.from_array(record.to_array())
        self.assertEqual(record.challenge, rebuilt.challenge)
        self.assertEqual(record.region, rebuilt.region)
        self.assertEqual(record.request_binding, rebuilt.request_binding)
        self.assertEqual(record.policy_version, rebuilt.policy_version)

    def test_ip_hash_never_emitted(self):
        record = mint_v2_record(protocol_version=1)
        self.assertNotIn("ip_hash", record.to_array())

    def test_unknown_key_rejected(self):
        data = mint_v2_record().to_array()
        data["evil_key"] = 1
        with self.assertRaises(MalformedRecordError):
            ChallengeRecord.from_array(data)

    def test_bad_algorithm_rejected(self):
        data = mint_v2_record().to_array()
        data["algorithm"] = "md5"
        with self.assertRaises(MalformedRecordError):
            ChallengeRecord.from_array(data)

    def test_string_range_rejected(self):
        data = mint_v2_record().to_array()
        data["m_kib"] = -1
        with self.assertRaises(MalformedRecordError):
            ChallengeRecord.from_array(data)
        data["m_kib"] = 2 ** 40
        with self.assertRaises(MalformedRecordError):
            ChallengeRecord.from_array(data)

    def test_protocol_grammar_matrix(self):
        # v1/v2: no extensions. v3: decoy mandatory. v4: execution
        # mandatory, decoy optional. v5: rsw identity mandatory.
        self.assertTrue(protocol_extension_grammar_ok(2, False, False, False))
        self.assertFalse(protocol_extension_grammar_ok(2, True, False, False))
        self.assertTrue(protocol_extension_grammar_ok(3, True, False, False))
        self.assertFalse(protocol_extension_grammar_ok(3, False, False, False))
        self.assertTrue(protocol_extension_grammar_ok(4, False, True, False))
        self.assertTrue(protocol_extension_grammar_ok(4, True, True, False))
        self.assertFalse(protocol_extension_grammar_ok(4, False, False, False))
        self.assertTrue(protocol_extension_grammar_ok(5, False, False, True))
        self.assertFalse(protocol_extension_grammar_ok(5, False, False, False))

    def test_execution_commitment_shape(self):
        program = minimal_program_b64()
        record = mint_v2_record(protocol_version=4, execution_program=program)
        self.assertEqual(4, record.execution_version)
        self.assertEqual(
            hashlib.sha256(program.encode("ascii")).hexdigest(),
            record.execution_commitment,
        )

    def test_identifier_helpers(self):
        self.assertTrue(is_valid_identifier("login.page", 128))
        self.assertFalse(is_valid_identifier("bad scope", 128))
        self.assertFalse(is_valid_identifier("", 128))
        self.assertTrue(is_valid_decoy_field_name("hp_field_1"))
        self.assertFalse(is_valid_decoy_field_name("has.dot"))
        self.assertFalse(is_valid_decoy_field_name("x" * 65))


def _generate_trapdoor(bits: int = 512):
    """A deterministic-enough RSA-style pair for the rsw tests.

    The primes come from a small Miller-Rabin search seeded from a
    fixed sha256 stream, so the test is self-contained and stable.
    """
    import random

    rng = random.Random(1800000100)

    def is_probable_prime(n):
        if n < 2:
            return False
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            if n % p == 0:
                return n == p
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1
        for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
            x = pow(a, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def prime():
        while True:
            candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
            if is_probable_prime(candidate):
                return candidate

    p = prime()
    q = prime()
    while q == p:
        q = prime()
    n = p * q
    # The 2048-bit product of two 1024-bit primes keeps its top bit.
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    return n, lam


class RswTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.n, cls.lam = _generate_trapdoor(bits=1024)
        cls.modulus_b64 = base64.b64encode(cls.n.to_bytes(256, "big")).decode("ascii")
        lam_bytes = cls.lam.to_bytes((cls.lam.bit_length() + 7) // 8, "big")
        cls.lambda_b64 = base64.b64encode(lam_bytes).decode("ascii")

    def test_trapdoor_consistency_and_expected_proof(self):
        rsw = Rsw(self.modulus_b64, self.lambda_b64)
        prefix = "challenge|SALT|"
        nonce = "NONCEBASE64"
        t = 10_000
        expected = rsw.expected_proof_hex(prefix, nonce, t)
        # The client's sequential squaring must land on the same value.
        base = derive_base(prefix, nonce, self.n)
        sequential = pow(base, 2 ** t, self.n)
        self.assertEqual(proof_hex(sequential), expected)
        self.assertEqual(512, len(expected))

    def test_fingerprint(self):
        from kiwicaptcha.rsw import fingerprint

        fp = fingerprint(self.modulus_b64)
        self.assertEqual(
            hashlib.sha256(base64.b64decode(self.modulus_b64)).hexdigest(), fp
        )
        self.assertIsNone(fingerprint("!!!not-base64!!!"))

    def test_weak_inputs_refused(self):
        # A probable-prime modulus is refused.
        prime = (1 << 1024) | 1  # not provably prime, but try known small
        small_prime_b64 = base64.b64encode((65537).to_bytes(256, "big")).decode()
        with self.assertRaises(ValueError):
            Rsw(small_prime_b64, self.lambda_b64)
        # A wrong-length modulus is refused.
        short = base64.b64encode(b"\x01" * 128).decode("ascii")
        with self.assertRaises(ValueError):
            Rsw(short, self.lambda_b64)
        # An odd lambda is refused.
        with self.assertRaises(ValueError):
            Rsw(self.modulus_b64, base64.b64encode(b"\x03").decode("ascii"))

    def test_validated_pair_memoized(self):
        a = Rsw(self.modulus_b64, self.lambda_b64)
        b = Rsw(self.modulus_b64, self.lambda_b64)
        self.assertEqual(a.n, b.n)


class DecisionTest(unittest.TestCase):
    def test_from_outcome_valid(self):
        outcome = VerifyOutcome.valid_outcome(nonce="N", request_binding="tx")
        decision = VerifyDecision.from_outcome(outcome)
        self.assertTrue(decision.ok)
        self.assertEqual("allow", decision.disposition)

    def test_retry_dispositions(self):
        for code in (
            VerifyError.STORAGE_UNAVAILABLE,
            VerifyError.CAPACITY_EXCEEDED,
            VerifyError.ADMISSION_UNAVAILABLE,
            VerifyError.CONSUME_INDETERMINATE,
        ):
            decision = VerifyDecision.from_outcome(VerifyOutcome.invalid(code))
            self.assertEqual("retry", decision.disposition, code)

    def test_deny_dispositions(self):
        for code in (
            VerifyError.EXPIRED,
            VerifyError.WRONG_SCOPE,
            VerifyError.INSUFFICIENT_WORK,
            VerifyError.ALREADY_CONSUMED,
        ):
            decision = VerifyDecision.from_outcome(VerifyOutcome.invalid(code))
            self.assertEqual("deny", decision.disposition, code)
            self.assertEqual(code.value, decision.error)

    def test_price_rungs(self):
        self.assertEqual("sha8", price_rung("sha256", 8, 0))
        self.assertEqual("argon64", price_rung("argon2id", 4, 64))
        self.assertEqual("rsw", price_rung("rsw", 1, 0))


if __name__ == "__main__":
    unittest.main()
