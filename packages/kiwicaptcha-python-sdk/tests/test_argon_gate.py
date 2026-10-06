"""The default Argon2id admission gate and the issuer guard: absurd
profiles refuse loudly, exhaustion answers capacity, and an issuance
rung this runtime cannot verify never boots."""

import sys
import unittest

sys.path.insert(0, ".")

from tests.support import NOW, mint_v2_record

from kiwicaptcha import argon2 as argon2_backend
from kiwicaptcha.config import Settings, argon_rung_verifiable
from kiwicaptcha.errors import VerifyError
from kiwicaptcha.stores.memory import MemoryStorage
from kiwicaptcha.tokens import SolutionToken
from kiwicaptcha.verify import (
    AdmissionGate,
    ArgonAdmissionGate,
    Verifier,
    VerifierConfig,
    VerifyOptions,
)


class DefaultGateTest(unittest.TestCase):
    def test_default_gate_is_installed_and_bounded(self):
        config = VerifierConfig()
        self.assertIsInstance(config.argon_gate, ArgonAdmissionGate)
        self.assertGreaterEqual(config.argon_gate.max_concurrent, 1)
        self.assertGreater(config.argon_gate.max_memory_kib, 0)
        self.assertGreater(config.argon_gate.max_time_cost, 0)

    def test_gate_refuses_out_of_budget_params_loudly(self):
        storage = MemoryStorage()
        record = mint_v2_record(
            algorithm="argon2id",
            m_kib=4 * 1024,
            t=16,
            p=1,
            target_bits=1,
        )
        storage.store(record)
        # A gate whose budget cannot cover the record: the refuse is
        # loud and typed, never a silent downgrade or a derivation.
        verifier = Verifier(
            storage,
            VerifierConfig(
                now_provider=lambda: NOW,
                argon_gate=ArgonAdmissionGate(max_memory_kib=1024, max_time_cost=3),
            ),
        )
        token = SolutionToken.create(record.nonce, 0, 5000, {}).encode()
        outcome = verifier.verify(
            token,
            VerifyOptions(
                secret_key="0123456789abcdef0123456789abcdef",
                expected_scope="login",
                client_ip="203.0.113.7",
            ),
        )
        self.assertFalse(outcome.is_ok())
        self.assertEqual(VerifyError.UNSUPPORTED_ARGON2_PARAMS, outcome.code)

    def test_exhaustion_answers_capacity_exceeded(self):
        class ExhaustionGate(AdmissionGate):
            def acquire(self):
                return None

        storage = MemoryStorage()
        record = mint_v2_record(
            algorithm="argon2id", m_kib=64, t=3, p=1, target_bits=1
        )
        storage.store(record)
        verifier = Verifier(storage, VerifierConfig(now_provider=lambda: NOW, argon_gate=ExhaustionGate()))
        token = SolutionToken.create(record.nonce, 0, 5000, {}).encode()
        outcome = verifier.verify(
            token,
            VerifyOptions(
                secret_key="0123456789abcdef0123456789abcdef",
                expected_scope="login",
                client_ip="203.0.113.7",
            ),
        )
        self.assertFalse(outcome.is_ok())
        self.assertEqual(VerifyError.CAPACITY_EXCEEDED, outcome.code)
        # The record stays intact under the capacity refusal.
        self.assertIsNotNone(storage.find(record.nonce))

    def test_budgeted_gate_admits_small_rungs(self):
        gate = ArgonAdmissionGate()
        self.assertTrue(gate.admits_params(64, 3))
        self.assertFalse(gate.admits_params(64 * 1024, 16))
        self.assertFalse(
            gate.admits_params(gate.max_memory_kib, gate.max_time_cost + 1)
        )


class NativeBackendTest(unittest.TestCase):
    def test_derive_matches_pure_on_the_protocol_profile(self):
        expected = (
            "381612cb120864032b674082eb0144f821e9395f3f1ca74ab41ce8bd8e328921"
        )
        from kiwicaptcha.argon2 import derive, derive_pure

        pure = derive_pure(b"prefix21", bytes(range(16)), 3, 64, lanes=1)
        self.assertEqual(expected, pure.hex())
        self.assertEqual(pure, derive(b"prefix21", bytes(range(16)), 3, 64, lanes=1))

    def test_secret_ad_input_falls_back_to_pure(self):
        from kiwicaptcha.argon2 import derive

        # argon2-cffi exposes neither adder, so the RFC input set with
        # secret/AD always answers from the pure implementation.
        tag = derive(
            password=b"\x01" * 32,
            salt=b"\x02" * 16,
            t_cost=3,
            m_cost=32,
            lanes=4,
            out_len=32,
            secret=b"\x03" * 8,
            ad=b"\x04" * 12,
        )
        self.assertEqual(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            tag.hex(),
        )

    def test_backend_name_is_reported(self):
        name = argon2_backend.backend_name()
        self.assertIn(name, ("argon2-cffi", "pure-python"))
        self.assertEqual(argon2_backend.native_available(), name == "argon2-cffi")


class IssuerGuardTest(unittest.TestCase):
    def test_standard_profile_always_boots(self):
        Settings(secret="k" * 32, profile="standard")

    def test_argon_rung_guard_refuses_unverifiable_rungs(self):
        tight = ArgonAdmissionGate(max_memory_kib=8192, max_time_cost=3)
        self.assertFalse(argon_rung_verifiable(16 * 1024, 3, tight))
        self.assertFalse(argon_rung_verifiable(32 * 1024, 3, tight))
        self.assertFalse(argon_rung_verifiable(64 * 1024, 3, tight))
        wide = ArgonAdmissionGate(max_memory_kib=65_536, max_time_cost=16)
        self.assertTrue(argon_rung_verifiable(16 * 1024, 3, wide))
        self.assertTrue(argon_rung_verifiable(64 * 1024, 3, wide))

    def test_settings_refuse_a_rung_the_verifier_cannot_verify(self):
        from kiwicaptcha.config import PROFILE_ARGON_PARAMS

        for profile in ("argon16", "argon32", "argon64"):
            with self.subTest(profile=profile):
                rung = PROFILE_ARGON_PARAMS[profile]
                if argon_rung_verifiable(*rung):
                    Settings(secret="k" * 32, profile=profile)
                else:
                    with self.assertRaises(ValueError) as caught:
                        Settings(secret="k" * 32, profile=profile)
                    self.assertIn("never silently", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
