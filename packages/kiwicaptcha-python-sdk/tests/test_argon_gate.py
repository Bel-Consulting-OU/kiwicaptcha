"""The default Argon2id admission gate and the issuer guard: absurd
profiles refuse loudly, exhaustion answers capacity, and an issuance
rung this runtime cannot verify never boots."""

import sys
import unittest
import unittest.mock

sys.path.insert(0, ".")

from tests.support import (
    CLIENT_IP,
    NOW,
    SECRET,
    minimal_program_b64,
    mint_v2_record,
    solve_sha,
)

from kiwicaptcha import argon2 as argon2_backend
from kiwicaptcha.config import PROFILE_ARGON_PARAMS, Settings, argon_rung_verifiable
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
        # The native runtime admits the whole protocol profile space.
        self.assertTrue(gate.admits_params(64, 3))
        self.assertTrue(gate.admits_params(64 * 1024, 16))
        self.assertTrue(gate.admits_params(8, 3))
        # An explicit budget stays the operator's own bound.
        tight = ArgonAdmissionGate(max_memory_kib=8192, max_time_cost=3)
        self.assertTrue(tight.admits_params(64, 3))
        self.assertFalse(tight.admits_params(64 * 1024, 16))
        self.assertFalse(
            tight.admits_params(tight.max_memory_kib, tight.max_time_cost + 1)
        )


class BackendAdmissionTest(unittest.TestCase):
    """The admission gate without the native binding.

    The flag is simulated: the refusal contract is what the test pins.
    Derivation refuses with the actionable message, the default gate
    refuses to build, the default verifier config constructs lazily and
    its SHA records verify, an argon2id record answers the typed
    unsupported-params refuse, and the sidecar-admitted constructions
    boot and delegate.
    """

    MESSAGE = (
        "Argon2id verification requires the [argon2] extra or a local"
        " sidecar. Install with: pip install kiwicaptcha[argon2]"
    )

    def setUp(self):
        from kiwicaptcha import argon2

        if argon2.native_available():
            self.patcher = unittest.mock.patch(
                "kiwicaptcha.argon2._NATIVE", False
            )
            self.patcher.start()
            self.addCleanup(self.patcher.stop)

    def test_derive_refuses_without_the_binding(self):
        from kiwicaptcha.argon2 import Argon2BackendUnavailable, derive

        with self.assertRaises(Argon2BackendUnavailable) as caught:
            # Protocol-shaped inputs: the pure implementation must not
            # answer where the production path would have derived.
            derive(b"prefix21", bytes(range(16)), 3, 64, lanes=1)
        self.assertEqual(self.MESSAGE, str(caught.exception))

    def test_pure_oracle_stays_callable_for_the_vectors(self):
        from kiwicaptcha.argon2 import derive_pure

        expected = (
            "381612cb120864032b674082eb0144f821e9395f3f1ca74ab41ce8bd8e328921"
        )
        pure = derive_pure(b"prefix21", bytes(range(16)), 3, 64, lanes=1)
        self.assertEqual(expected, pure.hex())

    def test_default_gate_refuses_to_construct(self):
        with self.assertRaises(ValueError) as caught:
            ArgonAdmissionGate()
        self.assertEqual(self.MESSAGE, str(caught.exception))

    def test_sidecar_admitted_gate_constructs_and_admits(self):
        gate = ArgonAdmissionGate(sidecar_url="http://127.0.0.1:7371/")
        self.assertEqual("http://127.0.0.1:7371/", gate.sidecar_url)
        self.assertTrue(gate.sidecar_admitted())
        self.assertTrue(gate.admits_params(64 * 1024, 16))

    def test_sidecar_admitted_gate_rejects_a_blank_url(self):
        with self.assertRaises(ValueError):
            ArgonAdmissionGate(sidecar_url="   ")

    def test_default_verifier_config_constructs_without_binding(self):
        # The lazy gate: construction stores the parameters and builds
        # nothing, so a SHA-only deployment on a binding-less runtime
        # boots and reports its posture through the readiness seam
        # instead of raising.
        config = VerifierConfig()
        self.assertFalse(config.argon_backend_ready())
        self.assertIsNone(config.argon_sidecar_url)
        self.assertFalse(config.argon_backend_ready())

    def test_sha_record_verifies_without_binding(self):
        # The work the stdlib can check stays verifiable: a SHA-256
        # record verifies end to end on a config whose default gate was
        # never built, because the binding was never needed.
        record = mint_v2_record(
            secret=SECRET,
            algorithm="sha256",
            target_bits=4,
        )
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = Verifier(storage, VerifierConfig(now_provider=lambda: NOW))
        token = SolutionToken.create(
            record.nonce,
            solve_sha(record.prefix, record.salt, record.target_bits),
            5000,
            {},
        ).encode()
        outcome = verifier.verify(
            token,
            VerifyOptions(
                secret_key=SECRET,
                expected_scope="login",
                client_ip=CLIENT_IP,
            ),
        )
        self.assertTrue(outcome.is_ok(), outcome.code)
        self.assertFalse(outcome.from_stored_result)

    def test_argon_record_denies_unsupported_params_without_a_raise(self):
        # An argon2id record on a binding-less runtime without a
        # sidecar: the typed refuse, logged once per process, and the
        # gate property is never read, so verification never raises.
        record = mint_v2_record(
            secret=SECRET,
            algorithm="argon2id",
            m_kib=64,
            t=3,
            p=1,
            target_bits=1,
        )
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = Verifier(storage, VerifierConfig(now_provider=lambda: NOW))
        token = SolutionToken.create(record.nonce, 0, 5000, {}).encode()
        with unittest.mock.patch(
            "kiwicaptcha.verify.ArgonAdmissionGate",
            side_effect=AssertionError("the default gate was built"),
        ):
            outcome = verifier.verify(
                token,
                VerifyOptions(
                    secret_key=SECRET,
                    expected_scope="login",
                    client_ip=CLIENT_IP,
                ),
            )
        self.assertFalse(outcome.is_ok())
        self.assertEqual(VerifyError.UNSUPPORTED_ARGON2_PARAMS, outcome.code)
        # The refusal sits before the consume, exactly like the budget
        # and capacity refuses: the record stays intact, so a fixed
        # deployment (the binding installed) verifies it.
        self.assertIsNotNone(storage.find(record.nonce))

    def test_verifier_config_admits_through_the_sidecar(self):
        config = VerifierConfig(argon_sidecar_url="http://127.0.0.1:7371")
        self.assertIsInstance(config.argon_gate, ArgonAdmissionGate)
        self.assertEqual(
            "http://127.0.0.1:7371", config.argon_gate.sidecar_url
        )

    def test_explicit_gate_still_installs(self):
        gate = ArgonAdmissionGate(sidecar_url="http://127.0.0.1:7371")
        config = VerifierConfig(argon_gate=gate)
        self.assertIs(gate, config.argon_gate)

    def test_settings_argon_profile_refuses_without_a_path(self):
        from kiwicaptcha.config import Settings

        with self.assertRaises(ValueError) as caught:
            Settings(secret="k" * 32, profile="argon32")
        self.assertIn("never silently", str(caught.exception))
        self.assertIn("pip install kiwicaptcha[argon2]", str(caught.exception))

    def test_settings_argon_profile_boots_with_a_sidecar(self):
        from kiwicaptcha.config import Settings

        settings = Settings(
            secret="k" * 32,
            profile="argon64",
            argon_sidecar_url="http://127.0.0.1:7371",
        )
        self.assertEqual("http://127.0.0.1:7371", settings.argon_sidecar_url)

    def test_risk_ladder_with_argon_requires_binding_at_boot(self):
        # The work ladder escalates to the argon rungs under attack, so
        # an issuer profile that can reach one must prove the runtime
        # can verify it: boot refuses with the actionable message, the
        # sidecar is the other admission path, and the standard profile
        # (pure SHA rungs) never needs either.
        from kiwicaptcha.config import Settings, argon_rung_verifiable

        self.assertFalse(argon_rung_verifiable(16 * 1024, 3))
        self.assertFalse(argon_rung_verifiable(64 * 1024, 3))
        with self.assertRaises(ValueError) as caught:
            Settings(secret="k" * 32, profile="argon16")
        self.assertIn("never silently", str(caught.exception))
        self.assertIn("pip install kiwicaptcha[argon2]", str(caught.exception))
        Settings(
            secret="k" * 32,
            profile="argon32",
            argon_sidecar_url="http://127.0.0.1:7371",
        )
        Settings(secret="k" * 32, profile="standard")


class ArgonSidecarDelegationTest(unittest.TestCase):
    """The argon2id delegation plane: a sidecar-admitted gate on a
    runtime without the binding hands the whole proof to the sidecar."""

    SECRET = "argon-sidecar-delegation-0123456789abcdef"

    def _setup(self):
        record = mint_v2_record(
            secret=self.SECRET, algorithm="argon2id", m_kib=64, t=3, p=1,
            target_bits=1,
        )
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        config = VerifierConfig(
            now_provider=lambda: NOW,
            argon_gate=ArgonAdmissionGate(
                sidecar_url="http://127.0.0.1:7371"
            ),
        )
        verifier = Verifier(storage, config)
        token = SolutionToken.create(
            record.nonce,
            solve_sha(record.prefix, record.salt, record.target_bits),
            5000,
            {},
        ).encode()
        options = VerifyOptions(
            secret_key=self.SECRET,
            expected_scope="login",
            client_ip=CLIENT_IP,
        )
        return verifier, token, options, record, storage

    def setUp(self):
        from kiwicaptcha import argon2

        if argon2.native_available():
            self.patcher = unittest.mock.patch(
                "kiwicaptcha.argon2._NATIVE", False
            )
            self.patcher.start()
            self.addCleanup(self.patcher.stop)

    def test_sidecar_verdict_accepts_the_record(self):
        verifier, token, options, record, storage = self._setup()
        with unittest.mock.patch(
            "kiwicaptcha.verify.delegate_to_sidecar", return_value=(True, "ok")
        ) as stub:
            outcome = verifier.verify(token, options)
        self.assertTrue(outcome.is_ok(), outcome.code)
        self.assertFalse(outcome.from_stored_result)
        self.assertEqual(record.nonce, outcome.nonce)
        stub.assert_called_once()

    def test_sidecar_refusal_maps_the_shared_vocabulary(self):
        verifier, token, options, record, storage = self._setup()
        with unittest.mock.patch(
            "kiwicaptcha.verify.delegate_to_sidecar",
            return_value=(False, "insufficient_work"),
        ):
            outcome = verifier.verify(token, options)
        self.assertFalse(outcome.is_ok())
        self.assertEqual(VerifyError.INSUFFICIENT_WORK, outcome.code)

    def test_unknown_sidecar_code_stays_a_deny(self):
        verifier, token, options, record, storage = self._setup()
        with unittest.mock.patch(
            "kiwicaptcha.verify.delegate_to_sidecar",
            return_value=(False, "mystery-code"),
        ):
            outcome = verifier.verify(token, options)
        self.assertFalse(outcome.is_ok())
        self.assertEqual(VerifyError.EXECUTION_MISMATCH, outcome.code)

    def test_execution_armed_record_still_fails_closed(self):
        verifier, token, options, record, storage = self._setup()
        armed = mint_v2_record(
            secret=self.SECRET, algorithm="argon2id", m_kib=64, t=3, p=1,
            target_bits=1, protocol_version=4,
            execution_program=minimal_program_b64(),
        )
        storage.store(armed)
        armed_token = SolutionToken.create(armed.nonce, 0, 5000, {}).encode()
        with unittest.mock.patch(
            "kiwicaptcha.verify.delegate_to_sidecar", return_value=(True, "ok")
        ) as stub:
            outcome = verifier.verify(armed_token, options)
        self.assertFalse(outcome.is_ok())
        self.assertEqual(VerifyError.EXECUTION_MISMATCH, outcome.code)
        stub.assert_not_called()

    def test_native_runtime_never_delegates(self):
        from kiwicaptcha import argon2

        verifier, token, options, record, storage = self._setup()
        if argon2.native_available():
            # The local native path answers; the delegation seam stays
            # untouched. The derive call must be the local one, so the
            # stub failing loud proves the branch never fired.
            with unittest.mock.patch(
                "kiwicaptcha.verify.delegate_to_sidecar",
                side_effect=AssertionError("delegated on a native runtime"),
            ):
                outcome = verifier.verify(token, options)
            self.assertTrue(outcome.is_ok(), outcome.code)
        else:
            with unittest.mock.patch(
                "kiwicaptcha.verify.delegate_to_sidecar", return_value=(True, "ok")
            ):
                outcome = verifier.verify(token, options)
            self.assertTrue(outcome.is_ok(), outcome.code)


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

    def test_argon_memory_profile_space_is_powers_of_two(self):
        from kiwicaptcha.config import valid_argon_memory_kib

        self.assertTrue(valid_argon_memory_kib(8))
        self.assertTrue(valid_argon_memory_kib(16 * 1024))
        self.assertTrue(valid_argon_memory_kib(64 * 1024))
        self.assertFalse(valid_argon_memory_kib(100))
        self.assertFalse(valid_argon_memory_kib(10_000))
        self.assertFalse(valid_argon_memory_kib(0))
        self.assertFalse(valid_argon_memory_kib(7))
        self.assertFalse(valid_argon_memory_kib(65_537))
        # The config gate refuses non-power-of-two rungs at
        # configuration time, never per request.
        wide = ArgonAdmissionGate(max_memory_kib=65_536, max_time_cost=16)
        self.assertFalse(argon_rung_verifiable(100, 3, wide))
        self.assertTrue(argon_rung_verifiable(16 * 1024, 3, wide))
        for rung in PROFILE_ARGON_PARAMS.values():
            self.assertTrue(valid_argon_memory_kib(rung[0]), rung)

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
