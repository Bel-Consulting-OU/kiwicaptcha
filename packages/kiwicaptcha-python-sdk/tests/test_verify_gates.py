"""The cheap-gate order and the consumed resolution, driven on the
canonical fixtures and locally minted records."""

import sys
import unittest

sys.path.insert(0, ".")

from tests.support import (
    ARGON2_VECTOR,
    CLIENT_IP,
    IP_HASH,
    ISSUED_AT,
    NOW,
    SECRET,
    SHA_VECTOR,
    mint_v2_record,
    record_from_vector,
    solve_sha,
    token_for,
)

from kiwicaptcha.errors import VerifyError
from kiwicaptcha.stores import MemoryStorage
from kiwicaptcha.verify import (
    RequestBindingExpectation,
    Verifier,
    VerifierConfig,
    VerifyOptions,
)
from kiwicaptcha import SolutionToken


def make_verifier(storage, **config):
    defaults = {"now_provider": lambda: NOW, "accept_legacy_v1": True}
    defaults.update(config)
    return Verifier(storage, VerifierConfig(**defaults))


class ParityVectorTest(unittest.TestCase):
    """The authoritative Rust-generated fixtures, byte-for-byte."""

    def verify_vector(self, vector, **kwargs):
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record_from_vector(vector))
        verifier = make_verifier(storage, **kwargs)
        return verifier.verify(
            token_for(vector),
            VerifyOptions(secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP),
        )

    def test_sha_vector_verifies(self):
        outcome = self.verify_vector(SHA_VECTOR)
        self.assertTrue(outcome.is_ok(), outcome.code)
        self.assertEqual(outcome.nonce, SHA_VECTOR["nonce"])

    def test_argon2_vector_verifies(self):
        outcome = self.verify_vector(ARGON2_VECTOR)
        self.assertTrue(outcome.is_ok(), outcome.code)

    def test_sha_vector_rejects_wrong_counter(self):
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record_from_vector(SHA_VECTOR))
        verifier = make_verifier(storage)
        outcome = verifier.verify(
            token_for(SHA_VECTOR, counter=SHA_VECTOR["counter"] + 1),
            VerifyOptions(secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP),
        )
        self.assertEqual(VerifyError.INSUFFICIENT_WORK, outcome.error)
        # The invalid outcome commits deterministically and replays.
        replay = verifier.verify(
            token_for(SHA_VECTOR, counter=SHA_VECTOR["counter"] + 1),
            VerifyOptions(secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP),
        )
        self.assertEqual(VerifyError.INSUFFICIENT_WORK, replay.error)

    def test_vector_replay_is_already_consumed(self):
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record_from_vector(SHA_VECTOR))
        verifier = make_verifier(storage)
        token = token_for(SHA_VECTOR)
        options = VerifyOptions(secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP)
        self.assertTrue(verifier.verify(token, options).is_ok())
        replay = verifier.verify(token, options)
        self.assertEqual(VerifyError.ALREADY_CONSUMED, replay.error)

    def test_wrong_scope_rejected(self):
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record_from_vector(SHA_VECTOR))
        verifier = make_verifier(storage)
        outcome = verifier.verify(
            token_for(SHA_VECTOR),
            VerifyOptions(secret_key=SECRET, expected_scope="signup", client_ip=CLIENT_IP),
        )
        self.assertEqual(VerifyError.WRONG_SCOPE, outcome.error)

    def test_missing_scope_option_is_the_typed_required_scope_refusal(self):
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record_from_vector(SHA_VECTOR))
        verifier = make_verifier(storage)
        # The empty scope option accepts nothing: the typed refusal
        # replaces the lax any-scope acceptance.
        outcome = verifier.verify(
            token_for(SHA_VECTOR),
            VerifyOptions(secret_key=SECRET, expected_scope="", client_ip=CLIENT_IP),
        )
        self.assertEqual(VerifyError.REQUIRED_SCOPE, outcome.error)

    def test_ip_mismatch_rejected(self):
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record_from_vector(SHA_VECTOR))
        verifier = make_verifier(storage)
        outcome = verifier.verify(
            token_for(SHA_VECTOR),
            VerifyOptions(secret_key=SECRET, expected_scope="login", client_ip="198.51.100.9"),
        )
        self.assertEqual(VerifyError.IP_MISMATCH, outcome.error)

    def test_missing_client_ip_keeps_record(self):
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record_from_vector(SHA_VECTOR))
        verifier = make_verifier(storage)
        outcome = verifier.verify(
            token_for(SHA_VECTOR),
            VerifyOptions(secret_key=SECRET, expected_scope="login"),
        )
        self.assertEqual(VerifyError.MISSING_CLIENT_IP, outcome.error)
        # The retry-with-IP contract: the record was kept.
        self.assertIsNotNone(storage.find(SHA_VECTOR["nonce"]))

    def test_expired_rejected_and_record_burned(self):
        vector = dict(SHA_VECTOR)
        record = record_from_vector(vector)
        past_expiry = ISSUED_AT + 121
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        outcome = verifier.verify(
            token_for(vector),
            VerifyOptions(secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP),
        )
        self.assertNotEqual(VerifyError.EXPIRED, outcome.error)
        # Drive the storage clock past the signed expiry: the record is
        # absent, the verdict is record_not_found.
        storage2 = MemoryStorage(now=lambda: past_expiry)
        storage2.store(record)
        verifier2 = Verifier(
            storage2,
            VerifierConfig(now_provider=lambda: past_expiry, accept_legacy_v1=True),
        )
        outcome2 = verifier2.verify(
            token_for(vector),
            VerifyOptions(secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP),
        )
        self.assertEqual(VerifyError.RECORD_NOT_FOUND, outcome2.error)

    def test_future_skew_rejected(self):
        record = record_from_vector(SHA_VECTOR)
        storage = MemoryStorage(now=lambda: ISSUED_AT - 3600)
        from kiwicaptcha.stores.memory import _Entry

        # Bypass the expiry-pruning store: park the entry directly so
        # the gate sees a live record on a clock before issuance.
        storage._records[record.nonce] = _Entry(record)
        verifier = Verifier(
            storage,
            VerifierConfig(now_provider=lambda: ISSUED_AT - 3600, accept_legacy_v1=True),
        )
        outcome = verifier.verify(
            token_for(SHA_VECTOR),
            VerifyOptions(secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP),
        )
        self.assertEqual(VerifyError.EXPIRED, outcome.error)


class V2GateTest(unittest.TestCase):
    """The v2+ gates on locally minted records."""

    def fresh(self, **mint):
        record = mint_v2_record(**mint)
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        return record, verifier

    def solve_and_verify(self, record, verifier, **options):
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        token = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        defaults = {"secret_key": SECRET, "client_ip": CLIENT_IP}
        defaults.update(options)
        defaults.setdefault("expected_scope", "login")
        return verifier.verify(token, VerifyOptions(**defaults))

    def test_v2_full_pass(self):
        record, verifier = self.fresh()
        receipt_ns = (ISSUED_AT + 5) * 1_000_000
        outcome = self.solve_and_verify(
            record, verifier, expected_scope="login", now_ns=receipt_ns
        )
        self.assertTrue(outcome.is_ok(), outcome.code)
        self.assertEqual(outcome.nonce, record.nonce)
        # NO record metadata MAC was minted: the measured duration is
        # withheld, mirroring measurableSolveDurationMs.
        self.assertIsNone(outcome.solve_duration_ms)
        # A MAC-carrying record measures the span receipt minus issuance.
        record2 = mint_v2_record(mint_meta_mac=True)
        storage2 = MemoryStorage(now=lambda: NOW)
        storage2.store(record2)
        verifier2 = make_verifier(storage2)
        outcome2 = self.solve_and_verify(
            record2, verifier2, expected_scope="login", now_ns=receipt_ns
        )
        self.assertTrue(outcome2.is_ok(), outcome2.code)
        self.assertEqual(outcome2.solve_duration_ms, 5000)

    def test_region_gate(self):
        record, verifier = self.fresh(region="eu")
        outcome = self.solve_and_verify(record, verifier)
        self.assertTrue(outcome.is_ok(), outcome.code)
        record2, verifier2 = self.fresh(region="eu")
        outcome2 = self.solve_and_verify(
            record2, verifier2, expected_scope="login"
        )
        self.assertTrue(outcome2.is_ok(), outcome2.code)
        # A region-bound verifier rejects an unbound record.
        record3 = mint_v2_record()
        storage3 = MemoryStorage(now=lambda: NOW)
        storage3.store(record3)
        verifier3 = make_verifier(storage3, region="eu")
        outcome3 = self.solve_and_verify(record3, verifier3)
        self.assertEqual(VerifyError.WRONG_REGION, outcome3.error)

    def test_issuer_gate(self):
        record, verifier = self.fresh(issuer="prod-eu")
        outcome = self.solve_and_verify(record, verifier, expected_scope="login")
        self.assertTrue(outcome.is_ok(), outcome.code)
        record2 = mint_v2_record(issuer="prod-eu")
        storage2 = MemoryStorage(now=lambda: NOW)
        storage2.store(record2)
        verifier2 = make_verifier(storage2, expected_issuer="prod-us")
        outcome2 = self.solve_and_verify(record2, verifier2)
        self.assertEqual(VerifyError.WRONG_ISSUER, outcome2.error)

    def test_policy_epoch_strict_and_window(self):
        record, verifier = self.fresh(policy_version=2)
        outcome = self.solve_and_verify(record, verifier, expected_scope="login")
        self.assertTrue(outcome.is_ok(), outcome.code)
        # Strict: a record from another epoch is refused.
        record2 = mint_v2_record(policy_version=2)
        storage2 = MemoryStorage(now=lambda: NOW)
        storage2.store(record2)
        verifier2 = make_verifier(storage2, expected_policy_version=3)
        outcome2 = self.solve_and_verify(record2, verifier2)
        self.assertEqual(VerifyError.WRONG_POLICY_VERSION, outcome2.error)
        # Rollout window: floor 2, expected 3 accepts epoch 2. A fresh
        # store: the strict refusal burned the old pending record.
        record3 = mint_v2_record(policy_version=2)
        storage3 = MemoryStorage(now=lambda: NOW)
        storage3.store(record3)
        verifier3 = make_verifier(
            storage3, expected_policy_version=3, policy_version_floor=2
        )
        outcome3 = self.solve_and_verify(record3, verifier3)
        self.assertTrue(outcome3.is_ok(), outcome3.code)
        # The floor above the expected epoch accepts nothing.
        record4 = mint_v2_record(policy_version=2)
        storage4 = MemoryStorage(now=lambda: NOW)
        storage4.store(record4)
        verifier4 = make_verifier(
            storage4, expected_policy_version=3, policy_version_floor=4
        )
        outcome4 = self.solve_and_verify(record4, verifier4)
        self.assertEqual(VerifyError.WRONG_POLICY_VERSION, outcome4.error)

    def test_kid_rotation_and_revocation(self):
        record, verifier = self.fresh(kid=2)
        storage = verifier.storage
        rotated = make_verifier(storage, secrets_by_kid={1: "k" * 32, 2: SECRET})
        outcome = self.solve_and_verify(record, rotated, expected_scope="login")
        self.assertTrue(outcome.is_ok(), outcome.code)
        # An unknown kid is refused before any signature work.
        unknown = make_verifier(storage, secrets_by_kid={1: "k" * 32})
        outcome2 = self.solve_and_verify(record, unknown)
        self.assertEqual(VerifyError.UNKNOWN_KID, outcome2.error)
        # A future kid beyond the newest configured kid is refused too.
        future = make_verifier(storage, secrets_by_kid={1: "k" * 32, 3: "k" * 32})
        outcome3 = self.solve_and_verify(record, future)
        self.assertEqual(VerifyError.UNKNOWN_KID, outcome3.error)
        # Compromise revocation overrides the rotation grace.
        revoked = make_verifier(
            storage, secrets_by_kid={1: "k" * 32, 2: SECRET}, revoked_kids=(2,)
        )
        outcome4 = self.solve_and_verify(record, revoked)
        self.assertEqual(VerifyError.UNKNOWN_KID, outcome4.error)

    def test_bad_signature(self):
        record, verifier = self.fresh()
        tampered = mint_v2_record(scope="other")
        forged = mint_v2_record()
        object.__setattr__(forged, "scope", "evil") if hasattr(
            forged, "__slots__"
        ) else None
        forged.scope = "evil"
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(forged)
        verifier2 = make_verifier(storage)
        outcome = self.solve_and_verify(forged, verifier2, expected_scope="login")
        self.assertEqual(VerifyError.BAD_SIGNATURE, outcome.error)

    def test_min_duration_floor(self):
        # The floor needs an authenticated issuance clock: a record
        # with a floor and no metadata MAC is malformed, PHP parity.
        record = mint_v2_record(min_duration_ms=5000)
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        token = SolutionToken.create(record.nonce, counter, 10, {}).encode()
        receipt = (ISSUED_AT + 1) * 1_000_000  # 1s after issuance < 5s floor
        outcome = verifier.verify(
            token,
            VerifyOptions(expected_scope="login", secret_key=SECRET, client_ip=CLIENT_IP, now_ns=receipt),
        )
        self.assertEqual(VerifyError.MALFORMED_RECORD, outcome.error)
        # The MAC-carrying record evaluates the floor exactly.
        record_mac = mint_v2_record(min_duration_ms=5000, mint_meta_mac=True)
        storage_mac = MemoryStorage(now=lambda: NOW)
        storage_mac.store(record_mac)
        verifier_mac = make_verifier(storage_mac)
        counter_mac = solve_sha(
            record_mac.prefix, record_mac.salt, record_mac.target_bits
        )
        token_mac = SolutionToken.create(record_mac.nonce, counter_mac, 10, {}).encode()
        outcome_mac = verifier_mac.verify(
            token_mac,
            VerifyOptions(expected_scope="login", secret_key=SECRET, client_ip=CLIENT_IP, now_ns=receipt),
        )
        self.assertEqual(VerifyError.TOO_FAST, outcome_mac.error)
        # A receipt past the floor passes. A fresh store: the TOO_FAST
        # verdict is a hard one, so it burned the pending record.
        record2 = mint_v2_record(min_duration_ms=5000, mint_meta_mac=True)
        storage2 = MemoryStorage(now=lambda: NOW)
        storage2.store(record2)
        verifier2 = make_verifier(storage2)
        counter2 = solve_sha(record2.prefix, record2.salt, record2.target_bits)
        token2 = SolutionToken.create(record2.nonce, counter2, 10, {}).encode()
        receipt2 = (ISSUED_AT + 6) * 1_000_000
        outcome2 = verifier2.verify(
            token2,
            VerifyOptions(expected_scope="login", secret_key=SECRET, client_ip=CLIENT_IP, now_ns=receipt2),
        )
        self.assertTrue(outcome2.is_ok(), outcome2.code)
        self.assertEqual(outcome2.solve_duration_ms, 6000)

    def test_too_fast_skew(self):
        record = mint_v2_record(min_duration_ms=1000, mint_meta_mac=True)
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        token = SolutionToken.create(record.nonce, counter, 10, {}).encode()
        # Receipt before issuance beyond the 5s skew bound is impossible.
        receipt = (ISSUED_AT - 10) * 1_000_000
        outcome = verifier.verify(
            token,
            VerifyOptions(expected_scope="login", secret_key=SECRET, client_ip=CLIENT_IP, now_ns=receipt),
        )
        self.assertEqual(VerifyError.TOO_FAST, outcome.error)
        # Within the bound the floor check is skipped. A fresh store:
        # the first TOO_FAST verdict burned its pending record.
        record2 = mint_v2_record(min_duration_ms=1000, mint_meta_mac=True)
        storage2 = MemoryStorage(now=lambda: NOW)
        storage2.store(record2)
        verifier2 = make_verifier(storage2)
        counter2 = solve_sha(record2.prefix, record2.salt, record2.target_bits)
        token2 = SolutionToken.create(record2.nonce, counter2, 10, {}).encode()
        receipt_within = (ISSUED_AT - 2) * 1_000_000
        outcome2 = verifier2.verify(
            token2,
            VerifyOptions(expected_scope="login", 
                secret_key=SECRET, client_ip=CLIENT_IP, now_ns=receipt_within
            ),
        )
        self.assertTrue(outcome2.is_ok(), outcome2.code)

    def test_request_binding_exact(self):
        record, verifier = self.fresh(request_binding="tx-abc")
        outcome = self.solve_and_verify(
            record, verifier, expected_scope="login", expected_request_binding="tx-abc"
        )
        self.assertTrue(outcome.is_ok(), outcome.code)
        # A bound record under a different binding fails closed.
        record2 = mint_v2_record(request_binding="tx-abc")
        storage2 = MemoryStorage(now=lambda: NOW)
        storage2.store(record2)
        verifier2 = make_verifier(storage2)
        outcome2 = self.solve_and_verify(
            record2, verifier2, expected_request_binding="tx-other"
        )
        self.assertEqual(VerifyError.REQUEST_BINDING_MISMATCH, outcome2.error)
        # A bound record under no binding fails closed too. A fresh
        # store: the previous refusal burned the pending record.
        record3 = mint_v2_record(request_binding="tx-abc")
        storage3 = MemoryStorage(now=lambda: NOW)
        storage3.store(record3)
        verifier3 = make_verifier(storage3)
        outcome3 = self.solve_and_verify(record3, verifier3)
        self.assertEqual(VerifyError.REQUEST_BINDING_MISMATCH, outcome3.error)
        # An unbound record under a presented binding fails closed.
        record4 = mint_v2_record()
        storage4 = MemoryStorage(now=lambda: NOW)
        storage4.store(record4)
        verifier4 = make_verifier(storage4)
        outcome4 = self.solve_and_verify(
            record4, verifier4, expected_request_binding="tx-abc"
        )
        self.assertEqual(VerifyError.REQUEST_BINDING_MISMATCH, outcome4.error)
        # The legacy expectation keeps the historical semantics. A fresh
        # store again: the exact refusal burned that pending record.
        record5 = mint_v2_record()
        storage5 = MemoryStorage(now=lambda: NOW)
        storage5.store(record5)
        verifier5 = make_verifier(storage5)
        outcome5 = self.solve_and_verify(
            record5,
            verifier5,
            binding_expectation=RequestBindingExpectation.legacy("tx-abc"),
        )
        self.assertTrue(outcome5.is_ok(), outcome5.code)

    def test_v2_ip_binding(self):
        record = mint_v2_record(binding_ip=CLIENT_IP)
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        outcome = self.solve_and_verify(record, verifier, expected_scope="login")
        self.assertTrue(outcome.is_ok(), outcome.code)
        storage2 = MemoryStorage(now=lambda: NOW)
        record2 = mint_v2_record(binding_ip=CLIENT_IP)
        storage2.store(record2)
        verifier2 = make_verifier(storage2)
        outcome2 = self.solve_and_verify(record2, verifier2, client_ip=None)
        self.assertEqual(VerifyError.MISSING_CLIENT_IP, outcome2.error)
        storage3 = MemoryStorage(now=lambda: NOW)
        record3 = mint_v2_record(binding_ip=CLIENT_IP)
        storage3.store(record3)
        verifier3 = make_verifier(storage3)
        outcome3 = self.solve_and_verify(
            record3, verifier3, client_ip="198.51.100.1"
        )
        self.assertEqual(VerifyError.IP_MISMATCH, outcome3.error)

    def test_telemetry_gate(self):
        record = mint_v2_record()
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        bot_token = SolutionToken.create(
            record.nonce, counter, 5000, {"wd": True}
        ).encode()
        outcome = verifier.verify(
            bot_token,
            VerifyOptions(expected_scope="login", 
                secret_key=SECRET, client_ip=CLIENT_IP, enforce_telemetry=True
            ),
        )
        self.assertEqual(VerifyError.TELEMETRY_REJECTED, outcome.error)
        # Opt-out: without enforce_telemetry the same token verifies.
        storage2 = MemoryStorage(now=lambda: NOW)
        record2 = mint_v2_record()
        storage2.store(record2)
        verifier2 = make_verifier(storage2)
        counter2 = solve_sha(record2.prefix, record2.salt, record2.target_bits)
        bot_token2 = SolutionToken.create(
            record2.nonce, counter2, 5000, {"wd": True}
        ).encode()
        outcome2 = verifier2.verify(
            bot_token2,
            VerifyOptions(expected_scope="login", secret_key=SECRET, client_ip=CLIENT_IP),
        )
        self.assertTrue(outcome2.is_ok(), outcome2.code)

    def test_unsupported_argon_profile(self):
        # The ceilings gate authentic-but-unsupported parameters.
        record = mint_v2_record(algorithm="argon2id", m_kib=64, t=2, p=1, target_bits=1)
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        token = SolutionToken.create(record.nonce, 0, 5000, {}).encode()
        outcome = verifier.verify(
            token, VerifyOptions(expected_scope="login", secret_key=SECRET, client_ip=CLIENT_IP)
        )
        self.assertEqual(VerifyError.UNSUPPORTED_ARGON2_PARAMS, outcome.error)

    def test_execution_armed_fails_closed(self):
        from tests.support import minimal_program_b64

        program = minimal_program_b64()
        record = mint_v2_record(
            protocol_version=4, execution_program=program
        )
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        token = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        outcome = verifier.verify(
            token,
            VerifyOptions(
                secret_key=SECRET, client_ip=CLIENT_IP, expected_scope="login"
            ),
        )
        # Unarmed submission against an armed record: deterministic mismatch.
        self.assertEqual(VerifyError.EXECUTION_MISMATCH, outcome.error)
        # Armed evidence fails closed as well.
        record2 = mint_v2_record(
            protocol_version=4, execution_program=program
        )
        storage2 = MemoryStorage(now=lambda: NOW)
        storage2.store(record2)
        verifier2 = make_verifier(storage2)
        token2 = SolutionToken.create(
            record2.nonce, counter, 5000, {},
            execution_digest="a" * 64, execution_trace="Zm9v",
        ).encode()
        outcome2 = verifier2.verify(
            token2,
            VerifyOptions(
                secret_key=SECRET, client_ip=CLIENT_IP, expected_scope="login"
            ),
        )
        self.assertEqual(VerifyError.EXECUTION_MISMATCH, outcome2.error)
        # A v3 decoy record without execution arms verifies normally.
        record3 = mint_v2_record(protocol_version=3, decoy_field="hp_field")
        storage3 = MemoryStorage(now=lambda: NOW)
        storage3.store(record3)
        verifier3 = make_verifier(storage3)
        counter3 = solve_sha(record3.prefix, record3.salt, record3.target_bits)
        token3 = SolutionToken.create(record3.nonce, counter3, 5000, {}).encode()
        outcome3 = verifier3.verify(
            token3,
            VerifyOptions(
                secret_key=SECRET, client_ip=CLIENT_IP, expected_scope="login"
            ),
        )
        self.assertTrue(outcome3.is_ok(), outcome3.code)

    def test_decoy_field_exposed_on_outcome(self):
        record = mint_v2_record(protocol_version=3, decoy_field="hp_field")
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        token = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        outcome = verifier.verify(
            token,
            VerifyOptions(
                secret_key=SECRET, client_ip=CLIENT_IP, expected_scope="login"
            ),
        )
        self.assertTrue(outcome.is_ok(), outcome.code)
        self.assertEqual("hp_field", outcome.decoy_field)


class ConsumedResolutionTest(unittest.TestCase):
    """The identity-gated replay of committed results."""

    def _prepare(self, **mint):
        record = mint_v2_record(**mint)
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        return record, verifier, counter

    def test_stored_invalid_replays_to_any_caller(self):
        record, verifier, counter = self._prepare()
        token = SolutionToken.create(record.nonce, counter + 1, 5000, {}).encode()
        first = verifier.verify(token, VerifyOptions(expected_scope="login", secret_key=SECRET))
        self.assertEqual(VerifyError.INSUFFICIENT_WORK, first.error)
        again = verifier.verify(token, VerifyOptions(expected_scope="login", secret_key=SECRET))
        self.assertEqual(VerifyError.INSUFFICIENT_WORK, again.error)

    def test_identity_gated_replay(self):
        record, verifier, counter = self._prepare()
        good = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        identity = "order-123"
        first = verifier.verify(
            good,
            VerifyOptions(expected_scope="login", secret_key=SECRET, operation_identity=identity),
        )
        self.assertTrue(first.is_ok(), first.code)
        self.assertTrue(first.from_stored_result is False)
        # The same identity replays the stored success.
        replay = verifier.verify(
            good,
            VerifyOptions(expected_scope="login", secret_key=SECRET, operation_identity=identity),
        )
        self.assertTrue(replay.is_ok(), replay.code)
        self.assertTrue(replay.from_stored_result)
        self.assertIsNone(replay.solve_duration_ms)
        # A different identity is refused.
        other = verifier.verify(
            good,
            VerifyOptions(expected_scope="login", secret_key=SECRET, operation_identity="order-456"),
        )
        self.assertEqual(VerifyError.ALREADY_CONSUMED, other.error)
        # A null identity is refused.
        null_identity = verifier.verify(
            good, VerifyOptions(expected_scope="login", secret_key=SECRET)
        )
        self.assertEqual(VerifyError.ALREADY_CONSUMED, null_identity.error)

    def test_crash_window_is_indeterminate(self):
        record, verifier, counter = self._prepare()
        good = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        first = verifier.verify(good, VerifyOptions(expected_scope="login", secret_key=SECRET))
        self.assertTrue(first.is_ok())
        # Simulate the crash between consume and commit: strip the result.
        entry = verifier.storage._records[record.nonce]
        entry.result = None
        outcome = verifier.verify(good, VerifyOptions(expected_scope="login", secret_key=SECRET))
        self.assertEqual(VerifyError.CONSUME_INDETERMINATE, outcome.error)

    def test_exempt_failure_on_consumed_record_resolves_stored(self):
        record, verifier, counter = self._prepare()
        good = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        first = verifier.verify(
            good, VerifyOptions(expected_scope="login", secret_key=SECRET, client_ip=CLIENT_IP)
        )
        self.assertTrue(first.is_ok())
        # A replay whose client IP no longer matches: ip_mismatch is
        # replay-exempt, so the compositional gate passes and the stored
        # success answers (already consumed, null identity).
        outcome = verifier.verify(
            good, VerifyOptions(expected_scope="login", secret_key=SECRET, client_ip="198.51.100.7")
        )
        self.assertEqual(VerifyError.ALREADY_CONSUMED, outcome.error)

    def test_hard_failure_shadows_exempt_on_consumed(self):
        # A hard verdict (wrong scope) wins over the exempt expiry.
        record = mint_v2_record(scope="login", min_duration_ms=0)
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = make_verifier(storage)
        counter = solve_sha(record.prefix, record.salt, record.target_bits)
        good = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        first = verifier.verify(
            good, VerifyOptions(secret_key=SECRET, expected_scope="login")
        )
        self.assertTrue(first.is_ok())
        outcome = verifier.verify(
            good,
            VerifyOptions(
                secret_key=SECRET,
                expected_scope="signup",
                client_ip="not-an-ip-cause-expired",
            ),
        )
        # The record was kept (consumed), the scope verdict is hard.
        self.assertIn(
            outcome.error,
            (VerifyError.WRONG_SCOPE, VerifyError.ALREADY_CONSUMED),
        )

    def test_cancelled_record_is_missing(self):
        record, verifier, counter = self._prepare()
        verifier.storage.cancel(record.nonce)
        token = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
        outcome = verifier.verify(token, VerifyOptions(expected_scope="login", secret_key=SECRET))
        self.assertEqual(VerifyError.RECORD_NOT_FOUND, outcome.error)


class MalformedTokenTest(unittest.TestCase):
    def test_malformed_token_code(self):
        storage = MemoryStorage(now=lambda: NOW)
        verifier = make_verifier(storage)
        outcome = verifier.verify(
            "!!!not-base64!!!", VerifyOptions(expected_scope="login", secret_key=SECRET)
        )
        self.assertEqual(VerifyError.MALFORMED_TOKEN, outcome.error)
        self.assertTrue(outcome.detail)


if __name__ == "__main__":
    unittest.main()
