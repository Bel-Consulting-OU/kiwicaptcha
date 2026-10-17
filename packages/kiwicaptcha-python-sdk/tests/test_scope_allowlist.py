"""The configured scope allowlist and the build-time deployment guards.

The settings' ``scopes`` tuple is an allowlist: a non-empty set refuses
a verify call whose expected scope is outside it with ``wrong_scope``;
an empty set keeps the historical any-scope acceptance.
"""

import sys
import unittest

sys.path.insert(0, ".")

from tests.support import (
    CLIENT_IP,
    NOW,
    SECRET,
    mint_v2_record,
    solve_sha,
)

from kiwicaptcha import SolutionToken
from kiwicaptcha.config import Settings
from kiwicaptcha.errors import VerifyError
from kiwicaptcha.stores import MemoryStorage
from kiwicaptcha.verify import Verifier, VerifierConfig, VerifyOptions


def verify_record(record, verifier, expected_scope):
    counter = solve_sha(record.prefix, record.salt, record.target_bits)
    token = SolutionToken.create(record.nonce, counter, 5000, {}).encode()
    return verifier.verify(
        token,
        VerifyOptions(
            secret_key=SECRET,
            expected_scope=expected_scope,
            client_ip=CLIENT_IP,
        ),
    )


class ScopeAllowlistTest(unittest.TestCase):
    def test_a_configured_scope_passes(self):
        record = mint_v2_record(scope="login")
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = Verifier(
            storage,
            VerifierConfig(now_provider=lambda: NOW, scopes=("login", "comment")),
        )
        outcome = verify_record(record, verifier, "login")
        self.assertTrue(outcome.is_ok(), outcome.code)

    def test_an_expected_scope_outside_the_allowlist_fails_wrong_scope(self):
        record = mint_v2_record(scope="signup")
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = Verifier(
            storage,
            VerifierConfig(now_provider=lambda: NOW, scopes=("login", "comment")),
        )
        # The record and the expected scope agree; only the allowlist
        # refuses, with the existing wrong_scope code.
        outcome = verify_record(record, verifier, "signup")
        self.assertEqual(VerifyError.WRONG_SCOPE, outcome.error)

    def test_an_empty_allowlist_accepts_any_scope(self):
        record = mint_v2_record(scope="signup")
        storage = MemoryStorage(now=lambda: NOW)
        storage.store(record)
        verifier = Verifier(storage, VerifierConfig(now_provider=lambda: NOW))
        outcome = verify_record(record, verifier, "signup")
        self.assertTrue(outcome.is_ok(), outcome.code)

    def test_settings_carry_the_allowlist_into_the_verifier(self):
        settings = Settings(
            secret=SECRET, store="memory://", scopes=("login",), profile="standard"
        )
        verifier = settings.build_verifier()
        # The settings-built verifier reads the wall clock; pin the
        # test clock on its config.
        verifier.config.now_provider = lambda: NOW
        record = mint_v2_record(scope="comment")
        verifier.storage.store(record)
        outcome = verify_record(record, verifier, "comment")
        self.assertEqual(VerifyError.WRONG_SCOPE, outcome.error)

    def test_build_revalidates_a_mutated_short_secret(self):
        settings = Settings(secret=SECRET, store="memory://")
        settings.secret = "short"
        with self.assertRaises(ValueError):
            settings.build_verifier()


class AuthenticatedHostnameTest(unittest.TestCase):
    """The public hostname seam of the PHP verifier, pinned directly."""

    def verifier(self, **config):
        return Verifier(MemoryStorage(now=lambda: NOW), VerifierConfig(**config))

    def test_an_authentic_metadata_mac_reports_the_hostname(self):
        record = mint_v2_record(mint_meta_mac=True, hostname="host-1")
        verifier = self.verifier()
        self.assertEqual("host-1", verifier.authenticated_hostname(record, SECRET))

    def test_a_forged_hostname_is_never_reported(self):
        record = mint_v2_record(mint_meta_mac=True, hostname="host-1")
        record.hostname = "host-2"
        verifier = self.verifier()
        self.assertIsNone(verifier.authenticated_hostname(record, SECRET))

    def test_a_record_without_a_metadata_mac_reports_none(self):
        record = mint_v2_record()
        verifier = self.verifier()
        self.assertIsNone(verifier.authenticated_hostname(record, SECRET))

    def test_an_unknown_kid_reports_none(self):
        record = mint_v2_record(mint_meta_mac=True, hostname="host-1", kid=3)
        verifier = self.verifier(secrets_by_kid={1: SECRET})
        self.assertIsNone(verifier.authenticated_hostname(record, SECRET))


if __name__ == "__main__":
    unittest.main()
