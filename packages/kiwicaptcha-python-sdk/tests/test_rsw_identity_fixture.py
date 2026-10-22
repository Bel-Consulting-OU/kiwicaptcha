"""The one canonical rsw modulus identity fixture against the Python binding.

protocol/rsw-identity-v1/fixtures.json pins the shared 2048-bit test
modulus and the identity values every language binding must agree on:
the canonical fingerprint (SHA-256 of the decoded 256-byte modulus) and
the legacy base64-text alias, plus the secondary pair used only for
cross-identity negative tests. This module is the Python side of that
conformance, so a fingerprint drift fails here rather than silently
disagreeing with the PHP, Rust or Go cores.
"""

import json
import os
import unittest

from kiwicaptcha.rsw import Rsw
from kiwicaptcha.verify import (
    rsw_modulus_fingerprint,
    rsw_modulus_identity_matches,
    rsw_modulus_legacy_identity,
)
from tests.support import PROTOCOL_DIR

FIXTURE = os.path.join(PROTOCOL_DIR, "rsw-identity-v1", "fixtures.json")


def load_fixture():
    with open(FIXTURE, encoding="utf-8") as handle:
        return json.load(handle)


class RswIdentityFixtureTest(unittest.TestCase):
    def test_the_fixture_parses_and_pins_the_expected_fields(self):
        fixture = load_fixture()
        self.assertEqual(1, fixture["format_version"])
        self.assertTrue(fixture["modulus_n_b64"])
        self.assertTrue(fixture["lambda_b64"])
        self.assertRegex(fixture["rsw_modulus_n_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(fixture["legacy_base64_text_sha256"], r"^[0-9a-f]{64}$")
        secondary = fixture["secondary"]
        self.assertTrue(secondary["modulus_n_b64"])
        self.assertRegex(secondary["rsw_modulus_n_sha256"], r"^[0-9a-f]{64}$")

    def test_the_canonical_and_legacy_identities_match_the_fixture(self):
        fixture = load_fixture()
        modulus = fixture["modulus_n_b64"]
        self.assertEqual(
            fixture["rsw_modulus_n_sha256"], rsw_modulus_fingerprint(modulus)
        )
        self.assertEqual(
            fixture["legacy_base64_text_sha256"],
            rsw_modulus_legacy_identity(modulus),
        )
        self.assertTrue(
            rsw_modulus_identity_matches(
                fixture["rsw_modulus_n_sha256"], modulus, False
            )
        )
        self.assertTrue(
            rsw_modulus_identity_matches(
                fixture["legacy_base64_text_sha256"], modulus, True
            )
        )
        # The legacy alias must not match a drained deployment.
        self.assertFalse(
            rsw_modulus_identity_matches(
                fixture["legacy_base64_text_sha256"], modulus, False
            )
        )
        # A foreign identity never matches.
        self.assertFalse(rsw_modulus_identity_matches("f" * 64, modulus, True))

    def test_the_secondary_pair_fingerprints_and_never_matches_the_primary(self):
        fixture = load_fixture()
        secondary = fixture["secondary"]
        self.assertEqual(
            secondary["rsw_modulus_n_sha256"],
            rsw_modulus_fingerprint(secondary["modulus_n_b64"]),
        )
        self.assertFalse(
            rsw_modulus_identity_matches(
                secondary["rsw_modulus_n_sha256"], fixture["modulus_n_b64"], True
            )
        )

    def test_the_fixture_trapdoor_pair_validates(self):
        fixture = load_fixture()
        trapdoor = Rsw(fixture["modulus_n_b64"], fixture["lambda_b64"])
        self.assertEqual(2048, trapdoor.n.bit_length())


if __name__ == "__main__":
    unittest.main()
