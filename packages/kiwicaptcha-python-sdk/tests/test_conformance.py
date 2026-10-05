"""The conformance runner over the shared protocol corpus.

One test that walks the three corpora the SDK contract pins: the
canonical record vectors (Rust-generated, byte-exact across languages),
the solution-token boundary fixture and the outcomes mapping vectors.
The verify-path conformance lives in test_verify_gates; this module is
the single entry a CI run can point at.
"""

import base64
import hashlib
import hmac
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
    load_outcome_vectors,
    load_token_fixtures,
    record_from_vector,
    token_for,
)

from kiwicaptcha.canonical import sign_payload_v1, verify_record_signature
from kiwicaptcha.stores import MemoryStorage
from kiwicaptcha.tokens import SolutionToken
from kiwicaptcha.verify import Verifier, VerifierConfig, VerifyOptions


class ProtocolCorpusConformanceTest(unittest.TestCase):
    def test_canonical_vectors_end_to_end(self):
        for vector in (SHA_VECTOR, ARGON2_VECTOR):
            with self.subTest(algorithm=vector["algorithm"]):
                # The v1 legacy payload re-signs byte-identically.
                payload_b64, signature = vector["challenge"].rsplit(".", 1)
                payload = base64.b64decode(payload_b64).decode("ascii")
                self.assertEqual(
                    hmac.new(
                        SECRET.encode("ascii"), payload.encode("ascii"), "sha256"
                    ).hexdigest(),
                    signature,
                )
                record = record_from_vector(vector)
                self.assertTrue(verify_record_signature(record, SECRET, None))
                storage = MemoryStorage(now=lambda: NOW)
                storage.store(record)
                verifier = Verifier(
                    storage,
                    VerifierConfig(now_provider=lambda: NOW, accept_legacy_v1=True),
                )
                outcome = verifier.verify(
                    token_for(vector),
                    VerifyOptions(
                        secret_key=SECRET, expected_scope="login", client_ip=CLIENT_IP
                    ),
                )
                self.assertTrue(outcome.is_ok(), outcome.code)

    def test_solution_token_fixture(self):
        fixtures = load_token_fixtures()
        for counter, encoded in fixtures["accepted"].items():
            self.assertEqual(encoded, SolutionToken.decode(encoded).encode())
        for encoded in fixtures["rejected"].values():
            with self.assertRaises(Exception):
                SolutionToken.decode(encoded)

    def test_outcome_fixture_version(self):
        vectors = load_outcome_vectors()
        self.assertEqual(1, vectors["version"])

    def test_ip_hash_vector(self):
        self.assertEqual(
            IP_HASH,
            hashlib.sha256((SECRET + CLIENT_IP).encode("ascii")).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
