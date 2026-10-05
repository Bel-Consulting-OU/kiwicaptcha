"""The solution token grammar: create, encode, decode, rejections.

The split mirrors the PHP SolutionToken: ``create`` is a plain value
constructor, ``encode`` assembles the canonical bytes, and ``decode``
is the strict boundary that accepts or rejects.
"""

import base64
import json
import sys
import unittest

sys.path.insert(0, ".")

from tests.support import load_token_fixtures

from kiwicaptcha.tokens import DecodeError, SolutionToken

NONCE = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="


class TokenFixtureTest(unittest.TestCase):
    """The shared boundary fixture at protocol/solution-token-v1."""

    def setUp(self):
        self.fixtures = load_token_fixtures()

    def test_accepted_counters_round_trip(self):
        for counter, encoded in self.fixtures["accepted"].items():
            token = SolutionToken.decode(encoded)
            self.assertEqual(int(counter), token.counter)
            self.assertEqual(self.fixtures["nonce_b64"], token.nonce)
            self.assertEqual(self.fixtures["duration_ms"], token.duration_ms)
            self.assertEqual({"me": 1}, token.telemetry)
            # The encoder reproduces the shared bytes exactly.
            self.assertEqual(encoded, token.encode())

    def test_cross_language_counter(self):
        cross = self.fixtures["cross_language"]
        token = SolutionToken.decode(cross["encoded"])
        self.assertEqual(cross["counter"], token.counter)
        self.assertEqual(cross["encoded"], token.encode())

    def test_rejected_counters(self):
        for counter, encoded in self.fixtures["rejected"].items():
            with self.assertRaises(DecodeError) as ctx:
                SolutionToken.decode(encoded)
            self.assertIn("solver maximum", str(ctx.exception))

    def test_encoder_matches_fixture_bytes(self):
        encoded = SolutionToken.create(
            self.fixtures["nonce_b64"], 5_000_000, 1234, {"me": 1}
        ).encode()
        self.assertEqual(self.fixtures["accepted"]["5000000"], encoded)

    def test_solver_ceiling_boundary_encodes_and_fails_decode(self):
        at_ceiling = SolutionToken.create(
            self.fixtures["nonce_b64"], 20_000_000, 1234, {"me": 1}
        ).encode()
        with self.assertRaises(DecodeError):
            SolutionToken.decode(at_ceiling)


class TokenGrammarTest(unittest.TestCase):
    def test_round_trip_all_optional_segments(self):
        token = SolutionToken.create(
            NONCE,
            42,
            9000,
            {"wd": False, "et": [1, 2, 3]},
            execution_digest="ab" * 32,
            execution_trace="aGlfaGk=",
            rsw_proof="cd" * 256,
        )
        decoded = SolutionToken.decode(token.encode())
        self.assertEqual(42, decoded.counter)
        self.assertEqual(9000, decoded.duration_ms)
        self.assertEqual({"wd": False, "et": [1, 2, 3]}, decoded.telemetry)
        self.assertEqual("ab" * 32, decoded.execution_digest)
        # The trace travels as unpadded base64url; decode hands back the
        # wire spelling, exactly like the PHP ExecutionEvidence.
        self.assertEqual("aGlfaGk", decoded.execution_trace)
        self.assertEqual("cd" * 256, decoded.rsw_proof)

    def test_canonical_base64_enforced(self):
        raw = SolutionToken.create(NONCE, 5, 100, {}).encode()
        unpadded = raw.replace("=", "")
        self.assertNotEqual(raw, unpadded)
        with self.assertRaises(DecodeError):
            SolutionToken.decode(unpadded)

    def test_nonce_shape_enforced(self):
        with self.assertRaises(DecodeError):
            SolutionToken.decode("dG9vLXNob3J0LjEuMS57fQ==")

    def test_canonical_decimal_enforced(self):
        payload = base64.b64encode(NONCE.encode("ascii")).decode("ascii")
        body = f"{payload}.042.100.{{}}"
        wire = base64.b64encode(body.encode("ascii")).decode("ascii")
        with self.assertRaises(DecodeError):
            SolutionToken.decode(wire)

    def test_counter_upper_bound_on_decode(self):
        # Create is a lenient value constructor, PHP parity: the
        # ceiling bites on decode.
        body = f"{NONCE}.20000000.100.{{}}"
        wire = base64.b64encode(body.encode("ascii")).decode("ascii")
        with self.assertRaises(DecodeError) as ctx:
            SolutionToken.decode(wire)
        self.assertIn("solver maximum", str(ctx.exception))

    def test_duration_bound_on_decode(self):
        body = f"{NONCE}.1.3600001.{{}}"
        wire = base64.b64encode(body.encode("ascii")).decode("ascii")
        with self.assertRaises(DecodeError):
            SolutionToken.decode(wire)
        ok = SolutionToken.decode(
            base64.b64encode(f"{NONCE}.1.3600000.{{}}".encode("ascii")).decode("ascii")
        )
        self.assertEqual(3_600_000, ok.duration_ms)

    def test_negative_duration_rejected_on_decode(self):
        body = f"{NONCE}.1.-5.{{}}"
        wire = base64.b64encode(body.encode("ascii")).decode("ascii")
        with self.assertRaises(DecodeError):
            SolutionToken.decode(wire)

    def test_array_telemetry_rejected_on_decode(self):
        # Create accepts the list (PHP parity: the value constructor is
        # lenient), the wire bytes carry [1,2], and the strict decode
        # refuses a non-object telemetry segment.
        token = SolutionToken.create(NONCE, 1, 100, [1, 2])
        with self.assertRaises(DecodeError):
            SolutionToken.decode(token.encode())

    def test_execution_digest_must_be_hex64_on_decode(self):
        token = SolutionToken.create(
            NONCE, 1, 100, {}, execution_digest="zz"
        )
        with self.assertRaises(DecodeError):
            SolutionToken.decode(token.encode())
        token2 = SolutionToken.create(
            NONCE, 1, 100, {}, execution_digest="ab" * 32, execution_trace="!!!"
        )
        with self.assertRaises(DecodeError):
            SolutionToken.decode(token2.encode())

    def test_rsw_proof_must_be_hex512_on_decode(self):
        token = SolutionToken.create(NONCE, 0, 100, {}, rsw_proof="cd" * 10)
        with self.assertRaises(DecodeError):
            SolutionToken.decode(token.encode())
        ok = SolutionToken.create(NONCE, 0, 100, {}, rsw_proof="ab" * 256)
        self.assertEqual("ab" * 256, SolutionToken.decode(ok.encode()).rsw_proof)

    def test_telemetry_json_is_compact(self):
        token = SolutionToken.create(NONCE, 7, 100, {"b": 1, "a": [True, None]})
        body = base64.b64decode(token.encode()).decode("ascii")
        segments = body.split(".")
        self.assertEqual('{"b":1,"a":[true,null]}', segments[3])

    def test_byte_ceiling_on_decode(self):
        token = SolutionToken.create(NONCE, 1, 100, {"big": "x" * 40000})
        with self.assertRaises(DecodeError):
            SolutionToken.decode(token.encode())


if __name__ == "__main__":
    unittest.main()
