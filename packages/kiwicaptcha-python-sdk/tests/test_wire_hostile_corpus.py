"""The shared hostile wire corpus against the Python decoder.

The fixture is expanded by
``packages/kiwicaptcha-php/tests/Fixtures/generate-wire-hostile-corpus.php``
and read byte-for-byte by every hosted SDK suite. The expected
verdicts are the reference decoder's, so a host that drifts fails here
rather than silently accepting a token its peers reject.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from kiwicaptcha.telemetry import score as telemetry_score
from kiwicaptcha.tokens import DecodeError, SolutionToken

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "wire-hostile-corpus.json"
CORPUS = json.loads(FIXTURE.read_text(encoding="utf-8"))
ROWS = CORPUS["vectors"]


def classify(code: str) -> str:
    if code == DecodeError.INVALID_BASE64:
        return "base64"
    if code == DecodeError.INVALID_UTF8:
        return "utf8"
    if code in (DecodeError.INVALID_COUNTER, DecodeError.COUNTER_EXCEEDS_SOLVER_MAXIMUM):
        return "counter"
    if code == DecodeError.INVALID_DURATION:
        return "duration"
    return "malformed"


class WireHostileCorpusTest(unittest.TestCase):
    def test_corpus_is_broad(self) -> None:
        self.assertGreaterEqual(CORPUS["counts"]["total"], 100)


def _make_test(row):
    def test(self: unittest.TestCase) -> None:
        expected = row["expect"]
        if expected["verdict"] == "accept":
            token = SolutionToken.decode(row["raw"])
            self.assertEqual(token.counter, expected["counter"], row["id"])
            self.assertEqual(token.duration_ms, expected["duration_ms"], row["id"])
            self.assertEqual(token.execution_digest, expected["execution_digest"], row["id"])
            self.assertEqual(token.execution_trace, expected["execution_trace"], row["id"])
            self.assertEqual(token.rsw_proof, expected["rsw_proof"], row["id"])
            if "telemetry" in expected:
                actual = json.loads(json.dumps(token.telemetry))
                self.assertEqual(actual, expected["telemetry"], row["id"] + ": telemetry value")
            if "telemetry_score" in expected:
                self.assertEqual(
                    telemetry_score(token.telemetry, token.duration_ms),
                    expected["telemetry_score"],
                    row["id"] + ": telemetry score",
                )
            return

        with self.assertRaises(DecodeError, msg=row["id"] + ": accepted a hostile row") as raised:
            SolutionToken.decode(row["raw"])
        if expected["class"] != "any":
            self.assertEqual(classify(raised.exception.code), expected["class"], row["id"])

    return test


for _row in ROWS:
    _name = "test_" + re.sub(r"[^A-Za-z0-9_]", "_", _row["id"])
    setattr(WireHostileCorpusTest, _name, _make_test(_row))


if __name__ == "__main__":
    unittest.main()
