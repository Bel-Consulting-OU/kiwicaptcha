"""The shared challenge-signature corpus against the Python verifier.

The fixture is expanded by the PHP generator and read byte-for-byte by
every hosted SDK suite. Each row carries a stored v2 record, the
presented challenge, the verifier secret and tenant, and the reference
verdict.
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from kiwicaptcha.canonical import verify_record_signature
from kiwicaptcha.records import ChallengeRecord

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "wire-signature-corpus.json"
CORPUS = json.loads(FIXTURE.read_text(encoding="utf-8"))
ROWS = CORPUS["vectors"]


class WireSignatureCorpusTest(unittest.TestCase):
    def test_corpus_is_broad(self) -> None:
        self.assertGreaterEqual(CORPUS["counts"]["total"], 40)


def _make_test(row):
    def test(self: unittest.TestCase) -> None:
        record = ChallengeRecord.from_array(row["record"])
        self.assertEqual(record.challenge, row["challenge"], row["id"])
        verified = verify_record_signature(
            record, row["verify_secret"], row["verify_tenant"]
        )
        self.assertEqual(verified, row["expect"] == "accept", row["id"])

    return test


for _row in ROWS:
    _name = "test_" + re.sub(r"[^A-Za-z0-9_]", "_", _row["id"])
    setattr(WireSignatureCorpusTest, _name, _make_test(_row))


if __name__ == "__main__":
    unittest.main()
