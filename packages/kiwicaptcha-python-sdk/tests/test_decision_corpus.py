"""The shared decision and authority register.

protocol/decision-v1/corpus.json is read by every server SDK suite and
by the D3.17 cross-SDK campaign. This module is the Python side of the
decision, HTTP status and token authority rows.
"""

import json
import unittest
from pathlib import Path

from kiwicaptcha.decision import _RETRY_CODES, VerifyDecision
from kiwicaptcha.errors import VerifyError, VerifyOutcome
from kiwicaptcha.middleware import _status_for_disposition, resolve_token_values

CORPUS = (
    Path(__file__).resolve().parents[3]
    / "protocol"
    / "decision-v1"
    / "corpus.json"
)


def corpus():
    with CORPUS.open(encoding="utf-8") as handle:
        return json.load(handle)


class DecisionCorpusTest(unittest.TestCase):
    def test_every_wire_code_maps_to_its_registered_disposition(self):
        register = corpus()
        self.assertEqual(
            sorted(register["codes"]),
            sorted(error.value for error in VerifyError),
        )
        for code, disposition in register["codes"].items():
            decision = VerifyDecision.from_outcome(
                VerifyOutcome.invalid(VerifyError(code))
            )
            self.assertFalse(decision.ok)
            self.assertEqual(disposition, decision.disposition, code)
            self.assertEqual(code, decision.error)

    def test_the_retry_table_is_exactly_the_four_transient_codes(self):
        register = corpus()
        self.assertEqual(
            sorted(register["retry_codes"]),
            sorted(_RETRY_CODES),
        )

    def test_the_middleware_status_rows_agree(self):
        register = corpus()
        self.assertEqual(200, register["http"]["allow_status"])
        self.assertEqual(503, register["http"]["retry_status"])
        self.assertEqual(403, register["http"]["deny_status"]["python"])
        self.assertEqual(503, _status_for_disposition("retry"))
        self.assertEqual(403, _status_for_disposition("deny"))

    def test_every_authority_row_resolves_under_reject_on_conflict(self):
        register = corpus()["authority"]
        self.assertEqual("token_source_conflict", register["conflict_code"])
        self.assertEqual("malformed_token", register["missing_code"])
        for row in register["matrix"]:
            token, failure = resolve_token_values(
                row["header"], row["form"], row["query"]
            )
            if row["verdict"] == "verify":
                self.assertIsNone(failure, row["case"])
                self.assertEqual(row["token"], token, row["case"])
            elif row["verdict"] == "conflict":
                self.assertEqual("token_source_conflict", failure, row["case"])
                self.assertIsNone(token, row["case"])
            else:
                self.assertEqual("malformed_token", failure, row["case"])


if __name__ == "__main__":
    unittest.main()
