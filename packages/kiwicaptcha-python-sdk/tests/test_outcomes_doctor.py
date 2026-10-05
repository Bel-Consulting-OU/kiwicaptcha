"""The outcomes mapping conformance, the doctor checks and the settings."""

import io
import sys
import contextlib
import unittest

sys.path.insert(0, ".")

from tests.support import load_outcome_vectors

from kiwicaptcha.config import Settings
from kiwicaptcha.doctor import run_checks
from kiwicaptcha.outcomes import (
    CHANNEL_AUTHENTICATION_FAILURE,
    CHANNEL_AUTHENTICATION_SUCCESS,
    CHANNEL_CONFIRMED_ABUSE,
    CHANNEL_CONFIRMED_LEGITIMATE,
    CHANNEL_PROTECTED_ACTION_FAILURE,
    CHANNEL_PROTECTED_ACTION_SUCCESS,
    MemoryOutcomeSink,
    Outcome,
    OutcomeHandle,
    OutcomeHandleDimension,
    OutcomeMap,
    OutcomesClient,
    VERSION,
)
from kiwicaptcha.verify import Verifier

_DIMENSION_BY_NAME = {d.value: d for d in OutcomeHandleDimension}

_CHANNEL_BY_VALUE = {
    12: CHANNEL_CONFIRMED_LEGITIMATE,
    8: CHANNEL_PROTECTED_ACTION_SUCCESS,
    10: CHANNEL_AUTHENTICATION_SUCCESS,
    11: CHANNEL_AUTHENTICATION_FAILURE,
    9: CHANNEL_PROTECTED_ACTION_FAILURE,
    13: CHANNEL_CONFIRMED_ABUSE,
}


class OutcomeVectorsTest(unittest.TestCase):
    """The cross-language vector corpus at protocol/risk-v1."""

    def setUp(self):
        self.vectors = load_outcome_vectors()

    def test_mapping_conformance(self):
        sink = MemoryOutcomeSink(namespace=self.vectors["namespace"])
        client = OutcomesClient(sink)
        handles = self.vectors["handles"]
        self.assertEqual(1, VERSION)
        for vector in self.vectors["vectors"]:
            with self.subTest(vector=vector["outcome"], handle=vector["handle"]):
                outcome = Outcome(vector["outcome"])
                dimension = _DIMENSION_BY_NAME[vector["handle"]["dimension"]]
                identifier = vector["handle"]["id"]
                # The factory validates the identifier shape: an
                # identifier rejection raises at construction.
                factories = {
                    OutcomeHandleDimension.NONCE: OutcomeHandle.nonce,
                    OutcomeHandleDimension.DECISION_ID: OutcomeHandle.decision_id,
                    OutcomeHandleDimension.PRINCIPAL: OutcomeHandle.principal,
                    OutcomeHandleDimension.TARGET: OutcomeHandle.target,
                    OutcomeHandleDimension.SESSION: OutcomeHandle.session,
                    OutcomeHandleDimension.AGENT: OutcomeHandle.agent,
                }
                try:
                    handle = factories[dimension](identifier)
                except ValueError:
                    self.assertFalse(vector["accepted"])
                    self.assertEqual("identifier", vector.get("reject"))
                    continue
                mapping = OutcomeMap.for_outcome(outcome)
                if not vector["accepted"]:
                    self.assertEqual("handle", vector.get("reject"))
                    with self.assertRaises(ValueError):
                        client.report(outcome, handle)
                    continue
                receipt = client.report(outcome, handle)
                self.assertEqual(
                    _CHANNEL_BY_VALUE[vector["channel_value"]], mapping.channel
                )
                self.assertEqual(vector["server_confirmed"], mapping.server_confirmed)
                self.assertEqual(
                    vector["may_subtract_risk"], mapping.may_subtract_risk
                )
                self.assertEqual(
                    vector["writes_abuse_mark"], mapping.writes_abuse_mark
                )
                self.assertEqual(vector["mark_kind"], mapping.mark_kind())
                if vector["mark_key"] is not None:
                    self.assertEqual(
                        vector["mark_key"],
                        sink.mark_key(dimension.mark_dimension(), identifier),
                    )
                    self.assertEqual(1, receipt.mark_count)
                    self.assertIn(vector["mark_key"], sink.marks)
                if vector["ledger_action"] is not None:
                    self.assertTrue(mapping.has_ledger_action())
                else:
                    self.assertFalse(mapping.has_ledger_action())

    def test_ledger_confirm_statuses(self):
        sink = MemoryOutcomeSink(namespace="d")
        decision = self.vectors["handles"]["decision"]
        # A nonce/decisionId handle without a registered ledger entry
        # answers 0; with one it confirms into the polarity of the row.
        client = OutcomesClient(sink)
        receipt = client.report(Outcome.CONFIRMED_LEGITIMATE, OutcomeHandle.decision_id(decision))
        self.assertEqual(0, receipt.status)
        sink.register_outcome(decision)
        receipt = client.report(Outcome.CONFIRMED_LEGITIMATE, OutcomeHandle.decision_id(decision))
        self.assertEqual(1, receipt.status)
        receipt = client.report(Outcome.CHARGEBACK, OutcomeHandle.decision_id(decision))
        self.assertEqual(-1, receipt.status)
        # forget clears the mark keys only.
        pseudonym = self.vectors["handles"]["principal"]
        client.report(Outcome.FRAUD_CONFIRMED, OutcomeHandle.principal(pseudonym))
        key = sink.mark_key("principal", pseudonym)
        self.assertIn(key, sink.marks)
        self.assertEqual(1, client.forget(OutcomeHandle.principal(pseudonym)))
        self.assertNotIn(key, sink.marks)

    def test_raw_identifier_refused(self):
        with self.assertRaises(ValueError):
            OutcomeHandle.principal("raw@example.com")
        with self.assertRaises(ValueError):
            OutcomeHandle.nonce("has:colon")


class SettingsTest(unittest.TestCase):
    def test_defaults_and_guards(self):
        settings = Settings(secret="k" * 32)
        self.assertEqual("memory://", settings.store)
        self.assertEqual("standard", settings.profile)
        with self.assertRaises(ValueError):
            Settings(secret="short")
        with self.assertRaises(ValueError):
            Settings(secret="k" * 32, profile="argon128")

    def test_build_verifier(self):
        settings = Settings(secret="k" * 32, store="memory://", scopes=("login",))
        verifier = settings.build_verifier()
        self.assertIsInstance(verifier, Verifier)


class DoctorTest(unittest.TestCase):
    def test_all_checks_pass(self):
        results = run_checks(
            "k" * 32, "memory://", ("login", "comment"), "standard"
        )
        self.assertEqual(4, len(results))
        for result in results:
            self.assertTrue(result.ok, f"{result.name}: {result.detail}")

    def test_failures_reported(self):
        results = run_checks("short", "memory://", ("bad scope!",), "standard")
        by_name = {r.name: r for r in results}
        self.assertFalse(by_name["settings"].ok)
        self.assertFalse(by_name["scopes"].ok)

    def test_cli_exit_code(self):
        from kiwicaptcha import doctor

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = doctor.main(
                ["--secret", "k" * 32, "--store", "memory://",
                 "--scopes", "login", "--profile", "standard"]
            )
        self.assertEqual(0, code)
        self.assertIn("every check passed", buffer.getvalue())
        with contextlib.redirect_stdout(buffer):
            code = doctor.main(["--secret", "short"])
        self.assertEqual(1, code)


if __name__ == "__main__":
    unittest.main()
