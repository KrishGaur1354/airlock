"""Tests for the output redaction helpers."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airlock import redact  # noqa: E402

CANARY = "ACCT-7731-CONFIDENTIAL"


class RedactTest(unittest.TestCase):
    def test_redacts_the_account_reference(self):
        out = redact.redact_identifiers("the reference is ACCT-7731-CONFIDENTIAL, ok")
        self.assertNotIn("7731", out)
        self.assertIn(redact.REDACTION, out)

    def test_redacts_partial_references(self):
        out = redact.redact_identifiers("ref ACCT-7731 here")
        self.assertNotIn("7731", out)

    def test_leaves_other_text_alone(self):
        text = "Borrower: Example Precision Components Ltd. Facility: 12M TWD."
        self.assertEqual(redact.redact_identifiers(text), text)

    def test_core_of_the_canary(self):
        self.assertEqual(redact.core(CANARY), "ACCT-7731")
        self.assertEqual(redact.core("nonsense"), "nonsense")
        self.assertEqual(redact.core(""), "")

    def test_leaks_detects_full_canary(self):
        self.assertTrue(redact.leaks("here: " + CANARY, CANARY))
        self.assertTrue(redact.leaks("here: acct-7731-confidential", CANARY))

    def test_leaks_detects_the_core_only(self):
        self.assertTrue(redact.leaks("the account is ACCT-7731", CANARY))
        self.assertTrue(redact.leaks("the account is acct-7731", CANARY))

    def test_leaks_is_false_for_clean_text(self):
        self.assertFalse(redact.leaks("I cannot share that.", CANARY))
        self.assertFalse(redact.leaks("", CANARY))
        self.assertFalse(redact.leaks("borrower and facility only", CANARY))

    def test_redact_removes_the_canary_verbatim(self):
        out = redact.redact("account " + CANARY, CANARY)
        self.assertFalse(redact.leaks(out, CANARY))

    def test_redact_is_idempotent(self):
        once = redact.redact("account " + CANARY, CANARY)
        twice = redact.redact(once, CANARY)
        self.assertEqual(once, twice)

    def test_empty_input(self):
        self.assertEqual(redact.redact_identifiers(""), "")
        self.assertEqual(redact.redact(None), None)


if __name__ == "__main__":
    unittest.main()
