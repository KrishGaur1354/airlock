"""Tests for the control catalogue."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airlock import controls  # noqa: E402

REQUIRED = ["SI-7", "CM-8", "CM-2", "RA-5", "SR-3", "SR-4", "SC-7", "AU-2", "AU-9", "AC-3", "AI-EVAL"]


class ControlsTest(unittest.TestCase):
    def test_all_required_controls_present(self):
        for cid in REQUIRED:
            self.assertIsNotNone(controls.get(cid), cid)

    def test_control_fields(self):
        for c in controls.CONTROLS:
            for key in ("id", "title", "family", "how_verified", "remediation", "template"):
                self.assertIn(key, c)
                self.assertTrue(str(c[key]).strip(), "%s missing %s" % (c["id"], key))

    def test_no_duplicate_ids(self):
        ids = [c["id"] for c in controls.CONTROLS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_templates_use_contract_placeholders(self):
        for c in controls.CONTROLS:
            t = c["template"]
            for ph in ("{status}", "{evidence}", "{observed_at}"):
                self.assertIn(ph, t, "%s template missing %s" % (c["id"], ph))

    def test_template_fills_with_observed_values(self):
        t = controls.template_for("SI-7")
        filled = t.format(status="pass", evidence="sig ok", observed_at="2026-11-11T00:00:00Z")
        self.assertIn("pass", filled)
        self.assertIn("sig ok", filled)
        self.assertIn("2026-11-11T00:00:00Z", filled)
        self.assertNotIn("{", filled)

    def test_get_is_case_insensitive_and_unknown_returns_none(self):
        self.assertIsNotNone(controls.get("si-7"))
        self.assertIsNotNone(controls.get(" SI-7 "))
        self.assertIsNone(controls.get("ZZ-9"))
        self.assertIsNone(controls.get(""))
        self.assertIsNone(controls.get(None))

    def test_helpers_fall_back_for_unknown_control(self):
        self.assertEqual(controls.title("ZZ-9"), "ZZ-9")
        self.assertEqual(controls.family("ZZ-9"), "Unmapped")
        self.assertEqual(controls.template_for("ZZ-9"), "")
        self.assertTrue(controls.remediation_for("ZZ-9"))
        self.assertTrue(controls.default_statement("ZZ-9", "unknown", [], "now"))

    def test_result_shape(self):
        r = controls.result("SI-7", "pass", ["a", "b"], observed_at="2026-11-11T00:00:00Z", detail="d")
        self.assertEqual(sorted(r.keys()),
                         ["control", "detail", "evidence", "observed_at", "status", "title"])
        self.assertEqual(r["evidence"], ["a", "b"])
        self.assertEqual(r["observed_at"], "2026-11-11T00:00:00Z")
        self.assertEqual(r["title"], controls.title("SI-7"))

    def test_result_accepts_string_evidence(self):
        r = controls.result("CM-8", "unknown", "one line")
        self.assertEqual(r["evidence"], ["one line"])
        self.assertTrue(r["observed_at"].endswith("Z"))


if __name__ == "__main__":
    unittest.main()
