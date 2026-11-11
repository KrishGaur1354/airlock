"""Contract tests for the shared evidence fixtures.

The fixtures are the contract every other module is built against, so they are
checked first: shape of evidence.json, control result shape, summary maths and
the two scenarios named in OPENCODE_TASKS.md (all-pass, SI-7 fail + RA-5
unknown).
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

FIXTURES = os.path.join(HERE, "fixtures")
CONTROL_IDS = ["SI-7", "CM-8", "CM-2", "RA-5", "SR-3", "SR-4", "SC-7",
               "AU-2", "AU-9", "AC-3", "AI-EVAL"]


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


class FixtureShapeTest(unittest.TestCase):
    def setUp(self):
        self.sample = load("evidence.sample.json")
        self.tampered = load("evidence.tampered.json")

    def test_top_level_keys(self):
        for name, ev in (("sample", self.sample), ("tampered", self.tampered)):
            for key in ("generated", "bundle", "device", "controls", "audit", "summary"):
                self.assertIn(key, ev, name)

    def test_bundle_block(self):
        for ev in (self.sample, self.tampered):
            b = ev["bundle"]
            for key in ("name", "version", "signer_fingerprint"):
                self.assertIn(key, b)
            self.assertIn("target", b)
            self.assertIn("arch", b["target"])

    def test_device_block(self):
        for ev in (self.sample, self.tampered):
            d = ev["device"]
            for key in ("arch", "l4t_release", "ram_mb", "backend", "model"):
                self.assertIn(key, d)

    def test_control_results_shape(self):
        for ev in (self.sample, self.tampered):
            for c in ev["controls"]:
                for key in ("control", "title", "status", "evidence", "observed_at", "detail"):
                    self.assertIn(key, c)
                self.assertIn(c["status"], ("pass", "fail", "unknown"))
                self.assertIsInstance(c["evidence"], list)
                self.assertTrue(c["evidence"], "evidence must not be empty")
                self.assertTrue(c["observed_at"].endswith("Z"))
                self.assertRegex(c["observed_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_audit_block(self):
        for ev in (self.sample, self.tampered):
            a = ev["audit"]
            self.assertIsInstance(a["ok"], bool)
            self.assertIsInstance(a["entries"], int)
            self.assertIsInstance(a["tail"], list)
            for h in a["tail"]:
                self.assertEqual(len(h), 64)
                int(h, 16)  # must be hex

    def test_control_ids_complete(self):
        for ev in (self.sample, self.tampered):
            ids = [c["control"] for c in ev["controls"]]
            self.assertEqual(ids, CONTROL_IDS)

    def test_summary_matches_controls(self):
        for ev in (self.sample, self.tampered):
            passed = len([c for c in ev["controls"] if c["status"] == "pass"])
            self.assertEqual(ev["summary"]["satisfied"], passed)
            self.assertEqual(ev["summary"]["total"], len(ev["controls"]))
            si7 = [c for c in ev["controls"] if c["control"] == "SI-7"][0]
            self.assertEqual(ev["summary"]["si7_failed"], si7["status"] == "fail")


class FixtureScenarioTest(unittest.TestCase):
    def test_sample_all_pass(self):
        ev = load("evidence.sample.json")
        self.assertEqual(ev["summary"], {"satisfied": 11, "total": 11, "si7_failed": False})
        for c in ev["controls"]:
            self.assertEqual(c["status"], "pass", c["control"])

    def test_tampered_si7_fail_ra5_unknown(self):
        ev = load("evidence.tampered.json")
        by_id = dict((c["control"], c) for c in ev["controls"])
        self.assertEqual(by_id["SI-7"]["status"], "fail")
        self.assertEqual(by_id["RA-5"]["status"], "unknown")
        self.assertEqual(ev["summary"]["satisfied"], 9)
        self.assertEqual(ev["summary"]["total"], 11)
        self.assertTrue(ev["summary"]["si7_failed"])


if __name__ == "__main__":
    unittest.main()
