"""Tests for the OSCAL-shaped assessment results builder."""
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airlock import oscal  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


class OscalTest(unittest.TestCase):
    def setUp(self):
        self.doc = oscal.build(load("evidence.sample.json"))

    def test_top_level_shape(self):
        self.assertIn("assessment-results", self.doc)
        ar = self.doc["assessment-results"]
        for key in ("uuid", "metadata", "results"):
            self.assertIn(key, ar)

    def test_uuid_is_uuid4_shaped(self):
        self.assertTrue(UUID_RE.match(self.doc["assessment-results"]["uuid"]))

    def test_results_findings_and_observations(self):
        results = self.doc["assessment-results"]["results"]
        self.assertTrue(results)
        findings = results[0]["findings"]
        self.assertEqual(len(findings), 11)
        for f in findings:
            self.assertTrue(UUID_RE.match(f["uuid"]))
            self.assertTrue(f["observations"])
            for o in f["observations"]:
                self.assertTrue(UUID_RE.match(o["uuid"]))

    def test_target_id_is_control_id_and_state_is_mapped(self):
        findings = self.doc["assessment-results"]["results"][0]["findings"]
        for f in findings:
            target = f["target"]
            self.assertEqual(target["target-id"], f["title"].split(" ")[0])
            self.assertIn(target["status"]["state"], ("satisfied", "not-satisfied"))
        by_id = dict((f["target"]["target-id"], f) for f in findings)
        self.assertEqual(by_id["SI-7"]["target"]["status"]["state"], "satisfied")

    def test_tampered_fixture_maps_fail_and_unknown_to_not_satisfied(self):
        doc = oscal.build(load("evidence.tampered.json"))
        findings = doc["assessment-results"]["results"][0]["findings"]
        by_id = dict((f["target"]["target-id"], f) for f in findings)
        self.assertEqual(by_id["SI-7"]["target"]["status"]["state"], "not-satisfied")
        self.assertEqual(by_id["SI-7"]["target"]["status"]["reason"], "fail")
        self.assertEqual(by_id["RA-5"]["target"]["status"]["state"], "not-satisfied")
        self.assertEqual(by_id["RA-5"]["target"]["status"]["reason"], "unknown")

    def test_labelled_oscal_shaped(self):
        text = json.dumps(self.doc)
        self.assertIn("OSCAL-shaped", text)
        props = self.doc["assessment-results"]["metadata"]["props"]
        self.assertEqual(props[0]["value"], "OSCAL-shaped")

    def test_observations_carry_evidence(self):
        findings = self.doc["assessment-results"]["results"][0]["findings"]
        by_id = dict((f["target"]["target-id"], f) for f in findings)
        obs = by_id["SI-7"]["observations"][0]
        self.assertTrue(obs["relevant-evidence"])
        self.assertIn("manifest.sig verified", obs["relevant-evidence"][0]["description"])

    def test_json_serialisable(self):
        text = oscal.to_json(load("evidence.sample.json"))
        self.assertTrue(json.loads(text))

    def test_empty_evidence_is_safe(self):
        doc = oscal.build({})
        self.assertIn("assessment-results", doc)
        self.assertEqual(doc["assessment-results"]["results"][0]["findings"], [])

    def test_findings_helper(self):
        self.assertEqual(len(oscal.findings(load("evidence.sample.json"))), 11)


if __name__ == "__main__":
    unittest.main()
