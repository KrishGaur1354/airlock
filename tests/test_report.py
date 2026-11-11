"""Tests for POA&M generation and the SSP / POA&M HTML renderers."""
import datetime
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airlock import controls, report  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


class PoamTest(unittest.TestCase):
    def test_all_pass_gives_no_items(self):
        self.assertEqual(report.poam_items(load("evidence.sample.json")), [])

    def test_tampered_gives_one_item_per_open_finding(self):
        items = report.poam_items(load("evidence.tampered.json"), today="2026-11-11")
        self.assertEqual(len(items), 2)
        by_control = dict((i["control"], i) for i in items)
        self.assertIn("SI-7", by_control)
        self.assertIn("RA-5", by_control)
        for it in items:
            self.assertEqual(sorted(it.keys()),
                             ["control", "id", "milestone_date", "remediation", "status", "weakness"])
            self.assertEqual(it["status"], "open")
            self.assertTrue(it["weakness"].strip())
            self.assertTrue(it["remediation"].strip())
            self.assertRegex(it["milestone_date"], r"^\d{4}-\d{2}-\d{2}$")

    def test_milestone_is_30_days_after_today(self):
        items = report.poam_items(load("evidence.tampered.json"), today="2026-11-11")
        for it in items:
            self.assertEqual(it["milestone_date"], "2026-12-11")
        items = report.poam_items(load("evidence.tampered.json"), today="2026-01-15")
        self.assertEqual(items[0]["milestone_date"], "2026-02-14")

    def test_milestone_uses_today_when_none_given(self):
        items = report.poam_items(load("evidence.tampered.json"))
        want = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
        self.assertEqual(items[0]["milestone_date"], want)

    def test_ids_are_unique_and_ordered(self):
        items = report.poam_items(load("evidence.tampered.json"))
        ids = [i["id"] for i in items]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids[0], "POAM-001")

    def test_weakness_mentions_the_control(self):
        items = report.poam_items(load("evidence.tampered.json"))
        for it in items:
            self.assertIn(it["control"], it["weakness"])

    def test_empty_evidence_is_safe(self):
        self.assertEqual(report.poam_items({}), [])
        self.assertEqual(report.poam_items(None), [])


class SspTest(unittest.TestCase):
    def setUp(self):
        self.ev = load("evidence.sample.json")

    def test_renders_html_document(self):
        out = report.render_ssp(self.ev)
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("</html>", out)

    def test_is_self_contained_no_cdn(self):
        out = report.render_ssp(self.ev)
        self.assertNotIn("http://", out)
        self.assertNotIn("https://", out)
        self.assertNotIn("<script", out.lower())

    def test_contains_every_control_and_status(self):
        out = report.render_ssp(self.ev)
        for c in self.ev["controls"]:
            self.assertIn(c["control"], out)
        self.assertIn("Satisfied", out)

    def test_templates_are_filled_with_observed_values(self):
        out = report.render_ssp(self.ev)
        self.assertIn("2026-11-11T11:29:52Z", out)
        self.assertIn("manifest.sig verified against pinned ed25519 public key", out)
        self.assertNotIn("{status}", out)
        self.assertNotIn("{evidence}", out)
        self.assertNotIn("{observed_at}", out)

    def test_custom_statement_is_used(self):
        out = report.render_ssp(self.ev, statements={"SI-7": "Custom SI-7 statement at {observed_at} ({status})"})
        self.assertIn("Custom SI-7 statement at 2026-11-11T11:29:52Z (pass)", out)

    def test_missing_statement_falls_back_to_catalogue_template(self):
        out = report.render_ssp(self.ev, statements={"SI-7": "only this one"})
        tpl = controls.template_for("CM-8")
        self.assertIn(tpl.split(".")[0][:40], out)

    def test_unknown_control_uses_plain_default(self):
        ev = {"generated": "2026-01-01T00:00:00Z", "bundle": {}, "device": {}, "audit": {},
              "summary": {}, "controls": [{"control": "ZZ-9", "title": "Odd", "status": "fail",
                                          "evidence": ["nope"], "observed_at": "2026-01-01T00:00:00Z",
                                          "detail": "weird"}]}
        out = report.render_ssp(ev)
        self.assertIn("ZZ-9", out)
        for ph in ("{status}", "{evidence}", "{observed_at}"):
            self.assertNotIn(ph, out)

    def test_unknown_placeholder_does_not_raise(self):
        out = report.render_ssp(self.ev, statements={"SI-7": "value {nope} and {status}"})
        self.assertIn("value", out)
        self.assertIn("pass", out)

    def test_braces_in_statement_do_not_raise(self):
        out = report.render_ssp(self.ev, statements={"SI-7": "literal { braces } here"})
        self.assertIn("literal", out)


class PoamRenderTest(unittest.TestCase):
    def test_renders_items(self):
        items = report.poam_items(load("evidence.tampered.json"), today="2026-11-11")
        out = report.render_poam(items)
        self.assertTrue(out.startswith("<!DOCTYPE html>"))
        self.assertIn("POAM-001", out)
        self.assertIn("SI-7", out)
        self.assertIn("2026-12-11", out)
        self.assertNotIn("http://", out)

    def test_empty_list_renders_no_findings(self):
        out = report.render_poam([])
        self.assertIn("No open findings", out)


if __name__ == "__main__":
    unittest.main()
