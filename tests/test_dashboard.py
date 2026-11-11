"""Tests for the dashboard: self-contained, no CDN, and in sync with the fixtures."""
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

DASH = os.path.join(ROOT, "dashboard", "index.html")


def read_dash():
    with open(DASH, encoding="utf-8") as f:
        return f.read()


def embedded(html, element_id):
    m = re.search(r'<script type="application/json" id="%s">(.*?)</script>' % element_id,
                  html, re.S)
    if not m:
        return None
    return json.loads(m.group(1).replace("<\\/", "</"))


class DashboardTest(unittest.TestCase):
    def setUp(self):
        self.html = read_dash()

    def test_exists_and_is_html(self):
        self.assertTrue(os.path.isfile(DASH))
        self.assertIn("<!DOCTYPE html>", self.html)

    def test_no_cdn_or_external_resources(self):
        for bad in ("http://", "https://", "//cdn", "cdn.", "googleapis", "unpkg", "jsdelivr"):
            self.assertNotIn(bad, self.html, "external reference: %s" % bad)

    def test_polls_evidence_every_two_seconds(self):
        self.assertIn("/evidence.json", self.html)
        self.assertIn("POLL_MS = 2000", self.html)
        self.assertIn("setInterval(poll, POLL_MS)", self.html)

    def test_banner_strings(self):
        self.assertIn("ACCREDITATION EVIDENCE:", self.html)
        self.assertIn("controls satisfied", self.html)
        self.assertIn("si7_failed", self.html)

    def test_has_control_grid_device_audit_and_exports(self):
        self.assertIn('id="controls"', self.html)
        self.assertIn('id="device"', self.html)
        self.assertIn('id="audit"', self.html)
        self.assertIn('id="audit-tail"', self.html)
        self.assertIn("/export/ssp.html", self.html)
        self.assertIn("/export/poam.html", self.html)
        self.assertIn("/export/assessment-results.json", self.html)

    def test_chat_box_posts_with_api_key_header(self):
        self.assertIn('id="apikey"', self.html)
        self.assertIn("X-Airlock-Key", self.html)
        self.assertIn("/v1/chat", self.html)
        self.assertIn('method: "POST"', self.html)

    def test_mock_query_supported(self):
        self.assertIn("mock", self.html)
        self.assertIn("mock-sample", self.html)
        self.assertIn("mock-tampered", self.html)

    def test_embedded_mock_data_matches_fixtures(self):
        sample = embedded(self.html, "mock-sample")
        tampered = embedded(self.html, "mock-tampered")
        with open(os.path.join(HERE, "fixtures", "evidence.sample.json")) as f:
            self.assertEqual(sample, json.load(f))
        with open(os.path.join(HERE, "fixtures", "evidence.tampered.json")) as f:
            self.assertEqual(tampered, json.load(f))

    def test_dark_theme(self):
        self.assertIn("--bg: #0b0e14", self.html)

    def test_vanilla_js_only(self):
        self.assertNotIn("<script src", self.html)
        self.assertNotIn("import ", self.html)


if __name__ == "__main__":
    unittest.main()
