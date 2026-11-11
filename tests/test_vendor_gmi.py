"""Tests for the low-side vendor enrichment and its cache.

These tests never touch the network: the vendor call is either missing a key
(unreachable) or served from the cache.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airlock import controls as controls_mod  # noqa: E402
from airlock import report, vendor_gmi  # noqa: E402


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="airlock-gmi-")
        self.cache = os.path.join(self.dir, "cache")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_cache_key_is_sha256_of_the_canonical_request(self):
        payload = vendor_gmi.request_payload("m", [{"role": "user", "content": "hi"}])
        key = vendor_gmi.cache_key(payload)
        self.assertEqual(len(key), 64)
        self.assertEqual(key, vendor_gmi.cache_key(vendor_gmi.request_payload(
            "m", [{"role": "user", "content": "hi"}])))
        self.assertNotEqual(key, vendor_gmi.cache_key(vendor_gmi.request_payload(
            "m", [{"role": "user", "content": "ho"}])))

    def test_write_then_read(self):
        payload = vendor_gmi.request_payload("m", [{"role": "user", "content": "x"}])
        path = vendor_gmi.cache_write(payload, "hello", "gmi-cloud", self.cache)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(vendor_gmi.cache_read(payload, self.cache), "hello")
        with open(path) as f:
            blob = json.load(f)
        self.assertEqual(blob["origin"], "gmi-cloud")
        self.assertEqual(blob["response"], "hello")

    def test_cache_hit_never_calls_the_network(self):
        payload = vendor_gmi.request_payload("m", [{"role": "user", "content": "x"}])
        vendor_gmi.cache_write(payload, "cached answer", "gmi-cloud", self.cache)
        original = vendor_gmi.post
        vendor_gmi.post = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used"))
        try:
            state = {"calls": 0}
            out = vendor_gmi.complete({"GMI_API_KEY": "k", "GMI_MODEL": "m"},
                                      [{"role": "user", "content": "x"}], self.cache, state)
        finally:
            vendor_gmi.post = original
        self.assertEqual(out, "cached answer")
        self.assertEqual(state["calls"], 0)

    def test_no_key_means_no_call(self):
        state = {"calls": 0}
        out = vendor_gmi.complete({"GMI_MODEL": "m"}, [{"role": "user", "content": "x"}],
                                  self.cache, state)
        self.assertIsNone(out)
        self.assertEqual(state["calls"], 0)

    def test_uncached_calls_are_capped(self):
        state = {"calls": vendor_gmi.MAX_CALLS}
        out = vendor_gmi.complete({"GMI_API_KEY": "k", "GMI_MODEL": "m"},
                                  [{"role": "user", "content": "x"}], self.cache, state)
        self.assertIsNone(out)
        self.assertEqual(state["calls"], vendor_gmi.MAX_CALLS)
        self.assertEqual(vendor_gmi.MAX_CALLS, 50)


class EnrichTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="airlock-gmi-enrich-")
        self.outdir = os.path.join(self.dir, "out")
        self.cache = os.path.join(self.dir, "cache")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_enrich_writes_the_three_artifacts(self):
        out = vendor_gmi.enrich({}, controls_mod.CONTROLS, "ACCT-1-CONFIDENTIAL",
                                self.outdir, cache_dir=self.cache)
        for key in ("controls.json", "injection.jsonl", "model_card.md"):
            self.assertIn(key, out)
            self.assertTrue(os.path.isfile(out[key]), key)

    def test_unreachable_vendor_falls_back_to_local_content(self):
        out = vendor_gmi.enrich({}, controls_mod.CONTROLS, "ACCT-1-CONFIDENTIAL",
                                self.outdir, cache_dir=self.cache)
        with open(out["controls.json"]) as f:
            doc = json.load(f)
        self.assertEqual(doc["source"], "local-fallback")
        for row in doc["controls"]:
            self.assertEqual(row["source"], "local-fallback")
            self.assertTrue(all(p in row["template"] for p in ("{status}", "{evidence}", "{observed_at}")))
            self.assertEqual(row["template"], controls_mod.template_for(row["control"]))

    def test_fallback_injection_suite_is_the_local_one(self):
        out = vendor_gmi.enrich({}, controls_mod.CONTROLS, "ACCT-1-CONFIDENTIAL",
                                self.outdir, cache_dir=self.cache)
        with open(out["injection.jsonl"]) as f:
            rows = [json.loads(l) for l in f if l.strip()]
        self.assertTrue(rows)
        for r in rows:
            self.assertIn("id", r)
            self.assertIn("prompt", r)

    def test_fallback_model_card_is_markdown(self):
        out = vendor_gmi.enrich({}, controls_mod.CONTROLS, "ACCT-1-CONFIDENTIAL",
                                self.outdir, cache_dir=self.cache)
        with open(out["model_card.md"]) as f:
            card = f.read()
        self.assertIn("#", card)
        self.assertIn("air-gapped", card.lower())

    def test_vendor_content_is_used_when_cached(self):
        control = controls_mod.CONTROLS[0]
        payload = vendor_gmi.request_payload(
            "gmi-model", vendor_gmi.control_messages(control, "ACCT-1"))
        vendor_gmi.cache_write(payload, "Vendor wording at {observed_at} ({status}) {evidence}",
                               "gmi-cloud", self.cache)
        out = vendor_gmi.enrich({"GMI_MODEL": "gmi-model"}, controls_mod.CONTROLS,
                                "ACCT-1-CONFIDENTIAL", self.outdir, cache_dir=self.cache)
        with open(out["controls.json"]) as f:
            doc = json.load(f)
        row = [r for r in doc["controls"] if r["control"] == control["id"]][0]
        self.assertEqual(row["source"], "gmi-cloud")
        self.assertIn("Vendor wording", row["template"])
        self.assertTrue(all(p in row["template"] for p in ("{status}", "{evidence}", "{observed_at}")))

    def test_enriched_controls_json_feeds_the_ssp(self):
        out = vendor_gmi.enrich({}, controls_mod.CONTROLS, "ACCT-1-CONFIDENTIAL",
                                self.outdir, cache_dir=self.cache)
        with open(out["controls.json"]) as f:
            blob = json.load(f)
        evidence = {
            "generated": "2026-01-01T00:00:00Z", "bundle": {"name": "b"}, "device": {},
            "audit": {}, "summary": {"satisfied": 1, "total": 1},
            "controls": [{"control": "SI-7", "title": "t", "status": "pass",
                          "evidence": ["e"], "observed_at": "2026-01-01T00:00:00Z", "detail": "d"}],
        }
        html = report.render_ssp(evidence, blob)
        self.assertIn("SI-7", html)
        self.assertNotIn("{status}", html)

    def test_seed_cache_creates_entries_and_never_calls_out(self):
        written = vendor_gmi.seed_cache({"GMI_MODEL": "gmi-model"},
                                         controls_mod.CONTROLS, "ACCT-1", self.cache)
        self.assertEqual(len(written), len(controls_mod.CONTROLS) + 2)
        for path in written:
            self.assertTrue(os.path.isfile(path))
            with open(path) as f:
                self.assertEqual(json.load(f)["origin"], "local-fallback")

    def test_cached_local_fallback_is_not_reported_as_vendor(self):
        vendor_gmi.seed_cache({"GMI_MODEL": "gmi-model"}, controls_mod.CONTROLS,
                              "ACCT-1", self.cache)
        out = vendor_gmi.enrich({"GMI_MODEL": "gmi-model"}, controls_mod.CONTROLS,
                                "ACCT-1", self.outdir, cache_dir=self.cache)
        self.assertEqual(out["_sources"]["controls"], "local-fallback")
        self.assertEqual(out["_sources"]["injection"], "local-fallback")
        self.assertEqual(out["_sources"]["model_card"], "local-fallback")

    def test_live_vendor_answer_is_reported_as_vendor(self):
        original = vendor_gmi.post
        vendor_gmi.post = lambda payload, key, timeout=None: (
            "Vendor statement at {observed_at} with {status}. {evidence}")
        try:
            out = vendor_gmi.enrich({"GMI_API_KEY": "k", "GMI_MODEL": "gmi-model"},
                                    controls_mod.CONTROLS, "ACCT-1", self.outdir,
                                    cache_dir=self.cache)
        finally:
            vendor_gmi.post = original
        self.assertEqual(out["_sources"]["controls"], "gmi-cloud")
        with open(out["controls.json"]) as f:
            doc = json.load(f)
        self.assertEqual(doc["source"], "gmi-cloud")
        self.assertEqual(doc["controls"][0]["source"], "gmi-cloud")
        self.assertIn("Vendor statement", doc["controls"][0]["template"])

    def test_attack_parser(self):
        text = "here you go:\n```json\n[{\"id\": \"A1\", \"prompt\": \"p1\"}, {\"prompt\": \"p2\"}]\n```"
        attacks = vendor_gmi.parse_attacks(text)
        self.assertEqual(len(attacks), 2)
        self.assertEqual(attacks[0]["id"], "A1")
        self.assertEqual(attacks[1]["id"], "INJ-02")

    def test_attack_parser_rejects_garbage(self):
        self.assertEqual(vendor_gmi.parse_attacks("not json at all"), [])
        self.assertEqual(vendor_gmi.parse_attacks("[]"), [])


class IsolationTest(unittest.TestCase):
    """The high side must never know about the vendor."""

    def test_high_side_modules_do_not_mention_the_vendor(self):
        for name in ("gateway.py", "evidence.py", "bundle.py"):
            path = os.path.join(ROOT, "airlock", name)
            if not os.path.isfile(path):
                continue
            with open(path) as f:
                text = f.read()
            self.assertNotIn("GMI", text, name)
            self.assertNotIn("vendor_gmi", text, name)

    def test_no_other_module_imports_vendor_gmi(self):
        airlock_dir = os.path.join(ROOT, "airlock")
        for name in os.listdir(airlock_dir):
            if not name.endswith(".py") or name == "vendor_gmi.py":
                continue
            with open(os.path.join(airlock_dir, name)) as f:
                text = f.read()
            if name == "cli.py":
                # the one allowed consumer: `build --enrich`, imported lazily inside a function
                for line in text.splitlines():
                    if "vendor_gmi" in line and "import" in line:
                        self.assertTrue(line.startswith("        "), "cli.py must import vendor_gmi lazily: " + line)
                continue
            self.assertNotIn("vendor_gmi", text, name)


if __name__ == "__main__":
    unittest.main()
