"""Tests for the SBOM generator and the vulnerability scan wrapper."""
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airlock import sbom, scan  # noqa: E402


def write_fake_trivy(directory, payload):
    """Create a fake trivy executable that prints `payload` as JSON."""
    path = os.path.join(directory, "trivy")
    with open(path, "w") as f:
        f.write("#!/bin/sh\ncat <<'EOF'\n" + payload + "\nEOF\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class SbomTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="airlock-sbom-")
        self.model = os.path.join(self.dir, "model.gguf")
        with open(self.model, "wb") as f:
            f.write(b"GGUF" + b"\x00" * 4096)
        self.meta = {"file": "model.gguf", "family": "qwen3", "params": "1.7b",
                     "quant": "Q4_K_M", "license": "apache-2.0", "source": "ollama:qwen3:1.7b"}

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_generate_is_cyclonedx(self):
        bom = sbom.generate(self.model, self.meta)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        self.assertIn("components", bom)
        self.assertIn("metadata", bom)

    def test_model_component_records_hash_licence_and_origin(self):
        bom = sbom.generate(self.model, self.meta)
        comp = [c for c in bom["components"] if c.get("type") == "machine-learning-model"][0]
        with open(self.model, "rb") as fh:
            want = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(comp["hashes"][0]["content"], want)
        self.assertEqual(comp["hashes"][0]["alg"], "SHA-256")
        self.assertEqual(comp["licenses"][0]["license"]["id"], "apache-2.0")
        props = dict((p["name"], p["value"]) for p in comp["properties"])
        self.assertEqual(props["airlock:family"], "qwen3")
        self.assertEqual(props["airlock:quant"], "Q4_K_M")
        self.assertEqual(props["airlock:source"], "ollama:qwen3:1.7b")

    def test_metadata_component_mirrors_the_model(self):
        bom = sbom.generate(self.model, self.meta)
        self.assertEqual(bom["metadata"]["component"]["type"], "machine-learning-model")

    def test_labelled_as_lite(self):
        bom = sbom.generate(self.model, self.meta)
        props = dict((p["name"], p["value"]) for p in bom["properties"])
        self.assertEqual(props["airlock:shape"], "CycloneDX-lite")

    def test_json_serialisable(self):
        bom = sbom.generate(self.model, self.meta)
        self.assertTrue(json.loads(json.dumps(bom)))

    def test_missing_file_does_not_crash(self):
        bom = sbom.generate(os.path.join(self.dir, "nope.gguf"), self.meta)
        self.assertEqual(bom["bomFormat"], "CycloneDX")


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="airlock-scan-")
        self.file = os.path.join(self.dir, "model.gguf")
        with open(self.file, "wb") as f:
            f.write(b"x" * 1024)
        self.old_path = os.environ.get("PATH", "")

    def tearDown(self):
        os.environ["PATH"] = self.old_path
        shutil.rmtree(self.dir, ignore_errors=True)

    def _without_trivy(self):
        os.environ["PATH"] = os.path.join(self.dir, "empty")
        if not os.path.isdir(os.environ["PATH"]):
            os.makedirs(os.environ["PATH"])

    def test_missing_scanner_is_unavailable_not_an_error(self):
        self._without_trivy()
        r = scan.scan(self.file)
        self.assertEqual(r["status"], "unavailable")
        self.assertIsNone(r["criticals"])
        self.assertIn("trivy", r["detail"])
        self.assertIn("tool", r)

    def test_result_shape(self):
        r = scan.scan(self.file)
        for key in ("status", "tool", "criticals", "detail"):
            self.assertIn(key, r)

    def test_trivy_result_is_parsed(self):
        write_fake_trivy(self.dir, json.dumps({
            "Results": [{"Vulnerabilities": [
                {"Severity": "CRITICAL", "VulnerabilityID": "CVE-1"},
                {"Severity": "CRITICAL", "VulnerabilityID": "CVE-2"},
                {"Severity": "HIGH", "VulnerabilityID": "CVE-3"}]}]}))
        os.environ["PATH"] = self.dir + os.pathsep + self.old_path
        r = scan.scan(self.file)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["tool"], "trivy")
        self.assertEqual(r["criticals"], 2)

    def test_clean_scan_reports_zero(self):
        write_fake_trivy(self.dir, json.dumps({"Results": [{"Vulnerabilities": []}]}))
        os.environ["PATH"] = self.dir + os.pathsep + self.old_path
        r = scan.scan(self.file)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["criticals"], 0)

    def test_missing_target_is_unavailable(self):
        write_fake_trivy(self.dir, json.dumps({"Results": []}))
        os.environ["PATH"] = self.dir + os.pathsep + self.old_path
        r = scan.scan(os.path.join(self.dir, "missing.gguf"))
        self.assertEqual(r["status"], "unavailable")
        self.assertIsNone(r["criticals"])


if __name__ == "__main__":
    unittest.main()
