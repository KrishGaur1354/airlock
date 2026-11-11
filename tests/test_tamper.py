"""Integration test for the tamper demo: one flipped byte must break the import."""
import hashlib
import importlib.util
import os
import shutil
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airlock import bundle  # noqa: E402

spec = importlib.util.spec_from_file_location("airlock_tamper",
                                              os.path.join(ROOT, "scripts", "tamper.py"))
tamper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tamper)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


class TamperTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="airlock-tamper-test-")
        cls.gguf = os.path.join(cls.dir, "model.gguf")
        with open(cls.gguf, "wb") as f:
            f.write(b"GGUF" + bytes(bytearray(range(256))) * 40)  # ~10 KB
        cls.bundle = os.path.join(cls.dir, "test.airlock")
        bundle.build(cls.gguf, cls.bundle, name="tamper-test", version="0.0.1",
                     family="qwen3", params="1.7b", quant="Q4_K_M",
                     license_="apache-2.0", source="ollama:qwen3:1.7b")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _members(self, path):
        out = {}
        with tarfile.open(path, "r:") as tar:
            for m in tar.getmembers():
                if m.isfile():
                    out[m.name] = tar.extractfile(m).read()
        return out

    def test_tampered_bundle_exists_next_to_the_original(self):
        out = os.path.join(self.dir, "out")
        os.makedirs(out, exist_ok=True)
        info = tamper.tamper(self.bundle, os.path.join(out, "test.tampered.airlock"))
        self.assertTrue(os.path.isfile(info["output"]))
        self.assertTrue(info["output"].endswith("test.tampered.airlock"))

    def test_manifest_and_signature_are_untouched(self):
        info = tamper.tamper(self.bundle, os.path.join(self.dir, "t1.airlock"))
        before = self._members(self.bundle)
        after = self._members(info["output"])
        self.assertEqual(sha256_bytes(before["manifest.json"]),
                         sha256_bytes(after["manifest.json"]))
        self.assertEqual(sha256_bytes(before["manifest.sig"]),
                         sha256_bytes(after["manifest.sig"]))

    def test_exactly_one_byte_is_flipped_in_the_model(self):
        info = tamper.tamper(self.bundle, os.path.join(self.dir, "t2.airlock"))
        before = self._members(self.bundle)["model.gguf"]
        after = self._members(info["output"])["model.gguf"]
        self.assertEqual(len(before), len(after))
        diffs = [i for i in range(len(before)) if before[i] != after[i]]
        self.assertEqual(len(diffs), 1)
        self.assertEqual(diffs[0], info["offset"])
        self.assertEqual(info["offset"], 4096)
        self.assertNotEqual(before[4096], after[4096])

    def test_members_are_preserved(self):
        info = tamper.tamper(self.bundle, os.path.join(self.dir, "t3.airlock"))
        self.assertEqual(sorted(self._members(self.bundle)), sorted(self._members(info["output"])))

    def test_verification_fails_on_the_tampered_bundle(self):
        out = os.path.join(self.dir, "t4.airlock")
        tamper.tamper(self.bundle, out)
        ok, checks, _manifest = bundle.verify(out)
        self.assertFalse(ok)
        bad = [c for c in checks if not c["ok"] and c["artifact"] == "model.gguf"]
        self.assertTrue(bad, "expected a failing sha256 check for model.gguf")

    def test_original_bundle_still_verifies(self):
        ok, _checks, _manifest = bundle.verify(self.bundle)
        self.assertTrue(ok)

    def test_cli_prints_what_changed(self):
        import subprocess
        out = os.path.join(self.dir, "t5.airlock")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "tamper.py"),
                            self.bundle, out], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = p.stdout.decode()
        self.assertEqual(p.returncode, 0)
        self.assertIn("flipped byte", text)
        self.assertIn("model.gguf", text)
        self.assertIn("sha256", text)


if __name__ == "__main__":
    unittest.main()
