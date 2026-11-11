"""Tests for the hash-chained audit log: clean chain, flipped byte, deleted line."""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from airlock import audit  # noqa: E402


def p(s):
    return audit.sha256_hex(s)


class AuditTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="airlock-audit-test-")
        self.path = os.path.join(self.dir, "audit.jsonl")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_append_creates_file_and_entry_shape(self):
        e = audit.append(self.path, "analyst", p("prompt"), p("response"), "ok")
        self.assertTrue(os.path.exists(self.path))
        for key in ("ts", "user", "prompt_sha256", "response_sha256", "status", "prev_hash", "hash"):
            self.assertIn(key, e)
        self.assertEqual(e["prev_hash"], audit.GENESIS)
        self.assertEqual(len(e["hash"]), 64)
        self.assertTrue(e["ts"].endswith("Z"))
        with open(self.path) as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["hash"], e["hash"])

    def test_chain_links_and_verify_clean(self):
        for i in range(6):
            e = audit.append(self.path, "u%d" % i, p("p%d" % i), p("r%d" % i), "ok")
            if i == 0:
                self.assertEqual(e["prev_hash"], audit.GENESIS)
            else:
                self.assertNotEqual(e["prev_hash"], audit.GENESIS)
        ok, count, bad = audit.verify(self.path)
        self.assertTrue(ok)
        self.assertEqual(count, 6)
        self.assertIsNone(bad)

    def test_prev_hash_links_to_previous_entry(self):
        first = audit.append(self.path, "u", p("p"), p("r"), "ok")
        second = audit.append(self.path, "u", p("p"), p("r"), "ok")
        self.assertEqual(second["prev_hash"], first["hash"])
        self.assertNotEqual(first["hash"], second["hash"])

    def test_flipped_byte_is_detected(self):
        for i in range(4):
            audit.append(self.path, "u%d" % i, p("p%d" % i), p("r%d" % i), "ok")
        with open(self.path, "r+b") as f:
            data = bytearray(f.read())
            # flip one bit inside the last entry's hash hex
            pos = data.rindex(b'"hash":"') + 9
            data[pos] = ord("a") if data[pos] != ord("a") else ord("b")
            f.seek(0)
            f.write(data)
        ok, count, bad = audit.verify(self.path)
        self.assertFalse(ok)
        self.assertEqual(bad, 3)
        self.assertLess(count, 4)

    def test_deleted_line_is_detected(self):
        for i in range(5):
            audit.append(self.path, "u%d" % i, p("p%d" % i), p("r%d" % i), "ok")
        with open(self.path) as f:
            lines = f.readlines()
        del lines[2]
        with open(self.path, "w") as f:
            f.writelines(lines)
        ok, count, bad = audit.verify(self.path)
        self.assertFalse(ok)
        self.assertEqual(bad, 2)

    def test_missing_file_verifies_empty(self):
        ok, count, bad = audit.verify(self.path)
        self.assertTrue(ok)
        self.assertEqual(count, 0)
        self.assertIsNone(bad)

    def test_tail_returns_last_entries(self):
        for i in range(8):
            audit.append(self.path, "u%d" % i, p("p%d" % i), p("r%d" % i), "ok")
        t = audit.tail(self.path, 3)
        self.assertEqual(len(t), 3)
        self.assertEqual([e["user"] for e in t], ["u5", "u6", "u7"])
        self.assertEqual(audit.tail(self.path, 0), [])
        self.assertEqual(len(audit.tail(self.path, 99)), 8)

    def test_tail_hashes_matches_summary(self):
        for i in range(3):
            audit.append(self.path, "u%d" % i, p("p%d" % i), p("r%d" % i), "ok")
        s = audit.summary(self.path)
        self.assertTrue(s["ok"])
        self.assertEqual(s["entries"], 3)
        self.assertEqual(len(s["tail"]), 3)
        self.assertEqual(s["tail"][-1], audit.tail(self.path, 1)[0]["hash"])

    def test_canonical_json_is_sorted_and_compact(self):
        self.assertEqual(audit.canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_entry_hash_ignores_own_hash_field(self):
        e = {"ts": "t", "user": "u", "prompt_sha256": "p", "response_sha256": "r",
             "status": "ok", "prev_hash": audit.GENESIS}
        h = audit.entry_hash(audit.GENESIS, e)
        e2 = dict(e)
        e2["hash"] = h
        self.assertEqual(audit.entry_hash(audit.GENESIS, e2), h)

    def test_concurrent_appends_do_not_interleave(self):
        def worker(n):
            for i in range(10):
                audit.append(self.path, "w%d" % n, p("p"), p("r"), "ok")
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ok, count, bad = audit.verify(self.path)
        self.assertTrue(ok)
        self.assertEqual(count, 40)
        with open(self.path) as f:
            for line in f:
                self.assertTrue(line.strip())
                json.loads(line)


class AuditAnchorTest(unittest.TestCase):
    """A hash chain alone cannot see its own tail being removed; the anchor can."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="airlock-audit-anchor-")
        self.path = os.path.join(self.dir, "audit.jsonl")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _fill(self, n):
        for i in range(n):
            audit.append(self.path, "u%d" % i, p("p%d" % i), p("r%d" % i), "ok")

    def test_anchor_is_written_next_to_the_log(self):
        self._fill(3)
        blob = audit.write_anchor(self.path)
        self.assertEqual(blob["count"], 3)
        self.assertTrue(os.path.isfile(self.path + ".anchor"))
        self.assertEqual(audit.read_anchor(self.path)["count"], 3)

    def test_anchored_verify_accepts_an_intact_log(self):
        self._fill(4)
        audit.write_anchor(self.path)
        ok, count, bad, detail = audit.verify_anchored(self.path)
        self.assertTrue(ok, detail)
        self.assertEqual(count, 4)
        self.assertIsNone(bad)

    def test_anchored_verify_detects_tail_truncation(self):
        self._fill(5)
        audit.write_anchor(self.path)
        with open(self.path) as f:
            lines = f.readlines()
        with open(self.path, "w") as f:
            f.writelines(lines[:-2])          # drop the last two entries
        ok, count, bad, detail = audit.verify_anchored(self.path)
        self.assertFalse(ok)
        self.assertIn("truncated", detail)
        self.assertEqual(count, 3)
        # the plain chain check alone would have accepted this log
        self.assertTrue(audit.verify(self.path)[0])

    def test_anchored_verify_detects_a_rewritten_head(self):
        self._fill(3)
        audit.write_anchor(self.path)
        with open(self.path) as f:
            lines = f.readlines()
        first = json.loads(lines[0])
        first["user"] = "someone-else"
        body = dict((k, v) for k, v in first.items() if k != "hash")
        first["hash"] = audit.entry_hash(first["prev_hash"], body)
        lines[0] = json.dumps(first) + "\n"
        with open(self.path, "w") as f:
            f.writelines(lines)
        ok, count, bad, detail = audit.verify_anchored(self.path)
        self.assertFalse(ok)
        self.assertIn("head changed", detail)

    def test_no_anchor_is_not_an_error(self):
        self._fill(2)
        ok, count, bad, detail = audit.verify_anchored(self.path)
        self.assertTrue(ok)
        self.assertEqual(count, 2)
        self.assertIn("no anchor", detail)

    def test_missing_anchor_file_is_handled(self):
        self._fill(2)
        self.assertIsNone(audit.read_anchor(self.path))


if __name__ == "__main__":
    unittest.main()
