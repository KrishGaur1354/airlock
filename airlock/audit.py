"""Append-only, hash-chained audit log (NIST 800-53 AU-2 / AU-9).

Each line of the JSONL log is one entry:

    {ts, user, prompt_sha256, response_sha256, status, prev_hash, hash}

The first entry chains from the GENESIS value ("0" * 64). Every later entry
chains from the hash of its predecessor:

    hash = sha256_hex(prev_hash + canonical_json(entry_without_hash))

Raw prompts and responses are never stored: only their digests. That keeps the
log usable as evidence (AU-9) without turning it into a transcript store.

Module API
    append(path, user, prompt_sha256, response_sha256, status) -> entry
    verify(path) -> (ok, count, bad_index)
    tail(path, n=5) -> [entry]
"""
import errno
import hashlib
import json
import os
import threading
import time

GENESIS = "0" * 64
LOCK = threading.Lock()


def canonical_json(x):
    """Contract canonical form: sorted keys, no spaces."""
    return json.dumps(x, sort_keys=True, separators=(",", ":"))


def sha256_hex(text):
    if not isinstance(text, bytes):
        text = text.encode("utf-8")
    return hashlib.sha256(text).hexdigest()


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def entry_hash(prev_hash, entry):
    """Digest of an entry (without its own "hash" field) chained to prev_hash."""
    body = dict((k, v) for k, v in entry.items() if k != "hash")
    return sha256_hex(prev_hash + canonical_json(body))


def _ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise


def read_entries(path):
    """Return (entries, bad_index). Stops at the first line that is not a JSON object."""
    entries = []
    bad_index = None
    if not os.path.exists(path):
        return entries, bad_index
    with open(path, "r") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            bad_index = len(entries)
            break
        if not isinstance(obj, dict):
            bad_index = len(entries)
            break
        entries.append(obj)
    return entries, bad_index


def _last_hash(path):
    """Hash of the last entry, or GENESIS for an empty/new log."""
    entries, bad = read_entries(path)
    if bad is not None or not entries:
        return GENESIS
    last = entries[-1]
    h = last.get("hash")
    if not isinstance(h, str) or len(h) != 64:
        return GENESIS
    return h


def append(path, user, prompt_sha256, response_sha256, status):
    """Append one audit entry and return it. Thread-safe; creates the file if missing."""
    with LOCK:
        _ensure_parent(path)
        prev_hash = _last_hash(path)
        entry = {
            "ts": now_iso(),
            "user": user,
            "prompt_sha256": prompt_sha256,
            "response_sha256": response_sha256,
            "status": status,
            "prev_hash": prev_hash,
        }
        entry["hash"] = entry_hash(prev_hash, entry)
        with open(path, "a") as f:
            f.write(canonical_json(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entry


def verify(path):
    """Verify the hash chain.

    Returns (ok, count, bad_index):
      ok        - True when every entry chains correctly
      count     - number of entries that chained correctly
      bad_index - 0-based index of the first entry that failed, else None
    """
    entries, bad = read_entries(path)
    if bad is not None:
        return False, bad, bad
    prev_hash = GENESIS
    for i, entry in enumerate(entries):
        if entry.get("prev_hash") != prev_hash:
            return False, i, i
        expect = entry_hash(prev_hash, entry)
        if entry.get("hash") != expect:
            return False, i, i
        prev_hash = entry.get("hash")
    return True, len(entries), None


def tail(path, n=5):
    """Return the last n entries (oldest first)."""
    entries, _bad = read_entries(path)
    if n <= 0:
        return []
    return entries[-n:]


def tail_hashes(path, n=5):
    """Return the last n entry hashes (oldest first) for dashboards."""
    return [e.get("hash", "") for e in tail(path, n)]


def summary(path, n=5):
    """Compact audit summary used by evidence.json: {ok, entries, tail}."""
    ok, count, _bad = verify(path)
    return {"ok": ok, "entries": count, "tail": tail_hashes(path, n)}


# ------------------------------------------------------------------ anchor
# A hash chain cannot detect the removal of its own tail: the remaining links
# still line up. The anchor closes that gap by remembering the head hash and
# the entry count observed at a point in time (for example after each evidence
# collection), so a later, shorter log is flagged.
def anchor_path_for(path):
    return path + ".anchor"


def write_anchor(path, anchor_path=None):
    """Record the current head hash and entry count. Returns the anchor dict."""
    ok, count, _bad = verify(path)
    entries, _b = read_entries(path)
    head = entries[0].get("hash", GENESIS) if entries else GENESIS
    blob = {"head": head, "count": count, "chain_ok": ok, "at": now_iso()}
    target = anchor_path or anchor_path_for(path)
    parent = os.path.dirname(os.path.abspath(target))
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
    with open(target, "w") as f:
        json.dump(blob, f, indent=2, sort_keys=True)
    return blob


def read_anchor(path, anchor_path=None):
    """Return the recorded anchor, or None."""
    target = anchor_path or anchor_path_for(path)
    if not os.path.isfile(target):
        return None
    try:
        with open(target) as f:
            blob = json.load(f)
    except (IOError, ValueError):
        return None
    return blob if isinstance(blob, dict) else None


def verify_anchored(path, anchor_path=None):
    """Verify the chain and, when an anchor exists, check it against it.

    Returns (ok, count, bad_index, detail). The detail explains why a log
    that still chains correctly is still refused.
    """
    ok, count, bad = verify(path)
    anchor = read_anchor(path, anchor_path)
    if anchor is None:
        return ok, count, bad, "no anchor recorded"
    entries, _b = read_entries(path)
    head = entries[0].get("hash", GENESIS) if entries else GENESIS
    if anchor.get("head") and head != anchor.get("head"):
        return False, count, 0, "audit head changed: expected %s, found %s" % (
            str(anchor.get("head"))[:12], str(head)[:12])
    if count < int(anchor.get("count", 0)):
        return False, count, bad, "audit log truncated: %d entries, %d were anchored" % (
            count, int(anchor.get("count", 0)))
    if not ok:
        return False, count, bad, "hash chain broken at entry %s" % bad
    return True, count, bad, "hash chain verified against the anchor"
