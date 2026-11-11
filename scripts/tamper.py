#!/usr/bin/env python3
"""Flip one byte inside a signed bundle to show that integrity checking works.

    python3 scripts/tamper.py out/qwen3.airlock
    -> out/qwen3.tampered.airlock

The manifest and its signature are copied byte for byte, so the ONLY difference
is one flipped byte in model.gguf. The signature still verifies (it was never
touched) but the sha256 of model.gguf no longer matches the signed manifest, so
the import must be refused.
"""
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
FLIP_OFFSET = 4096
MODEL_NAME = "model.gguf"
MEMBERS = ("manifest.json", "manifest.sig")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def flip_byte(path, offset=FLIP_OFFSET):
    """Flip one byte in `path` at `offset`. Returns (offset, old, new)."""
    size = os.path.getsize(path)
    if size == 0:
        raise ValueError("cannot tamper with an empty file: %s" % path)
    pos = offset if offset < size else size - 1
    with open(path, "r+b") as f:
        f.seek(pos)
        old = f.read(1)
        if not old:
            raise ValueError("cannot read byte at %d of %s" % (pos, path))
        old_val = old[0]
        new_val = (old_val ^ 0xFF)
        f.seek(pos)
        f.write(bytes([new_val]))
        f.flush()
        os.fsync(f.fileno())
    return pos, old_val, new_val


def tamper(bundle, out_path=None, offset=FLIP_OFFSET):
    """Create a tampered copy of `bundle`. Returns a dict describing the change."""
    if not os.path.isfile(bundle):
        raise IOError("bundle not found: %s" % bundle)
    base = os.path.basename(bundle)
    name = os.path.splitext(base)[0]
    if out_path is None:
        if not os.path.isdir(OUT):
            os.makedirs(OUT)
        out_path = os.path.join(OUT, name + ".tampered.airlock")

    work = tempfile.mkdtemp(prefix="airlock-tamper-")
    try:
        with tarfile.open(bundle, "r:") as tar:
            names = [m.name for m in tar.getmembers() if m.isfile()]
            if MODEL_NAME not in names:
                raise ValueError("%s does not contain %s" % (bundle, MODEL_NAME))
            tar.extractall(work)

        model_path = os.path.join(work, MODEL_NAME)
        before_sha = sha256_file(model_path)
        pos, old_val, new_val = flip_byte(model_path, offset)
        after_sha = sha256_file(model_path)

        # rebuild with the original member order; manifest + signature untouched
        with tarfile.open(out_path, "w") as out:
            for arc in names:
                out.add(os.path.join(work, arc), arcname=arc)

        manifest_sha = None
        sig_sha = None
        for member, key in (("manifest.json", "manifest_sha"), ("manifest.sig", "sig_sha")):
            p = os.path.join(work, member)
            if os.path.isfile(p):
                value = sha256_file(p)
                if key == "manifest_sha":
                    manifest_sha = value
                else:
                    sig_sha = value

        return {
            "source": os.path.abspath(bundle),
            "output": os.path.abspath(out_path),
            "file": MODEL_NAME,
            "offset": pos,
            "old_byte": old_val,
            "new_byte": new_val,
            "sha256_before": before_sha,
            "sha256_after": after_sha,
            "manifest_sha256": manifest_sha,
            "manifest_sig_sha256": sig_sha,
            "members": names,
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__.strip())
        return 2
    bundle = argv[0]
    out_path = argv[1] if len(argv) > 1 else None
    try:
        info = tamper(bundle, out_path)
    except (IOError, OSError, ValueError, tarfile.TarError) as e:
        print("tamper failed: %s" % e)
        return 1
    print("tampered bundle written : %s" % info["output"])
    print("changed file            : %s" % info["file"])
    print("flipped byte            : offset %d  0x%02x -> 0x%02x"
          % (info["offset"], info["old_byte"], info["new_byte"]))
    print("model sha256 before     : %s" % info["sha256_before"])
    print("model sha256 after      : %s" % info["sha256_after"])
    print("manifest sha256         : %s (unchanged)" % (info["manifest_sha256"] or "-"))
    print("manifest.sig sha256     : %s (unchanged)" % (info["manifest_sig_sha256"] or "-"))
    print("the signature still verifies, but model.gguf no longer matches it -> import must be refused")
    return 0


if __name__ == "__main__":
    sys.exit(main())
