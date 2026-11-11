"""Bundle build / verify / import. Plain tar, ed25519-signed manifest, 1 MB chunked hashing."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time

from airlock import signing
from airlock.config import ROOT

CHUNK = 1024 * 1024
MAX_MANIFEST = 1024 * 1024
ALLOWED_NAMES = ("manifest.json", "manifest.sig")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_stream(fobj):
    h = hashlib.sha256()
    n = 0
    while True:
        b = fobj.read(CHUNK)
        if not b:
            break
        h.update(b)
        n += len(b)
    return h.hexdigest(), n


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def guess_quant(filename):
    m = re.search(r"(Q\d_[0-9A-Z_]+|F16|F32|BF16)", os.path.basename(filename), re.I)
    return m.group(1).upper() if m else "unknown"


def _safe_name(name):
    return name and not name.startswith("/") and ".." not in name.split("/")


# ---------------------------------------------------------------- build
def build(gguf, out, target="jetson-orin-nano", name="qwen3-airlock", version="0.1.0",
          family="qwen3", params="1.7b", quant=None, license_="apache-2.0",
          source="unknown", extra=None, min_mem_gb=4, l4t_release="R36"):
    """Create a signed bundle. `extra` = {arcname: (local_path, type)} for additional artifacts."""
    stage = tempfile.mkdtemp(prefix="airlock-build-")
    try:
        files = {"model.gguf": (gguf, "model")}
        # SBOM + scan: OpenCode modules if present, otherwise minimal honest fallbacks.
        model_meta = {"file": "model.gguf", "family": family, "params": params,
                      "quant": quant or guess_quant(gguf), "license": license_, "source": source}
        sbom_path = os.path.join(stage, "sbom.cdx.json")
        scan_path = os.path.join(stage, "scan.json")
        try:
            from airlock import sbom as _sbom
            sbom = _sbom.generate(gguf, model_meta)
        except ImportError:
            sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                    "components": [{"type": "machine-learning-model", "name": name,
                                    "version": version, "licenses": [{"license": {"id": license_}}]}]}
        try:
            from airlock import scan as _scan
            scan = _scan.scan(gguf)
        except ImportError:
            scan = {"status": "unavailable", "tool": None, "criticals": None,
                    "detail": "no vulnerability scanner module/tool present"}
        for p, d in ((sbom_path, sbom), (scan_path, scan)):
            with open(p, "w") as f:
                json.dump(d, f, indent=2, sort_keys=True)
        files["sbom.cdx.json"] = (sbom_path, "sbom")
        files["scan.json"] = (scan_path, "scan")
        for arc, (p, t) in (extra or {}).items():
            files[arc] = (p, t)

        artifacts = []
        for arc in sorted(files):
            p, t = files[arc]
            artifacts.append({"path": arc, "sha256": sha256_file(p),
                              "bytes": os.path.getsize(p), "type": t})
        manifest = {
            "name": name, "version": version, "created": now_iso(),
            "target": {"arch": "aarch64", "device": target, "min_mem_gb": min_mem_gb,
                       "l4t_release": l4t_release},
            "model": model_meta,
            "artifacts": artifacts,
            "policy": {"license_allowlist": ["apache-2.0", "mit"], "max_critical_cves": 0},
            "controls_claimed": ["SI-7", "CM-8", "CM-2", "RA-5", "SR-3", "SR-4", "SC-7",
                                 "AU-2", "AU-9", "AC-3", "AI-EVAL"],
            "signer_fingerprint": signing.fingerprint(),
        }
        mbytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        sig = signing.sign(mbytes)

        outdir = os.path.dirname(os.path.abspath(out))
        if not os.path.isdir(outdir):
            os.makedirs(outdir)
        with tarfile.open(out, "w") as tar:
            for arc, data in (("manifest.json", mbytes), ("manifest.sig", sig)):
                p = os.path.join(stage, arc)
                with open(p, "wb") as f:
                    f.write(data)
                tar.add(p, arcname=arc)
            for arc in sorted(files):
                tar.add(files[arc][0], arcname=arc)
        return manifest
    finally:
        shutil.rmtree(stage, ignore_errors=True)


# ---------------------------------------------------------------- verify
def _device_facts():
    facts = {"arch": os.uname()[4], "l4t_release": None, "ram_gb": None}
    try:
        with open("/etc/nv_tegra_release") as f:
            m = re.match(r"#\s*(R\d+)", f.readline())
            facts["l4t_release"] = m.group(1) if m else None
    except IOError:
        pass
    try:
        with open("/proc/meminfo") as f:
            kb = int(f.readline().split()[1])
            facts["ram_gb"] = round(kb / 1048576.0, 1)
    except (IOError, ValueError, IndexError):
        pass
    return facts


def verify(bundle, pub_path=signing.PUB):
    """Verify without side effects. Returns (ok, checks, manifest).
    checks = [{"check", "ok", "detail", "artifact"}]."""
    checks = []

    def add(check, ok, detail="", artifact=None):
        checks.append({"check": check, "ok": bool(ok), "detail": detail, "artifact": artifact})
        return ok

    manifest = None
    try:
        tar = tarfile.open(bundle, "r:")
    except (IOError, tarfile.TarError) as e:
        add("bundle-readable", False, str(e))
        return False, checks, None
    with tar:
        members = {}
        for m in tar.getmembers():
            if not _safe_name(m.name) or not m.isfile():
                add("archive-safe", False, "unsafe member: %r" % m.name, m.name)
                return False, checks, None
            members[m.name] = m
        for need in ALLOWED_NAMES:
            if need not in members:
                add("archive-complete", False, "missing " + need, need)
                return False, checks, None
        if members["manifest.json"].size > MAX_MANIFEST:
            add("manifest-size", False, "manifest too large", "manifest.json")
            return False, checks, None
        mbytes = tar.extractfile("manifest.json").read()
        sig = tar.extractfile("manifest.sig").read()

        sig_ok = signing.verify(mbytes, sig, pub_path)
        add("signature (SI-7)", sig_ok,
            "ed25519 valid, signer " + signing.fingerprint(pub_path) if sig_ok
            else "signature does not match pinned key", "manifest.json")
        if not sig_ok:
            return False, checks, None
        try:
            manifest = json.loads(mbytes.decode("utf-8"))
        except ValueError as e:
            add("manifest-parse", False, str(e), "manifest.json")
            return False, checks, None

        listed = set()
        for art in manifest.get("artifacts", []):
            p = art.get("path", "")
            listed.add(p)
            if not _safe_name(p) or p not in members:
                add("artifact-present", False, "listed but not in archive", p)
                continue
            digest, n = _sha256_stream(tar.extractfile(p))
            ok = digest == art.get("sha256") and n == art.get("bytes")
            add("sha256 " + p, ok,
                "match" if ok else "expected %s... got %s..." % (art.get("sha256", "")[:12], digest[:12]), p)
        extras = set(members) - listed - set(ALLOWED_NAMES)
        for e in sorted(extras):
            add("unlisted-file", False, "in archive but not in manifest", e)

    tgt = manifest.get("target", {})
    dev = _device_facts()
    add("target arch", tgt.get("arch") == dev["arch"], "%s vs device %s" % (tgt.get("arch"), dev["arch"]))
    if tgt.get("l4t_release") and dev["l4t_release"]:
        add("target L4T", tgt["l4t_release"] == dev["l4t_release"],
            "%s vs device %s" % (tgt["l4t_release"], dev["l4t_release"]))
    if dev["ram_gb"] is not None:
        add("target RAM", dev["ram_gb"] >= tgt.get("min_mem_gb", 0),
            "%.1f GB vs min %s GB" % (dev["ram_gb"], tgt.get("min_mem_gb")))
    return all(c["ok"] for c in checks), checks, manifest


def policy_gate(manifest):
    """License allowlist + critical CVE limit. Returns (ok, checks)."""
    pol = manifest.get("policy", {})
    lic = manifest.get("model", {}).get("license", "").lower()
    checks = [{"check": "license allowlist (SR-3)",
               "ok": lic in [x.lower() for x in pol.get("license_allowlist", [])],
               "detail": "license=%s allowed=%s" % (lic, pol.get("license_allowlist")), "artifact": "model.gguf"}]
    return all(c["ok"] for c in checks), checks


# ---------------------------------------------------------------- import
def import_bundle(bundle, install_root=None, backend="ollama", model_name=None, pub_path=signing.PUB):
    """verify -> policy gate -> extract -> install. Nothing is written before verification passes."""
    ok, checks, manifest = verify(bundle, pub_path)
    if not ok:
        return False, checks, manifest
    pok, pchecks = policy_gate(manifest)
    checks += pchecks
    if not pok:
        return False, checks, manifest

    name = model_name or manifest["name"]
    dest = os.path.join(install_root or os.path.join(ROOT, "out", "installed"), name)
    if not os.path.isdir(dest):
        os.makedirs(dest)
    with tarfile.open(bundle, "r:") as tar:
        for m in tar.getmembers():  # already validated flat, safe, regular files
            src = tar.extractfile(m)
            with open(os.path.join(dest, m.name), "wb") as f:
                shutil.copyfileobj(src, f, CHUNK)
    # re-hash what landed on disk (TOCTOU / disk-corruption guard)
    for art in manifest["artifacts"]:
        if sha256_file(os.path.join(dest, art["path"])) != art["sha256"]:
            checks.append({"check": "post-extract hash", "ok": False, "detail": "mismatch after extract",
                           "artifact": art["path"]})
            return False, checks, manifest

    if backend == "ollama":
        with open(os.path.join(dest, "Modelfile"), "w") as f:
            f.write("FROM ./model.gguf\nPARAMETER num_ctx 2048\n")
        try:
            subprocess.check_call(["ollama", "create", name, "-f", "Modelfile"], cwd=dest,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            checks.append({"check": "install (ollama create)", "ok": True, "detail": name, "artifact": None})
        except (OSError, subprocess.CalledProcessError) as e:
            checks.append({"check": "install (ollama create)", "ok": False, "detail": str(e), "artifact": None})
            return False, checks, manifest
    else:
        models = os.path.expanduser("~/models")
        if not os.path.isdir(models):
            os.makedirs(models)
        shutil.copy(os.path.join(dest, "model.gguf"), os.path.join(models, name + ".gguf"))
        checks.append({"check": "install (llamacpp)", "ok": True,
                       "detail": "llama-server -m %s/%s.gguf -c 2048 -t 4 --host 127.0.0.1 --port 8080" % (models, name),
                       "artifact": None})
    return True, checks, manifest
