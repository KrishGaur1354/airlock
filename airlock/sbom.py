"""CycloneDX-lite SBOM for the bundle.

Uses syft when it is on PATH, otherwise builds the inventory from the signed
manifest metadata. Either way the result is a CycloneDX 1.5 document that names
the machine-learning model, its licence, its origin and the SHA-256 of the
weight file.

    generate(model_path, model_meta) -> dict
"""
import hashlib
import json
import os
import shutil
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHUNK = 1024 * 1024
SPEC_VERSION = "1.5"
BOM_FORMAT = "CycloneDX"


def _sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(CHUNK)
                if not b:
                    break
                h.update(b)
    except (IOError, OSError):
        return None
    return h.hexdigest()


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _model_component(model_path, model_meta):
    """The ML model as a CycloneDX component with its digest and licence."""
    meta = model_meta or {}
    name = os.path.basename(model_path) if model_path else meta.get("file", "model.gguf")
    digest = _sha256_file(model_path) if model_path else None
    comp = {
        "type": "machine-learning-model",
        "bom-ref": "model:%s" % name,
        "name": name,
        "version": meta.get("params") or meta.get("version") or "unknown",
    }
    if digest:
        comp["hashes"] = [{"alg": "SHA-256", "content": digest}]
    lic = meta.get("license")
    if lic:
        comp["licenses"] = [{"license": {"id": lic}}]
    props = []
    for key in ("family", "params", "quant", "source", "license", "file"):
        if meta.get(key):
            props.append({"name": "airlock:%s" % key, "value": str(meta[key])})
    if props:
        comp["properties"] = props
    return comp


def _syft_bom(model_path):
    """Run syft if available; return (bom, detail)."""
    syft = shutil.which("syft")
    if not syft:
        return None, "syft not found on PATH"
    target = model_path if model_path and os.path.isfile(model_path) else ROOT
    try:
        out = subprocess.check_output([syft, "scan", target, "-o", "cyclonedx-json"],
                                      stderr=subprocess.STDOUT, timeout=180)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return None, "syft failed: %s" % e
    try:
        bom = json.loads(out.decode("utf-8"))
    except ValueError as e:
        return None, "syft output was not JSON: %s" % e
    if not isinstance(bom, dict):
        return None, "syft output was not a JSON object"
    return bom, "generated with syft"


def generate(model_path, model_meta=None):
    """Build the CycloneDX-lite SBOM for a model file."""
    meta = dict(model_meta or {})
    meta.setdefault("file", os.path.basename(model_path) if model_path else "model.gguf")
    component = _model_component(model_path, meta)

    bom, detail = _syft_bom(model_path)
    if bom is None:
        bom = {
            "bomFormat": BOM_FORMAT,
            "specVersion": SPEC_VERSION,
            "version": 1,
            "metadata": {
                "timestamp": _now(),
                "tools": [{"vendor": "airlock", "name": "airlock.sbom", "version": "0.1.0"}],
                "component": component,
            },
            "components": [component],
        }
    else:
        bom.setdefault("bomFormat", BOM_FORMAT)
        bom.setdefault("specVersion", SPEC_VERSION)
        bom.setdefault("version", 1)
        md = bom.setdefault("metadata", {})
        md.setdefault("timestamp", _now())
        md.setdefault("tools", []).append({"vendor": "airlock", "name": "airlock.sbom", "version": "0.1.0"})
        md["component"] = component
        comps = bom.setdefault("components", [])
        if not any(c.get("bom-ref") == component.get("bom-ref") for c in comps):
            comps.append(component)

    bom["properties"] = [
        {"name": "airlock:shape", "value": "CycloneDX-lite"},
        {"name": "airlock:sbom-source", "value": detail},
    ]
    return bom


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="airlock.sbom")
    p.add_argument("model")
    p.add_argument("--family", default="")
    p.add_argument("--params", default="")
    p.add_argument("--quant", default="")
    p.add_argument("--license", default="")
    p.add_argument("--source", default="")
    p.add_argument("-o", "--output", default=None)
    args = p.parse_args(argv)
    meta = {"family": args.family, "params": args.params, "quant": args.quant,
            "license": args.license, "source": args.source}
    bom = generate(args.model, meta)
    text = json.dumps(bom, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print("wrote " + args.output)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
