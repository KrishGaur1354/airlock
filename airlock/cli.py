import argparse
import sys

from airlock import bundle, config, signing


def _mark(ok):
    return "✔" if ok else "✘"


def print_checks(checks):
    w = max([len(c["check"]) for c in checks] + [10])
    for c in checks:
        print("  %s %-*s  %s" % (_mark(c["ok"]), w, c["check"], c["detail"]))


def cmd_keygen(a):
    created = signing.keygen()
    print(("generated" if created else "exists") + " keys/airlock.pub fingerprint " + signing.fingerprint())
    return 0


def cmd_hash(a):
    for p in a.paths:
        print(bundle.sha256_file(p) + "  " + p)
    return 0


def cmd_build(a):
    m = bundle.build(a.gguf, a.output, target=a.target, name=a.name, version=a.version,
                     family=a.family, params=a.params, quant=a.quant, license_=a.license,
                     source=a.source)
    print("built %s (%d artifacts, signer %s)" % (a.output, len(m["artifacts"]), m["signer_fingerprint"]))
    for art in m["artifacts"]:
        print("  %-18s %12d  %s..." % (art["path"], art["bytes"], art["sha256"][:16]))
    return 0


def cmd_verify(a):
    ok, checks, m = bundle.verify(a.bundle)
    print_checks(checks)
    bad = [c["artifact"] for c in checks if not c["ok"] and c["artifact"]]
    print("VERIFIED" if ok else "VERIFICATION FAILED" + (": " + ", ".join(bad) if bad else ""))
    return 0 if ok else 1


def cmd_import(a):
    conf = config.load()
    backend = a.backend or conf.get("AIRLOCK_BACKEND", "ollama")
    ok, checks, m = bundle.import_bundle(a.bundle, backend=backend, model_name=a.name)
    print_checks(checks)
    bad = [c["artifact"] or c["check"] for c in checks if not c["ok"]]
    print("IMPORTED" if ok else "IMPORT REFUSED: " + ", ".join(bad))
    return 0 if ok else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="airlock")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("keygen").set_defaults(fn=cmd_keygen)
    s = sub.add_parser("hash"); s.add_argument("paths", nargs="+"); s.set_defaults(fn=cmd_hash)
    s = sub.add_parser("build")
    s.add_argument("--gguf", required=True); s.add_argument("-o", "--output", required=True)
    s.add_argument("--target", default="jetson-orin-nano"); s.add_argument("--name", default="qwen3-airlock")
    s.add_argument("--version", default="0.1.0"); s.add_argument("--family", default="qwen3")
    s.add_argument("--params", default="1.7b"); s.add_argument("--quant", default=None)
    s.add_argument("--license", default="apache-2.0"); s.add_argument("--source", default="unknown")
    s.set_defaults(fn=cmd_build)
    s = sub.add_parser("verify"); s.add_argument("bundle"); s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("import"); s.add_argument("bundle"); s.add_argument("--backend", default=None)
    s.add_argument("--name", default=None); s.set_defaults(fn=cmd_import)
    a = p.parse_args(argv)
    if not getattr(a, "fn", None):
        p.print_help()
        return 2
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
