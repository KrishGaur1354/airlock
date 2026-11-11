import argparse
import os
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
    extra = {}
    if a.enrich:
        # LOW SIDE ONLY: the vendor module is imported here and nowhere on the high side.
        from airlock import controls, evals, vendor_gmi
        conf = config.load()
        for k in ("GMI_API_KEY", "GMI_MODEL"):
            if os.environ.get(k):
                conf[k] = os.environ[k]
        outdir = os.path.join(config.ROOT, "out", "enriched")
        files = vendor_gmi.enrich(conf, controls.CONTROLS, evals.memo_canary(), outdir)
        extra["controls.json"] = (files["controls.json"], "controls")
        extra["injection.jsonl"] = (files["injection.jsonl"], "evals")
        extra["model_card.md"] = (files["model_card.md"], "doc")
    m = bundle.build(a.gguf, a.output, target=a.target, name=a.name, version=a.version,
                     family=a.family, params=a.params, quant=a.quant, license_=a.license,
                     source=a.source, extra=extra)
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
    bundle.save_state(ok, checks, m, a.bundle)
    print_checks(checks)
    bad = [c["artifact"] or c["check"] for c in checks if not c["ok"]]
    print("IMPORTED" if ok else "IMPORT REFUSED: " + ", ".join(bad))
    return 0 if ok else 1


def cmd_evidence(a):
    from airlock import evidence
    ev = evidence.write_all()
    for c in ev["controls"]:
        print("  %s %-8s %-8s %s" % (_mark(c["status"] == "pass"), c["control"], c["status"], c["detail"]))
    s = ev["summary"]
    print("%d/%d controls satisfied%s" % (s["satisfied"], s["total"], "  [SI-7 FAILED]" if s["si7_failed"] else ""))
    return 0


def cmd_eval(a):
    from airlock import evals, gateway, redact
    gw = gateway.Gateway()
    state = bundle.load_state() or {}
    suite = os.path.join(config.ROOT, "out", "installed", (state.get("manifest") or {}).get("name", ""), "injection.jsonl")
    suite = suite if os.path.isfile(suite) else None  # prefer the signed suite shipped in the bundle
    result = evals.run(gw.chat_raw, suite, evals.memo_canary(), filter_fn=redact.redact)
    evals.write(result)
    print("  suite: %s" % (suite or "evals/injection.jsonl (repo default)"))
    print("  %s served replies : %d/%d did not leak the canary (%.0f%%, threshold %.0f%%)" % (
        _mark(evals.verdict(result)), result["passed"], result["total"], result["pct"], evals.PASS_THRESHOLD))
    print("  %s raw model alone: %d/%d (%.0f%%)  failures: %s" % (
        _mark(result["raw_pct"] >= evals.PASS_THRESHOLD), result["raw_passed"], result["total"], result["raw_pct"],
        ", ".join(result["raw_failures"]) or "none"))
    return 0 if evals.verdict(result) else 1


def cmd_serve(a):
    from airlock import gateway
    gateway.serve()
    return 0


def cmd_audit_verify(a):
    from airlock import audit
    ok, n, bad = audit.verify(gateway_audit_path())
    print("%s audit chain: %d entries%s" % (_mark(ok), n, "" if ok else " (first bad entry #%d)" % bad))
    return 0 if ok else 1


def gateway_audit_path():
    from airlock import gateway
    return gateway.AUDIT_PATH


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
    s.add_argument("--enrich", action="store_true", help="low side: add vendor-generated controls/evals/model card")
    s.set_defaults(fn=cmd_build)
    s = sub.add_parser("verify"); s.add_argument("bundle"); s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("import"); s.add_argument("bundle"); s.add_argument("--backend", default=None)
    s.add_argument("--name", default=None); s.set_defaults(fn=cmd_import)
    sub.add_parser("eval").set_defaults(fn=cmd_eval)
    sub.add_parser("evidence").set_defaults(fn=cmd_evidence)
    sub.add_parser("serve").set_defaults(fn=cmd_serve)
    sub.add_parser("audit-verify").set_defaults(fn=cmd_audit_verify)
    a = p.parse_args(argv)
    if not getattr(a, "fn", None):
        p.print_help()
        return 2
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
