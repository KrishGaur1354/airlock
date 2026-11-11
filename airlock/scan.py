"""Vulnerability scan of the bundle artifacts.

A missing scanner is NOT an error: the result is recorded as
status="unavailable" with criticals=None, which the RA-5 collector turns into
an "unknown" control and a POA&M entry. We never invent a clean result.

    scan(path) -> {"status": "unavailable"|"ok", "tool", "criticals": int|None, "detail"}
"""
import json
import os
import shutil
import subprocess
import time

TIMEOUT = 300


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _count_criticals(trivy_json):
    """Count CRITICAL findings in a trivy JSON report."""
    count = 0
    for result in trivy_json.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            sev = str(vuln.get("Severity", "")).upper()
            if sev == "CRITICAL":
                count += 1
    return count


def _scan_with_trivy(trivy, path):
    try:
        out = subprocess.check_output(
            [trivy, "fs", "--quiet", "--format", "json", "--scanners", "vuln", path],
            stderr=subprocess.STDOUT, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"status": "unavailable", "tool": "trivy", "criticals": None,
                "detail": "trivy timed out after %ds" % TIMEOUT}
    except (OSError, subprocess.CalledProcessError) as e:
        detail = e.output.decode("utf-8", "replace")[:400] if getattr(e, "output", None) else str(e)
        return {"status": "unavailable", "tool": "trivy", "criticals": None,
                "detail": "trivy failed: %s" % detail.strip()}
    try:
        report = json.loads(out.decode("utf-8"))
    except ValueError as e:
        return {"status": "unavailable", "tool": "trivy", "criticals": None,
                "detail": "trivy output was not JSON: %s" % e}
    criticals = _count_criticals(report)
    return {"status": "ok", "tool": "trivy", "criticals": criticals,
            "detail": "trivy fs %s: %d critical finding(s)" % (os.path.basename(path), criticals)}


def scan(path):
    """Scan `path` for vulnerabilities. Never raises; never fakes a clean result."""
    trivy = shutil.which("trivy")
    if not trivy:
        return {"status": "unavailable", "tool": None, "criticals": None,
                "detail": "no vulnerability scanner on PATH (trivy not found); "
                          "scan not performed and no result is claimed"}
    if not path or not os.path.exists(path):
        return {"status": "unavailable", "tool": "trivy", "criticals": None,
                "detail": "scan target does not exist: %s" % path}
    result = _scan_with_trivy(trivy, path)
    result["scanned_at"] = _now()
    return result


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog="airlock.scan")
    p.add_argument("path")
    p.add_argument("-o", "--output", default=None)
    args = p.parse_args(argv)
    result = scan(args.path)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print("wrote " + args.output)
    else:
        print(text)
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
