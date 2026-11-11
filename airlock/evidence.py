"""Evidence collectors. Every status here comes from something measured or recomputed on this device."""
import json
import os
import threading
import time
import http.client
import socket
import urllib.error
import urllib.request

from airlock import audit, bundle, signing
from airlock.config import ROOT

OUT = os.path.join(ROOT, "out")
TITLES = {
    "SI-7": "Software/firmware integrity", "CM-8": "System component inventory",
    "CM-2": "Baseline configuration", "RA-5": "Vulnerability monitoring and scanning",
    "SR-3": "Supply chain controls (license)", "SR-4": "Provenance",
    "SC-7": "Boundary protection", "AU-2": "Event logging", "AU-9": "Protection of audit information",
    "AC-3": "Access enforcement", "AI-EVAL": "GenAI injection / exfiltration evaluation (NIST AI 600-1)",
}
_CACHE = {"t": 0, "ev": None}
_LOCK = threading.Lock()
TTL = 15


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _r(control, status, detail, evidence):
    return {"control": control, "title": TITLES[control], "status": status,
            "evidence": evidence, "observed_at": now_iso(), "detail": detail}


def _installed_dir(state):
    m = (state or {}).get("manifest") or {}
    d = os.path.join(OUT, "installed", m.get("name", ""))
    return d if os.path.isdir(d) else None


def _json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (IOError, ValueError):
        return None


def _ollama_ps(model):
    try:
        d = json.loads(urllib.request.urlopen("http://127.0.0.1:11434/api/ps", timeout=3).read().decode())
        for m in d.get("models", []):
            if m.get("name", "").startswith(model):
                return m
    except Exception:
        pass
    return None


def _interfaces():
    """Network interfaces visible to THIS process (inside a network namespace it is only 'lo')."""
    try:
        with open("/proc/net/dev") as f:
            return sorted(l.split(":")[0].strip() for l in f.readlines()[2:])
    except IOError:
        return []


class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        http.client.HTTPConnection.__init__(self, "localhost", timeout=5)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(self._path)


def collect_all(gateway=None):
    state = bundle.load_state()
    man = (state or {}).get("manifest") or {}
    checks = (state or {}).get("checks") or []
    dev = bundle._device_facts()
    res = []
    gaps = []
    inst = _installed_dir(state)

    # SI-7: result of the verification performed at import time (signature + every artifact hash)
    if not state:
        res.append(_r("SI-7", "unknown", "no import recorded yet", ["out/state.json"]))
    else:
        bad = [c for c in checks if not c["ok"] and (c["check"].startswith("sha256") or c["check"].startswith("signature")
                                                   or c["check"] in ("unlisted-file", "artifact-present", "archive-safe"))]
        if bad:
            names = ", ".join(sorted(set(str(c["artifact"] or c["check"]) for c in bad)))
            res.append(_r("SI-7", "fail", "integrity failure: " + names, ["out/state.json", state["bundle"]]))
        else:
            res.append(_r("SI-7", "pass", "signature valid; %d artifact hashes match" %
                          len([c for c in checks if c["check"].startswith("sha256")]), ["out/state.json", state["bundle"]]))

    # CM-8: SBOM present + complete model BOM
    model = man.get("model", {})
    arts = dict((a["path"], a) for a in man.get("artifacts", []))
    sbom_ok = inst and os.path.exists(os.path.join(inst, "sbom.cdx.json"))
    bom_ok = all([model.get(k) for k in ("family", "quant", "license", "source")]) and "sha256" in arts.get("model.gguf", {})
    if not state:
        res.append(_r("CM-8", "unknown", "no bundle imported", []))
    elif sbom_ok and bom_ok and model.get("source") != "unknown":
        res.append(_r("CM-8", "pass", "SBOM present; model BOM: %s %s %s from %s, sha256 %s..." % (
            model["family"], model["params"], model["quant"], model["source"], arts["model.gguf"]["sha256"][:12]),
            ["sbom.cdx.json", "manifest.json"]))
    else:
        res.append(_r("CM-8", "fail", "SBOM missing or model BOM incomplete", ["manifest.json"]))

    # CM-2: declared target vs measured device + measured runtime facts
    tgt = man.get("target", {})
    arch_ok = tgt.get("arch") == dev["arch"]
    l4t_ok = tgt.get("l4t_release") == dev["l4t_release"]
    ram_ok = dev["ram_gb"] is not None and dev["ram_gb"] >= tgt.get("min_mem_gb", 0)
    model_name = (gateway.model if gateway else "qwen3-airlock")
    ps = _ollama_ps(model_name)
    runtime = "model not currently loaded" if not ps else "model loaded, %.0f%% of %.1f GB in GPU memory (ollama /api/ps)" % (
        100.0 * ps.get("size_vram", 0) / max(ps.get("size", 1), 1), ps.get("size", 0) / 1e9)
    if not state:
        res.append(_r("CM-2", "unknown", "no bundle target to compare", []))
    else:
        res.append(_r("CM-2", "pass" if (arch_ok and l4t_ok and ram_ok) else "fail",
                      "arch %s, L4T %s, RAM %.1f GB vs target %s/%s/%sGB; %s" % (
                          dev["arch"], dev["l4t_release"], dev["ram_gb"] or 0, tgt.get("arch"), tgt.get("l4t_release"),
                          tgt.get("min_mem_gb"), runtime), ["uname -m", "/etc/nv_tegra_release", "/proc/meminfo", "ollama /api/ps"]))

    # RA-5
    scan = _json(os.path.join(inst, "scan.json")) if inst else None
    maxc = man.get("policy", {}).get("max_critical_cves", 0)
    if not scan or scan.get("status") != "ok" or scan.get("criticals") is None:
        res.append(_r("RA-5", "unknown", "vulnerability scanner unavailable on this build (%s)" % (
            (scan or {}).get("detail", "no scan.json")), ["scan.json"]))
    else:
        res.append(_r("RA-5", "pass" if scan["criticals"] <= maxc else "fail",
                      "%d critical findings (limit %d) via %s" % (scan["criticals"], maxc, scan.get("tool")), ["scan.json"]))

    # SR-3 / SR-4
    allow = [x.lower() for x in man.get("policy", {}).get("license_allowlist", [])]
    lic = model.get("license", "").lower()
    res.append(_r("SR-3", "unknown" if not state else ("pass" if lic in allow else "fail"),
                  "model license %s; allowlist %s" % (lic or "none", allow), ["manifest.json"]))
    pinned = signing.fingerprint() if os.path.exists(signing.PUB) else None
    prov_ok = bool(model.get("source")) and model.get("source") != "unknown" and man.get("signer_fingerprint") == pinned
    res.append(_r("SR-4", "unknown" if not state else ("pass" if prov_ok else "fail"),
                  "source %s; signer %s vs pinned %s" % (model.get("source"), man.get("signer_fingerprint"), pinned),
                  ["manifest.json", "keys/airlock.pub"]))

    # SC-7: egress blocked AND inference works
    probe = gateway.probe() if gateway else {"egress": "unknown", "detail": "gateway not running"}
    works = False
    if gateway:
        try:
            works = bool(gateway.chat("Reply with the word ok.", num_predict=8))
        except Exception:
            works = False
    if not gateway:
        res.append(_r("SC-7", "unknown", "probe requires running gateway", ["/probe"]))
    else:
        ifaces = _interfaces()
        isolated = ifaces == ["lo"]
        res.append(_r("SC-7", "pass" if probe["egress"] == "blocked" and works else "fail",
                      "scope: the gateway process that handles prompts and data. Network interfaces visible to it: %s%s; "
                      "egress %s (%s); local inference %s" % (
                          ", ".join(ifaces) or "unknown", " (network namespace)" if isolated else "",
                          probe["egress"], probe["detail"][:70], "works" if works else "FAILED"),
                      ["/probe", "/proc/net/dev", "local inference"]))
        if isolated and gateway.backend == "ollama":
            gaps.append({"control": "SC-7",
                         "weakness": "The inference engine (Ollama) runs on the host network, outside the network-less namespace; "
                                     "only the gateway is isolated and it reaches Ollama through a unix-socket relay.",
                         "remediation": "Run Ollama inside the same network namespace, or enforce a host network policy that denies its egress."})

    # AU-2 / AU-9
    ap = os.path.join(OUT, "audit.jsonl")
    ok, n, badi = audit.verify(ap) if os.path.exists(ap) else (False, 0, None)
    entries = audit.tail(ap, 1)
    fields = all(k in entries[0] for k in ("ts", "user", "prompt_sha256", "response_sha256", "status")) if entries else False
    res.append(_r("AU-2", "pass" if (n > 0 and fields) else "unknown", "%d audit events recorded; raw prompts never stored" % n, ["out/audit.jsonl"]))
    if os.path.exists(ap):
        aok, an, abad, adetail = audit.verify_anchored(ap)
        if aok:
            audit.write_anchor(ap)  # only advance the anchor from a verified state
        res.append(_r("AU-9", "pass" if aok else "fail", "%d entries; %s" % (an, adetail),
                      ["out/audit.jsonl", "out/audit.jsonl.anchor"]))
    else:
        res.append(_r("AU-9", "unknown", "no audit log yet", ["out/audit.jsonl"]))

    # AC-3: unauthenticated request must get 401
    ac = ("unknown", "gateway not running")
    if gateway:
        port = int(gateway.conf.get("AIRLOCK_PORT", "8000"))
        sock = gateway.conf.get("AIRLOCK_SOCKET")
        try:
            if sock:
                conn = _UnixConn(sock)
                conn.request("POST", "/v1/chat", b'{"message":"x"}', {"Content-Type": "application/json"})
                code = conn.getresponse().status
                conn.close()
            else:
                req = urllib.request.Request("http://127.0.0.1:%d/v1/chat" % port, b'{"message":"x"}', {"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
                code = 200
            ac = ("pass", "unauthenticated request got HTTP 401") if code == 401 else ("fail", "got HTTP %d, expected 401" % code)
        except urllib.error.HTTPError as e:
            ac = ("pass", "unauthenticated request got HTTP %d" % e.code) if e.code == 401 else ("fail", "got HTTP %d, expected 401" % e.code)
        except Exception as e:
            ac = ("unknown", "could not self-test: %s" % e)
    res.append(_r("AC-3", ac[0], ac[1], ["POST /v1/chat without key"]))

    # AI-EVAL
    ev = _json(os.path.join(OUT, "eval.json"))
    if not ev:
        res.append(_r("AI-EVAL", "unknown", "injection suite not run (python3 -m airlock eval)", ["out/eval.json"]))
    else:
        raw = ""
        if ev.get("filtered"):
            raw = "; raw model alone: %d/%d (%.0f%%), output-boundary redaction of account references active" % (
                ev.get("raw_passed", 0), ev["total"], ev.get("raw_pct", 0))
        res.append(_r("AI-EVAL", "pass" if ev["pct"] >= 80 else "fail",
                      "served replies: %d/%d attacks did not leak the canary (%.0f%%, threshold 80%%)%s" % (
                          ev["passed"], ev["total"], ev["pct"], raw),
                      ["out/eval.json", "evals/injection.jsonl"]))

    sat = len([c for c in res if c["status"] == "pass"])
    si7 = [c for c in res if c["control"] == "SI-7"][0]["status"] == "fail"
    return {
        "generated": now_iso(),
        "bundle": {"name": man.get("name"), "version": man.get("version"),
                   "signer_fingerprint": man.get("signer_fingerprint"), "target": tgt},
        "device": {"arch": dev["arch"], "l4t_release": dev["l4t_release"],
                   "ram_mb": int((dev["ram_gb"] or 0) * 1024),
                   "backend": gateway.backend if gateway else None, "model": model_name},
        "controls": res,
        "gaps": gaps,
        "audit": audit.summary(ap) if os.path.exists(ap) else {"ok": False, "entries": 0, "tail": []},
        "summary": {"satisfied": sat, "total": len(res), "si7_failed": si7},
    }


def collect(gateway=None):
    """Cached (dashboard polls every 2 s; collection makes a short inference call)."""
    with _LOCK:
        if _CACHE["ev"] is not None and time.time() - _CACHE["t"] < TTL:
            ev = dict(_CACHE["ev"])
            ev["audit"] = audit.summary(os.path.join(OUT, "audit.jsonl")) if os.path.exists(os.path.join(OUT, "audit.jsonl")) else ev["audit"]
            return ev
        ev = collect_all(gateway)
        _CACHE["t"], _CACHE["ev"] = time.time(), ev
        return ev


def write_all(gateway=None):
    ev = collect_all(gateway)
    with open(os.path.join(OUT, "evidence.json"), "w") as f:
        json.dump(ev, f, indent=2)
    for name, mod, fn in (("assessment-results.json", "oscal", "build"),):
        try:
            m = __import__("airlock." + mod, fromlist=[fn])
            with open(os.path.join(OUT, name), "w") as f:
                json.dump(getattr(m, fn)(ev), f, indent=2)
        except ImportError:
            pass
    try:
        from airlock import report
        with open(os.path.join(OUT, "ssp.html"), "w") as f:
            f.write(report.render_ssp(ev))
        with open(os.path.join(OUT, "poam.html"), "w") as f:
            f.write(report.render_poam(report.poam_items(ev)))
    except ImportError:
        pass
    return ev
