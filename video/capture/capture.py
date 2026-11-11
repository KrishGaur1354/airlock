#!/usr/bin/env python3
"""Capture the real assets for the Airlock demo video.

Everything the video shows comes from here: real command output from the
Jetson (over ssh) and real screenshots of the live dashboard (through the
existing ssh tunnel on localhost:8000). Remotion only animates them.

    python capture/capture.py            # from video/

Outputs
    public/term/{a-verify,b-import,c-tamper,c-import}.json  {command, lines[], exitCode}
    public/shots/0N-*.png                                    1920x1080 viewport @2x, full page
    public/shots/boxes.json                                  element boxes (CSS px, page coords)

The API key is read from the Jetson's airlock.conf over ssh, kept in memory,
typed into the dashboard's password field (rendered masked) and never printed.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(os.path.dirname(HERE), "public")
TERM = os.path.join(PUBLIC, "term")
SHOTS = os.path.join(PUBLIC, "shots")

HOST = os.environ.get("JETSON", "krish@100.104.188.95")
SSH = os.environ.get("SSH_BIN", r"C:\Windows\System32\OpenSSH\ssh.exe" if os.name == "nt" else "ssh")
DASH = os.environ.get("DASH", "http://localhost:8000")
BUNDLE = "out/qwen3e.airlock"


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def log(*a):
    print("[capture]", *a, flush=True)


def ssh(cmd, timeout=900):
    """Run `cmd` in ~/yc-compiled on the Jetson. Returns (exit_code, text)."""
    remote = "cd ~/yc-compiled && export PYTHONIOENCODING=utf-8 && { %s ; } 2>&1" % cmd
    p = subprocess.run([SSH, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST, remote],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if p.returncode == 255:
        raise SystemExit("ssh failed: " + p.stderr.decode("utf-8", "replace"))
    return p.returncode, p.stdout.decode("utf-8", "replace")


def run_term(name, command):
    """Run a demo command for real and save exactly what it printed."""
    log("running:", command)
    t0 = time.time()
    code, out = ssh(command)
    lines = [ln.split("\r")[-1] for ln in out.replace("\r\n", "\n").split("\n")]
    while lines and not lines[-1].strip():
        lines.pop()
    rec = {"command": command, "lines": lines, "exitCode": code, "seconds": round(time.time() - t0, 1)}
    with open(os.path.join(TERM, name + ".json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=2)
    log("  exit %d, %d lines, %.1fs" % (code, len(lines), rec["seconds"]))
    for ln in lines:
        log("  |", ln)
    return rec


def read_api_key():
    code, out = ssh("sed -n 's/^AIRLOCK_API_KEY=//p' airlock.conf | head -1")
    key = out.strip().strip('"').strip("'")
    if code != 0 or not key:
        raise SystemExit("could not read AIRLOCK_API_KEY from the Jetson's airlock.conf")
    return key


def box(page, selector):
    loc = page.locator(selector).first
    if loc.count() == 0:
        return None
    loc.scroll_into_view_if_needed()
    b = loc.bounding_box()
    sy = page.evaluate("window.scrollY")
    sx = page.evaluate("window.scrollX")
    if not b:
        return None
    return {"x": round(b["x"] + sx, 1), "y": round(b["y"] + sy, 1),
            "w": round(b["width"], 1), "h": round(b["height"], 1)}


def shoot(page, name, boxes, selectors):
    entry = {}
    for k, sel in selectors.items():
        b = box(page, sel)
        if b:
            entry[k] = b
        else:
            log("  WARNING: no box for", k, sel)
    page.evaluate("window.scrollTo(0, 0)")
    page.wait_for_timeout(400)
    size = page.evaluate("({w: document.documentElement.scrollWidth, h: document.documentElement.scrollHeight})")
    page.screenshot(path=os.path.join(SHOTS, name + ".png"), full_page=True)
    boxes[name] = {"size": size, "boxes": entry}
    log("  shot", name, size, sorted(entry))


def dash_state(page):
    return page.evaluate("""() => ({
        num: document.getElementById('gauge-num').textContent,
        title: document.getElementById('banner-title').textContent,
        cls: document.getElementById('banner').className,
        egress: document.getElementById('egress-big').textContent,
        probe: document.getElementById('egress-detail').textContent,
        live: document.getElementById('live-text').textContent })""")


def wait_healthy(page, timeout_s=120):
    end = time.time() + timeout_s
    s = None
    while time.time() < end:
        s = dash_state(page)
        if s["num"] == "10/11" and "1 unknown" in s["title"] and s["egress"] == "Egress blocked" and s["probe"]:
            return s
        page.wait_for_timeout(1000)
    raise SystemExit("dashboard is not healthy (expected 10/11 · 1 unknown, egress blocked): %r" % (s,))


def ask(page, preset, key):
    page.fill("#apikey", key)
    page.click(".presets button:text-is('%s')" % preset)
    page.click("#send")
    page.wait_for_function("""() => { const r = document.getElementById('reply');
        return r.textContent !== 'thinking…' && !r.classList.contains('muted'); }""", timeout=180000)
    page.wait_for_timeout(600)
    txt = page.inner_text("#reply")
    log("  reply (%s): %s" % (preset, txt.replace("\n", " ")[:160]))
    if "HTTP" in txt[:8] or "request failed" in txt:
        raise SystemExit("chat failed: " + txt[:200])


def main():
    os.makedirs(TERM, exist_ok=True)
    os.makedirs(SHOTS, exist_ok=True)

    code = urllib.request.urlopen(DASH + "/", timeout=10).status
    log("dashboard HTTP", code)
    if code != 200:
        raise SystemExit("dashboard tunnel not returning 200")

    key = read_api_key()
    log("api key read (%d chars, kept in memory only)" % len(key))
    boxes = {"_meta": {"viewport": [1920, 1080], "dpr": 2, "units": "css px, page coordinates"}}
    tampered = False

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1920, "height": 1080}, device_scale_factor=2)
        page = ctx.new_page()
        page.goto(DASH + "/", wait_until="networkidle")
        s = wait_healthy(page)
        log("pre-check OK:", s["num"], "|", s["title"], "|", s["egress"], "|", s["probe"])
        try:
            # ---- terminal a, b
            run_term("a-verify", "python3 -m airlock verify " + BUNDLE)
            run_term("b-import", "python3 -m airlock import " + BUNDLE)

            # ---- 01 healthy dashboard
            page.reload(wait_until="networkidle")
            page.fill("#apikey", key)
            wait_healthy(page)
            page.wait_for_timeout(1500)
            shoot(page, "01-healthy", boxes, {
                "banner": "#banner", "gauge": "#banner .gauge",
                "sc7": '.ctl[data-id="SC-7"]', "probe": "#egress-detail",
                "boundary": ".panel:has(#egress-big)", "ra5": '.ctl[data-id="RA-5"]',
                "si7": '.ctl[data-id="SI-7"]', "export": ".panel:has(.btn-row)"})

            # ---- 02 SSP export
            page.goto(DASH + "/export/ssp.html", wait_until="networkidle")
            page.wait_for_timeout(800)
            shoot(page, "02-ssp", boxes, {"title": "h1", "body": "body"})

            # ---- 03 / 04 chat presets (only the two presets)
            page.goto(DASH + "/", wait_until="networkidle")
            wait_healthy(page)
            ask(page, "Memo question", key)
            shoot(page, "03-chat-memo", boxes, {"reply": "#reply", "chat": ".panel:has(#reply)"})
            ask(page, "Injection attack", key)
            shoot(page, "04-chat-injection", boxes, {"reply": "#reply", "chat": ".panel:has(#reply)"})

            # ---- terminal c: flip one byte, import the tampered copy (must be refused)
            tampered = True
            rec = run_term("c-tamper", "python3 scripts/tamper.py " + BUNDLE)
            m = re.search(r"(out/\S+?\.tampered\.airlock)", "\n".join(rec["lines"]))
            tpath = m.group(1) if m else "out/qwen3e.tampered.airlock"
            rec = run_term("c-import", "python3 -m airlock import " + tpath)
            if rec["exitCode"] == 0:
                raise SystemExit("tampered import unexpectedly SUCCEEDED; not capturing a fake failure")

            # ---- 05 tampered dashboard (wait for the live refresh)
            page.wait_for_function("() => document.getElementById('banner').className.includes('bad')", timeout=60000)
            page.wait_for_timeout(2500)
            log("  tampered state:", dash_state(page)["title"])
            shoot(page, "05-tampered", boxes, {
                "banner": "#banner", "gauge": "#banner .gauge", "bannerText": "#banner > div:nth-child(2)",
                "si7": '.ctl[data-id="SI-7"]'})

            # ---- 06 POA&M with the new item
            page.goto(DASH + "/export/poam.html", wait_until="networkidle")
            page.wait_for_timeout(800)
            shoot(page, "06-poam", boxes, {"title": "h1", "si7": "tr:has-text('SI-7')", "si7any": ":text('SI-7')"})
        finally:
            with open(os.path.join(SHOTS, "boxes.json"), "w", encoding="utf-8") as f:
                json.dump(boxes, f, indent=2)
            if tampered:
                log("RESTORE: python3 -m airlock import " + BUNDLE)
                code, out = ssh("python3 -m airlock import " + BUNDLE)
                log("  restore exit", code, "|", out.strip().splitlines()[-1] if out.strip() else "")
                page.goto(DASH + "/", wait_until="networkidle")
                s = wait_healthy(page, 180)
                log("restored:", s["num"], "|", s["title"], "|", s["egress"])
            browser.close()
    log("done")


if __name__ == "__main__":
    main()
