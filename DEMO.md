# Airlock demo runbook (90 s)

Board: Jetson Orin Nano (R36), reached over SSH only. Repo on the board: `~/yc-compiled`.

## Pre-flight (5 min before recording)

On the Jetson (in `tmux` so it survives the SSH session):
```bash
cd ~/yc-compiled
python3 scripts/airgap.py          # gateway in a network-less namespace; leave running
```

On the laptop:
```bash
ssh -L 8000:/home/krish/yc-compiled/run/gateway.sock krish@<jetson>   # dashboard tunnel
ssh krish@<jetson>                                                     # second window: demo terminal
```
- Open `http://localhost:8000` in a **clean browser profile** (no extension icons).
- Paste the `AIRLOCK_API_KEY` from the board's `airlock.conf` into the key field **before** recording (the field is masked).
- Check the dashboard shows **10/11 · 1 unknown (RA-5)** and **Egress blocked**.
- In the demo terminal: `cd ~/yc-compiled && clear`.

## Recording

| Time | Screen | Run / do | Say |
|---|---|---|---|
| 0–10 s | Title | — | "Air-gapped sites can't run AI they can't accredit. Airlock ships a signed model that proves itself and writes its own accreditation evidence." |
| 10–25 s | Terminal | `python3 -m airlock verify out/qwen3e.airlock` | "Low side signed this bundle: model, SBOM, scan, and GMI-written control statements. On the device we check the ed25519 signature and every hash." |
| 25–40 s | Terminal | `python3 -m airlock import out/qwen3e.airlock` | "Verify first, license gate, then install into local Ollama. Nothing touches disk until it verifies." |
| 40–55 s | Dashboard | Point at gauge, SC-7 panel, RA-5 card; click **SSP** | "Eleven NIST 800-53 controls, measured on this device. The kernel blocks egress: *Network is unreachable*. No scanner here, so RA-5 is honestly *unknown* and lands in the POA&M." |
| 55–70 s | Dashboard chat | Preset **Memo question** → Send; preset **Injection attack** → Send | "Answers from the confidential memo, fully offline. A jailbreak gets refused. Every exchange is hash-chained in the audit log; raw prompts are never stored." |
| 70–90 s | Terminal + dashboard | `python3 scripts/tamper.py out/qwen3e.airlock && python3 -m airlock import out/qwen3e.tampered.airlock` | "Flip one byte in the model. Import refused, named file, dashboard goes red, new POA&M item. That's the evidence an assessor needs." |

After recording, restore the healthy state:
```bash
python3 -m airlock import out/qwen3e.airlock
```

## Rules for the live demo
- Use only the two chat presets. INJ-03 is refused by the model itself; free-form attacks can leak on a 1.7B model.
- Use the preset memo question exactly; a shorter "what is the rating?" has produced a wrong answer once.
- If AI-EVAL or anything else goes red live, leave it: the product is reporting what it measured.

## Honest scope (for Q&A)
- **SC-7** covers the gateway process (kernel network namespace). Ollama still runs on the host network; this is listed in the POA&M as a residual gap.
- **AI-EVAL**: raw model alone 7/10 attacks resisted; 10/10 with the output-boundary filter, which redacts account identifiers only. Both numbers are in the evidence.
- **RA-5** is unknown because no vulnerability scanner is installed on the device.
- **GMI Cloud** (DeepSeek-V3.2) wrote the 11 control statements and the model card on the low side; the attack suite fell back to the hand-written set. Outputs are cached, signed into the bundle, and the high side never contacts GMI.
- Output is "OSCAL-shaped", not schema-validated OSCAL.
