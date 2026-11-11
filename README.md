# Airlock

**Signed offline AI bundles that verify themselves on an air-gapped device and write their own accreditation evidence.**

> The world's most valuable data never leaves the building, so AI never gets in.
> Zarf moves the bits. **Airlock moves the authorization.**

Built at **c0mpiled-18 Taipei**, running live on a **Jetson Orin Nano** with no route to the internet.

<p align="center">
  <a href="https://github.com/KrishGaur1354/airlock/raw/main/video/demo/airlock-demo-90s.mp4">
    <img src="docs/img/video-thumb.jpg" width="720" alt="Watch the 90-second demo">
  </a>
  <br>
  <b><a href="https://github.com/KrishGaur1354/airlock/raw/main/video/demo/airlock-demo-90s.mp4">▶ Watch the 90-second demo</a></b>
  · <a href="video/SCRIPT.md">voiceover script</a>
  · every frame is real output from the device
</p>

---

## The problem

Banks, chip fabs, defense suppliers and hospitals keep their most sensitive data on networks
that are cut off from the internet. Getting an AI model onto one of those networks isn't really a
technical problem. The hard part is **authorization**: security review wants proof of where the
model came from, that it hasn't been modified, that it can't send data out, and which controls it
satisfies. Today that evidence is written by hand, and AI vendors' deals stall for months waiting
for it.

## What Airlock does

One signed file carries the model across the gap. On the far side, the device **measures its own
compliance** and produces the paperwork an assessor asks for.

| | |
|---|---|
| **Build (low side)** | Packages the model (Qwen3-1.7B Q4_K_M, 1.1 GB) with an SBOM, scan result, control statements and a model card. SHA-256s every file and signs the manifest with ed25519. Builds in about 4 s. |
| **Verify** | Checks the signature against a pinned key and **every file hash before anything is extracted**. One flipped byte and the import is refused, naming the file. |
| **Import** | License allowlist gate (SR-3), target check (arch, L4T, RAM), then installs into the local Ollama. |
| **Serve** | The gateway runs in a **network-less Linux namespace** (loopback only), behind an API key, with a hash-chained audit log that never stores raw prompts. |
| **Prove** | 11 collectors measure NIST 800-53 controls *on the device* and export an **SSP**, a **POA&M** and **OSCAL-shaped JSON**, plus a live dashboard. |

<p align="center"><img src="docs/img/dashboard-healthy.png" width="900" alt="Airlock dashboard: 10/11 controls satisfied, RA-5 unknown, egress blocked"></p>

## Measured on the Jetson

The evidence is collected, not written. Every number below was measured on the device.

| | |
|---|---|
| **10 / 11** | NIST 800-53 controls satisfied. RA-5 is **unknown** (no scanner on the device), and that is reported as such and tracked in the POA&M. |
| **0 routes out** | Live egress probe from inside the gateway: `1.1.1.1:443 -> Network is unreachable (no route)`. |
| **1 byte** | flipped in the 1.1 GB bundle → `IMPORT REFUSED: model.gguf`. The dashboard goes red (9/11) and a POA&M item opens automatically. |
| **7 → 10 of 10** | prompt-injection attacks blocked: the raw model alone, then with the output-boundary filter. Both numbers are in the evidence. |
| **0.27 s** | answer from a confidential credit memo, fully offline (about 30 tokens/s on the GPU). |
| **141** | unit tests, all passing on the board (`python3 -m unittest discover tests`). |

<table>
<tr>
<td width="50%"><img src="docs/img/tamper-refused.png" alt="Tampered bundle: sha256 model.gguf mismatch, import refused"></td>
<td width="50%"><img src="docs/img/dashboard-tampered.png" alt="Dashboard after tamper: 9/11, SI-7 not satisfied, red banner"></td>
</tr>
<tr>
<td align="center"><sub>One byte flipped: the signature still verifies, but the model hash doesn't match</sub></td>
<td align="center"><sub>The dashboard reports it within 2 s; nothing was installed</sub></td>
</tr>
</table>

## Architecture

```mermaid
flowchart LR
  subgraph LOW["Low side · vendor"]
    M["Qwen3-1.7B GGUF<br/>hf://unsloth"] --> B["airlock build<br/>SBOM · scan · hashes"]
    G["GMI Cloud<br/>DeepSeek-V3.2"] -. "control statements,<br/>model card (cached)" .-> B
    B --> S["ed25519 sign"]
  end
  S == "one .airlock tar<br/>USB / data diode" ==> V
  subgraph HIGH["High side · Jetson Orin Nano (air-gapped)"]
    V["verify<br/>signature + every hash"] --> I["import<br/>license gate → Ollama"]
    I --> O["Ollama"]
    W["Gateway<br/>network namespace, loopback only<br/>API key · redaction"] -- "unix socket" --> O
    W --> A["Audit log<br/>SHA-256 hash chain + anchor"]
    C["11 evidence collectors"] --> E["SSP · POA&M · OSCAL JSON"]
    C --> D["Live dashboard"]
  end
```

GMI Cloud is used **only on the vendor side**. Its output is cached and signed into the bundle;
the Jetson never contacts GMI and never sees the key. The test suite enforces this:
`grep -rn GMI airlock/gateway.py airlock/evidence.py airlock/bundle.py` must come back empty.

## The 11 controls

| Control | What is measured on the device |
|---|---|
| **SI-7** Integrity | ed25519 signature valid against the pinned key; every artifact hash matches the signed manifest |
| **CM-8** Inventory | SBOM present and matches the manifest (model, source, sha256) |
| **CM-2** Baseline | arch / L4T / RAM vs the declared target; model actually loaded on the GPU (`ollama /api/ps`) |
| **RA-5** Vulnerability scan | trivy scan result; **unknown** when no scanner is available, never assumed |
| **SR-3** Supply chain | model license on the allowlist (Apache-2.0, MIT) |
| **SR-4** Provenance | real origin URI, sha256 and quantization read from the file; signer matches the pinned key |
| **SC-7** Boundary | gateway's visible interfaces (loopback only) plus a live egress probe |
| **AU-2** Event logging | every request audited by prompt and response SHA-256; raw prompts are never stored |
| **AU-9** Audit protection | hash chain verified, plus an anchor that detects truncation or head rewrites |
| **AC-3** Access | unauthenticated request gets HTTP 401, and the denial is audited |
| **AI-EVAL** (NIST AI 600-1) | injection / exfiltration suite against the served model, with a canary in the memo |

Anything that fails or can't be measured becomes a POA&M item with a remediation and a 30-day milestone.

## Run it

Requirements: Python 3.6+ and `cryptography` (ed25519); Ollama with a Qwen3 GGUF for inference;
Linux with unprivileged user namespaces for the air-gapped gateway. Everything else is stdlib.

```bash
# low side: keys + signed bundle (--enrich adds the cached vendor control statements and model card)
python3 -m airlock keygen
python3 -m airlock build --gguf Qwen3-1.7B-Q4_K_M.gguf -o out/qwen3e.airlock \
    --source hf://unsloth/Qwen3-1.7B-GGUF/Qwen3-1.7B-Q4_K_M.gguf --enrich

# high side
python3 -m airlock verify out/qwen3e.airlock      # signature + every hash, nothing extracted
python3 -m airlock import out/qwen3e.airlock      # verify, license gate, install into Ollama
python3 -m airlock eval                           # prompt-injection suite -> out/eval.json
python3 scripts/airgap.py                         # gateway in a network-less namespace (leave running)
python3 -m airlock evidence                       # print the 11 controls
python3 -m airlock audit-verify                   # check the audit hash chain

# dashboard from a laptop
ssh -L 8000:/home/<user>/<repo>/run/gateway.sock <user>@<jetson>   # then open http://localhost:8000

# the tamper beat
python3 scripts/tamper.py out/qwen3e.airlock && python3 -m airlock import out/qwen3e.tampered.airlock
python3 -m airlock import out/qwen3e.airlock      # restore
```

`scripts/demo.sh` runs the whole flow end to end. **No Jetson?** Open
`dashboard/index.html?mock=1` in a browser to see the dashboard with an embedded sample payload.

## What it doesn't do yet

Airlock reports its own gaps, so this README does too. These items are open in the POA&M:

- **SC-7 scope:** only the gateway is in the network namespace. Ollama still runs on the host network and the gateway reaches it through a unix-socket relay.
- **RA-5:** there is no vulnerability scanner on the device, so this control is reported as unknown.
- **Redaction:** the output filter removes account identifiers only. The 10/10 result is measured against the canary, so it is not general exfiltration protection.
- **OSCAL:** the output is OSCAL-*shaped*; it isn't validated against the schema.

**Roadmap:** TUF root of trust, in-toto and SLSA attestations · FIPS 140-3 crypto, TPM-backed device
attestation · schema-validated OSCAL, eMASS export · control packs for CMMC, FedRAMP, HIPAA and
ISO 42001 · inference engine inside the namespace.

## Who pays

**Land:** AI vendors selling into regulated companies, whose deals stall for months in security
review. Airlock ships the evidence that closes them.
**Expand:** every enclave they sell into: banks and insurers (model-risk rules), chip design and
fabs (design IP, export controls), defense suppliers (CMMC 2.0, RMF), hospitals and energy
(HIPAA, NERC CIP).

## Repository

```
airlock/      core: bundle, signing, gateway, audit, evidence, controls, oscal, report, evals, redact, vendor_gmi
dashboard/    single-file dashboard (polls /evidence.json every 2 s)
scripts/      airgap.py (network-less gateway), tamper.py, demo.sh
evals/        prompt-injection suite        data/   the confidential credit memo used in the demo
lowside/      cached vendor (GMI Cloud) responses, signed into the bundle
tests/        141 unit tests
video/        the 90-second demo: Remotion source, capture script, voiceover script
```

Stack: Python (stdlib + `cryptography`, Python 3.6-compatible) · Ollama · Qwen3-1.7B Q4_K_M ·
Jetson Orin Nano (L4T R36) · GMI Cloud (vendor side only) · Remotion for the video.

---

Built by **Krish Gaur** at c0mpiled-18 Taipei.
