# Airlock: 90-second voiceover script (synced to `out/airlock-demo-90s.mp4`)

**▶ [Watch the video (90 s, silent)](https://github.com/KrishGaur1354/airlock/raw/main/video/demo/airlock-demo-90s.mp4)**
On a phone, open it in the browser and read the cues below while it plays.

The words are the locked lines from `voiceover.md`. The timecodes are the real
frames of the rendered cut, so you can drop the audio straight onto the video.
About 190 words. Record in one take per block, with a short pause between blocks.

Each **block** starts on its exact second. **Cue** lines show when something
appears on screen, so you can land the matching words on it.

---

### 1 · 0:00 – 0:08 · Slide 1 (8 s, 14 words)
> "The world's most valuable data never leaves the building. So AI never gets in."

---

### 2 · 0:08 – 0:17 · Terminal: `airlock verify` (9 s, 26 words: the tightest block)
> "Airlock fixes that. One signed bundle carries the model in. On this Jetson, verify checks the signature and every file hash before anything is extracted."

- 0:08.4–0:09.9 command types
- 0:10.5 first ✔ `signature (SI-7)` → say **"verify checks the signature"** here
- 0:10.3 caption *Signature + every hash verified*
- 0:14.7 **VERIFIED** (held to 0:17)

Start speaking right at 0:08. If it runs long, drop "before anything is extracted".

---

### 3 · 0:17 – 0:25 · Terminal: `airlock import` (8 s, 14 words)
> "Import adds a license gate, then installs the model locally. No internet involved."

- 0:19.1 ✔ lines start
- 0:22.1 ✔ `license allowlist (SR-3)` → **"license gate"**
- 0:22.4 ✔ `install (ollama create)` → **"installs the model locally"**
- 0:22.7 **IMPORTED**

---

### 4 · 0:25 – 0:40 · Dashboard → SSP (15 s, 37 words)
> "And the accreditation evidence writes itself. Eleven NIST controls, measured on the device. Ten pass. The gateway has no network route out. The vulnerability scan is marked unknown, not hidden. One click exports the security plan."

- 0:25.0 full dashboard · caption *11 NIST 800-53 controls, measured on device*
- 0:26.0 zoom to the **10/11** gauge → **"Eleven NIST controls … Ten pass"**
- 0:29.0 SC-7 card · caption *No network route out* → **"no network route out"**
- 0:30.5 zoom to the probe text `Network is unreachable (no route)`
- 0:33.0 RA-5 card, **UNKNOWN** → **"marked unknown, not hidden"**
- 0:36.0 SSP export page → **"One click exports the security plan"**

---

### 5 · 0:40 – 0:52 · Chat (12 s, 17 words)
> "The model answers from a confidential credit memo in under a second. A prompt injection gets refused."

- 0:40.0 memo answer `BBB- - approve` · `0.27 s · local inference` · caption *Fully offline inference*
- 0:46.0 injection preset → `I cannot share that.` (0.34 s) → **"A prompt injection gets refused"**

Say the first sentence over 0:40–0:46 and the second after 0:46.

---

### 6 · 0:52 – 1:07 · Tamper → red dashboard → POA&M (15 s, 26 words)
> "Now flip one byte in the 1.1-gigabyte model. Import refuses it, by name. The dashboard goes red, and the fix is logged for the auditor."

- 0:52.1 `tamper.py` types · caption *1 byte flipped → rejected* → **"flip one byte"**
- 0:53.4 tamper output (`flipped byte : offset 4096 0x03 -> 0xfc`)
- 0:55.6 ✘ `sha256 model.gguf` · 0:55.9 **IMPORT REFUSED: model.gguf** → **"Import refuses it, by name"**
- 0:58.0 dashboard turns red, **9/11** → **"The dashboard goes red"**
- 1:00.8 SI-7 card **NOT SATISFIED**
- 1:02.8 POA&M item POAM-001 (SI-7) · 1:04.8 pans to the remediation → **"the fix is logged for the auditor"**

---

### 7 · 1:07 – 1:20 · Slide 5, who pays (13 s, 23 words)
> "Who pays? AI vendors whose deals stall in security review. Then the banks, chip makers, defense suppliers and hospitals they sell to."

---

### 8 · 1:20 – 1:30 · Slide 6 (10 s, 12 words)
> "Zarf moves the bits. Airlock moves the authorization. I'm Krish. Let's talk."

Finish around 1:28 and leave about 2 s of silence on the closing slide.

---

## Recording notes
- Pace is about 150 words per minute everywhere except block 2 (about 170). Read block 2 a bit brisker, or trim it as noted.
- Record on your phone as m4a or mp3. The video is silent (`--muted`), so lay the audio from 0:00.
- Every claim on screen is real: 0.27 s and 0.34 s latencies, the 1.1 GB bundle, 10/11 → 9/11, and the POA&M item, all captured on the Jetson on 2026-11-11.
