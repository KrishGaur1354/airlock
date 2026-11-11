# Airlock: the 90-second demo

**[▶ Watch it](https://github.com/KrishGaur1354/airlock/raw/main/video/demo/airlock-demo-90s.mp4)** ·
**[Voiceover script with cue times](SCRIPT.md)** · 1920×1080 · 30 fps · exactly 90.0 s

## Nothing in this video is mocked

Every terminal line and every dashboard pixel was captured from the Jetson Orin Nano by
[`capture/capture.py`](capture/capture.py). Remotion only *animates* those captures: it types
the commands, reveals the recorded output, and moves a camera over the real screenshots.

| On screen | Where it comes from |
|---|---|
| `airlock verify` / `airlock import` | the real commands, run over ssh; stdout and exit codes are saved verbatim to JSON |
| Dashboard, 10/11 | Playwright screenshot of the live dashboard (2× resolution so zooms stay sharp), with the API key typed into a masked field |
| Memo answer, injection refusal | the dashboard's own two chat presets, sent to the model on the device (0.27 s and 0.34 s) |
| Tamper → refused import | `scripts/tamper.py` flips one byte, then the tampered bundle is imported for real (exit code 1) |
| Red dashboard, POA&M item | screenshots taken after the dashboard's live refresh |
| Zoom targets | element bounding boxes recorded at capture time, not hand-placed |

The capture script restores the good bundle when it finishes, and checks that the dashboard is
back at 10/11 before it exits.

## Timeline

| Time | Block |
|---|---|
| 0:00 | Slide 1: the problem |
| 0:08 | `airlock verify`: signature and every hash |
| 0:17 | `airlock import`: license gate, local install |
| 0:25 | Dashboard: 10/11 → SC-7 + "Network is unreachable" → RA-5 unknown → SSP export |
| 0:40 | Chat: memo answer, then a prompt injection refused |
| 0:52 | Tamper one byte → `IMPORT REFUSED: model.gguf` |
| 0:58 | Dashboard turns red (9/11) → new POA&M item |
| 1:07 | Slide 5: who pays |
| 1:20 | Slide 6: Zarf moves the bits, Airlock moves the authorization |

Frame-exact block starts are in [`timeline.txt`](timeline.txt). The source of truth is
[`src/timeline.ts`](src/timeline.ts).

## Rebuild it

```bash
npm install
JETSON=krish@<jetson> npm run capture   # needs key-based ssh + the dashboard tunnel on :8000
# export slides 1, 5, 6 of the deck to public/slides/slide{1,5,6}.png (1920x1080)
npm run render                          # -> out/airlock-demo-90s.mp4 (silent, voiceover added in post)
```

Captured assets (`public/term`, `public/shots`, `public/slides`) and renders are git-ignored; the
final cut is committed at [`demo/airlock-demo-90s.mp4`](demo/airlock-demo-90s.mp4).

## How it's built

- [`src/Airlock.tsx`](src/Airlock.tsx): the composition, a `TransitionSeries` with 9-frame crossfades timed so each block starts on its exact second
- [`src/components/Terminal.tsx`](src/components/Terminal.tsx): types the command at about 30 chars/s, reveals the recorded output, holds the final ✔/✘ lines for at least 2 s
- [`src/components/Shot.tsx`](src/components/Shot.tsx): eases a camera (up to 2.2×) between the recorded element boxes, with a highlight ring
- [`src/components/Slide.tsx`](src/components/Slide.tsx), [`Caption.tsx`](src/components/Caption.tsx): deck slides with a slow push-in; bottom-centre captions
