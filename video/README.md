# Airlock 90-second demo video (Remotion)

Silent 1920x1080 / 30 fps / 2700-frame cut, timed to `../../voiceover.md`.
Narration script with frame-accurate cues: [SCRIPT.md](SCRIPT.md).
Everything on screen is real: command output captured from the Jetson and
screenshots of the live dashboard. Remotion only animates them (typing, zoom, captions).

## Rebuild

```bash
npm install

# 1. Real assets (needs key-based ssh to the Jetson and the dashboard tunnel on :8000)
#    ssh -L 8000:/home/krish/yc-compiled/run/gateway.sock krish@<jetson>
JETSON=krish@<jetson> npm run capture
#    -> public/term/*.json, public/shots/*.png + boxes.json
#    It runs verify, import, the two chat presets, tamper + refused import, then
#    restores the healthy bundle and checks the dashboard is back to 10/11.

# 2. Slides 1, 5, 6 of ../../airlock-deck.pptx as 1920x1080 PNG -> public/slides/slide{1,5,6}.png

# 3. Render
npm run render
```

`public/term`, `public/shots`, `public/slides`, `out/`, `frames/` are generated and not committed.

## Layout

- `src/timeline.ts`: block lengths and captions (single source of truth; see `timeline.txt`)
- `src/Airlock.tsx`: the composition (`TransitionSeries`, 9-frame crossfades, camera focus plans)
- `src/components/`: `Slide`, `Terminal` (typing + line reveal), `Shot` (camera over boxes.json), `Caption`
- `capture/capture.py`: Playwright + ssh capture of the real assets
