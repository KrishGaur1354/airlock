// Single source of truth for the 90 s timeline (30 fps, 2700 frames).
// Each block's frame 0 is exactly its slot start in the voiceover script.
// The 9-frame crossfade into the next block happens in the first 9 frames
// of the next slot (the outgoing block is extended by XFADE to cover it).

export const FPS = 30;
export const XFADE = 9;
export const s = (sec: number) => Math.round(sec * FPS);

export type BlockId =
  | "slide1" | "termA" | "termB" | "shot01" | "shot02" | "shot03"
  | "shot04" | "termC" | "shot05" | "shot06" | "slide5" | "slide6";

export const BLOCKS: { id: BlockId; frames: number; label: string }[] = [
  { id: "slide1", frames: s(8), label: "Slide 1" },
  { id: "termA", frames: s(9), label: "Terminal a: airlock verify" },
  { id: "termB", frames: s(8), label: "Terminal b: airlock import" },
  { id: "shot01", frames: s(11), label: "Dashboard 01: gauge -> SC-7 + probe -> RA-5" },
  { id: "shot02", frames: s(4), label: "Dashboard 02: SSP export" },
  { id: "shot03", frames: s(6), label: "Dashboard 03: memo answer" },
  { id: "shot04", frames: s(6), label: "Dashboard 04: injection refused" },
  { id: "termC", frames: s(6), label: "Terminal c: tamper + refused import" },
  { id: "shot05", frames: 145, label: "Dashboard 05: red banner -> SI-7" },
  { id: "shot06", frames: 125, label: "Dashboard 06: POA&M item" },
  { id: "slide5", frames: s(13), label: "Slide 5" },
  { id: "slide6", frames: s(10), label: "Slide 6" },
];

export const TOTAL = BLOCKS.reduce((a, b) => a + b.frames, 0); // 2700

export const startOf = (id: BlockId) => {
  let f = 0;
  for (const b of BLOCKS) {
    if (b.id === id) return f;
    f += b.frames;
  }
  throw new Error(id);
};

// Captions, absolute frames.
export const CAPTIONS: { from: number; to: number; text: string }[] = [
  { from: s(10.3), to: s(16.7), text: "Signature + every hash verified" },
  { from: s(25.15), to: s(28.85), text: "11 NIST 800-53 controls, measured on device" },
  { from: s(29.0), to: s(32.85), text: "No network route out" },
  { from: s(40.3), to: s(51.75), text: "Fully offline inference" },
  { from: s(52.3), to: s(57.85), text: "1 byte flipped → rejected" },
];
