import React from "react";
import { AbsoluteFill, Easing, Img, interpolate, staticFile, useCurrentFrame } from "remotion";
import boxesJson from "../../public/shots/boxes.json";

// A real dashboard screenshot (1920-wide CSS page captured at 2x) with a camera
// that eases between element boxes recorded at capture time (boxes.json).

export type Box = { x: number; y: number; w: number; h: number };
export type Focus = {
  frames: number;
  box?: Box; // undefined = overview (top of page, zoom 1)
  ring?: Box | null; // highlight; defaults to `box`, null = no ring
  zoom?: number;
};
type Cam = { z: number; cx: number; cy: number };
type ShotMeta = { size: { w: number; h: number }; boxes: Record<string, Box> };

const W = 1920;
const H = 1080;
const MOVE = 18; // 0.6 s ease between focus boxes
const MAX_Z = 2.2;

export const shotBoxes = (name: string): ShotMeta => (boxesJson as unknown as Record<string, ShotMeta>)[name];

export const union = (...bs: Box[]): Box => {
  const x = Math.min(...bs.map((b) => b.x));
  const y = Math.min(...bs.map((b) => b.y));
  const r = Math.max(...bs.map((b) => b.x + b.w));
  const btm = Math.max(...bs.map((b) => b.y + b.h));
  return { x, y, w: r - x, h: btm - y };
};

const clampCam = (c: Cam, size: { w: number; h: number }): Cam => {
  const hw = W / 2 / c.z;
  const hh = H / 2 / c.z;
  const cx = size.w <= 2 * hw ? size.w / 2 : Math.min(Math.max(c.cx, hw), size.w - hw);
  const cy = size.h <= 2 * hh ? hh : Math.min(Math.max(c.cy, hh), size.h - hh);
  return { z: c.z, cx, cy };
};

const camFor = (f: Focus | null, size: { w: number; h: number }): Cam => {
  if (!f || !f.box) return clampCam({ z: f?.zoom ?? 1, cx: W / 2, cy: 0 }, size);
  const b = f.box;
  const z = f.zoom ?? Math.max(1, Math.min(MAX_Z, (0.82 * W) / b.w, (0.78 * H) / b.h));
  return clampCam({ z, cx: b.x + b.w / 2, cy: b.y + b.h / 2 }, size);
};

export const Shot: React.FC<{ name: string; focus: Focus[]; startZoomed?: boolean; bg?: string; dim?: number }> = ({
  name,
  focus,
  startZoomed,
  bg = "#0b0e14",
  dim = 0.3,
}) => {
  const frame = useCurrentFrame();
  const { size } = shotBoxes(name);

  // which focus segment are we in
  let idx = 0;
  let segStart = 0;
  for (let i = 0, acc = 0; i < focus.length; i++) {
    if (frame >= acc) {
      idx = i;
      segStart = acc;
    }
    acc += focus[i].frames;
  }
  const local = frame - segStart;
  const prev = idx === 0 ? (startZoomed ? camFor(focus[0], size) : camFor(null, size)) : camFor(focus[idx - 1], size);
  const cur = camFor(focus[idx], size);
  const t = interpolate(local, [0, MOVE], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.inOut(Easing.cubic),
  });
  const lz = Math.log(prev.z) + (Math.log(cur.z) - Math.log(prev.z)) * t;
  const total = focus.reduce((a, f) => a + f.frames, 0);
  const drift = 1 + 0.02 * Math.min(1, frame / total); // slow continuous push-in
  const cam = clampCam(
    { z: Math.exp(lz) * drift, cx: prev.cx + (cur.cx - prev.cx) * t, cy: prev.cy + (cur.cy - prev.cy) * t },
    size,
  );

  const f = focus[idx];
  const ring = f.ring === null ? null : (f.ring ?? f.box);
  const moved = idx === 0 && startZoomed ? 0 : MOVE;
  const isLast = idx === focus.length - 1;
  const ringOp = ring
    ? interpolate(local, [moved - 2, moved + 8, f.frames - 8, f.frames], [0, 1, 1, isLast ? 1 : 0], {
        extrapolateLeft: "clamp",
        extrapolateRight: "clamp",
      })
    : 0;
  const pad = 8;

  return (
    <AbsoluteFill style={{ backgroundColor: bg, overflow: "hidden" }}>
      <div
        style={{
          position: "absolute",
          left: 0,
          top: 0,
          width: size.w,
          height: size.h,
          transformOrigin: "0 0",
          transform: `translate(${W / 2 - cam.cx * cam.z}px, ${H / 2 - cam.cy * cam.z}px) scale(${cam.z})`,
        }}
      >
        <Img src={staticFile(`shots/${name}.png`)} style={{ width: size.w, height: size.h, display: "block" }} />
        {ring ? (
          <div
            style={{
              position: "absolute",
              left: ring.x - pad,
              top: ring.y - pad,
              width: ring.w + pad * 2,
              height: ring.h + pad * 2,
              borderRadius: 14,
              opacity: ringOp,
              border: `${3 / cam.z}px solid #E07A5F`,
              boxShadow: `0 0 ${18 / cam.z}px ${4 / cam.z}px rgba(224,122,95,0.55), 0 0 0 6000px rgba(0,0,0,${dim})`,
            }}
          />
        ) : null}
      </div>
    </AbsoluteFill>
  );
};
