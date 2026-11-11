import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";

// One real command and exactly what it printed on the Jetson (capture/capture.py).
export type TermData = { command: string; lines: string[]; exitCode: number };

export const PROMPT = "krish@jetson:~/yc-compiled$ ";
const BG = "#0B0F14";
const FG = "#D7DEE8";
const MONO = "'Cascadia Mono', 'Cascadia Code', Consolas, 'DejaVu Sans Mono', monospace";

// ---- ANSI SGR -> coloured spans (output is kept verbatim; ANSI only changes colour)
const ANSI: Record<number, string> = {
  30: "#4B5563", 31: "#F87171", 32: "#34D399", 33: "#FBBF24", 34: "#60A5FA", 35: "#C084FC", 36: "#22D3EE", 37: "#E5E7EB",
  90: "#6B7280", 91: "#FCA5A5", 92: "#6EE7B7", 93: "#FDE68A", 94: "#93C5FD", 95: "#D8B4FE", 96: "#67E8F9", 97: "#FFFFFF",
};
type Seg = { text: string; color?: string; bold?: boolean };
const parseAnsi = (line: string): Seg[] => {
  const out: Seg[] = [];
  let color: string | undefined;
  let bold = false;
  const re = /\x1b\[([0-9;]*)m/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) {
    if (m.index > last) out.push({ text: line.slice(last, m.index), color, bold });
    for (const c of (m[1] || "0").split(";").map(Number)) {
      if (c === 0) { color = undefined; bold = false; }
      else if (c === 1) bold = true;
      else if (c === 22) bold = false;
      else if (c === 39) color = undefined;
      else if (ANSI[c]) color = ANSI[c];
    }
    last = re.lastIndex;
  }
  if (last < line.length) out.push({ text: line.slice(last), color, bold });
  return out;
};

// The CLI prints no ANSI; tint its own status marks so they read at a glance.
const tint = (seg: Seg): React.ReactNode[] => {
  if (seg.color) return [<span key={0} style={{ color: seg.color, fontWeight: seg.bold ? 700 : 400 }}>{seg.text}</span>];
  return seg.text.split(/(✔|✘)/).map((t, i) =>
    t === "✔" ? <span key={i} style={{ color: "#34D399", fontWeight: 700 }}>{t}</span>
    : t === "✘" ? <span key={i} style={{ color: "#F87171", fontWeight: 700 }}>{t}</span>
    : <span key={i} style={{ fontWeight: seg.bold ? 700 : 400 }}>{t}</span>,
  );
};

const lineStyle = (line: string): React.CSSProperties => {
  const plain = line.replace(/\x1b\[[0-9;]*m/g, "");
  if (/^(VERIFIED|IMPORTED)\b/.test(plain)) return { color: "#34D399", fontWeight: 700 };
  if (/^(IMPORT REFUSED|VERIFICATION FAILED)\b/.test(plain)) return { color: "#F87171", fontWeight: 700 };
  if (plain.includes("✘")) return { color: "#FCA5A5", background: "rgba(248,113,113,0.12)", borderRadius: 6, margin: "0 -10px", padding: "0 10px" };
  return {};
};

const Prompt: React.FC = () => (
  <>
    <span style={{ color: "#34D399", fontWeight: 700 }}>krish@jetson</span>
    <span style={{ color: FG }}>:</span>
    <span style={{ color: "#60A5FA", fontWeight: 700 }}>~/yc-compiled</span>
    <span style={{ color: FG }}>$ </span>
  </>
);

const Cursor: React.FC<{ frame: number; solid?: boolean }> = ({ frame, solid }) => (
  <span
    style={{
      display: "inline-block", width: "0.6em", height: "1.1em", verticalAlign: "-0.2em", marginLeft: 1,
      background: "#D7DEE8", opacity: solid || Math.floor(frame / 15) % 2 === 0 ? 0.9 : 0,
    }}
  />
);

type Plan = { typeStart: number; typeEnd: number; enter: number; lineAt: number[] };

/**
 * Timing: each command is typed at `cps` chars/s, Enter, then its output lines
 * are revealed over the remaining time, leaving at least `hold` frames at the
 * end with the final ✔/✘ lines on screen.
 */
const plan = (steps: TermData[], slot: number, cps: number, hold: number, startDelay: number, enterPause: number, gap: number): Plan[] => {
  const fpc = 30 / cps;
  const typing = steps.map((st) => Math.ceil(st.command.length * fpc));
  const totalLines = steps.reduce((a, st) => a + st.lines.length, 0);
  const fixed = startDelay + typing.reduce((a, b) => a + b, 0) + steps.length * enterPause + (steps.length - 1) * gap;
  const budget = Math.max(totalLines, slot - hold - fixed);
  const perLine = budget / Math.max(1, totalLines);
  const plans: Plan[] = [];
  let t = startDelay;
  steps.forEach((st, i) => {
    const typeStart = t;
    const typeEnd = typeStart + typing[i];
    const enter = typeEnd + enterPause;
    const lineAt = st.lines.map((_, j) => Math.round(enter + (j + 1) * perLine));
    plans.push({ typeStart, typeEnd, enter, lineAt });
    t = (lineAt[lineAt.length - 1] ?? enter) + gap;
  });
  return plans;
};

export const Terminal: React.FC<{
  steps: TermData[];
  slot: number; // frames of this block's slot (excluding the outgoing crossfade)
  cps?: number;
  hold?: number;
  startDelay?: number;
  enterPause?: number;
  gap?: number;
}> = ({ steps, slot, cps = 30, hold = 70, startDelay = 12, enterPause = 8, gap = 6 }) => {
  const frame = useCurrentFrame();
  const plans = plan(steps, slot, cps, hold, startDelay, enterPause, gap);
  const fpc = 30 / cps;
  const rows: React.ReactNode[] = [];
  let showFinalPrompt = false;

  steps.forEach((st, i) => {
    const p = plans[i];
    if (frame < p.typeStart && i > 0) return;
    const typed = Math.max(0, Math.min(st.command.length, Math.floor((frame - p.typeStart) / fpc)));
    const typing = frame < p.enter;
    rows.push(
      <div key={`c${i}`}>
        <Prompt />
        <span style={{ color: "#F3F6FA" }}>{st.command.slice(0, typed)}</span>
        {typing ? <Cursor frame={frame} solid={frame >= p.typeStart && frame < p.typeEnd} /> : null}
      </div>,
    );
    st.lines.forEach((ln, j) => {
      if (frame < p.lineAt[j]) return;
      rows.push(
        <div key={`l${i}-${j}`} style={lineStyle(ln)}>
          {ln === "" ? " " : parseAnsi(ln).flatMap((seg, k) => tint(seg).map((n, q) => <React.Fragment key={`${k}-${q}`}>{n}</React.Fragment>))}
        </div>,
      );
    });
    if (i === steps.length - 1) showFinalPrompt = frame >= (p.lineAt[p.lineAt.length - 1] ?? p.enter) + 4;
  });

  const appear = interpolate(frame, [0, 6], [0.985, 1], { extrapolateRight: "clamp" });

  return (
    <AbsoluteFill style={{ backgroundColor: "#06080B", padding: 48 }}>
      <div
        style={{
          flex: 1, background: BG, borderRadius: 18, border: "1px solid #1E2633", overflow: "hidden",
          boxShadow: "0 30px 80px rgba(0,0,0,0.55)", display: "flex", flexDirection: "column", transform: `scale(${appear})`,
        }}
      >
        <div style={{ height: 52, display: "flex", alignItems: "center", gap: 10, padding: "0 22px", background: "#10151C", borderBottom: "1px solid #1E2633" }}>
          {["#F87171", "#FBBF24", "#34D399"].map((c) => (
            <div key={c} style={{ width: 14, height: 14, borderRadius: 7, background: c, opacity: 0.85 }} />
          ))}
          <div style={{ flex: 1, textAlign: "center", color: "#8A96AB", fontFamily: MONO, fontSize: 18, marginRight: 70 }}>
            ssh krish@jetson · Jetson Orin Nano
          </div>
        </div>
        <div style={{ padding: "26px 34px", fontFamily: MONO, fontSize: 24, lineHeight: 1.45, color: FG, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
          {rows}
          {showFinalPrompt ? (
            <div>
              <Prompt />
              <Cursor frame={frame} />
            </div>
          ) : null}
        </div>
      </div>
    </AbsoluteFill>
  );
};
