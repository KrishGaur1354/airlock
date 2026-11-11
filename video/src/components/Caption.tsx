import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";

// Bottom-centre pill. `from`/`to` are absolute frames of the parent timeline.
export const Caption: React.FC<{ text: string; from: number; to: number }> = ({ text, from, to }) => {
  const frame = useCurrentFrame();
  if (frame < from || frame > to) return null;
  const opacity = interpolate(frame, [from, from + 8, to - 8, to], [0, 1, 1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const y = interpolate(frame, [from, from + 8], [10, 0], { extrapolateRight: "clamp" });
  return (
    <AbsoluteFill style={{ justifyContent: "flex-end", alignItems: "center", paddingBottom: 56, pointerEvents: "none" }}>
      <div
        style={{
          opacity,
          transform: `translateY(${y}px)`,
          fontFamily: "'Segoe UI', Inter, Helvetica, Arial, sans-serif",
          fontSize: 34,
          fontWeight: 600,
          color: "#fff",
          background: "rgba(0,0,0,0.7)",
          padding: "12px 30px",
          borderRadius: 999,
          letterSpacing: 0.2,
          boxShadow: "0 8px 30px rgba(0,0,0,0.25)",
        }}
      >
        {text}
      </div>
    </AbsoluteFill>
  );
};
