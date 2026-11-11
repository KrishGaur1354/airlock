import React from "react";
import { AbsoluteFill, Img, interpolate, staticFile, useCurrentFrame, useVideoConfig } from "remotion";

// A still PNG exported from the deck, with a gentle 1.00 -> 1.03 push-in.
export const Slide: React.FC<{ src: string }> = ({ src }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const scale = interpolate(frame, [0, durationInFrames], [1, 1.03], { extrapolateRight: "clamp" });
  return (
    <AbsoluteFill style={{ backgroundColor: "#F9F8F5" }}>
      <Img src={staticFile(src)} style={{ width: 1920, height: 1080, transform: `scale(${scale})` }} />
    </AbsoluteFill>
  );
};
