import React from "react";
import { Composition } from "remotion";
import { Airlock } from "./Airlock";
import { FPS, TOTAL } from "./timeline";

export const RemotionRoot: React.FC = () => {
  return (
    <Composition id="Airlock" component={Airlock} durationInFrames={TOTAL} fps={FPS} width={1920} height={1080} />
  );
};
