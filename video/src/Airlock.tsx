import React from "react";
import { AbsoluteFill } from "remotion";
import { linearTiming, TransitionSeries } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { Slide } from "./components/Slide";
import { Terminal, TermData } from "./components/Terminal";
import { Box, Focus, Shot, shotBoxes } from "./components/Shot";
import { Caption } from "./components/Caption";
import { BLOCKS, BlockId, CAPTIONS, XFADE } from "./timeline";

// Real output captured from the Jetson by capture/capture.py (never edited).
import aVerify from "../public/term/a-verify.json";
import bImport from "../public/term/b-import.json";
import cTamper from "../public/term/c-tamper.json";
import cImport from "../public/term/c-import.json";

const slot = (id: BlockId) => BLOCKS.find((b) => b.id === id)!.frames;

const b01 = shotBoxes("01-healthy").boxes;
const b03 = shotBoxes("03-chat-memo").boxes;
const b04 = shotBoxes("04-chat-injection").boxes;
const b05 = shotBoxes("05-tampered").boxes;
const b06 = shotBoxes("06-poam").boxes;

// 0:25-0:36  overview 1 s -> gauge 3 s -> SC-7 card 1.5 s + probe text 2.5 s -> RA-5 3 s
const gaugeAndTitle: Box = { x: b01.banner.x, y: b01.banner.y, w: 960, h: b01.banner.h };
const focus01: Focus[] = [
  { frames: 30 },
  { frames: 90, box: gaugeAndTitle, ring: b01.gauge },
  { frames: 45, box: b01.sc7 },
  { frames: 75, box: b01.boundary, ring: b01.probe },
  { frames: 90, box: b01.ra5 },
];
// 0:36-0:40  SSP: whole page, then the header + "Controls satisfied 10 of 11"
const focus02: Focus[] = [{ frames: 30 }, { frames: 90, box: { x: 20, y: 20, w: 900, h: 320 }, ring: null }];
// 0:40-0:52  chat answer, then the refusal (same framing, crossfaded)
const focus03: Focus[] = [{ frames: slot("shot03"), box: b03.chat, ring: b03.reply }];
const focus04: Focus[] = [{ frames: slot("shot04"), box: b04.chat, ring: b04.reply }];
// 0:58-1:07  red banner -> SI-7 card, then the new POA&M item
const focus05: Focus[] = [{ frames: 20 }, { frames: 65, box: b05.banner }, { frames: 60, box: b05.si7 }];
// POA&M: the new SI-7 item, weakness first, then pan right to the remediation + "open" status
const focus06: Focus[] = [
  { frames: 60, box: { x: 20, y: 120, w: 1130, h: 110 }, ring: b06.si7 },
  { frames: 65, box: { x: 1100, y: 120, w: 800, h: 110 }, ring: b06.si7, zoom: 1.39 },
];

const render = (id: BlockId): React.ReactNode => {
  switch (id) {
    case "slide1": return <Slide src="slides/slide1.png" />;
    case "termA": return <Terminal steps={[aVerify as TermData]} slot={slot("termA")} />;
    case "termB": return <Terminal steps={[bImport as TermData]} slot={slot("termB")} />;
    case "shot01": return <Shot name="01-healthy" focus={focus01} />;
    case "shot02": return <Shot name="02-ssp" focus={focus02} bg="#f4f5f7" />;
    case "shot03": return <Shot name="03-chat-memo" focus={focus03} />;
    case "shot04": return <Shot name="04-chat-injection" focus={focus04} startZoomed />;
    case "termC":
      return (
        <Terminal steps={[cTamper as TermData, cImport as TermData]} slot={slot("termC")}
          cps={40} hold={62} startDelay={4} enterPause={4} gap={4} />
      );
    case "shot05": return <Shot name="05-tampered" focus={focus05} />;
    case "shot06": return <Shot name="06-poam" focus={focus06} bg="#f4f5f7" dim={0.08} />;
    case "slide5": return <Slide src="slides/slide5.png" />;
    case "slide6": return <Slide src="slides/slide6.png" />;
  }
};

export const Airlock: React.FC = () => {
  return (
    <AbsoluteFill style={{ backgroundColor: "#000" }}>
      <TransitionSeries>
        {BLOCKS.map((b, i) => {
          const last = i === BLOCKS.length - 1;
          return (
            <React.Fragment key={b.id}>
              {/* outgoing block runs XFADE frames into the next slot so the next block starts on its exact second */}
              <TransitionSeries.Sequence durationInFrames={b.frames + (last ? 0 : XFADE)} name={b.label}>
                {render(b.id)}
              </TransitionSeries.Sequence>
              {last ? null : (
                <TransitionSeries.Transition presentation={fade()} timing={linearTiming({ durationInFrames: XFADE })} />
              )}
            </React.Fragment>
          );
        })}
      </TransitionSeries>
      {CAPTIONS.map((c) => (
        <Caption key={c.text} {...c} />
      ))}
    </AbsoluteFill>
  );
};
