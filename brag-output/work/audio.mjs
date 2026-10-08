// Soundtrack for the Morse brag video: music and effects written as one piece, 120 BPM in D major.
// node audio.mjs -> work/audio.wav (48 kHz stereo). Loudness is set later by ffmpeg loudnorm.
import { writeFileSync } from "node:fs";

const SR = 48000, DUR = 23.0, N = Math.round(SR * DUR);
const L = new Float32Array(N), R = new Float32Array(N);      // dry bus
const SL = new Float32Array(N), SRv = new Float32Array(N);   // reverb send
const bus = {pad: [new Float32Array(N), new Float32Array(N)], arp: [new Float32Array(N), new Float32Array(N)], bass: [new Float32Array(N), new Float32Array(N)]};
const busSend = {pad: .5, arp: .45, bass: 0};           // music buses are filtered and ducked first, then sent
const mtof = m => 440 * 2 ** ((m - 69) / 12);
let seed = 7; const rnd = () => (seed = seed * 16807 % 2147483647) / 2147483647 * 2 - 1;

// Place a mono voice into a bus with pan (-1..1) and a reverb send.
globalThis.BUS = bus;
function add(buf, start, gain, pan = 0, send = 0, bus = "dry") {
  const i0 = Math.round(start * SR), gl = gain * Math.cos((pan + 1) * Math.PI / 4), gr = gain * Math.sin((pan + 1) * Math.PI / 4);
  const [a, b] = bus === "dry" ? [L, R] : globalThis.BUS[bus];
  for (let i = 0; i < buf.length; i++) {
    const j = i0 + i; if (j < 0 || j >= N) continue;
    a[j] += buf[i] * gl; b[j] += buf[i] * gr;
    if (send && bus === "dry") { SL[j] += buf[i] * gl * send; SRv[j] += buf[i] * gr * send; }
  }
}

// Band-limited saw wavetable
const TW = 4096, saw = new Float32Array(TW);
for (let h = 1; h <= 10; h++) for (let i = 0; i < TW; i++) saw[i] += Math.sin(2 * Math.PI * h * i / TW) / h ** 1.6 * (h % 2 ? 1 : .5);
const tab = (ph) => { const x = (ph % 1) * TW, i = x | 0; return saw[i] + (saw[(i + 1) % TW] - saw[i]) * (x - i); };

// ---------------------------------------------------------------- Harmony
const CH = [ // [start, end, pad notes, bass root]
  [0, 4, [57, 61, 64, 66, 69], 38],      // Dmaj9
  [4, 7, [57, 61, 62, 66, 69], 35],      // Bm9
  [7, 11, [57, 59, 62, 66, 69], 31],     // Gmaj9
  [11, 14, [55, 59, 62, 66, 67], 40],    // Em9
  [14, 16, [55, 57, 62, 64, 69], 33],    // A7sus4
  [16, 18, [57, 61, 64, 66, 69], 38],    // Dmaj9
  [18, 20, [57, 61, 62, 66, 69], 35],    // Bm9
  [20, 21, [57, 59, 62, 66, 71], 31],    // Gmaj9 (IV)
  [21, 23, [57, 61, 64, 66, 69, 74], 38] // D (I)
];
const chordAt = t => CH.find(c => t >= c[0] && t < c[1]) || CH[CH.length - 1];

// Pad: three detuned saws per note, slow attack, overlapping releases
for (const [a, b, notes] of CH) {
  const att = .35, rel = a >= 20 ? 3 : .7, len = Math.round((b - a + rel) * SR);
  notes.forEach((m, k) => {
    const buf = new Float32Array(len), f = mtof(m), dets = [-.07, 0, .08].map(c => f * 2 ** (c / 12));
    const ph = [Math.random(), Math.random(), Math.random()];
    for (let i = 0; i < len; i++) {
      const t = i / SR, env = Math.min(1, t / att) * (t > b - a ? Math.exp(-(t - (b - a)) / (rel / 3)) : 1);
      let v = 0; for (let d = 0; d < 3; d++) { ph[d] += dets[d] / SR; v += tab(ph[d]); }
      buf[i] = v / 3 * env;
    }
    add(buf, a, .03, (k / (notes.length - 1)) * 1.2 - .6, 0, "pad");
  });
}

// Bass: 8th-note pulses on the root, from the pull-back on, resting in the night intro
for (let t = 2.0; t < 20.0; t += .25) {
  if (t >= 11 && t < 12.5) continue;
  const root = chordAt(t)[3], f = mtof(root), len = Math.round(.3 * SR), buf = new Float32Array(len);
  const accent = Math.abs(t % .5) < 1e-6 ? 1 : .7;
  for (let i = 0; i < len; i++) { const tt = i / SR, e = Math.min(1, tt / .006) * Math.exp(-tt / .16); buf[i] = (Math.sin(2 * Math.PI * f * tt) + .35 * Math.sin(4 * Math.PI * f * tt) + .12 * Math.sin(6 * Math.PI * f * tt)) * e * accent; }
  add(buf, t, .2, 0, 0, "bass");
}

// Arp keyed in Morse: the wordmark "MORSE" (-- --- .-. ... .), one 16th per unit, cycling the chord's tones
const pattern = []; // [unitStart, units]
{ let u = 0; const word = ["--", "---", ".-.", "...", "."];
  word.forEach((letter, li) => { [...letter].forEach((s, si) => { const n = s === "-" ? 3 : 1; pattern.push([u, n]); u += n + (si < letter.length - 1 ? 1 : 0); }); u += li < word.length - 1 ? 3 : 7; });
  pattern.total = u; }
{ const U = .125; let step = 0;
  for (let loop = 0; ; loop++) {
    const base = 2.0 + loop * pattern.total * U; if (base > 20) break;
    for (const [u, n] of pattern) {
      const t = base + u * U; if (t >= 19.75) break;
      const notes = chordAt(t)[2], m = notes[(step * 2) % notes.length] + 12 + (step % 5 === 4 ? 12 : 0); step++;
      const f = mtof(m), dec = n === 3 ? .32 : .11, len = Math.round((dec * 4) * SR), buf = new Float32Array(len);
      for (let i = 0; i < len; i++) { const tt = i / SR, e = Math.min(1, tt / .003) * Math.exp(-tt / dec); buf[i] = (Math.sin(2 * Math.PI * f * tt) + .25 * Math.sin(4 * Math.PI * f * tt + .5) + .08 * Math.sin(6 * Math.PI * f * tt)) * e; }
      const quiet = t >= 11 && t < 12.5 ? .5 : 1;
      add(buf, t, .05 * quiet, step % 2 ? .35 : -.35, 0, "arp");
    }
  }
}

// ---------------------------------------------------------------- Drums
const kicks = [];
function kick(t, g = 1) {
  kicks.push(t);
  const len = Math.round(.45 * SR), buf = new Float32Array(len); let ph = 0;
  for (let i = 0; i < len; i++) { const tt = i / SR, f = 52 + 95 * Math.exp(-tt / .035); ph += f / SR; buf[i] = Math.sin(2 * Math.PI * ph) * Math.exp(-tt / .2) * Math.min(1, tt / .002) + (i < 60 ? rnd() * .15 * (1 - i / 60) : 0); }
  add(buf, t, .5 * g, 0, 0);
}
function clap(t, g = 1) {
  const len = Math.round(.35 * SR), buf = new Float32Array(len); let lp = 0, hp = 0, prev = 0;
  for (let i = 0; i < len; i++) {
    const tt = i / SR, bursts = [0, .011, .022].reduce((s, o) => s + (tt >= o ? Math.exp(-(tt - o) / (o === .022 ? .09 : .008)) : 0), 0);
    const n = rnd(); lp += (n - lp) * .45; hp = lp - prev; prev = lp; buf[i] = hp * bursts;
  }
  add(buf, t, .085 * g, .05, .55);
}
function hat(t, g = 1) {
  const len = Math.round(.06 * SR), buf = new Float32Array(len); let prev = 0;
  for (let i = 0; i < len; i++) { const n = rnd(), h = n - prev; prev = n; buf[i] = h * Math.exp(-i / SR / .014); }
  add(buf, t, .03 * g, .3, .15);
}
for (let bar = 1; bar < 10; bar++) {           // bars of 2s; bar 1 starts at 2.0
  const b0 = bar * 2;
  for (let beat = 0; beat < 4; beat++) {
    const t = b0 + beat * .5;
    if (t >= 19.75) break;
    const night = t >= 11 && t < 12.5, build = t >= 12.5 && t < 15.5;
    if (!night) {
      if (build) { if (beat === 0 || beat === 2) kick(t, .8); }
      else { if (beat === 0 || beat === 2) kick(t); if (beat === 1) kick(t + .25, .6); }
      if (!build && (beat === 1 || beat === 3)) clap(t);
    }
    hat(t + .25, night ? .5 : 1);
    if (!night && !build) hat(t, .45);
  }
}
kick(19.75, .9); // the wipe lands on a kick

// ---------------------------------------------------------------- Effects (in key, in the same room)
function tone(t, f, dur, g, pan = 0, send = .45) { // a Morse key tone: soft edges, a touch of 2nd harmonic
  const len = Math.round((dur + .02) * SR), buf = new Float32Array(len);
  for (let i = 0; i < len; i++) { const tt = i / SR, e = Math.min(1, tt / .006, Math.max(0, (dur - tt) / .012 + 1)); buf[i] = (Math.sin(2 * Math.PI * f * tt) + .15 * Math.sin(4 * Math.PI * f * tt)) * Math.max(0, Math.min(1, e)); }
  add(buf, t, g, pan, send);
}
function blip(t, m, g = 1, pan = 0) { // a bubble landing: a short pitched drop
  const f = mtof(m), len = Math.round(.2 * SR), buf = new Float32Array(len); let ph = 0;
  for (let i = 0; i < len; i++) { const tt = i / SR; ph += f * (1 + .25 * Math.exp(-tt / .015)) / SR; buf[i] = Math.sin(2 * Math.PI * ph) * Math.min(1, tt / .002) * Math.exp(-tt / .05); }
  add(buf, t, .07 * g, pan, .3);
}
function air(t, dur, g = 1, fLo = 400, fHi = 3000, pan = 0) { // filtered-noise breath: sweeps a band from fLo to fHi
  const len = Math.round(dur * SR), buf = new Float32Array(len); let lp1 = 0, lp2 = 0;
  for (let i = 0; i < len; i++) {
    const p = i / len, fc = fLo * (fHi / fLo) ** p, a = 1 - Math.exp(-2 * Math.PI * fc / SR), n = rnd();
    lp1 += (n - lp1) * a; lp2 += (lp1 - lp2) * a; const band = lp1 - lp2 * .85;
    buf[i] = band * Math.sin(Math.PI * p) ** 1.6;
  }
  add(buf, t, .16 * g, pan, .5);
}
function click(t, g = 1, pan = 0) {
  const len = Math.round(.03 * SR), buf = new Float32Array(len); let prev = 0;
  for (let i = 0; i < len; i++) { const n = rnd(), h = n - prev; prev = n; buf[i] = (h * .6 + Math.sin(2 * Math.PI * 2400 * i / SR) * .4) * Math.exp(-i / SR / .005); }
  add(buf, t, .05 * g, pan, .15);
}
function thud(t, g = 1, f0 = 160) {
  const len = Math.round(.3 * SR), buf = new Float32Array(len); let ph = 0, lp = 0;
  for (let i = 0; i < len; i++) { const tt = i / SR, f = f0 * (.7 + .3 * Math.exp(-tt / .03)); ph += f / SR; lp += (rnd() - lp) * .08; buf[i] = (Math.sin(2 * Math.PI * ph) * .8 + lp * .6) * Math.exp(-tt / .07) * Math.min(1, tt / .003); }
  add(buf, t, .12 * g, 0, .25);
}
function boom(t, g = 1) { // the verdict: a low D under a soft noise hit
  const len = Math.round(1.2 * SR), buf = new Float32Array(len); let ph = 0, lp = 0;
  for (let i = 0; i < len; i++) { const tt = i / SR, f = mtof(38) * (1 + .6 * Math.exp(-tt / .04)); ph += f / SR; lp += (rnd() - lp) * .05; buf[i] = (Math.sin(2 * Math.PI * ph) * Math.exp(-tt / .35) + lp * 1.2 * Math.exp(-tt / .12)) * Math.min(1, tt / .003); }
  add(buf, t, .3 * g, 0, .35);
}

// Hook: the sealed bubble chatters in Morse, then opens with a breath
[[0.02, .06], [0.1, .06], [0.18, .16], [0.4, .06]].forEach(([t, d]) => tone(t, mtof(81), d, .05, .2, .6));
air(0.4, 1.0, 1.1, 600, 4200, -.1);
blip(1.3, 86, 1, .25);                                  // reply lands (D6)
blip(2.25, 83, .7, .25); blip(2.65, 81, .7, -.2); blip(3.05, 86, .7, .2); blip(3.45, 81, .7, -.2);
air(3.0, .9, .4, 800, 4200, -.2); air(3.8, .9, .35, 800, 4200, -.2);
blip(3.72, 90, .6, .3);                                  // reaction
air(1.95, 1.6, .9, 200, 1800, 0);                         // the pull-back
blip(4.25, 93, .45, .5); blip(4.6, 90, .45, -.5);        // float pills
// Scroll to the username scene, typing, the request
air(6.5, 1.0, .7, 300, 2400, 0);
[7.95, 8.1, 8.25, 8.4].forEach((t, i) => click(t, .8, (i % 2 ? .1 : -.1)));
thud(8.8, .8, 180);
// Night unfolds; the switch; the scan seals each bubble with a dit
air(10.9, 1.1, .7, 200, 1600, 0);
click(12.5, 1.2); blip(12.52, 74, .5);
air(12.6, .95, 1.1, 500, 7000, 0);
[12.9, 12.969, 13.061, 13.157, 13.25, 13.343].forEach((t, i) => tone(t, mtof([81, 78, 81, 76, 78, 74][i]), .05, .04, i % 2 ? .25 : -.25, .55));
// Witnesses: slips land, the clash, the ring, the verdict
air(15.5, .7, .5, 400, 2000, 0);
thud(16.15, .8, 170); thud(16.55, .8, 150);
tone(17.0, mtof(62), .12, .06, 0, .4);
click(17.3, .8, .2);
boom(17.6, 1);
// Outro: the dash sweeps, then the mark keys itself, dit then dah
air(19.55, .8, 1.3, 250, 5000, 0);
tone(20.25, mtof(81), .09, .07, 0, .6);
tone(20.5, mtof(81), .32, .07, 0, .6);
blip(21.1, 86, .5);

// ---------------------------------------------------------------- Music buses: filter sweep + sidechain duck, then out
{
  const lerpExp = (a, b, p) => a * (b / a) ** Math.min(1, Math.max(0, p));
  const cutoff = t => {
    if (t < 1.95) return 1300;
    if (t < 3.6) return lerpExp(1300, 11000, (t - 1.95) / 1.65);
    if (t < 11) return 11000;
    if (t < 11.6) return lerpExp(11000, 1200, (t - 11) / .6);
    if (t < 12.5) return 1200;
    if (t < 15.55) return lerpExp(1200, 11000, ((t - 12.5) / 3.05) ** 2);
    return 11000;
  };
  // the hook sits back; the pull-back is the drop
  const level = t => t < 1.95 ? .8 : t < 3 ? lerpExp(.8, 1, (t - 1.95) / 1.05) : t >= 11 && t < 12.5 ? 1 : t >= 20 ? 1.5 : 1;
  const duck = new Float32Array(N).fill(1);
  for (const k of kicks) for (let i = Math.round(k * SR), e = Math.min(N, i + Math.round(.4 * SR)); i < e; i++) duck[i] = Math.min(duck[i], 1 - .45 * Math.exp(-(i / SR - k) / .1));
  for (const name of Object.keys(bus)) {
    const st = [[0, 0, 0, 0], [0, 0, 0, 0]]; let b0, b1, b2, a1, a2;
    const [bl, br] = bus[name], sendAmt = busSend[name];
    for (let i = 0; i < N; i++) {
      const t = i / SR;
      if (i % 32 === 0) {
        const w = 2 * Math.PI * Math.min(cutoff(t), 18000) / SR, q = .75, al = Math.sin(w) / (2 * q), c = Math.cos(w), a0 = 1 + al;
        b0 = (1 - c) / 2 / a0; b1 = (1 - c) / a0; b2 = b0; a1 = -2 * c / a0; a2 = (1 - al) / a0;
      }
      const g = level(t) * (name === "bass" ? 1 : duck[i]);
      for (const [buf, ch] of [[bl, 0], [br, 1]]) {
        const s = st[ch], x = buf[i], y = b0 * x + b1 * s[0] + b2 * s[1] - a1 * s[2] - a2 * s[3];
        s[1] = s[0]; s[0] = x; s[3] = s[2]; s[2] = y; buf[i] = y * g;
      }
      L[i] += bl[i]; R[i] += br[i]; SL[i] += bl[i] * sendAmt; SRv[i] += br[i] * sendAmt;
    }
  }
}

// ---------------------------------------------------------------- Freeverb
{
  const combs = [1116, 1188, 1277, 1356, 1422, 1491, 1557, 1617].map(d => Math.round(d * SR / 44100));
  const alls = [556, 441, 341, 225].map(d => Math.round(d * SR / 44100));
  const room = .84, damp = .45, wet = 1.0;
  const run = (inp, spread) => {
    const out = new Float32Array(N);
    const cs = combs.map(d => ({ b: new Float32Array(d + spread), i: 0, f: 0 }));
    const as = alls.map(d => ({ b: new Float32Array(d + spread), i: 0 }));
    for (let n = 0; n < N; n++) {
      const x = inp[n] * .015; let y = 0;
      for (const c of cs) { const o = c.b[c.i]; c.f = o * (1 - damp) + c.f * damp; c.b[c.i] = x + c.f * room; c.i = (c.i + 1) % c.b.length; y += o; }
      for (const a of as) { const o = a.b[a.i]; const v = -y + o; a.b[a.i] = y + o * .5; a.i = (a.i + 1) % a.b.length; y = v; }
      out[n] = y;
    }
    return out;
  };
  const wl = run(SL, 0), wr = run(SRv, 23);
  for (let i = 0; i < N; i++) { L[i] += wl[i] * wet * 3; R[i] += wr[i] * wet * 3; }
}

// ---------------------------------------------------------------- Master: gentle glue, fade the tail, write
let peak = 0;
for (let i = 0; i < N; i++) {
  const t = i / SR, fade = t > DUR - 1.2 ? Math.max(0, (DUR - t) / 1.2) ** 1.5 : 1, fin = Math.min(1, t / .01);
  L[i] = Math.tanh(L[i] * 1.4) / 1.4 * fade * fin; R[i] = Math.tanh(R[i] * 1.4) / 1.4 * fade * fin;
  peak = Math.max(peak, Math.abs(L[i]), Math.abs(R[i]));
}
const g = .89 / peak, data = Buffer.alloc(44 + N * 4);
data.write("RIFF", 0); data.writeUInt32LE(36 + N * 4, 4); data.write("WAVEfmt ", 8); data.writeUInt32LE(16, 16);
data.writeUInt16LE(1, 20); data.writeUInt16LE(2, 22); data.writeUInt32LE(SR, 24); data.writeUInt32LE(SR * 4, 28); data.writeUInt16LE(4, 32); data.writeUInt16LE(16, 34);
data.write("data", 36); data.writeUInt32LE(N * 4, 40);
for (let i = 0; i < N; i++) { data.writeInt16LE(Math.round(L[i] * g * 32767), 44 + i * 4); data.writeInt16LE(Math.round(R[i] * g * 32767), 46 + i * 4); }
writeFileSync(new URL("audio.wav", import.meta.url), data);
console.log("peak before normalize", peak.toFixed(3), "pattern units", pattern.total);
