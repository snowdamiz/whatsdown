// v2 soundtrack: the user's track (~/Desktop/idea.mp3, 120 BPM) with one cut, and a few quiet effects for emphasis.
// node audio2.mjs -> work/audio2.wav (48 kHz stereo float, unnormalized; mux.sh sets loudness)
// It loops: one pass is 2580 frames; the final hit's fade wraps onto the track's opening.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { homedir } from "node:os";

const SR = 48000, DUR = 2580 / 30, N = Math.round(SR * DUR);
const SFX = "/Users/sn0w/.claude/skills/brag/assets/sfx/";
const G = k => 0.18 + 0.5 * k; // kicks (same grid as explainer2.html)
const decode = f => { const b = execFileSync("ffmpeg", ["-loglevel", "error", "-i", f, "-f", "f32le", "-ac", "2", "-ar", String(SR), "-"], { maxBuffer: 1 << 29 }); return new Float32Array(b.buffer, b.byteOffset, b.length / 4); };

const L = new Float32Array(N), R = new Float32Array(N);
// ---- music: the track as it is up to two beats before the outro's third bar, then its last two beats, final hit and fade
const mus = decode(homedir() + "/Desktop/idea.mp3"), MN = mus.length / 2;
const CUT = G(166) - .03, SKIP = 12; // dest CUT <- source CUT + 12s: the outro's repeats are dropped, its pickup into the final hit is kept
const XF = .015;
for (let i = 0; i < N + Math.round(4 * SR); i++) {
  const tt = i / SR;
  const parts = [];
  if (tt < CUT + XF) parts.push([tt, tt < CUT - XF ? 1 : Math.cos(Math.PI / 2 * (tt - CUT + XF) / (2 * XF))]);
  if (tt > CUT - XF) parts.push([tt + SKIP, tt > CUT + XF ? 1 : Math.sin(Math.PI / 2 * (tt - CUT + XF) / (2 * XF))]);
  for (const [st, g] of parts) {
    const si = Math.round(st * SR); if (si < 0 || si >= MN) continue;
    const j = i % N; L[j] += mus[si * 2] * g; R[j] += mus[si * 2 + 1] * g; // the fade past the loop point continues under the next pass
  }
}

// ---- effects bus: sparing, soft, sitting under the music
const EL = new Float32Array(N), ER = new Float32Array(N);
// Every effect is levelled against the music around it: `rel` dB relative to the music's RMS there (its loudest 100 ms against the music's 400 ms).
const rms = (a, i0, n, stride = 2) => { let s = 0, c = 0; for (let i = Math.max(0, i0); i < Math.min(a.length / stride, i0 + n); i++) { const v = (a[i * stride] + a[i * stride + 1]) / 2; s += v * v; c++; } return Math.sqrt(s / Math.max(1, c)); };
const peakRms = st => { const n = st.length / 2, w = Math.min(n, Math.round(.1 * SR)); let m = 1e-9; for (let i = 0; i + w <= n; i += Math.max(1, w >> 2)) m = Math.max(m, rms(st, i, w)); return m; };
const musicAt = t => { const i = Math.round((t - .2) * SR), n = Math.round(.4 * SR); let s = 0; for (let k = i; k < i + n; k++) { const j = (k % N + N) % N, v = (L[j] + R[j]) / 2; s += v * v; } return Math.sqrt(s / n); };
const place = (st, t, rel, pan = 0) => {
  const g = musicAt(t + .05) * 10 ** (rel / 20) / peakRms(st);
  const i0 = Math.round(t * SR), gl = g * Math.min(1, 1 - pan), gr = g * Math.min(1, 1 + pan);
  for (let i = 0; i * 2 + 1 < st.length; i++) { const j = ((i0 + i) % N + N) % N; EL[j] += st[i * 2] * gl; ER[j] += st[i * 2 + 1] * gr; }
};
const cache = {};
const sample = (name, t, rel, pan = 0) => place(cache[name] ??= decode(SFX + name), t, rel, pan);
let seed = 9; const rnd = () => (seed = seed * 16807 % 2147483647) / 2147483647 * 2 - 1;
function whoosh(t, dur, { f0 = 300, f1 = 2400, peak = .6, pan0 = 0, pan1 = 0, rel = -14, rev = false } = {}) {
  const n = Math.round(dur * SR), st = new Float32Array(n * 2);
  let l1 = 0, l2 = 0, h = 0, pin = 0;
  for (let i = 0; i < n; i++) {
    const p = i / n, fc = f0 * (f1 / f0) ** p, a = 1 - Math.exp(-2 * Math.PI * fc / SR), ah = 1 - Math.exp(-2 * Math.PI * fc * .35 / SR);
    pin = .97 * pin + .03 * rnd(); const x = rnd() * .5 + pin * 4;
    l1 += (x - l1) * a; l2 += (l1 - l2) * a; h += (l2 - h) * ah; const y = l2 - h;
    const env = rev ? Math.pow(p, 3) * Math.min(1, (1 - p) * 60) : (p < peak ? Math.pow(p / peak, 2) : Math.exp(-(p - peak) / (1 - peak) * 4));
    const pan = pan0 + (pan1 - pan0) * p;
    st[i * 2] = y * env * Math.min(1, 1 - pan); st[i * 2 + 1] = y * env * Math.min(1, 1 + pan);
  }
  place(st, t, rel);
}
function sub(t, rel = -12) {
  const n = Math.round(1.1 * SR), st = new Float32Array(n * 2); let ph = 0;
  for (let i = 0; i < n; i++) { const tt = i / SR, f = 40 + 30 * Math.exp(-tt / .12); ph += f / SR; const v = Math.sin(2 * Math.PI * ph) * Math.min(1, tt / .01) * Math.exp(-tt / .35); st[i * 2] = st[i * 2 + 1] = v; }
  place(st, t, rel);
}
const seal = (t, pan = 0, rel = -16) => whoosh(t, .45, { f0: 1600, f1: 6000, peak: .55, pan0: pan, pan1: pan + .1, rel }); // a soft bright swish as something seals

// the first message: typed, sent, sealed, received
Array.from({ length: 13 }, (_, k) => G(11) + k * .11).forEach((t, k) => sample(`keyboard/keypress-${String([3, 7, 12, 18, 5, 9, 14, 21, 2, 11, 16, 24, 8][k]).padStart(3, "0")}.wav`, t, -21, -.45));
sample("interface/click_002.ogg", G(14), -15, -.45);
seal(G(15.2), -.4);
sample("interface/drop_002.ogg", G(20.6), -16, .5);
// into the blue; a quiet tick as each message lands on its key; the blue lifts away
whoosh(G(31) - .1, 1.1, { f0: 300, f1: 2200, peak: .5, pan0: .4, pan1: 0, rel: -15 });
[36, 39, 42, 45].forEach((k, n) => sample("ui/switch" + [3, 11, 19, 27][n] + ".ogg", G(k), -19, 0));
whoosh(G(47) - .05, 1.1, { f0: 500, f1: 2600, peak: .55, rel: -16 });
// the directory hands over a key; the key turns out to be the server's; the server reads the message
sample("casino/card-slide-2.ogg", G(76), -16, -.3);
sample("interface/glitch_004.ogg", G(84) + .15, -16, -.4);
sub(G(89.6), -12);
// into the log; the proof lands
whoosh(G(95.6) - .1, 1.2, { f0: 300, f1: 2200, peak: .5, pan0: -.2, pan1: .4, rel: -15 });
sample("interface/click_005.ogg", G(110.5), -16, .45);
// a majority signs; the fork is caught
sample("casino/chip-lay-1.ogg", G(125) + .75, -15, .3);
sub(G(149), -15);
sub(G(150), -10); sample("impact/impactSoft_heavy_003.ogg", G(150), -11, -.3);

// ---- mix
let pk = 0;
for (let i = 0; i < N; i++) { L[i] += EL[i]; R[i] += ER[i]; pk = Math.max(pk, Math.abs(L[i]), Math.abs(R[i])); }
const wav = (a, b) => {
  const out = Buffer.alloc(44 + N * 8);
  out.write("RIFF", 0); out.writeUInt32LE(36 + N * 8, 4); out.write("WAVEfmt ", 8); out.writeUInt32LE(16, 16);
  out.writeUInt16LE(3, 20); out.writeUInt16LE(2, 22); out.writeUInt32LE(SR, 24); out.writeUInt32LE(SR * 8, 28); out.writeUInt16LE(8, 32); out.writeUInt16LE(32, 34);
  out.write("data", 36); out.writeUInt32LE(N * 8, 40);
  for (let i = 0; i < N; i++) { out.writeFloatLE(a[i], 44 + i * 8); out.writeFloatLE(b[i], 48 + i * 8); }
  return out;
};
writeFileSync(new URL("audio2.wav", import.meta.url), wav(L, R));
writeFileSync(new URL("fx2.wav", import.meta.url), wav(EL, ER));
console.log("peak", pk.toFixed(3), "duration", DUR.toFixed(3));
