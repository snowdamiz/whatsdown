// Explainer soundtrack: the user's track (~/Desktop/indie.mp3), re-arranged on bar lines to fit the story,
// with sound design tied to the motion. No pitched beeps: noise whooshes, sub hits and a few recorded samples.
// node audio.mjs -> work/audio.wav (48 kHz stereo float, unnormalized; the mux step sets loudness)
// It loops: one pass is 1488 frames, and everything that rings past the end wraps onto the start.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { homedir } from "node:os";

const SR = 48000, DUR = 1488 / 30, N = Math.round(SR * DUR), B = 0.6122;
const SFX = "/Users/sn0w/.claude/skills/brag/assets/sfx/";
const G = k => 0.703 + B * k; // kicks: what the picture cuts to (same grid as explainer.html)
const S = k => 0.318 + B * k; // the pickup before each kick: where the song changes section, so the splices go here
const decode = f => { const b = execFileSync("ffmpeg", ["-loglevel", "error", "-i", f, "-f", "f32le", "-ac", "2", "-ar", String(SR), "-"], { maxBuffer: 1 << 28 }); return new Float32Array(b.buffer, b.byteOffset, b.length / 4); };

const L = new Float32Array(N), R = new Float32Array(N);
// ---- music: verse, chorus, verse, chorus, the chorus's last two bars, the final hit and its fade
const mus = decode(homedir() + "/Desktop/indie.mp3"), MN = mus.length / 2;
const SEG = [ // [dest start, dest end, source offset in beats, tail]  (source time = dest time - offset * B)
  [0, S(32), 0, 1.3], // the original's final hit rings on over the splice: the verse starts from the track's opening silence
  [S(32), S(48), 32],
  [S(48), S(64), 32],
  [S(64), Infinity, 40],
];
const XF = .012; // equal-power crossfade at every splice, centred on the bar line
for (const [a, b, off, tail = 0] of SEG) {
  const i0 = Math.max(0, Math.round((a - XF) * SR)), i1 = Math.round(Math.min(b + Math.max(XF, tail), off * B + MN / SR) * SR);
  for (let i = i0; i < i1; i++) {
    const tt = i / SR, si = Math.round((tt - off * B) * SR);
    if (si < 0 || si >= MN) continue;
    let g = 1;
    if (a > 0 && tt < a + XF) g *= Math.sin(Math.PI / 2 * Math.min(1, (tt - a + XF) / (2 * XF)));
    if (tail && tt > b + .3) g *= Math.cos(Math.PI / 2 * Math.min(1, (tt - b - .3) / (tail - .3)));
    else if (!tail && b < Infinity && tt > b - XF) g *= Math.cos(Math.PI / 2 * Math.min(1, (tt - b + XF) / (2 * XF)));
    const j = i % N; L[j] += mus[si * 2] * g; R[j] += mus[si * 2 + 1] * g; // the fade past the loop point continues under the next pass
  }
}

// ---- effects bus, mixed in at the end
const EL = new Float32Array(N), ER = new Float32Array(N);
const place = (st, t, g, pan = 0) => {
  const i0 = Math.round(t * SR), gl = g * Math.min(1, 1 - pan), gr = g * Math.min(1, 1 + pan);
  for (let i = 0; i * 2 + 1 < st.length; i++) { const j = ((i0 + i) % N + N) % N; EL[j] += st[i * 2] * gl; ER[j] += st[i * 2 + 1] * gr; }
};
const cache = {};
const sample = (name, t, g, pan = 0) => place(cache[name] ??= decode(SFX + name), t, g, pan);
let seed = 9; const rnd = () => (seed = seed * 16807 % 2147483647) / 2147483647 * 2 - 1;
function whoosh(t, dur, { f0 = 300, f1 = 2400, peak = .6, pan0 = 0, pan1 = 0, g = 1, rev = false } = {}) {
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
  place(st, t, g * 3.2);
}
function sub(t, g = 1) {
  const n = Math.round(1.1 * SR), st = new Float32Array(n * 2); let ph = 0;
  for (let i = 0; i < n; i++) { const tt = i / SR, f = 38 + 34 * Math.exp(-tt / .12); ph += f / SR; const v = Math.sin(2 * Math.PI * ph) * Math.min(1, tt / .008) * Math.exp(-tt / .38); st[i * 2] = st[i * 2 + 1] = v; }
  place(st, t, g * .5);
}
const seal = (t, pan = 0, g = .22) => whoosh(t, .3, { f0: 1800, f1: 7000, peak: .5, pan0: pan, pan1: pan + .1, g }); // a bright little swish as something seals

// 1 · the opening card: the field bursts on the first beat, then the title flies through the camera
sub(G(0), .75); whoosh(G(0) - .15, 1.2, { f0: 180, f1: 3200, peak: .2, g: .5 });
whoosh(G(4.6) - .1, .7, { f0: 500, f1: 3600, peak: .5, g: .5 });
// 2 · typing, send, seal, the flight through the servers, unsealed on Ada's phone
Array.from({ length: 13 }, (_, k) => G(6.09) + k * .085).forEach((t, k) => sample(`keyboard/keypress-${String([3, 7, 12, 18, 5, 9, 14, 21, 2, 11, 16, 24, 8][k]).padStart(3, "0")}.wav`, t, 1.5, -.45));
sample("interface/click_002.ogg", G(8), .8, -.45);
seal(G(8.55), -.4);
whoosh(G(9), 2.0, { f0: 300, f1: 1900, peak: .5, pan0: -.6, pan1: .6, g: .3 });
seal(G(11.2), .45, .16); sample("interface/drop_002.ogg", G(11.05), .35, .5);
// into the drop
whoosh(G(15.55) - .05, .38, { f0: 400, f1: 5000, rev: true, g: .5 });
sub(G(16), 1); sample("impact/impactSoft_heavy_001.ogg", G(16), .35);
whoosh(G(16) - .05, 1.0, { f0: 2500, f1: 250, peak: .12, pan0: .6, pan1: .2, g: .45 });
// 3 · the ratchet: a tick as each message lands on its key, and the key breaking into dots
for (let k = 0; k < 7; k++) {
  sample("ui/switch" + [3, 7, 11, 15, 19, 23, 27][k] + ".ogg", G(17 + k), .45, 0);
  seal(G(17 + k) - .1, 0, .12);
  sample("impact/impactGlass_light_00" + [1, 2, 3][k % 3] + ".ogg", G(17 + k) + .12, .09, (k % 2 ? .2 : -.2));
}
whoosh(G(24) - .42, .6, { f0: 600, f1: 3200, peak: .6, g: .4 });
// 4 · three messages through the gate, into the queue
[G(25.3), G(26.2), G(27.1)].forEach((a, n) => {
  seal(a + .42, -.1 + n * .05, .25);
  sample("casino/card-place-" + (n + 1) + ".ogg", a + 1.28, .28, .55);
});
// 5 · the callback, the phones return, the directory hands over a key
whoosh(G(31.35) - .05, .42, { f0: 3000, f1: 400, rev: true, g: .45 });
sub(G(32), .8); sample("impact/impactSoft_medium_001.ogg", G(32), .6);
whoosh(G(34.7) - .05, .8, { f0: 350, f1: 2800, peak: .45, g: .45 });
sample("interface/drop_001.ogg", G(36), .3, 0);
sample("casino/card-slide-2.ogg", G(37), .35, -.35);
// 6 · the lie: the key flips, the message is sealed to the wrong key, opened on the server, sealed again
sample("interface/glitch_004.ogg", G(40.8), .2, -.4);
sample("interface/click_002.ogg", G(41.5), .7, -.45); seal(G(41.95), -.4);
whoosh(G(42.3), 1.1, { f0: 300, f1: 1500, peak: .5, pan0: -.6, pan1: 0, g: .28 });
sample("interface/glitch_002.ogg", G(43.4), .16, 0); sub(G(43.4), .35);
seal(G(44.3), 0, .2);
whoosh(G(44.8), 1.1, { f0: 300, f1: 1500, peak: .5, pan0: 0, pan1: .6, g: .28 });
seal(G(46), .45, .14);
// 7 · the drop into the log; three entries appended; the proof lights up
whoosh(G(47.55) - .05, .38, { f0: 400, f1: 5000, rev: true, g: .5 });
sub(G(48), 1); sample("impact/impactSoft_heavy_001.ogg", G(48), .35);
whoosh(G(48) - .05, 1.0, { f0: 2500, f1: 250, peak: .12, pan0: -.2, pan1: .4, g: .45 });
[G(50), G(51), G(52)].forEach((a, n) => sample("casino/card-place-" + (n + 2) + ".ogg", a, .25, .35));
whoosh(G(53), .9, { f0: 400, f1: 3000, peak: .7, pan0: .3, pan1: .3, g: .25 });
sample("interface/click_005.ogg", G(54), .5, .45);
// 8 · the checkpoint; five witnesses check and sign
whoosh(G(55.9) - .05, .6, { f0: 500, f1: 2500, peak: .5, pan0: .3, pan1: .3, g: .35 });
[G(57.4), G(57.9), G(58.4), G(59.3), G(59.8)].forEach((a, n) => sample("ui/click" + [1, 2, 3, 4, 5][n] + ".ogg", a, .45, .1 + (n - 2) * .12));
sample("casino/chip-lay-1.ogg", G(58.4) + .45, .35, .35);
// 9 · the log forks; two majorities sign; C signed both; the verdict
sample("casino/card-slide-3.ogg", G(64), .3, .35); whoosh(G(64) - .05, .7, { f0: 350, f1: 2400, peak: .4, pan0: .3, pan1: .4, g: .35 });
sample("interface/glitch_004.ogg", G(65), .14, .4);
[G(65.6), G(65.8), G(66), G(66.2), G(66.4), G(66.6)].forEach((a, n) => sample("ui/click" + [1, 2, 3, 3, 4, 5][n] + ".ogg", a + .6, .35, .35));
sub(G(67), .45);
sub(G(67.5), .9); sample("impact/impactSoft_heavy_003.ogg", G(67.5), .7, -.3);
// 10 · everything drawn into the mark, blue floods out on the final hit, then drains back for the loop
whoosh(G(71.1) - .05, .9, { f0: 3500, f1: 300, rev: true, g: .5 });
sub(G(72), 1); sample("impact/impactSoft_medium_004.ogg", G(72), .6);
whoosh(DUR - 1.45, .55, { f0: 2400, f1: 350, rev: true, g: .32 });

// ---- mix: effects under the music
let pk = 0;
for (let i = 0; i < N; i++) { L[i] += EL[i] * .55; R[i] += ER[i] * .55; pk = Math.max(pk, Math.abs(L[i]), Math.abs(R[i])); }
const wav = (a, b) => {
  const out = Buffer.alloc(44 + N * 8);
  out.write("RIFF", 0); out.writeUInt32LE(36 + N * 8, 4); out.write("WAVEfmt ", 8); out.writeUInt32LE(16, 16);
  out.writeUInt16LE(3, 20); out.writeUInt16LE(2, 22); out.writeUInt32LE(SR, 24); out.writeUInt32LE(SR * 8, 28); out.writeUInt16LE(8, 32); out.writeUInt16LE(32, 34);
  out.write("data", 36); out.writeUInt32LE(N * 8, 40);
  for (let i = 0; i < N; i++) { out.writeFloatLE(a[i], 44 + i * 8); out.writeFloatLE(b[i], 48 + i * 8); }
  return out;
};
writeFileSync(new URL("audio.wav", import.meta.url), wav(L, R));
writeFileSync(new URL("fx.wav", import.meta.url), wav(EL.map(v => v * .55), ER.map(v => v * .55))); // the effects alone, for checking the balance
console.log("peak", pk.toFixed(3), "duration", DUR.toFixed(3));
