// v2 soundtrack: the user's track (~/Desktop/indie.mp3) with sound design tied to the camera moves.
// No pitched beeps: noise whooshes, sub hits and a few recorded clicks/impacts, all sitting under the music.
// node audio2.mjs -> work/audio2.wav (48 kHz stereo, unnormalized; the mux step sets loudness)
// It loops: one pass is exactly 38 beats (698 frames), and everything that rings past the end wraps onto the start.
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { homedir } from "node:os";

const SR = 48000, DUR = 698 / 30, N = Math.round(SR * DUR);
const SFX = "/Users/sn0w/.claude/skills/brag/assets/sfx/";
const G = k => 0.318 + 0.6122 * k;
const decode = f => { const b = execFileSync("ffmpeg", ["-loglevel", "error", "-i", f, "-f", "f32le", "-ac", "2", "-ar", String(SR), "-"], { maxBuffer: 1 << 28 }); return new Float32Array(b.buffer, b.byteOffset, b.length / 4); };

const L = new Float32Array(N), R = new Float32Array(N);
// ---- music
const mus = decode(homedir() + "/Desktop/indie.mp3");
for (let i = 0; i * 2 + 1 < mus.length; i++) { L[i % N] += mus[i * 2]; R[i % N] += mus[i * 2 + 1]; } // the fade-out past the loop point continues under the next pass

// ---- effects bus, mixed in at the end
const EL = new Float32Array(N), ER = new Float32Array(N);
const place = (st, t, g, pan = 0) => { // st: interleaved stereo
  const i0 = Math.round(t * SR), gl = g * Math.min(1, 1 - pan), gr = g * Math.min(1, 1 + pan);
  for (let i = 0; i * 2 + 1 < st.length; i++) { const j = ((i0 + i) % N + N) % N; EL[j] += st[i * 2] * gl; ER[j] += st[i * 2 + 1] * gr; }
};
const sample = (name, t, g, pan = 0) => place(decode(SFX + name), t, g, pan);
let seed = 9; const rnd = () => (seed = seed * 16807 % 2147483647) / 2147483647 * 2 - 1;

// A whoosh: noise through a band that sweeps f0 -> f1, swelling to `peak` (0..1 of its length) then falling away,
// panning pan0 -> pan1. `rev` makes it a reverse swell that stops dead at its end (a suck into a hit).
function whoosh(t, dur, { f0 = 300, f1 = 2400, peak = .6, pan0 = 0, pan1 = 0, g = 1, rev = false } = {}) {
  const n = Math.round(dur * SR), st = new Float32Array(n * 2);
  let l1 = 0, l2 = 0, h = 0, pin = 0;
  for (let i = 0; i < n; i++) {
    const p = i / n, fc = f0 * (f1 / f0) ** p, a = 1 - Math.exp(-2 * Math.PI * fc / SR), ah = 1 - Math.exp(-2 * Math.PI * fc * .35 / SR);
    // pinkish noise
    pin = .97 * pin + .03 * rnd(); const x = rnd() * .5 + pin * 4;
    l1 += (x - l1) * a; l2 += (l1 - l2) * a; h += (l2 - h) * ah; const y = l2 - h;
    const env = rev ? Math.pow(p, 3) * Math.min(1, (1 - p) * 60) : (p < peak ? Math.pow(p / peak, 2) : Math.exp(-(p - peak) / (1 - peak) * 4));
    const pan = pan0 + (pan1 - pan0) * p;
    st[i * 2] = y * env * Math.min(1, 1 - pan); st[i * 2 + 1] = y * env * Math.min(1, 1 + pan);
  }
  place(st, t, g * 3.2);
}
// A sub hit: a low sine that drops in pitch, felt more than heard
function sub(t, g = 1) {
  const n = Math.round(1.1 * SR), st = new Float32Array(n * 2); let ph = 0;
  for (let i = 0; i < n; i++) { const tt = i / SR, f = 38 + 34 * Math.exp(-tt / .12); ph += f / SR; const v = Math.sin(2 * Math.PI * ph) * Math.min(1, tt / .008) * Math.exp(-tt / .38); st[i * 2] = st[i * 2 + 1] = v; }
  place(st, t, g * .5);
}

// 1 · the field bursts on the first beat
sub(.93, .8); whoosh(.78, 1.2, { f0: 180, f1: 3200, peak: .2, g: .55 });
// 2 · the field collapses into the mark; the dot lands
whoosh(3.9, .52, { f0: 3000, f1: 400, rev: true, g: .5 });
sample("impact/impactSoft_medium_001.ogg", 4.42, .8);
// 3 · whip to "Just a username"; keys; each strike
whoosh(6.2, .5, { f0: 500, f1: 3500, peak: .45, pan0: .7, pan1: -.7, g: .6 });
[[7.36, "003"], [7.5, "007"], [G(12), "012"], [7.82, "018"]].forEach(([t, k]) => sample(`keyboard/keypress-${k}.wav`, t, 2.0, .1));
[G(13), G(13) + .306, G(14), G(14) + .306].forEach((a, n) => sample("interface/click_003.ogg", a + .28, 1.0, [-.3, -.1, .1, .3][n]));
// 4 · push through into the drop; the phone flies in; the flip; it leaves
whoosh(9.8, .32, { f0: 400, f1: 5000, rev: true, g: .5 });
sub(G(16), 1); sample("impact/impactSoft_heavy_001.ogg", G(16), .35);
whoosh(G(16) - .05, 1.0, { f0: 2500, f1: 250, peak: .12, pan0: .6, pan1: .2, g: .5 });
whoosh(G(20) - .08, .85, { f0: 350, f1: 2800, peak: .5, pan0: .5, pan1: -.3, g: .8 });
whoosh(G(25) - .34, .55, { f0: 600, f1: 3000, peak: .6, pan0: .2, pan1: .8, g: .4 });
// 5 · the slips land; the tampered group; the verdict
sample("casino/card-slide-1.ogg", G(26), .3, .4); sample("casino/card-slide-1.ogg", G(26) + .306, .3, .5);
sample("interface/glitch_002.ogg", G(27) + .3, .18, .3);
sub(G(28) + .306, .9); sample("impact/impactSoft_heavy_003.ogg", G(28) + .306, .7, .2);
// 6 · everything is drawn into the mark, then the blue floods out of it
whoosh(19.45, .46, { f0: 3500, f1: 300, rev: true, g: .55 });
sub(G(32), 1); sample("impact/impactSoft_medium_004.ogg", G(32), .65);
// the blue drains back into the dot, and the loop starts over
whoosh(22.62, .55, { f0: 2400, f1: 350, rev: true, g: .35 });

// ---- mix: effects under the music; fade the tail
let pk = 0;
for (let i = 0; i < N; i++) {
  L[i] = L[i] + EL[i] * .55; R[i] = R[i] + ER[i] * .55;
  pk = Math.max(pk, Math.abs(L[i]), Math.abs(R[i]));
}
const out = Buffer.alloc(44 + N * 8);
out.write("RIFF", 0); out.writeUInt32LE(36 + N * 8, 4); out.write("WAVEfmt ", 8); out.writeUInt32LE(16, 16);
out.writeUInt16LE(3, 20); out.writeUInt16LE(2, 22); out.writeUInt32LE(SR, 24); out.writeUInt32LE(SR * 8, 28); out.writeUInt16LE(8, 32); out.writeUInt16LE(32, 34);
out.write("data", 36); out.writeUInt32LE(N * 8, 40);
for (let i = 0; i < N; i++) { out.writeFloatLE(L[i], 44 + i * 8); out.writeFloatLE(R[i], 48 + i * 8); }
writeFileSync(new URL("audio2.wav", import.meta.url), out);
// the effects alone, for checking the balance
const fx = Buffer.from(out); for (let i = 0; i < N; i++) { fx.writeFloatLE(EL[i] * .55, 44 + i * 8); fx.writeFloatLE(ER[i] * .55, 48 + i * 8); }
writeFileSync(new URL("fx2.wav", import.meta.url), fx);
console.log("peak", pk.toFixed(3));
