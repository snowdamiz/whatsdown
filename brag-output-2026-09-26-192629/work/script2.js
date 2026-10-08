// Every frame is a pure function of t: render(t) sets all animated state from scratch.
const $ = s => document.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];

// Kick grid of idea.mp3 (120 BPM): intro to G(32), build to G(96), big section to G(160),
// then audio2.mjs cuts from the outro's second bar straight to the final hit on G(168).
const G = k => 0.18 + 0.5 * k;
const LOOP = 2580 / 30;   // the final hit's fade wraps onto the track's opening
let MEASURE = false;      // while ready() measures, no camera moves

// ---- Sealed strips are seeded random Morse noise, as on the landing page
const M = {A:".-",B:"-...",C:"-.-.",D:"-..",E:".",F:"..-.",G:"--.",H:"....",I:"..",J:".---",K:"-.-",L:".-..",M:"--",N:"-.",O:"---",P:".--.",Q:"--.-",R:".-.",S:"...",T:"-",U:"..-",V:"...-",W:".--",X:"-..-",Y:"-.--",Z:"--.."};
let seed = 11;
const rand = () => (seed = seed * 16807 % 2147483647) / 2147483647, letters = Object.keys(M);
const group = () => Array.from({length: 2 + rand() * 3 | 0}, () => [...M[letters[rand() * 26 | 0]]].map(s => s === "-" ? '<i class="D"></i>' : "<i></i>").join("")).join('<i class="g"></i>');
const noise = n => Array.from({length: n}, () => `<span class="mc">${group()}</span>`).join("");
const hex4 = () => (rand() * 65536 | 0).toString(16).padStart(4, "0");

// ---- Easing: long soft settles, springs for things that land
const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const lerp = (a, b, p) => a + (b - a) * p;
function bez(x1, y1, x2, y2) {
  const cx = 3 * x1, bx = 3 * (x2 - x1) - cx, ax = 1 - cx - bx, cy = 3 * y1, by = 3 * (y2 - y1) - cy, ay = 1 - cy - by;
  const X = s => ((ax * s + bx) * s + cx) * s, Y = s => ((ay * s + by) * s + cy) * s;
  return t => { if (t <= 0) return 0; if (t >= 1) return 1; let lo = 0, hi = 1, s = t; for (let i = 0; i < 30; i++) { X(s) < t ? lo = s : hi = s; s = (lo + hi) / 2; } return Y(s); };
}
const OUT = bez(.16, 1, .3, 1), INOUT = bez(.65, 0, .35, 1), IN = bez(.55, 0, .8, .3), SOFT = bez(.3, .05, .2, 1), BLOOM = bez(.5, 0, .15, 1);
const spring = (x, w = 13, z = 9) => x <= 0 ? 0 : 1 - Math.exp(-x * z) * Math.cos(x * w); // x in seconds: ~10% overshoot, settled by .5s
const P = (t, a, d, e = SOFT) => e(clamp((t - a) / d));
const smooth = (a, b, x) => { const p = clamp((x - a) / (b - a)); return p * p * (3 - 2 * p); };
const on = (t, a, b, fa = .25, fb = .25) => smooth(a - fa, a, t) * (1 - smooth(b, b + fb, t));

// ---- Moves
function rev(w, t, a, d = 1.05) { // a word rising through its line
  const p = P(t, a, d, OUT);
  w.style.opacity = t < a ? 0 : clamp((t - a) / .3);
  w.style.transform = p >= 1 ? "none" : `translateY(${(1 - p) * 118}%) rotate(${(1 - p) * 5}deg)`;
}
function unrev(w, t, a, d = .6) { if (t < a) return; const p = P(t, a, d, IN); w.style.opacity = 1 - p; w.style.transform = `translateY(${-p * 118}%)`; }
const words = (sel, t, a, step = .07, d) => $$(sel + " .wd").forEach((w, n) => rev(w, t, a + n * step, d));
const wordsOut = (sel, t, a, step = .025) => $$(sel + " .wd").forEach((w, n) => unrev(w, t, a + n * step));
function rise(el, t, a, d = 1, dy = 28) {
  const p = P(t, a, d, OUT);
  el.style.opacity = t < a ? 0 : clamp((t - a) / (d * .45)); el.style.transform = `translateY(${(1 - p) * dy}px)`;
  el.style.filter = p > .995 || t < a ? "none" : `blur(${(1 - p) * 8}px)`;
}
function fall(el, t, a, d = .55, dy = -18) {
  if (t < a) return false;
  const p = P(t, a, d, IN);
  el.style.opacity = 1 - p; el.style.transform = `translateY(${p * dy}px)`; el.style.filter = p > 0 ? `blur(${p * 6}px)` : "none";
  return true;
}
function pop(el, t, a, from = .5) { const x = t - a; el.style.opacity = x < 0 ? 0 : clamp(x / .15); el.style.scale = x < 0 ? .01 : lerp(from, 1, spring(x)); }
function sheen(el, t, a, d = 1.1) { const s = el.querySelector(".sh"); if (s) s.style.backgroundPosition = `${lerp(150, -50, P(t, a, d, INOUT))}% 0`; }
const show = (el, v) => { el.style.visibility = v ? "" : "hidden"; }; // "" inherits, so a hidden layer hides everything in it
const tr3 = (el, {x = 0, y = 0, z = 0, rx = 0, ry = 0, rz = 0, s = 1}) => { el.style.transform = `translate3d(${x}px,${y}px,${z}px) rotateX(${rx}deg) rotateY(${ry}deg) rotateZ(${rz}deg) scale(${s})`; };
const at = (el, x, y) => { el.style.left = x + "px"; el.style.top = y + "px"; };
const dolly = (t, a, b, amt = .025) => MEASURE ? 1 : 1 + amt * smooth(a, b, t);
// a hard wipe with a glowing edge: `lead` covers [0, u] of the width, `rest` covers [u, 1]
function wipe(lead, rest, u, edge) {
  const e = clamp(u) * 100;
  lead.style.clipPath = `inset(0 ${100 - e}% 0 0)`; rest.style.clipPath = `inset(0 0 0 ${e}%)`;
  if (edge) { edge.style.left = e + "%"; edge.style.opacity = u > .01 && u < .99 ? 1 : 0; }
}
const seal = (el, u) => wipe(el.querySelector(".sl"), el.querySelector(".pl"), u, el.querySelector(".edge"));
const unseal = (el, u) => wipe(el.querySelector(".pl"), el.querySelector(".sl"), u, el.querySelector(".edge"));
const qbez = (a, c, b, p) => [(1 - p) ** 2 * a[0] + 2 * (1 - p) * p * c[0] + p * p * b[0], (1 - p) ** 2 * a[1] + 2 * (1 - p) * p * c[1] + p * p * b[1]];

// ---- Particles: a calm field of Morse dots and dashes drifting through depth
const fx = $("#fx"), cx = fx.getContext("2d");
let ps = 5; const R = () => (ps = ps * 16807 % 2147483647) / 2147483647;
const NP = 800, parts = Array.from({length: NP}, () => {
  const a = R() * Math.PI * 2, r = .22 + Math.pow(R(), .7) * 1.9;
  return {x: Math.cos(a) * r * 1.35, y: Math.sin(a) * r * .8, z0: R(), dash: R() < .38, s: [.5, .75, 1, 1.25][R() * 4 | 0], w: R(), k: R(), jx: R(), jy: R()};
});
function vel(t) {
  const burst = (a, amp, tau) => t >= a ? amp * Math.exp(-(t - a) / tau) : 0;
  return burst(G(0), .8, .7) + burst(G(31.4), .7, .7) + burst(G(64), .5, .7) + burst(G(95.8), .7, .7) + burst(G(159) - .1, .5, .7)
    + .05 * smooth(G(0), G(2), t) * (1 - smooth(G(6), G(8), t));
}
const DT = .001, DN = Math.ceil(LOOP / DT) + 10, Dtab = new Float32Array(DN + 1);
for (let i = 1; i <= DN; i++) Dtab[i] = Dtab[i - 1] + vel(i * DT) * DT;
{ const iL = Math.round(LOOP / DT), target = 4 * Math.ceil((Dtab[iL] + 1) / 4), drift = (target - Dtab[iL]) / LOOP; for (let i = 0; i <= DN; i++) Dtab[i] += drift * i * DT; } // whole depth cycles per pass, so the field loops
const Dist = t => Dtab[Math.min(DN, Math.max(0, Math.round(t / DT)))];
function inten(t) {
  let I = .12;
  I += .33 * (1 - smooth(G(7), G(8.5), t));      // the opening card's field
  I += .25 * on(t, G(0), G(5), .1, 1.2);          // the track's first hit
  I += .3 * on(t, G(31.5), G(33.5), .3, 1.2);     // into the blue
  I += .3 * on(t, G(64), G(68), .2, 1.2);         // "That was the easy part."
  I += .3 * on(t, G(96), G(97.5), .2, 1.2);
  I += .33 * smooth(LOOP - 1.4, LOOP - .3, t);    // back to the opening card
  return I;
}
let tg10 = null;
function tgt(p, T) {
  if (!p.dash) { const a = p.jx * Math.PI * 2, r = Math.sqrt(p.jy) * T.dot.r * .8; return [T.dot.x + Math.cos(a) * r, T.dot.y + Math.sin(a) * r]; }
  return [T.dash.x + T.dash.r * .6 + p.jx * (T.dash.w - T.dash.r * 1.2), T.dash.y + (p.jy - .5) * T.dash.r * 1.2];
}
const E10 = G(168); // the final hit: the end card drains back into its dot
function floodR(t) { return (t < G(159) - .1 ? 0 : P(t, G(159) - .1, 1.3, BLOOM) * 2300) * (1 - P(t, E10 + .15, .7, INOUT)); }
const shatters = []; // [time, x, y, w, h, seed] key tiles that break into dots
function drawParticles(t) {
  cx.clearRect(0, 0, 1920, 1080);
  const I = inten(t), fr = floodR(t), D = Dist(t), F = 560;
  const blueOn = t > G(31.8) && t < G(47.2);
  const cst = G(157.3), conv = t > cst && t < G(159) + .05;
  for (const p of parts) {
    const z = ((p.z0 - D * p.s) % 1 + 1) % 1, zz = .07 + z;
    let X = 960 + p.x * F / zz, Y = 540 + p.y * F / zz, h = 3.6 / zz;
    let a = I * smooth(1.07, .78, zz) * smooth(.07, .16, zz) * (.45 + .55 * p.k);
    if (conv) {
      if (p.k < .6) {
        const k = INOUT(clamp((t - cst - p.w * .25) / .95)), [tx, ty] = tgt(p, tg10);
        X = lerp(X, tx, k); Y = lerp(Y, ty, k); h = lerp(h, 9, k);
        a = lerp(a, .9, Math.min(1, k * 1.5)) * (1 - smooth(.9, 1, k));
      } else a *= 1 - smooth(cst, cst + .5, t);
    }
    if (a < .01 || X < -80 || X > 2000 || Y < -80 || Y > 1160) continue;
    const w = p.dash ? h * 3 : h;
    const onBlue = blueOn || (fr > 0 && (X - tg10.dot.x) ** 2 + (Y - tg10.dot.y) ** 2 < fr * fr);
    cx.globalAlpha = Math.min(1, a * (onBlue ? .45 : 1.1));
    cx.fillStyle = onBlue ? "#FFFFFF" : (p.k > .82 ? "#0B0B0F" : p.k > .6 ? "#6AA6FF" : "#2F6BEA");
    cx.beginPath(); cx.roundRect(X - w / 2, Y - h / 2, w, h, h / 2); cx.fill();
  }
  // key tiles dissolving into Morse dots
  cx.fillStyle = "#FFFFFF";
  for (const [ts, x0, y0, w0, h0, sd] of shatters) {
    const dt = t - ts; if (dt < 0 || dt > 1.3) continue;
    let q = sd; const r = () => (q = q * 16807 % 2147483647) / 2147483647;
    for (let n = 0; n < 38; n++) {
      const px = x0 + (r() - .5) * w0, py = y0 + (r() - .5) * h0, ang = Math.atan2(py - y0, px - x0) + (r() - .5) * .9, sp = 140 + r() * 320, dash = r() < .4, sz = 5 + r() * 6;
      const k = 1 - Math.exp(-dt * 2.4), X = px + Math.cos(ang) * sp * k / 2.4, Y = py + Math.sin(ang) * sp * k / 2.4 + 50 * dt * dt;
      cx.globalAlpha = clamp(1 - dt / 1.3) ** 1.5 * .9;
      const w = dash ? sz * 3 : sz; cx.beginPath(); cx.roundRect(X - w / 2, Y - sz / 2, w, sz, sz / 2); cx.fill();
    }
  }
  cx.globalAlpha = 1;
}

// ---- Film grain, one pattern per video frame
const gr = $("#grain"), gx = gr.getContext("2d"), gimg = gx.createImageData(480, 270);
function drawGrain(t) {
  let s = (Math.round(t * 30) * 7919 + 13) % 2147483647 || 1;
  for (let i = 0; i < gimg.data.length; i += 4) { s = s * 16807 % 2147483647; const v = s & 255; gimg.data[i] = gimg.data[i + 1] = gimg.data[i + 2] = v; gimg.data[i + 3] = 255; }
  gx.putImageData(gimg, 0, 0);
}

function spell(root, t, a, step = .06) {
  $$("span", root).forEach((s, n) => {
    const p = P(t, a + n * step, .95, OUT);
    s.style.opacity = t < a + n * step ? 0 : clamp((t - a - n * step) / .3);
    s.style.transform = `translateY(${(1 - p) * 50}px)`; s.style.filter = p > .99 ? "none" : `blur(${(1 - p) * 10}px)`;
  });
}
function mark(mk, t, dotAt, dashAt, dashDur = .7) {
  const d = mk.querySelector(".d1"), s = mk.querySelector(".d2");
  const x = t - dotAt;
  d.style.opacity = x < 0 ? 0 : 1; d.style.scale = x < 0 ? .5 : lerp(.5, 1, spring(x, 11, 8));
  d.style.boxShadow = `0 0 ${50 * clamp(1 - x / .6)}px rgba(170,205,255,${.8 * clamp(1 - x / .6)})`;
  const sp = P(t, dashAt, dashDur, OUT);
  s.style.clipPath = `inset(0 ${(1 - sp) * 100}% 0 0 round 999px)`;
  s.style.opacity = t < dashAt ? 0 : 1;
}

// =================================================================== build the generated parts
for (const w of $$(".wd")) { const m = document.createElement("span"); m.className = "wk"; w.replaceWith(m); m.append(w); }
for (const el of $$("[data-seal]")) el.innerHTML = noise(+el.dataset.seal);

// 3 · the ratchet: key tiles on a chain, one message dropped onto each
const MSGS = ["Did the scans arrive?", "Dinner on Friday?", "By the river?", "See you at 7."];
const L3 = MSGS.map((_, k) => G(36 + 3 * k)); // each message lands on a kick, three beats apart
const A3 = L3.map(l => l - .8);                // the chain starts moving
const NT = 7, tiles = [], links = [], drops = [];
for (let i = 0; i < NT; i++) {
  const k = document.createElement("div"); k.className = "kt";
  k.innerHTML = `<small><svg class="ic"><use href="#i-key"/></svg>Message key</small><b>${hex4()} ${hex4()}</b>`;
  $("#chain").append(k); tiles.push(k);
  const l = document.createElement("i"); l.className = "lnk"; $("#chain").append(l); links.push(l);
}
MSGS.forEach(m => {
  const d = document.createElement("div"); d.className = "drop";
  d.innerHTML = `<span class="pl">${m}</span><span class="sl"><span>${noise(2 + m.length / 8 | 0)}</span></span><i class="edge"></i>`;
  $("#drops").append(d); drops.push(d);
});
const SLOT = 960, STEP = 300, CHY = 700;
function chainPos(t) {
  let s = -1; for (const a of A3) s += INOUT(clamp((t - a) / .65));
  return s - 5 * (1 - P(t, G(32.4), 1.6, OUT));
}
{ // a ratchet wheel: sawtooth teeth
  const N = 18, Ro = 330, Ri = 292; let d = `M${Ri} 0`;
  for (let i = 0; i < N; i++) { const a1 = (i + 1) / N * 2 * Math.PI; d += `L${Ro * Math.cos(a1 - .02)} ${Ro * Math.sin(a1 - .02)}L${Ri * Math.cos(a1)} ${Ri * Math.sin(a1)}`; }
  $("#gearP").setAttribute("d", d + "Z");
}

// 4 · three messages of very different lengths
const ROWS = ["OK", "Running late, save me a seat!", "Here’s the plan for Friday: dinner at 7, then the late show if the rain holds off."];
const rows = ROWS.map(m => {
  const r = document.createElement("div"); r.className = "row";
  r.innerHTML = `<span class="from"><img src="img/you.jpg" alt="">From @you</span><div class="bub"><span class="pl"><span>${m}</span></span><span class="sl"><svg class="ic"><use href="#i-lock"/></svg><span>${noise(5)}</span></span><i class="edge"></i></div>`;
  $("#rows").append(r); return r;
});
const ROWY = [520, 668, 846], SLOTY = [604, 700, 796], STRIP = [490, 66], QX = 1475;
const R4 = [G(52), G(55), G(58)];

// 8 · the tree: 8 leaves, 4, 2, a root
const TX = 1350, LY = [790, 630, 470, 300];
const tnodes = [];
const mkNode = (cls, html, lvl, i, x, y) => { const e = document.createElement("div"); e.className = "tn c " + cls; e.innerHTML = html; $("#tree").append(e); const n = {el: e, lvl, i, x, y}; tnodes.push(n); at(e, x, y); return n; };
const HX = Array.from({length: 64}, hex4);
const leaves = Array.from({length: 8}, (_, i) => mkNode("lf", `<svg class="ic"><use href="#i-key"/></svg><span>${HX[i]}</span>`, 0, i, TX + (i - 3.5) * 104, LY[0]));
const l1 = Array.from({length: 4}, (_, j) => mkNode("in", `<span>${HX[8 + j]}</span>`, 1, j, TX + (j - 1.5) * 208, LY[1]));
const l2 = Array.from({length: 2}, (_, j) => mkNode("in", `<span>${HX[12 + j]}</span>`, 2, j, TX + (j - .5) * 416, LY[2]));
const root = mkNode("rt", `<small>Root</small><span>9f3a c107</span><i class="sh"></i>`, 3, 0, TX, LY[3]);
const adaTag = document.createElement("span"); adaTag.className = "tag c"; adaTag.textContent = "@ada"; $("#tree").append(adaTag); at(adaTag, leaves[2].x, LY[0] + 62);
const parentOf = n => n.lvl === 0 ? l1[n.i >> 1] : n.lvl === 1 ? l2[n.i >> 1] : root;
const edgeEls = [];
for (const n of [...leaves, ...l1, ...l2]) {
  const p = parentOf(n), e = document.createElementNS("http://www.w3.org/2000/svg", "path");
  const hA = n.lvl === 0 ? 35 : 23, hB = p.lvl === 3 ? 37 : 23;
  const y1 = n.y - hA, y2 = p.y + hB;
  e.setAttribute("d", `M${n.x} ${y1}C${n.x} ${lerp(y1, y2, .55)} ${p.x} ${lerp(y1, y2, .45)} ${p.x} ${y2}`);
  e.setAttribute("fill", "none"); e.setAttribute("stroke", "#2F6BEA"); e.setAttribute("stroke-width", "3"); e.setAttribute("stroke-linecap", "round");
  $("#edges").append(e); edgeEls.push({el: e, n, p, len: 0});
}
const proofEdges = [[leaves[2], l1[1]], [l1[1], l2[0]], [l2[0], root]].map(([n]) => {
  const src = edgeEls.find(e => e.n === n), g = document.createElementNS("http://www.w3.org/2000/svg", "path");
  g.setAttribute("d", src.el.getAttribute("d")); g.setAttribute("fill", "none"); g.setAttribute("stroke", "#2F6BEA"); g.setAttribute("stroke-width", "8"); g.setAttribute("stroke-linecap", "round");
  g.style.filter = "drop-shadow(0 0 8px rgba(47,107,234,.6))";
  $("#proof").append(g); return {el: g, len: 0};
});
const APP = [G(102), G(104), G(106)]; // leaves 5, 6, 7 are appended on the kicks
const PROOF = G(108);

// 9 · five witnesses
const WG = ["t0", "t4", "t3", "t1", "t2"], WL = "ABCDE";
const WARC = [0, 1, 2, 3, 4].map(n => [TX + (n - 2) * 172, [770, 812, 828, 812, 770][n]]);
const WROW = [0, 1, 2, 3, 4].map(n => [TX + (n - 2) * 172, 530]);
const wits = WL.split("").map((L, n) => {
  const w = document.createElement("div"); w.className = `wt ${WG[n]}`;
  w.innerHTML = `<svg viewBox="0 0 112 112"><circle cx="56" cy="56" r="52" fill="none" stroke="#2F6BEA" stroke-width="5" stroke-linecap="round" transform="rotate(-90 56 56)" stroke-dasharray="327" stroke-dashoffset="327"/></svg><b>${L}</b><i><svg class="ic"><use href="#i-check"/></svg></i>`;
  $("#wits").append(w); return w;
});
const toks = [0, 1].map(() => WL.split("").map((L, n) => { const k = document.createElement("span"); k.className = `tok ${WG[n]}`; k.textContent = L; $("#wits").append(k); return k; }));
const wline = [0, 1].map(() => [0, 1, 2, 3, 4].map(() => { const p = document.createElementNS("http://www.w3.org/2000/svg", "path"); p.setAttribute("fill", "none"); p.setAttribute("stroke-width", "4"); p.setAttribute("stroke-linecap", "round"); $("#wlines").append(p); return p; }));
const SIGN8 = [G(121), G(123), G(125), G(127.5), G(129)];
const SIGN9 = [[G(141), G(142), G(143)], [G(144.5), G(145.5), G(146.5)]]; // upper: A, B, C  lower: C, D, E
const who = n => ["A", "A and B", "A, B and C", "A, B, C and D", "All five"][n];
const SPLIT = G(135.4), CRED = G(149), VERD = G(150);

let pk1Path = null, pk2Path = null, slotOff = null, routes = {};
const NS = "http://www.w3.org/2000/svg";
function mkRoute(id, d) { // a visible dotted path revealed by a masked stroke
  const svg = $("#routes"), m = document.createElementNS(NS, "mask"), mp = document.createElementNS(NS, "path"), v = document.createElementNS(NS, "path");
  m.id = "m" + id; m.setAttribute("maskUnits", "userSpaceOnUse"); m.setAttribute("x", 0); m.setAttribute("y", 0); m.setAttribute("width", 1920); m.setAttribute("height", 1080);
  for (const e of [mp, v]) e.setAttribute("d", d);
  mp.setAttribute("fill", "none"); mp.setAttribute("stroke", "#fff"); mp.setAttribute("stroke-width", 24);
  m.append(mp); svg.append(m); v.setAttribute("class", "rv"); v.setAttribute("mask", `url(#m${id})`); svg.append(v);
  const len = mp.getTotalLength(); mp.style.strokeDasharray = len;
  return routes[id] = {v, mp, len};
}
function route(id, t, p, alpha, color) {
  const r = routes[id]; if (!r) return; // not built yet while ready() measures
  r.mp.style.strokeDashoffset = r.len * (1 - clamp(p));
  r.v.style.opacity = p > 0 ? alpha : 0; r.v.style.stroke = color; r.v.style.strokeDashoffset = -t * 30; // the dots flow along it
}

// =================================================================== render
function render(t) {
  const ph = 2 * Math.PI * t / LOOP;
  $("#gA").style.transform = `translate(${-300 + Math.sin(ph) * 180}px,${-420 + Math.cos(ph) * 100}px)`;
  $("#gB").style.transform = `translate(${900 + Math.cos(ph) * 200}px,${300 + Math.sin(ph * 2) * 100}px)`;
  drawParticles(t); drawGrain(t);
  const rings = [[G(0), 960, 540, 900], [G(64), 960, 540, 820]], rg = rings.filter(r => t >= r[0] && t < r[0] + 1.3).pop(), ringEl = $("#ring");
  if (rg) { const p = (t - rg[0]) / 1.3, r = BLOOM(p) * rg[3]; Object.assign(ringEl.style, {left: rg[1] - r + "px", top: rg[2] - r + "px", width: 2 * r + "px", height: 2 * r + "px", opacity: (1 - p) * .55}); }
  else ringEl.style.opacity = 0;

  sc1(t); sc2(t); sc3(t); sc4(t); sc5(t); scNet(t); sc11(t);
  // red light while the server lies, and while the fork is caught
  const gR = $("#gR"), r6 = on(t, G(84), G(94), .8, .8), r9 = on(t, CRED, G(156), .6, .8);
  gR.style.opacity = .9 * Math.max(r6, r9);
  gR.style.transform = r9 > r6 ? "translate(-150px,-100px)" : "translate(260px,-40px)";
}

// ===== 1 · "Encryption was the easy part." Settled at frame 0; rises again at the end of the loop.
function sc1(t) {
  const back = t > LOOP - 1.4;
  show($("#s1"), t < G(10) || back);
  $$("#s1T .wd").forEach((w, n) => { if (back) rev(w, t, LOOP - 1.25 + n * .06, .95); else { w.style.opacity = 1; w.style.transform = "none"; } });
  const L = $("#s1L"), T = $("#s1T");
  const e = back ? 0 : P(t, G(7), 1.2, INOUT);
  T.style.transform = `translateY(${-e * 50}px) scale(${(1 + .03 * smooth(G(0), G(7), t) * (back ? 0 : 1)) * lerp(1, .9, e)})`;
  T.style.opacity = 1 - e; T.style.filter = e > 0 ? `blur(${e * 12}px)` : "none";
  if (back) rise(L, t, LOOP - .95, .9, 20); else Object.assign(L.style, {opacity: 1 - clamp(e * 2), transform: "none", filter: "none"});
  mark($("#s1Mk"), back ? t : 99, LOOP - .85, LOOP - .7, .6);
}

// ===== 2, 6, 7 · the phones
const S6 = G(60); // after this the phones are in their second appearance
function phonePose(t, side) { // side -1: you (left), +1: Ada (right)
  const second = t > S6, a = second ? G(70.3) : G(7.6), p = P(t, a + (side > 0 ? .14 : 0), 1.8, OUT);
  return {x: second ? 0 : lerp(side * 220, 0, p), y: lerp(640, 0, p) + Math.sin(t * 1.1 + side) * 5, z: lerp(-500, 0, p),
          rx: lerp(40, 3, p), ry: -side * lerp(34, 13, p) + Math.sin(t * .7 + side) * 1.6, p};
}
function grow(el, t, a) { // a new bubble opens its space in the thread
  const h = +el.dataset.h, p = P(t, a, .6, OUT), x = t - a;
  el.style.height = x < 0 ? "0px" : h * p + "px"; el.style.marginTop = x < 0 ? "-7px" : lerp(-7, 0, p) + "px";
  el.style.opacity = x < 0 ? 0 : clamp(x / .2);
  el.firstElementChild.style.transform = `scale(${lerp(.7, 1, spring(x))})`;
  el.firstElementChild.style.transformOrigin = el.classList.contains("r") ? "100% 100%" : "0 100%";
}
function sc2(t) {
  const vis = (t > G(7.4) && t < G(34)) || (t > G(70) && t < G(97.4));
  show($("#dia"), vis); if (!vis) return;
  const dia = $("#dia"), first = t < S6;
  const ex = MEASURE ? 0 : first ? P(t, G(31), .9, IN) : P(t, G(95.2), 1.1, IN);
  const dl = first ? dolly(t, G(8), G(31)) : dolly(t, G(71), G(95));
  dia.style.transform = `scale(${dl * (1 + ex * .1)})`; dia.style.opacity = 1 - ex; dia.style.filter = ex > .01 ? `blur(${ex * 12}px)` : "none";

  const PY = phonePose(t, -1), PA = phonePose(t, 1);
  tr3($("#pY"), PY); tr3($("#pA"), PA);
  $("#glY").style.backgroundPosition = `${lerp(100, 0, (PY.ry + 20) / 40)}% 0`; $("#glA").style.backgroundPosition = `${lerp(100, 0, (PA.ry + 20) / 40)}% 0`;
  [["#shY", PY, 250], ["#shA", PA, 1312]].forEach(([id, p, x]) => { const s = $(id); at(s, x - 10 + p.x, 1004 + p.y * .15); s.style.opacity = p.p * (1 - clamp(p.y / 400)); s.style.transform = `scale(${lerp(.6, 1, p.p)})`; });
  // the server reads the message: everything else goes soft
  const dof = MEASURE ? 0 : on(t, G(89.4), G(92), .45, .45);
  for (const id of ["#pY", "#pA", "#dir", "#kc", "#kcNote"]) $(id).style.filter = dof > .01 ? `blur(${dof * 4}px)` : "none";

  // headlines
  words("#h2 div:first-child", t, G(8.8), .07); words("#h2 .acc", t, G(22), .07);
  words("#h5", t, G(72), .07); words("#h6a", t, G(82), .09); words("#h6b", t, G(89), .08);
  wordsOut("#h5", t, G(81)); wordsOut("#h6a", t, G(88.4));
  show($("#h2"), first); show($("#h5"), !first && t < G(83)); show($("#h6a"), t > G(80) && t < G(90)); show($("#h6b"), t > G(88));
  first ? rise($("#spec2"), t, G(24)) : ($("#spec2").style.opacity = 0);

  // typing, then send
  const keys = Array.from({length: 13}, (_, k) => G(11) + k * .11), txt = "See you at 7.", n = keys.filter(k => t >= k).length;
  const sent = t >= G(14), typing = n > 0 && !sent && first;
  $("#yTyped").innerHTML = typing ? txt.slice(0, n) + "<u></u>" : "Message";
  $("#yComp").classList.toggle("typing", typing);
  const sx = t - G(14), sendOn = typing || (sx > 0 && sx < .4);
  $("#ySend").style.background = sendOn ? "#2F6BEA" : "#A9C1F3"; $("#ySend").style.scale = sx > 0 && sx < .6 ? lerp(.8, 1, spring(sx)) : 1;
  grow($("#yN1"), t, G(14)); grow($("#aN1"), t, G(20.6)); grow($("#yN2"), t, G(85.5)); grow($("#aN2"), t, G(93.8));
  unseal($("#aN1 .seal"), P(t, G(21), .9));
  unseal($("#aN2 .seal"), P(t, G(94), .7));

  // packet 1: lifts off the bubble, seals, arcs over the servers, lands in Ada's thread
  const k1 = $("#pk1");
  if (t > G(14.6) && t < G(21)) {
    const lift = P(t, G(14.6), .7, OUT), fl = INOUT(clamp((t - G(16.6)) / 2)), land = P(t, G(20.2), .45, IN);
    const [x, y] = t < G(16.6) ? [pk1Path.a[0], pk1Path.a[1] - 50 * lift] : qbez([pk1Path.a[0], pk1Path.a[1] - 50], pk1Path.c, pk1Path.b, fl);
    at(k1, x, y); k1.style.opacity = clamp((t - G(14.6)) / .2) * (1 - land);
    k1.style.transform = `scale(${lerp(.62, 1, lift) * lerp(1, .55, land)}) rotate(${Math.sin(fl * Math.PI) * -3}deg)`;
    seal(k1, P(t, G(15.2), .85)); sheen(k1, t, G(16.3));
  } else k1.style.opacity = 0;
  const srvHit = on(t, G(18.3), G(18.9), .25, .45);
  $("#srv").style.boxShadow = `0 0 0 ${12 * srvHit}px rgba(106,166,255,${.25 * srvHit}),0 26px 46px -22px rgba(11,11,15,.55)`;
  first ? (rise($("#srvNote"), t, G(18.6)), fall($("#srvNote"), t, G(30.4))) : ($("#srvNote").style.opacity = 0);
  // the servers pill: in with the phones, back with them, red while it lies
  const srv = $("#srv"), sa = first ? G(9.5) : G(71);
  pop(srv, t, sa, .6);
  const red = first ? 0 : P(t, G(88.6), .5) * (1 - P(t, G(94.5), .6));
  srv.style.background = `rgb(${lerp(11, 216, red)},${lerp(13, 50, red)},${lerp(20, 58, red)})`;
  $("#srvI1").style.opacity = 1 - red; $("#srvI2").style.opacity = red;

  // the routes things travel
  const BL = "rgba(47,107,234,1)", RD = "rgba(216,50,58,1)";
  if (first) {
    route("r1", t, INOUT(clamp((t - G(16.6)) / 2)), .45 * (1 - P(t, G(30), .6)), BL);
    for (const id of ["rk", "r2a", "r2b"]) route(id, t, 0, 0, BL);
  } else {
    route("r1", t, 0, 0, BL);
    const kp = P(t, G(76), 1.1, OUT), fl = P(t, G(84), .7, INOUT);
    route("rk", t, kp, .45 + .15 * fl, fl > .5 ? RD : BL);
    route("r2a", t, INOUT(clamp((t - G(87.4)) / 1)), .5, RD);
    route("r2b", t, INOUT(clamp((t - G(92.2)) / .8)), .5, RD);
  }

  // 6 · the directory hands your phone a key
  const dir = $("#dir"); first ? (dir.style.opacity = 0) : pop(dir, t, G(74), .6);
  const kc = $("#kc");
  if (!first && t > G(76)) {
    const p = P(t, G(76), 1.1, OUT), [x, y] = qbez([960, 486], [720, 560], [440, 404], p);
    at(kc, x, y); kc.style.opacity = clamp((t - G(76)) / .2);
    const flip = P(t, G(84), .7, INOUT);
    kc.style.transform = `perspective(900px) rotateX(${180 * flip + (1 - p) * -24}deg) rotateZ(${(1 - p) * -10 + Math.sin(t * 1.1) * 1}deg) scale(${lerp(.45, 1, p) * (1 + .1 * Math.sin(flip * Math.PI))})`;
  } else kc.style.opacity = 0;
  first ? ($("#kcNote").style.opacity = 0) : rise($("#kcNote"), t, G(85));

  // 7 · the lie: sealed to the server's key, opened and read there, sealed again for Ada
  const k2 = $("#pk2");
  if (!first && t > G(86) && t < G(94.2)) {
    const lift = P(t, G(86), .7, OUT), mid = [960, 706], start = [pk2Path.a[0], pk2Path.a[1] - 50];
    let x, y;
    if (t < G(87.4)) { x = pk2Path.a[0]; y = pk2Path.a[1] - 50 * lift; }
    else if (t < G(92.2)) [x, y] = qbez(start, [640, 560], mid, INOUT(clamp((t - G(87.4)) / 1)));
    else [x, y] = qbez(mid, [1280, 560], pk2Path.b, INOUT(clamp((t - G(92.2)) / .8)));
    const land = P(t, G(93.6), .35, IN), atSrv = on(t, G(89.4), G(91.9), .4, .35);
    at(k2, x, y - atSrv * 96); k2.style.opacity = clamp((t - G(86)) / .2) * (1 - land);
    k2.style.transform = `scale(${lerp(.62, 1, lift) * lerp(1, .55, land) * (1 + .14 * atSrv)})`;
    if (t < G(89.6)) seal(k2, P(t, G(86.4), .7));
    else if (t < G(91.6)) unseal(k2, P(t, G(89.6), .7));
    else seal(k2, P(t, G(91.6), .6));
    k2.querySelector(".pl").style.background = t > G(88.6) ? "var(--red)" : "var(--blue)";
    sheen(k2, t, G(87.2));
  } else k2.style.opacity = 0;
}

// ===== 3 · a new key for every message
function sc3(t) {
  const vis = t > G(30.8) && t < G(49.4);
  const bl = $("#blue"); show(bl, vis); show($("#s3"), vis); if (!vis) return;
  const b = pk1Path.b, burst = P(t, G(31), 1.4, BLOOM), away = P(t, G(47), 1.2, INOUT);
  bl.style.clipPath = `circle(${burst * 2400}px at ${b[0] - 24}px ${b[1] - 24}px)`;
  const flyAway = `perspective(1600px) translateY(${-away * 1180}px) rotateX(${away * 10}deg) scale(${(1 - away * .05) * dolly(t, G(32), G(47), .02)})`;
  bl.style.transform = flyAway; $("#s3").style.transform = flyAway;
  words("#h3", t, G(32), .08);
  const s = chainPos(t);
  $("#gearG").setAttribute("transform", `translate(${SLOT} ${CHY}) rotate(${s * 20 + 30 * (1 - burst)})`);
  $("#gearG").style.opacity = .15 * P(t, G(32), 1.2);
  tiles.forEach((k, i) => {
    const x = SLOT + (i - s) * STEP, L = L3[i] ?? 999, brk = P(t, L + .55, .45, IN);
    const cur = on(t, (A3[i] ?? 999) + .45, L + .55, .25, .15);
    at(k, x - 118, CHY - 66);
    k.style.opacity = brk >= 1 || x < -300 || x > 2300 ? 0 : 1 - brk;
    k.style.transform = `scale(${(1 + .08 * cur) * (1 - .2 * brk)})`; k.style.filter = brk > 0 ? `blur(${brk * 10}px)` : "none";
    k.style.boxShadow = `0 0 0 ${6 * cur}px rgba(255,255,255,${.3 * cur}),0 30px 50px -26px rgba(6,14,50,.6)`;
    const l = links[i], nxt = SLOT + (i + 1 - s) * STEP;
    at(l, x + 118 + 8, CHY - 2); l.style.width = (nxt - x - 236 - 20) + "px";
    l.style.opacity = (x > -300 && x < 2200 ? .9 : 0) * (1 - clamp(brk * 2));
  });
  drops.forEach((d, k) => {
    const L = L3[k], a = A3[k] + .25, p = P(t, a, L - a, OUT), fly = P(t, L + .55, .95, INOUT);
    if (t < a || fly >= 1) { d.style.opacity = 0; return; }
    at(d, lerp(SLOT, 1640, fly), lerp(lerp(420, CHY, p), 320, fly)); d.style.translate = "-50% -50%";
    d.style.opacity = clamp((t - a) / .2) * (1 - fly);
    d.style.transform = `scale(${lerp(1, .55, fly)}) rotate(${fly * -6}deg)`;
    seal(d, P(t, L + .02, .45));
  });
  rise($("#s3Sub"), t, G(38)); rise($("#s3Spec"), t, G(40));
}

// ===== 4 · sealed and padded
function sc4(t) {
  const vis = t > G(46.6) && t < G(65);
  show($("#s4"), vis); if (!vis) return;
  const o = P(t, G(63), .9, IN), s4 = $("#s4");
  s4.style.opacity = 1 - o; s4.style.filter = o > .01 ? `blur(${o * 14}px)` : "none"; s4.style.transform = `scale(${dolly(t, G(48), G(63), .02) * (1 + o * .04)})`;
  words("#h4", t, G(48.4), .09);
  rise($("#s4Sub"), t, G(50)); rise($("#gateNote"), t, G(50.6));
  const gp = P(t, G(48.4), 1.1, OUT);
  $("#gate").style.transform = `scaleY(${gp})`; $("#gate").style.opacity = gp;
  const q = $("#queue"), qp = P(t, G(48), 1.4, OUT);
  q.style.opacity = clamp(qp * 3); q.style.transform = `translateX(${(1 - qp) * 260}px) scale(${lerp(.94, 1, qp)})`;
  let arrived = 0, glow = 0;
  rows.forEach((r, n) => {
    const a = R4[n], b = r.querySelector(".bub"), ch = r.querySelector(".from");
    const w0 = +b.dataset.w, h0 = +b.dataset.h, ia = G(49) + n * .15;
    const pA = P(t, a, .8, INOUT), pB = P(t, a + .65, .7), pC = P(t, a + 1.3, .95, OUT);
    let x = lerp(150 + w0 / 2, 860, pA), y = ROWY[n];
    x = lerp(x, 940, pB); x = lerp(x, QX, pC); y = lerp(y, SLOTY[n], pC);
    const w = lerp(w0, STRIP[0], pB), h = lerp(h0, STRIP[1], pB);
    Object.assign(b.style, {width: w + "px", height: h + "px", left: x - w / 2 + "px", top: y - h / 2 + "px"});
    b.style.opacity = t < ia ? 0 : clamp((t - ia) / .2); b.style.transform = `scale(${lerp(.7, 1, spring(t - ia))})`;
    b.style.borderRadius = lerp(30, 33, pB) + "px"; b.style.borderBottomRightRadius = lerp(10, 33, pB) + "px";
    seal(b, pB);
    // the sender's name stays behind at the gate
    const drop = P(t, a + .65, 1.2), ca = ia + .15;
    at(ch, lerp(150, 860 - w0 / 2, pA) + drop * 16, ROWY[n] - h0 / 2 - 50 + drop * 110);
    ch.style.opacity = (t < ca ? 0 : clamp((t - ca) / .2)) * (1 - drop);
    ch.style.transform = `rotate(${drop * 8}deg)`; ch.style.filter = drop > .01 ? `blur(${drop * 4}px)` : "none";
    if (t > a + 1.9) arrived++;
    glow = Math.max(glow, on(t, a + .65, a + 1.35, .15, .3));
  });
  $("#gateGlow").style.opacity = .5 + .8 * glow; $("#gateGlow").style.transform = `scaleX(${1 + glow * .5})`;
  $("#qCount").textContent = arrived ? `${arrived} sealed envelope${arrived > 1 ? "s" : ""}` : "Waiting";
  $$("#rows .bub .sl>span").forEach((s, n) => { s.style.transform = `translateX(${-((t * (10 + n * 2)) % 60)}px)`; });
}

// ===== 5 · "That was the easy part."
function sc5(t) {
  const vis = t > G(63.4) && t < G(73);
  show($("#s5t"), vis); if (!vis) return;
  $$("#s5T .wd").forEach((w, n) => rev(w, t, G(64) + n * .16, 1.15));
  const o = P(t, G(70.4), 1, INOUT), T = $("#s5T");
  T.style.transform = `translateY(${-o * 50}px) scale(${(1 + .03 * smooth(G(64), G(70.4), t)) * lerp(1, .94, o)})`; T.style.opacity = 1 - o; T.style.filter = o > .01 ? `blur(${o * 12}px)` : "none";
}

// ===== 8, 9, 10 · the log, the witnesses, a fork
function scNet(t) {
  const vis = t > G(95.4) && t < G(158.6);
  show($("#net"), vis); if (!vis) return;
  const o = P(t, G(157.2), .9, IN), net = $("#net");
  net.style.opacity = 1 - o; net.style.filter = o > .01 ? `blur(${o * 14}px)` : "none"; net.style.transform = `scale(${dolly(t, G(96), G(157), .02) * (1 + o * .04)})`;
  const sk = P(t, G(95.6), 1.4, OUT), sky = $("#sky");
  sky.style.transform = `scale(${lerp(.35, 1, sk)})`; sky.style.opacity = clamp(sk * 3); sky.style.borderRadius = `${lerp(300, 64, sk)}px`;

  // --- 8 · the tree
  const treeOut = P(t, G(115.4), .75, IN), treeVis = t < G(117.4);
  show($("#tree"), treeVis); show($("#edges"), treeVis); show($("#proof"), treeVis);
  const appearAt = n => n.lvl === 0 ? (n.i < 5 ? G(96.4) + n.i * .07 : APP[n.i - 5]) : n.lvl === 1 ? (n.i < 3 ? G(97.2) + n.i * .07 : APP[1]) : n.lvl === 2 ? G(97.8) + n.i * .08 : G(98.3);
  const flashAt = n => { let best = -9; APP.forEach((ap, k) => { let m = leaves[5 + k], d = 0; while (m) { if (m === n && t >= ap + d * .2) best = Math.max(best, ap + d * .2); m = m.lvl < 3 ? parentOf(m) : null; d++; } }); return best; };
  for (const n of tnodes) {
    const a = appearAt(n), x = t - a, e = n.el, appended = n.lvl === 0 && n.i >= 5;
    const fa = flashAt(n), fl = fa > 0 ? Math.exp(-(t - fa) / .3) : 0;
    e.style.opacity = (x < 0 ? 0 : clamp(x / .2)) * (1 - treeOut);
    const p = P(t, a, .9, OUT);
    e.style.transform = `translate(${appended ? (1 - p) * 150 : 0}px,${treeOut * 40 + (n.lvl === 0 && !appended ? (1 - p) * 40 : 0)}px) scale(${lerp(appended ? .85 : .4, 1, spring(x, 12, 8)) * (1 + .1 * fl)})`;
    e.style.filter = treeOut > .01 ? `blur(${treeOut * 8}px)` : "none";
    if (n !== root) e.style.boxShadow = `0 0 0 ${5 * fl}px rgba(47,107,234,${.45 * fl}),0 14px 26px -16px rgba(20,40,110,.45)`;
    // every append rewrites the hashes above it
    const ver = APP.filter(ap => t >= ap + n.lvl * .2 && n.lvl > 0 && (n === root || n.lvl === 2 && n.i === 1 || n.lvl === 1 && n.i >= 2)).length;
    const sp = e.querySelector("span");
    if (n === root) sp.textContent = ["5b2e 11c9", "d7a0 3e58", "40fc 9a17", "9f3a c107"][ver];
    else if (n.lvl > 0) sp.textContent = ver ? HX[16 + n.lvl * 4 + n.i + ver * 8 % 24] : HX[8 + (n.lvl === 1 ? n.i : 4 + n.i)];
  }
  root.el.style.boxShadow = `0 0 0 ${8 * Math.max(0, ...APP.map(a => t > a + .6 ? Math.exp(-(t - a - .6) / .3) : 0))}px rgba(47,107,234,.3),0 18px 34px -16px rgba(20,40,110,.6)`;
  sheen(root.el, t, APP[2] + .6);
  adaTag.style.opacity = P(t, G(97), .5) * (1 - treeOut) * (1 - .4 * (1 - on(t, PROOF - .3, G(115), .3, .3)));
  for (const E of edgeEls) {
    if (!E.len) E.len = E.el.getTotalLength();
    const a = Math.max(appearAt(E.n), appearAt(E.p)) - .05, p = P(t, a, .8, OUT);
    E.el.style.strokeDasharray = E.len; E.el.style.strokeDashoffset = E.len * (1 - p);
    E.el.style.opacity = (t < a ? 0 : .5) * (1 - treeOut);
  }
  proofEdges.forEach((E, k) => {
    if (!E.len) E.len = E.el.getTotalLength();
    const p = P(t, PROOF + k * .45, .5, x => x);
    E.el.style.strokeDasharray = E.len; E.el.style.strokeDashoffset = E.len * (1 - p);
    E.el.style.opacity = (t < PROOF ? 0 : 1) * (1 - treeOut);
  });
  [leaves[2], l1[1], l2[0]].forEach((n, k) => { const p = P(t, PROOF + k * .45, .4); if (t > PROOF + k * .45) n.el.style.boxShadow = `0 0 0 ${4 * p}px #2F6BEA,0 0 0 ${10 * p}px rgba(47,107,234,.18)`; });
  [leaves[3], l1[0], l2[1]].forEach((n, k) => { const a = PROOF + .25 + k * .45, p = P(t, a, .4); if (t > a) n.el.style.boxShadow = `0 0 0 ${3 * p}px rgba(47,107,234,.4)`; });
  const inl = $("#inlog"); pop(inl, t, G(110.5)); inl.style.opacity = t < G(110.5) ? 0 : clamp((t - G(110.5)) / .15) * (1 - treeOut);
  words("#h7", t, G(96.6), .07); rise($("#s7Sub"), t, G(107)); rise($("#s7Spec"), t, G(109));
  if (t > G(115.2)) { wordsOut("#h7", t, G(115.2)); fall($("#s7Sub"), t, G(115.3)); fall($("#s7Spec"), t, G(115.3)); }
  show($("#c7"), t < G(117)); show($("#s7Spec"), t < G(117));

  // --- 9 · the root becomes a checkpoint; witnesses check and sign it
  const ck = $("#ck"), ck2 = $("#ck2");
  const cIn = P(t, G(115.6), 1.3, OUT), split = P(t, SPLIT, 1.4, INOUT);
  const ckY = lerp(lerp(LY[3], 420, cIn), 250, split), ck2Y = lerp(420, 810, split), ckS = lerp(.45, 1.1, cIn) * lerp(1, 1 / 1.1, split), ck2S = lerp(1.05, 1, split);
  at(ck, TX, ckY); ck.style.translate = "-50% -50%";
  ck.style.opacity = t < G(115.6) ? 0 : clamp((t - G(115.6)) / .3); ck.style.transform = `scale(${ckS})`;
  root.el.style.opacity = parseFloat(root.el.style.opacity || 1) * (1 - P(t, G(115.6), .4));
  at(ck2, TX, ck2Y); ck2.style.translate = "-50% -50%"; ck2.style.opacity = t < SPLIT ? 0 : clamp((t - SPLIT) / .3); ck2.style.transform = `scale(${ck2S})`;
  $("#ckS").textContent = t < SPLIT ? "2,981 keys" : "Shown to you";
  rise($("#wsNote"), t, G(118)); fall($("#wsNote"), t, G(134.6));
  const d = $("#diff"), cl = P(t, G(139), .6, x => x);
  d.textContent = t < G(139) ? "b82e" : "5d0e";
  d.style.background = `rgba(251,213,215,${cl})`; d.style.color = `rgb(${lerp(10, 216, cl)},${lerp(10, 50, cl)},${lerp(12, 58, cl)})`;
  d.style.boxShadow = `0 0 ${24 * cl * (1 - smooth(G(140), G(141.5), t) * .6)}px rgba(216,50,58,${.7 * cl})`;

  // witnesses: an arc under the checkpoint, then a row between the two versions
  const wOut = P(t, G(157.2), .5, IN), wpos = [];
  wits.forEach((w, n) => {
    const a = G(116.4) + n * .12, x0 = t - a;
    const [ax, ay] = WARC[n], [bx, by] = WROW[n], x = lerp(ax, bx, split), y = lerp(ay, by, split) + (1 - P(t, a, 1, OUT)) * 140;
    wpos[n] = [x, y];
    at(w, x - 44, y - 44);
    w.style.opacity = x0 < 0 ? 0 : clamp(x0 / .2); w.style.scale = x0 < 0 ? .01 : lerp(.5, 1, spring(x0));
    // checking: a ring sweeps round, then a tick
    const sa = SIGN8[n], rp = P(t, sa - .6, .6), reset = P(t, G(134.6), .5);
    w.querySelector("circle").style.strokeDashoffset = 327 * (1 - rp * (1 - reset));
    const ti = w.querySelector("i"); ti.style.opacity = t < sa ? 0 : 1 - reset; ti.style.scale = t < sa ? .01 : spring(t - sa);
    const isC = n === 2, c9 = isC ? P(t, CRED, .6) : 0;
    w.querySelector("b").style.boxShadow = `0 16px 30px -14px rgba(20,40,110,.55),0 0 0 4px ${c9 > 0 ? `rgb(${lerp(255, 216, c9)},${lerp(255, 50, c9)},${lerp(255, 58, c9)})` : "#fff"},0 0 ${30 * c9}px ${8 * c9}px rgba(216,50,58,${.5 * c9})`;
    const dim = t > CRED && !isC ? .45 * P(t, CRED, .6) : 0;
    w.style.filter = dim ? `saturate(${1 - dim}) opacity(${1 - dim * .6})` : "none";
    const sh = isC && t > VERD ? Math.exp(-(t - VERD) / .15) * 5 : 0;
    w.style.translate = `${Math.sin(t * 93) * sh}px ${Math.cos(t * 71) * sh}px`;
  });
  // signatures: tokens arc from each witness to the checkpoint's row of signers
  const slot = (c, n) => { const [ox, oy] = slotOff[c][n], s = c ? ck2S : ckS; return [TX + ox * s, (c ? ck2Y : ckY) + oy * s]; };
  const signed = [[], []];
  toks.flat().forEach(k => { k.style.opacity = 0; });
  const fire = (tok, c, n, a, d = .7) => {
    const [sx, sy] = slot(c, n), [wx, wy] = wpos[n], p = P(t, a, d, INOUT);
    const [x, y] = qbez([wx, wy], [lerp(wx, sx, .5) + (n - 2) * 40, Math.min(wy, sy) - 60], [sx, sy], p);
    at(tok, x - 15, y - 15); tok.style.opacity = t < a ? 0 : p < 1 ? 1 : 0; tok.style.scale = lerp(1.4, .9, p);
    return t >= a + d;
  };
  if (t < G(134.8)) SIGN8.forEach((a, n) => { if (fire(toks[0][n], 0, n, a)) signed[0].push(n); });
  else {
    SIGN9[0].forEach((a, k) => { if (fire(toks[0][k], 0, k, a, .6)) signed[0].push(k); });
    SIGN9[1].forEach((a, k) => { if (fire(toks[1][k + 2], 1, k + 2, a, .6)) signed[1].push(k + 2); });
  }
  [$$("#ck .sig .ava"), $$("#ck2 .sig .ava")].forEach((slots, c) => slots.forEach((s, n) => {
    const onS = signed[c].includes(n);
    s.classList.toggle("off", !onS); s.classList.toggle(WG[n], onS);
    const landed = t < G(134.8) ? SIGN8[n] + .7 : (c ? SIGN9[1][n - 2] : SIGN9[0][n]) + .6;
    s.style.scale = onS ? lerp(.6, 1, spring(t - landed)) : 1;
    const isC = n === 2 && t > CRED, c9 = P(t, CRED, .6);
    s.style.boxShadow = isC ? `0 0 0 2px #fff,0 0 0 ${2 + 3 * c9}px rgba(216,50,58,${c9}),0 0 ${16 * c9}px rgba(216,50,58,${.8 * c9})` : "0 0 0 2px #fff";
  }));
  $("#ck .by").textContent = signed[0].length ? (t < G(134.8) ? who(signed[0].length - 1) : ["A", "A and B", "A, B and C"][signed[0].length - 1]) + " signed" : (t < G(134.8) && t > G(119.5) ? "Checking…" : "");
  $("#ck2 .by").textContent = signed[1].length ? ["C", "C and D", "C, D and E"][signed[1].length - 1] + " signed" : "";
  // lines from each witness to what it signed
  wline.forEach((set, c) => set.forEach((pth, n) => {
    let a = null, s8 = false;
    if (c === 0 && t < G(134.8)) { a = G(119) + n * .08; s8 = true; }
    else if (t >= G(134.8) && (c === 0 ? n <= 2 : n >= 2)) a = SIGN9[c][c === 0 ? n : n - 2] - .5;
    if (a == null || t < a) { pth.style.opacity = 0; return; }
    const [wx, wy] = wpos[n];
    let x2, y2, y1;
    if (s8) { x2 = TX + (n - 2) * 60; y2 = ckY + 110; y1 = wy - 50; }
    else if (c === 0) { x2 = TX + (n - 2) * 70; y2 = ckY + 118; y1 = wy - 50; }
    else { x2 = TX + (n - 2) * 70; y2 = ck2Y - 118; y1 = wy + 50; }
    pth.setAttribute("d", `M${wx} ${y1}C${wx} ${lerp(y1, y2, .5)} ${x2} ${lerp(y1, y2, .5)} ${x2} ${y2}`);
    const len = 400, p = P(t, a, s8 ? .7 : .5, OUT);
    pth.style.strokeDasharray = len; pth.style.strokeDashoffset = len * (1 - p);
    const redC = n === 2 && !s8 ? P(t, CRED, .6) : 0, fade8 = s8 ? 1 - P(t, G(134.6), .5) : 1, dim9 = !s8 && n !== 2 ? 1 - .55 * P(t, CRED, .6) : 1;
    pth.setAttribute("stroke", redC > .5 ? "#D8323A" : "#2F6BEA");
    pth.style.strokeWidth = 4 + 3 * redC;
    pth.style.opacity = (s8 ? .45 : .8) * fade8 * dim9 * (1 - wOut);
    pth.style.filter = redC > .5 ? "drop-shadow(0 0 6px rgba(216,50,58,.8))" : "none";
  }));
  const acc = $("#accept"); pop(acc, t, SIGN8[2] + .75, .7); if (t > G(134.6)) acc.style.opacity = 1 - P(t, G(134.6), .5);
  words("#h8", t, G(116.6), .07); rise($("#s8Sub"), t, G(122)); rise($("#s8Spec"), t, G(126));
  if (t > G(134.6)) { wordsOut("#h8", t, G(134.6)); fall($("#s8Sub"), t, G(134.7)); fall($("#s8Spec"), t, G(134.7)); }
  show($("#c8"), t > G(115) && t < G(136.6)); show($("#s8Spec"), t > G(115) && t < G(136.6));

  // --- 10 · a lie proves itself
  show($("#c9"), t > G(135));
  rise($("#s9Soon"), t, G(136)); words("#h9", t, G(136.4), .1, 1.15);
  const v = $("#s9V"), vx = t - VERD;
  v.style.opacity = vx < 0 ? 0 : clamp(vx / .15); v.style.transformOrigin = "0 50%"; v.style.transform = `scale(${vx < 0 ? 1.12 : lerp(1.12, 1, spring(vx, 12, 9))})`;
  sheen(v, t, VERD + .5);
  const sh = vx > 0 ? Math.exp(-vx / .15) * 5 : 0;
  $("#netG").style.translate = `${Math.sin(t * 91) * sh}px ${Math.cos(t * 77) * sh}px`;
  rise($("#s9Tx"), t, G(152));
}

// ===== 11 · end card: blue floods out of the mark's dot, then drains back for the loop
function sc11(t) {
  const vis = t > G(157) && t < LOOP - .6;
  show($("#s10"), vis);
  const fr = floodR(t);
  $("#flood").style.clipPath = fr <= 0 ? "circle(0px at 0 0)" : `circle(${fr}px at ${tg10.dot.x}px ${tg10.dot.y}px)`;
  if (!vis) return;
  mark($("#s10Mk"), t, G(159) - .1, G(159) + .25);
  spell($("#s10W"), t, G(159.6));
  rise($("#s10Soon"), t, G(161)); rise($("#s10Tag"), t, G(161.4)); rise($("#s10Cta"), t, G(162));
  sheen($("#s10Cta"), t, G(164));
  $("#s10C").style.transform = `scale(${1 + .025 * smooth(G(161), E10, t)})`;
  Object.assign($("#s10W").style, {opacity: 1, filter: "none", transform: "none"});
  [["#s10Cta", 0], ["#s10Tag", .05], ["#s10Soon", .08], ["#s10W", .12]].forEach(([id, d]) => fall($(id), t, E10 + d, .5, -24));
  const rt = P(t, E10 + .15, .5, INOUT), dz = P(t, E10 + .6, .35, IN);
  if (t > E10) { const m = $("#s10Mk"); m.querySelector(".d2").style.clipPath = `inset(0 ${rt * 100}% 0 0 round 999px)`; m.querySelector(".d1").style.scale = 1 - dz; }
}

window.ready = (async () => {
  await document.fonts.ready;
  await Promise.all([...document.fonts].map(f => f.load()));
  await Promise.all([...document.images].map(i => i.decode().catch(() => {})));
  MEASURE = true;
  const mk = $("#s10Mk"), dd = mk.querySelector(".d1").getBoundingClientRect(), ds = mk.querySelector(".d2").getBoundingClientRect();
  tg10 = {dot: {x: dd.left + dd.width / 2, y: dd.top + dd.height / 2, r: dd.width / 2}, dash: {x: ds.left, y: ds.top + ds.height / 2, w: ds.width, r: ds.height / 2}};
  // natural sizes of the things that grow or morph
  for (const el of $$(".nw")) { el.style.height = "auto"; el.dataset.h = el.firstElementChild.getBoundingClientRect().height / 1.06; }
  for (const b of $$("#rows .bub")) { const r = b.querySelector(".pl span").getBoundingClientRect(); b.dataset.w = r.width + 48; b.dataset.h = r.height + 28; }
  // where each signer sits on a checkpoint card, relative to its centre at scale 1
  for (const c of ["#ck", "#ck2"]) { const el = $(c); el.style.translate = "-50% -50%"; el.style.transform = "none"; at(el, TX, 540); }
  slotOff = ["#ck", "#ck2"].map(c => $$(c + " .sig .ava").map(s => { const r = s.getBoundingClientRect(); return [r.left + r.width / 2 - TX, r.top + r.height / 2 - 540]; }));
  // where the packets start and land: measured on the settled phones
  const centre = el => { const r = el.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; };
  render(G(27)); const a1 = centre($("#yN1 .b")), b1 = centre($("#aN1 .b"));
  pk1Path = {a: a1, b: b1, c: [960, (628 - .25 * (a1[1] - 50) - .25 * b1[1]) / .5]}; // skims over the servers pill
  render(G(95)); pk2Path = {a: centre($("#yN2 .b")), b: centre($("#aN2 .b"))};
  const q = (a, c, b) => `M${a[0]} ${a[1]}Q${c[0]} ${c[1]} ${b[0]} ${b[1]}`, up = a => [a[0], a[1] - 50];
  mkRoute("r1", q(up(pk1Path.a), pk1Path.c, pk1Path.b));
  mkRoute("rk", q([960, 486], [720, 560], [440, 404]));
  mkRoute("r2a", q(up(pk2Path.a), [640, 560], [960, 706]));
  mkRoute("r2b", q([960, 706], [1280, 560], pk2Path.b));
  L3.forEach((l, k) => shatters.push([l + .55, SLOT, CHY, 236, 132, 97 + k * 131]));
  MEASURE = false;
  render(0);
  return true;
})();
window.render = render;
window.DURATION = LOOP;
