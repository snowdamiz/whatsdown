s=open('v3.html').read()
def R(a,b):
    global s
    assert a in s, a[:90]
    s=s.replace(a,b)
# particles: blue and ink on paper, white on the blue card and the end card
R('''    cx.globalAlpha = Math.min(1, a) * (white ? lerp(1, .35, white) : 1);
    cx.fillStyle = white > .5 ? "#FFFFFF" : (p.k > .8 ? "#FFFFFF" : "#6AA6FF");''',
'''    const onBlue = white > .5 || (t > G(16) + .1 && t < G(25) - .05);
    cx.globalAlpha = Math.min(1, a) * (onBlue ? .45 : .85);
    cx.fillStyle = onBlue ? "#FFFFFF" : (p.k > .82 ? "#0B0B0F" : p.k > .6 ? "#6AA6FF" : "#2F6BEA");''')
# ring pulses instead of the glow flash
R('''  $("#flash").style.opacity = .12 * Math.exp(-Math.max(0, t - .93) / .25) * (t >= .93) + .38 * Math.exp(-Math.max(0, t - G(16)) / .3) * (t >= G(16));''',
'''  const rings = [[.93, 960, 540, 900], [4.42, tg2.dot.x, tg2.dot.y, 520]], rg = rings.filter(r => t >= r[0] && t < r[0] + .9).pop(), ring = $("#ring");
  if (rg) { const p = (t - rg[0]) / .9, r = EXPO(p) * rg[3]; Object.assign(ring.style, {left: rg[1] - r + "px", top: rg[2] - r + "px", width: 2 * r + "px", height: 2 * r + "px", opacity: (1 - p) * .8}); }
  else ring.style.opacity = 0;
  // the blue card bursts out of a circle on the drop, with the mark keying in behind the phone, and flies away at the end
  const bc = $("#blueCard"), burst = P(t, G(16) - .02, .65, EXPO), away = P(t, G(25) - .34, .4, IN);
  bc.style.clipPath = `circle(${burst * 2300}px at 1376px 516px)`;
  bc.style.visibility = t > G(16) - .05 && t < G(25) + .1 ? "visible" : "hidden";
  const flyAway = `perspective(1600px) translateY(${-away * 1180}px) rotateX(${away * 14}deg) scale(${1 - away * .08})`;
  bc.style.transform = flyAway; $("#s4").style.transform = flyAway;
  const bd = P(t, G(16) + .25, .7, x => clamp(x));
  $("#bDot").style.cssText = `left:1040px;top:67px;width:381px;height:381px;opacity:${clamp(bd * 2)};scale:${lerp(.4, 1, back(bd))};translate:${-(t - G(16)) * 9}px 0`;
  $("#bDash").style.cssText = `left:1040px;top:584px;width:1100px;height:381px;clip-path:inset(0 ${(1 - P(t, G(16) + .5, 1.1, EXPO)) * 100}% 0 0 round 190px);translate:${-(t - G(16)) * 5}px 0`;''')
# the phone no longer slides off right on its own: the card carries it away
R('''  let ry = lerp(80, -20, fly) + 9 * smooth(G(16) + .9, G(20), t) + 180 * flip + 5 * smooth(G(21), G(25), t) + leave * 50;''',
  '''  let ry = lerp(80, -20, fly) + 9 * smooth(G(16) + .9, G(20), t) + 180 * flip + 5 * smooth(G(21), G(25), t);''')
R('''  tilt3d(rig, {x: lerp(360, 0, fly) + leave * 900, y:''','''  tilt3d(rig, {x: lerp(360, 0, fly), y:''')
R('''  const l4 = P(t, G(25) - .3, .3, IN);
  $("#s4L").style.transform = `translateX(${-l4 * 200}px)`; $("#s4L").style.opacity = 1 - l4; $("#s4L").style.filter = l4 > 0 ? `blur(${l4 * 16}px)` : "none";''','')
# the heart pops onto the reply
R('''  strips.forEach((s, n) =>''','''  const rp = clamp((t - 12.3) / .5); $("#react").style.opacity = clamp(rp * 2); $("#react").style.scale = t < 12.3 ? .01 : rp < .55 ? lerp(.3, 1.18, rp / .55) : lerp(1.18, 1, (rp - .55) / .45);
  strips.forEach((s, n) =>''')
# butter field grows in under the To card; sky field under the slips
R('''  const cp = P(t, G(11), .8, EXPO), card = $("#s3Card");''','''  const bf = P(t, G(10) + .25, .8, EXPO);
  $("#butter").style.transform = `scale(${lerp(.25, 1, bf)}, ${lerp(.05, 1, bf)})`; $("#butter").style.opacity = clamp(bf * 3);
  const cp = P(t, G(11), .8, EXPO), card = $("#s3Card");''')
R('''  card.style.boxShadow = `inset 0 0 0 1.5px rgba(255,255,255,.14),0 0 0 ${3 * focus}px rgba(106,166,255,${focus}),0 0 ${90 * focus}px rgba(106,166,255,${.35 * focus}),0 50px 90px -40px rgba(0,0,0,.9)`;''',
  '''  card.style.boxShadow = `0 0 0 ${3 * focus}px rgba(47,107,234,${focus}),0 0 0 ${12 * focus}px rgba(47,107,234,${.12 * focus}),0 40px 70px -34px rgba(11,11,15,.4)`;''')
R('''  rise($("#s5Soon"), t, G(25));''','''  rise($("#s5Soon"), t, G(25));
  const sk = P(t, G(25) - .05, .8, EXPO);
  $("#sky").style.transform = `scale(${lerp(.55, 1, sk)})`; $("#sky").style.opacity = clamp(sk * 3); $("#sky").style.borderRadius = `${lerp(400, 64, sk)}px`;''')
open('v3.html','w').write(s)
print("js ok")
