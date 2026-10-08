s=open('v2.html').read()
def R(a,b):
    global s
    assert a in s, a[:80]
    s=s.replace(a,b)
R('<title>Morse brag v2</title>','<title>Morse brag v3</title>')
R(':root{--blue:#2459D0;--blue-2:#2F6BEA;--blue-3:#6AA6FF;--red:#D8323A;--green:#178A4E;--lift:0 34px 56px -34px rgba(0,0,0,.6)}',
  ':root{--paper:#F6F2EA;--ink:#0B0B0F;--ink-2:#4A4A55;--ink-3:#6B6B77;--blue:#2459D0;--blue-2:#2F6BEA;--blue-3:#6AA6FF;--sky:#D5E2FF;--butter:#FFE8AD;--red:#D8323A;--green:#178A4E;--lift:0 40px 70px -34px rgba(11,11,15,.38)}')
R('html,body{margin:0;width:1920px;height:1080px;overflow:hidden;background:#05060A}','html,body{margin:0;width:1920px;height:1080px;overflow:hidden;background:#F6F2EA}')
R('body{font:400 17px/1.5 "Geist",system-ui,sans-serif;color:#fff;','body{font:400 17px/1.5 "Geist",system-ui,sans-serif;color:#0B0B0F;')
R('#stage{position:relative;width:1920px;height:1080px;overflow:hidden;background:radial-gradient(120% 95% at 50% 45%,#0D1120 0%,#07080E 55%,#030409 100%)}',
  '#stage{position:relative;width:1920px;height:1080px;overflow:hidden;background:radial-gradient(120% 100% at 50% 40%,#FBF8F2 0%,#F6F2EA 60%,#EFE9DD 100%)}')
R('#gA{width:1500px;height:1500px;background:radial-gradient(closest-side,rgba(47,107,234,.30),rgba(47,107,234,0))}',
  '#gA{width:1500px;height:1500px;background:radial-gradient(closest-side,rgba(106,166,255,.30),rgba(106,166,255,0))}')
R('#gB{width:1300px;height:1300px;background:radial-gradient(closest-side,rgba(106,166,255,.16),rgba(106,166,255,0))}',
  '#gB{width:1300px;height:1300px;background:radial-gradient(closest-side,rgba(255,221,140,.45),rgba(255,221,140,0))}')
R('background:radial-gradient(closest-side,rgba(216,50,58,.28),rgba(216,50,58,0));opacity:0}','background:radial-gradient(closest-side,rgba(255,150,140,.35),rgba(255,150,140,0));opacity:0}')
R('#grain{width:1920px;height:1080px;opacity:.08;mix-blend-mode:overlay}','#grain{width:1920px;height:1080px;opacity:.05;mix-blend-mode:soft-light}')
R('#vign{background:radial-gradient(ellipse 75% 70% at 50% 50%,rgba(0,0,0,0) 55%,rgba(0,0,0,.55) 100%);pointer-events:none}',
  '#vign{background:radial-gradient(ellipse 80% 75% at 50% 50%,rgba(120,95,60,0) 60%,rgba(120,95,60,.10) 100%);pointer-events:none}')
R('#flash{background:radial-gradient(60% 60% at 50% 50%,rgba(160,200,255,.9),rgba(106,166,255,0));opacity:0;mix-blend-mode:screen}',
  '#flash{opacity:0}\n#ring{position:absolute;border-radius:50%;box-shadow:inset 0 0 0 6px var(--blue-2);opacity:0}\n#blueCard{position:absolute;left:24px;top:24px;right:24px;bottom:24px;border-radius:48px;overflow:hidden;background:var(--blue);clip-path:circle(0px at 50% 50%)}\n.shape{position:absolute;border-radius:999px;background:var(--blue-2)}')
R('.acc{color:var(--blue-3);text-shadow:0 0 50px rgba(106,166,255,.35)}','.acc{color:var(--blue)}')
R('.mk i{position:absolute;left:0;background:#fff;border-radius:999px}','.mk i{position:absolute;left:0;background:var(--blue-2);border-radius:999px}\n#s6Mk i{background:#fff}')
R('.tagl{margin-top:54px;font-weight:500;font-size:58px;letter-spacing:-.03em;color:rgba(255,255,255,.9);opacity:0}',
  '.tagl{margin-top:54px;font-weight:500;font-size:58px;letter-spacing:-.03em;color:var(--ink-2);opacity:0}\n#s6Tag{color:rgba(255,255,255,.94)}\n#s6W{color:#fff}')
R('''  background:linear-gradient(180deg,rgba(255,255,255,.11),rgba(255,255,255,.04));font-size:84px;font-weight:600;letter-spacing:-.04em}
.to em{font-style:normal;font-weight:500;color:rgba(255,255,255,.4)}
.to i{display:inline-block;width:6px;height:92px;border-radius:3px;background:var(--blue-3);box-shadow:0 0 24px rgba(106,166,255,.8);margin-left:-18px}''',
'''  background:#fff;color:var(--ink);font-size:84px;font-weight:600;letter-spacing:-.04em}
.to em{font-style:normal;font-weight:500;color:#9A9AA6}
.to i{display:inline-block;width:6px;height:92px;border-radius:3px;background:var(--blue-2);margin-left:-18px}
#butter{position:absolute;left:240px;top:380px;width:1440px;height:560px;border-radius:64px;background:var(--butter)}''')
R('.pill{position:relative;padding:20px 38px 22px;border-radius:999px;font-size:46px;font-weight:500;letter-spacing:-.02em;background:rgba(255,255,255,.07);box-shadow:inset 0 0 0 1.5px rgba(255,255,255,.13);opacity:0}',
  '.pill{position:relative;padding:20px 38px 22px;border-radius:999px;font-size:46px;font-weight:500;letter-spacing:-.02em;background:#fff;color:var(--ink);box-shadow:0 16px 30px -18px rgba(11,11,15,.35);opacity:0}')
R('.pill i{position:absolute;left:26px;right:26px;top:50%;height:5px;margin-top:-2px;border-radius:3px;background:#fff;','.pill i{position:absolute;left:26px;right:26px;top:50%;height:5px;margin-top:-2px;border-radius:3px;background:var(--ink);')
R('.lab{position:relative;height:130px;font-size:120px}','.lab{position:relative;height:130px;font-size:120px;color:#fff}\n#labB{color:#fff}')
R('.cap{margin-top:60px;font-size:44px;line-height:1.35;letter-spacing:-.02em;color:rgba(255,255,255,.78);opacity:0;width:760px}',
  '.cap{margin-top:60px;font-size:44px;line-height:1.35;letter-spacing:-.02em;color:rgba(255,255,255,.88);opacity:0;width:760px}')
R('  box-shadow:inset 0 0 0 1px rgba(255,255,255,.1),0 60px 110px -40px rgba(0,0,0,.9),0 0 120px -20px rgba(47,107,234,.35)}',
  '  box-shadow:inset 0 0 0 1px rgba(255,255,255,.1),0 70px 110px -44px rgba(8,10,40,.7),0 24px 50px -24px rgba(8,10,40,.5)}')
R('.screen{position:relative;display:flex;flex-direction:column;height:640px;border-radius:44px;overflow:hidden;background:#0A0A0C;color:#F2F2F4;',
  '.screen{position:relative;display:flex;flex-direction:column;height:640px;border-radius:44px;overflow:hidden;background:#fff;color:#0A0A0C;')
R('.glare{position:absolute;inset:0;z-index:4;pointer-events:none;background:linear-gradient(112deg,rgba(255,255,255,0) 38%,rgba(255,255,255,.13) 47%,rgba(255,255,255,.03) 52%,rgba(255,255,255,0) 60%) 0 0/320% 100% no-repeat}',
  '.glare{position:absolute;inset:0;z-index:4;pointer-events:none;background:linear-gradient(112deg,rgba(255,255,255,0) 38%,rgba(255,255,255,.14) 47%,rgba(255,255,255,.03) 52%,rgba(255,255,255,0) 60%) 0 0/320% 100% no-repeat}\n.face:first-child .glare{background-image:linear-gradient(112deg,rgba(120,150,220,0) 38%,rgba(120,150,220,.10) 47%,rgba(120,150,220,.02) 52%,rgba(120,150,220,0) 60%)}\n.back .screen{background:#0A0A0C;color:#F2F2F4}')
R('.chead small{display:block;font-size:11.5px;color:#8E8E98}','.chead small{display:block;font-size:11.5px;color:#8E8E98}\n.chead .end{margin-left:auto;display:grid;place-items:center;width:32px;height:32px;border-radius:50%;box-shadow:0 1px 5px rgba(10,10,12,.14)}\n.chead .end .ic{width:17px;height:17px}')
R('.day{align-self:center;margin-bottom:5px;padding:4px 11px;border-radius:999px;background:#15151A;font-size:11px;color:#8E8E98}',
  '.day{align-self:center;margin-bottom:5px;padding:4px 11px;border-radius:999px;background:#F2F2F5;font-size:11px;color:#63636D}')
R('.b.in{align-self:flex-start;background:#1E1E25;border-bottom-left-radius:6px}','.b.in{align-self:flex-start;background:#E9E9EE;border-bottom-left-radius:6px}')
R('.b.out{align-self:flex-end;background:var(--blue-2);color:#fff;border-bottom-right-radius:6px}','.b.out{align-self:flex-end;background:var(--blue);color:#fff;border-bottom-right-radius:6px}')
R('.composer{display:flex;align-items:center;gap:9px;flex:none;height:44px;margin:0 12px 22px;padding:0 6px 0 13px;border-radius:999px;font-size:13.5px;box-shadow:inset 0 0 0 1px #27272F;background:#15151A;color:#63636D}',
  '.composer{display:flex;align-items:center;gap:9px;flex:none;height:44px;margin:0 12px 22px;padding:0 6px 0 13px;border-radius:999px;font-size:13.5px;box-shadow:inset 0 0 0 1px #DFDFE6,0 2px 8px rgba(10,10,12,.05);color:#8E8E98}')
R('.composer i{display:grid;place-items:center;width:32px;height:32px;margin-left:auto;border-radius:50%;background:#23427F;color:#9DB6EA}',
  '.composer i{display:grid;place-items:center;width:32px;height:32px;margin-left:auto;border-radius:50%;background:#A9C1F3;color:#fff}\n.react{position:absolute;left:12px;bottom:-13px;display:flex;align-items:center;height:24px;padding:0 8px;border-radius:999px;background:#fff;box-shadow:0 1px 5px rgba(10,10,12,.18);font-size:12px}\n.b.reacted{margin-bottom:12px}')
R('.seal>i{position:absolute;inset:0;display:flex;flex-wrap:wrap;align-content:flex-start;gap:14.7px 9px;padding-top:7.4px;overflow:hidden;color:rgba(255,255,255,.4)}',
  '.seal>i{position:absolute;inset:0;display:flex;flex-wrap:wrap;align-content:flex-start;gap:14.7px 9px;padding-top:7.4px;overflow:hidden;color:rgba(10,10,12,.42)}')
R('.soon{display:inline-flex;align-self:flex-start;align-items:center;gap:12px;padding:11px 24px 11px 18px;border-radius:999px;background:rgba(255,255,255,.1);font-weight:500;font-size:28px;color:rgba(255,255,255,.9);opacity:0}\n.soon i{width:12px;height:12px;border-radius:50%;background:var(--blue-3);box-shadow:0 0 12px var(--blue-3)}',
  '.soon{display:inline-flex;align-self:flex-start;align-items:center;gap:12px;padding:11px 24px 11px 18px;border-radius:999px;background:#fff;box-shadow:0 10px 24px -14px rgba(11,11,15,.3);font-weight:500;font-size:28px;color:var(--ink-2);opacity:0}\n.soon i{width:12px;height:12px;border-radius:50%;background:var(--blue-2)}\n#sky{position:absolute;left:1000px;top:96px;width:870px;height:900px;border-radius:64px;background:var(--sky)}')
R('.slip{zoom:1.7;width:380px;padding:20px 20px 22px;box-shadow:0 40px 80px -30px rgba(0,0,0,.9)}','.slip{zoom:1.7;width:380px;padding:20px 20px 22px;box-shadow:0 34px 56px -30px rgba(11,11,15,.4)}')
R('box-shadow:0 20px 60px -10px rgba(216,50,58,.6);opacity:0}','box-shadow:0 22px 40px -18px rgba(216,50,58,.7);opacity:0}')
R('.tx{position:absolute;font-size:24px;color:rgba(255,255,255,.62);opacity:0;white-space:nowrap}','.tx{position:absolute;font-size:24px;color:#3B4A73;opacity:0;white-space:nowrap}')
R('border-radius:999px;background:#fff;color:#0B0B0F;font-weight:600;font-size:36px;','border-radius:999px;background:#0B0B0F;color:#fff;font-weight:600;font-size:36px;')
R('.plat{margin-top:44px;font-size:26px;color:rgba(255,255,255,.72);opacity:0}','.plat{margin-top:44px;font-size:26px;color:rgba(255,255,255,.8);opacity:0}')
# markup
R('''  <div class="layer" id="flood"></div>''','''  <div id="blueCard"><i class="shape" id="bDot"></i><i class="shape" id="bDash"></i></div>
  <div class="layer" id="flood"></div>''')
R('''    <div id="s3C" class="layer">''','''    <div id="s3C" class="layer">
      <div id="butter"></div>''')
R('''<div class="chead"><svg class="ic"><use href="#i-back"/></svg><span class="ava t0">AD</span><b>@ada</b></div>''',
  '''<div class="chead"><svg class="ic"><use href="#i-back"/></svg><span class="ava t0">AD</span><b>@ada</b><span class="end"><svg class="ic"><use href="#i-info"/></svg></span></div>''')
R('''<p class="b out">Yes! I’ll book the place by the river.<small>9:32 AM<svg class="ic"><use href="#i-checks"/></svg></small></p>''',
  '''<p class="b out reacted">Yes! I’ll book the place by the river.<small>9:32 AM<svg class="ic"><use href="#i-checks"/></svg></small><span class="react" id="react">❤️</span></p>''')
R('''    <div id="s5G" class="layer">''','''    <div id="s5G" class="layer">
      <div id="sky"></div>''')
R('''  <div class="layer" id="flash"></div>''','''  <div class="layer" id="flash"></div><i id="ring"></i>''')
R('<path id="cPathG" fill="none" stroke="#FF5A62" stroke-width="10" stroke-linecap="round" filter="url(#gl)" opacity=".7"/>','<path id="cPathG" fill="none" stroke="#FF5A62" stroke-width="10" stroke-linecap="round" filter="url(#gl)" opacity=".35"/>')
R('<path id="cPath" fill="none" stroke="#FF6B72" stroke-width="4" stroke-linecap="round"/>','<path id="cPath" fill="none" stroke="#D8323A" stroke-width="4" stroke-linecap="round"/>')
open('v3.html','w').write(s)
print("css+markup ok")
