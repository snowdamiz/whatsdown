// The network's live state, wherever a page has room for it: the trust profile and "Current witnesses"
// (WITNESS_NETWORK_PLAN.md §4.4), the bond counter (§6.17) and the map's "Next" marks. Both files come from
// this site: waitlist.mjs fetches them from the backend and passes on only what it has checked. With no
// answer, or no script, every place keeps the words written into the page, which are true today, and a
// place with nothing true to show stays hidden.
(async () => {
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const has = (...names) => names.some((n) => document.querySelector(`[data-net="${n}"],[data-next="${n}"]`));
  const get = (name) => fetch(`network/${name}.json`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
  const [reg, net] = await Promise.all([
    has("profile", "outvote", "witnesses", "need", "outside") ? get("registry") : null,
    has("counter", "witnesses", "anchor") ? get("status") : null,
  ]);
  const el = (tag, attrs, ...kids) => { const e = Object.assign(document.createElement(tag), attrs); e.append(...kids); return e; };
  const put = (name, ...kids) => $$(`[data-net="${name}"]`).forEach((e) => e.replaceChildren(...kids.map((k) => (k.cloneNode ? k.cloneNode(true) : k))));
  const dollars = (usd) => { const f = usd.endsWith(".00") ? 0 : 2; return Number(usd).toLocaleString("en-US", { style: "currency", currency: "USD", minimumFractionDigits: f, maximumFractionDigits: f }); };
  const rtf = new Intl.RelativeTimeFormat("en");
  const ago = (iso) => {
    const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
    return s < 90 ? rtf.format(-s, "second") : s < 5400 ? rtf.format(-Math.round(s / 60), "minute") : s < 129600 ? rtf.format(-Math.round(s / 3600), "hour") : rtf.format(-Math.round(s / 86400), "day");
  };

  if (reg) {
    const { profile, k, witnesses } = reg, n = witnesses.length, m = witnesses.filter((w) => w.morse_run).length;
    const every = n === 1 ? "the only witness is" : n === 2 ? "both witnesses are" : `all ${n} witnesses are`;
    const some = `${m} of ${n} witnesses are`, outside = (x) => `${x} outside witness${x === 1 ? "" : "es"}`;
    const cap = (s) => s[0].toUpperCase() + s.slice(1);
    put("profile", {
      bootstrap: m === n ? `Bootstrap: ${every} run by Morse. Independent witnesses join in stages.`
        : `Bootstrap: ${some} run by Morse, enough for a majority on their own. Outside operators run the other ${n - m}.`,
      transitional: `Transitional: ${some} run by Morse, short of the ${k} phones need. A fork would take at least ${outside(k - m)} too.`,
      open: `Open: ${n - m} of ${n} witnesses are independent. Morse runs ${m ? "one" : "none"}, and phones need ${k}.`,
    }[profile]);
    put("outvote", {
      bootstrap: `Today, yes. ${cap(m === n ? every : some)} run by Morse, enough for a majority without anyone else. Once the network is open, Morse runs one witness, and the threshold is set so it can never reach a majority, alone or with the directory.`,
      transitional: `Not on its own. ${some} run by Morse, short of the ${k} phones need, so a fork would take at least ${outside(k - m)} signing it too. Once the network is open, Morse runs one.`,
      open: `No. Morse runs ${m ? "one" : "none"} of the ${n} witnesses, and phones need ${k}, so it can never reach a majority, alone or with the directory.`,
    }[profile]);
    put("need", `Phones need ${n === 1 ? "its signature" : k === n ? `${n === 2 ? "both" : `all ${n}`} signatures` : `${k} of ${n} signatures`}`);
    put("witnesses", ...witnesses.map((w, i) => {
      const bond = net?.witnesses[w.witness_id];
      const operator = w.morse_run && w.operator !== "Morse" ? `${w.operator} (Morse)` : w.operator;
      return el("li", {},
        el("span", { className: `ava t${i % 5}`, ariaHidden: "true" }, w.witness_id.split("-").pop()[0].toUpperCase()),
        el("div", {}, el("b", {}, w.witness_id), el("small", {}, `Key ${w.public_key.slice(0, 16).match(/..../g).join(" ")}`),
          ...(bond ? [el("small", {}, el("a", { href: bond.link }, dollars(bond.usd)), " bonded")] : [])),
        el("em", {}, operator));
    }));
    if (m < n) $$('[data-next="outside"]').forEach((e) => (e.hidden = true));
  }

  if (net) {
    const a = (text, href) => el("a", { href }, text);
    const lines = [];
    if (net.bonded) lines.push([a(dollars(net.bonded.usd), net.bonded.link), " bonded."]);
    if (net.slashes.length) lines.push(net.slashes.length === 1 ? ["Slashed: ", a("once", net.slashes[0].link), "."]
      : [`Slashed ${net.slashes.length} times: `, ...net.slashes.flatMap((s, i) => [i ? ", " : "", a(`#${i + 1}`, s.link)]), "."]);
    else if (net.slashed && !net.slashed.never) lines.push(["Slashed: ", a("yes", net.slashed.link), "."]);
    else if (net.slashed?.never && net.bonded) lines.push(["Slashed: ", a("never", net.slashed.link), "."]);
    if (net.checkpoint) {
      const when = a(ago(net.checkpoint.time), net.checkpoint.link);
      when.dataset.age = net.checkpoint.time;
      lines.push([el("i", { ariaHidden: "true" }), "Last public checkpoint: ", when, "."]);
    }
    if (net.state === "unavailable") lines.push(["Live numbers unavailable: two chain providers must agree before we show any."]);
    $$('[data-net="counter"]').forEach((c) => {
      c.replaceChildren(...lines.map((l) => el("span", {}, ...l.map((k) => (k.cloneNode ? k.cloneNode(true) : k)))));
      c.hidden = !lines.length;
    });
    if (net.checkpoint) {
      $$('[data-next="anchor"]').forEach((e) => (e.hidden = true));
      // Ticks every copy, including ones the map's popover made after this ran.
      setInterval(() => $$("[data-age]").forEach((e) => (e.textContent = ago(e.dataset.age))), 1000);
    }
  }
})();
