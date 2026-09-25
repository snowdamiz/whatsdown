// The blog's pages share this script: Morse, the nav's hairline, reveals and rising headings, as on witnesses.html.
(() => {
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // Readable Morse: these lines only ever spell out our own words.
  const M = {A:".-",B:"-...",C:"-.-.",D:"-..",E:".",F:"..-.",G:"--.",H:"....",I:"..",J:".---",K:"-.-",L:".-..",M:"--",N:"-.",O:"---",P:".--.",Q:"--.-",R:".-.",S:"...",T:"-",U:"..-",V:"...-",W:".--",X:"-..-",Y:"-.--",Z:"--.."};
  for (const el of $$("[data-morse]")) {
    const chars = [...el.dataset.morse.toUpperCase()].filter(ch => ch === " " || M[ch]);
    el.innerHTML = chars.map((ch, n) => ch === " " ? '<i class="G"></i>'
      : [...M[ch]].map(s => s === "-" ? '<i class="D"></i>' : "<i></i>").join("") + (chars[n + 1] && chars[n + 1] !== " " ? '<i class="g"></i>' : "")).join("");
  }

  const nav = document.querySelector(".nav"), stuck = () => nav.classList.toggle("stuck", scrollY > 4);
  addEventListener("scroll", stuck, {passive: true}); stuck();
  // Narrow, the links open from the menu button. Any other click (following a link too), or Escape, folds them away.
  const menu = document.querySelector(".menu"), fold = open => menu.setAttribute("aria-expanded", nav.classList.toggle("open", open));
  addEventListener("click", e => e.target.closest(".menu") ? fold() : fold(false));
  addEventListener("keydown", e => e.key === "Escape" && nav.classList.contains("open") && (fold(false), menu.focus()));

  const io = new IntersectionObserver(es => es.forEach(e => e.isIntersecting && (e.target.classList.add("in"), io.unobserve(e.target))), {rootMargin: "0px 0px -12% 0px"});
  $$(".reveal").forEach(el => io.observe(el));

  const words = el => {
    for (const n of [...el.childNodes]) {
      if (n.nodeType !== 3) { words(n); continue; }
      const f = document.createDocumentFragment();
      for (const part of n.textContent.split(/(\s+)/)) {
        if (!part.trim()) { f.append(part); continue; }
        const w = document.createElement("span"), i = document.createElement("i");
        w.className = "w"; i.textContent = part; w.append(i); f.append(w);
      }
      n.replaceWith(f);
    }
  };
  if (!calm) for (const h of $$("main h2")) {
    words(h); h.classList.add("split");
    $$(".w>i", h).forEach((i, n) => i.style.setProperty("--wi", n));
    io.observe(h);
  }
})();
