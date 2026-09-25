// The one part of these pages that isn't a static file: the waitlist form posts here. Each address is a key in
// KV, so joining twice changes nothing, and its value is only the day it joined. No IP, browser or referrer
// is kept. `wrangler deploy` creates the namespace the first time. To read the list, from this directory:
//   ../../ops/cloudflare/node_modules/.bin/wrangler kv key list --binding WAITLIST --remote
// ponytail: no rate limit; add a `ratelimits` binding if junk starts filling the list.
const looksLikeEmail = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/waitlist") return new Response("Not found", { status: 404 });
    if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });

    const form = await request.formData().catch(() => new FormData());
    const email = String(form.get("email") ?? "").trim().toLowerCase();
    if (email.length > 254 || !looksLikeEmail.test(email)) return new Response("That doesn’t look like an email address.", { status: 400 });
    // People never see this field; bots fill in everything. They're told it worked.
    if (!form.get("company")) await env.WAITLIST.put(email, new Date().toISOString().slice(0, 10));

    // The page's script only needs to know it worked. A form posted without script goes back to the page, which
    // then shows it's done.
    if (request.headers.get("sec-fetch-mode") === "navigate") return Response.redirect(new URL("/#joined", url), 303);
    return new Response(null, { status: 204 });
  },
};
