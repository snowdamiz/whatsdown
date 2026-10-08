# Morse explainer — how the encryption and the witnesses work

## v2 (current): `work/explainer2.html` + `work/audio2.mjs`, ~86s

User feedback on v1: some parts too fast to read, animations should feel more premium, use `~/Desktop/idea.mp3` instead, and add a few tasteful sound effects for emphasis, sparingly.

- **Music:** idea.mp3, 120 BPM, kicks on G(k) = 0.18 + 0.5k. Intro to G(32), build to G(96), big section to G(160), quiet outro, final hit G(192). Played as is up to G(166), then cut 12s ahead (the outro's repeats) so the final hit lands on G(168); its fade wraps onto the opening. Loop = 2580 frames (86.0s).
- **Story on the song:** intro = hook + the lock (0–16s); build = ratchet, sealed and padded, "That was the easy part.", the question, the quiet swap (16–48s); big section = log, witnesses, fork (48–80s); final hit = end card and the drain back to the opening card.
- **Pacing:** every step has room: 4 messages on the ratchet (one every 1.5s), rows 1.5s apart, witnesses sign 1–1.5s apart, headlines hold ≥2.5s after settling.
- **Motion:** words rise through a mask with a long soft settle; springs for things that land; slow dolly per scene; the blue grows out of Ada's message and masks the phone scene away; the second key-log version slides out from under the first; depth of field while the server reads the message; light sheens on sealed packets, the root, the verdict and the CTA; contact shadows under the phones; calmer particle field; signature tokens fly in arcs.
- **Sound:** effects levelled against the music around them: typing (−21 dB), send click, seal swish, arrival, one tick per ratchet key, two soft whooshes into and out of the blue plus one into the log, the key sliding in, a glitch on the key flip, a low thud when the server reads the message, a click on "In the log", a chip on the majority, and a thud + soft impact on the verdict (−10 dB). Nothing else.

## v1 (kept as `work/brag-v1.mp4`, `work/explainer.html`, `work/audio.mjs`)

Built alongside the launch video in `brag-output/` (untouched). /brag-slim on Opus 5.5.

**What it is:** a messenger that locks every message on your phone, and then checks the one thing encryption can't: that the key it locked it with really is your friend's.
**For:** people who care how a private messenger actually keeps a secret, and the crypto community Morse is courting for witnesses.
**Sets it apart:** the key directory is checked. Every key sits in a log that only grows; witnesses sign each version; a server that shows two people two different logs leaves a witness who signed both, and that witness's bond is slashed.
**Most impressive claim:** "A lie proves itself." (two majorities always share a witness)
**Visual hook:** the blog's own thesis as the opening card: "Encryption was the easy part."
**Real UI shown:** the app's chat screen as the landing page copies it (bubbles, ticks, @ada/@you avatars from `apps/landing/img`), the sealed Morse-noise strips, the key-log slips.
**Tone:** polished explainer in the launch video's light language (paper, ink, blue ramp, Geist, 3D, Morse particle field, motion blur). One idea per scene, big type, small spec lines for the technical viewer.
**Share caption:** how Morse locks a message, and how it proves the key was really your friend's.

## Why ~49s and not 20

The ask is an explainer of two systems. The story needs eight ideas (lock, ratchet, sealed+padded, the question, the swap, the log, witnesses, the fork proof) and each line has to hold long enough to read (~0.3s/word). The song is arranged to fit rather than cut short.

## Claims (every line traces to a doc)

| On screen | Source |
|---|---|
| Locked on your phone. Opened only on Ada's. | blog "Encryption was the easy part", recipient-transport-v1 |
| X25519 + ML-KEM-768 · ChaCha20-Poly1305 | crypto-profile-v1, hybrid-handshake-v1 (new accounts publish hybrid credentials) |
| A new key for every message. Used once, then destroyed. · Double Ratchet | crypto-profile-v1 (message keys, never reused; dropped after use) |
| Sealed and padded. Our servers can't see who sent it, or tell "OK" from a paragraph. | blog, sealed-delivery-v1, recipient-transport-v1 (padding buckets) |
| Where did your phone get Ada's key? / Encrypted perfectly. For the wrong person. | blog "The quiet swap" |
| Every key goes into a log that only grows. Your phone checks it. Every time. | key-transparency-v1 (inclusion proof, consistency, witnesses on every lookup) |
| Witnesses check every version, then sign it. Your phone needs a majority. | key-transparency-v1 client rules; blog |
| All a witness ever sees: version, size, fingerprint | key-transparency-v1 ("checkpoint commitments only") |
| A lie proves itself. Witness C signed both. Bond slashed. Proof checked on Solana. | witness-network-v1 (**proposed**), so this scene carries the "Launching in stages" pill |

Never "independent" witnesses, no audit talk, no "unbreakable"/"military-grade". End card keeps "In development" and the waitlist CTA.

## Music

The user's track `~/Desktop/indie.mp3` (98 BPM, beat grid G(k) = 0.318 + 0.6122k), re-arranged on bar lines into verse → chorus → verse → chorus → last two bars → final hit:

| Arranged beats | Source beats | Story |
|---|---|---|
| 0–16 | 0–16 (verse) | hook, the lock |
| 16–32 | 16–32 (chorus) | ratchet, sealed and padded |
| 32–48 | 0–16 (verse) | the easy part, the question, the quiet swap |
| 48–64 | 16–32 (chorus) | the log, the witnesses |
| 64–72 | 24–32 (chorus, 2nd half) | the fork proof |
| 72– | 32–end (hit + fade) | end card; the fade wraps onto the start |

Loop = 80 beats = 1469 frames (48.97s). It loops seamlessly: the end card drains back into the opening card, so frame 0 is both the poster and the seam.

## Storyboard (1920×1080, 30fps)

| # | Beats (time) | Scene | Motion |
|---|---|---|---|
| 1 | 0–5 (0–3.4s) | **Encryption was / the easy part.** | Settled at frame 0 over the drifting Morse field, small Morse lockup below. Burst + ring on G1; the title zooms through the camera |
| 2 | 5–16 (3.4–10.1) | **Locked on your phone. / Opened only on Ada's.** | Two 3D phones fly in; "See you at 7." is typed and sent; the bubble lifts off, seals into Morse noise, arcs through "Morse servers" (which only see noise) and unseals on Ada's phone. Spec: X25519 + ML-KEM-768 · ChaCha20-Poly1305 |
| 3 | 16–24 (10.1–15.0) | **A new key for every message. / Used once. Then destroyed.** | Drop: blue bursts out of the packet. A ratchet gear turns a tooth per beat; a chain of key tiles advances; each message drops onto the current key, seals and flies off while the key shatters into dots. Spec: Double Ratchet |
| 4 | 24–32 (15.0–19.9) | **Sealed and padded.** Our servers can't see who sent it, or tell "OK" from a paragraph. | Three bubbles of very different lengths, each tagged "From @you", pass a light gate: the tag falls away and all three come out as identical sealed strips that stack into "Our delivery queue" |
| 5 | 32–40 (19.9–24.8) | **That was the easy part.** → **Where did your phone get Ada's key?** | The hook, called back on the verse's return. The phones come back; a Directory card appears above the servers and hands "@ada's key 9f3a c107 b82e 64d1" to your phone |
| 6 | 40–48 (24.8–29.7) | **Suppose it lies.** → **Encrypted perfectly. For the wrong person.** | The key flips to 7c21 e0a4 5d0e b913 (red); the message seals to it, the server turns red, opens it, reads it, re-seals it for Ada; Ada's phone shows it as if nothing happened |
| 7 | 48–56 (29.7–34.6) | **Every key goes into a log that only grows. / Your phone checks it. Every time.** | Drop: a Merkle tree assembles; three new entries append on the beat, each re-hashing its path and flipping the root fingerprint; the proof path from @ada's entry to the root lights up: "In the log". Spec: append-only Merkle log |
| 8 | 56–64 (34.6–39.5) | **Witnesses check every version, then sign it. / Your phone needs a majority.** | The root becomes a checkpoint card (version, size, fingerprint: "All a witness ever sees"); five witnesses around it check and stamp; a counter fills to 3 of 5 and the phone accepts |
| 9 | 64–72 (39.5–44.4) | **Launching in stages · A lie proves itself.** | The log forks into "Shown to you" and "Shown to Ada"; A, B, C sign one, C, D, E the other; C's two signatures join in red; "Witness C signed both. Bond slashed." slams with a shake; "Proof checked on Solana" |
| 10 | 72–80 (44.4–49.0) | **Morse · Private messaging, kept honest. · Join the waitlist · morseapp.io** | Final hit: the field forms the mark and blue floods out of its dot; "In development". Then the blue drains back into the dot and the opening card rises: the loop |

Sound: the track as the bed; effects ~10–13 dB under it: noise whooshes on the camera moves, sub hits on the drops (G16, G48, G72), recorded keypresses for the typing, a click on send, card slides for the slips and key tiles, one glitch for the swap, one soft impact for the verdict. No pitched tones.
