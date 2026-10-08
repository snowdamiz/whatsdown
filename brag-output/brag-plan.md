# Morse — brag plan

**What it is:** a private messenger you sign up to with just a username, where not even Morse can read your chats, and witnesses check every key it hands out.
**For:** people who want Signal-grade privacy without a phone number, and crypto communities who meet in chats that weren't built for them.
**Sets it apart:** "kept honest": the key directory is checked by witnesses, so a server that lies about a key gets caught ("Don't trust us. Make lying expensive.").
**Most impressive claim:** "We can't read a word of it." Flip the switch and the same chat becomes sealed envelopes.
**Visual hook:** Morse's own motion signature, *sealing*: a message arrives as dot-dash noise and opens into words.
**Real UI shown:** the landing page's app mockups (copied from the real app): the hero chat, the new-message and message-request sheets, the dark phone with the servers' view, and the key-log slips.
**Tone:** polished / app-store. Light, warm, confident, the WhatsApp/Signal bar the landing page aims for. No jargon on screen.
**Share caption:** a messenger that seals every message and puts witnesses on the servers.

## Identity (from apps/landing and the pitch deck)

Paper `#F6F2EA`, ink `#0B0B0F`, blue `#2459D0` / `#2F6BEA` / `#6AA6FF`, night `#0B0D14`, butter `#FFE8AD`, red `#D8323A`. Geist 400/500/600, tight tracking. Big flat colour fields with a bubble radius, no borders. The dot-over-dash mark. Ease `cubic-bezier(.2,.7,.2,1)`.

## Claims (all copy is lifted from index.html)

Status is honest: "In development" pill in the hero, "Launching in stages" on the network scene, and the call to action is the waitlist. No "free", "audit", "open source", no invented numbers (the deck's waitlist/tester counts stay out).

## Storyboard v4 (23.27s = 38 beats, 1920×1080, 30fps, cut to indie.mp3 at 98 BPM, loops seamlessly)

v1 read as a scroll through the landing page and its synthesized music and beeps didn't land. v3 keeps the light palette but is a motion piece: kinetic type on the beat, a Morse particle field, 2D shape morphs, 3D cards and a 3D phone, and motion blur (5 samples per frame, 180° shutter). Beat grid G(k) = 0.318 + 0.6122k.

| # | Time | Scene | Motion |
|---|---|---|---|
| 1 | 0–4.0 | **"We can't read / a word of it."** | Paper, Morse dots/dashes fly through depth; a blue ring pulses on the first beat; each word slams in on a beat (blur-to-sharp) |
| 2 | 4.0–6.4 | **Morse / Private messaging, kept honest.** | The headline zooms through the camera; the field collapses, dots into the dot and dashes into the dash; the letters rise |
| 3 | 6.4–10.1 | **Just a username.** | Whip pan in; a butter panel grows; a white "To" card tilts in in 3D and types "@ada"; "Phone number, Email, Address book, Wallet" drop in and are struck through on the beat |
| 4 | 10.1–15.6 | **On your phone → On our servers** | Push-through into the drop: the blue card bursts out of a circle; the logo's dot and dash key in behind a 3D phone that flies in from depth; chat bubbles land and unseal; the phone flips 180° to its back, the servers' dark view of sealed strips. "No names, no words, just sealed envelopes." The whole card flies up and away |
| 5 | 15.6–19.9 | **Launching in stages · Don't trust us. Make lying expensive.** | A sky panel grows; two key-log slips fly in in 3D; signers pop in; the tampered group turns red; a red line joins witness C on both slips; "Witness C signed both. Bond slashed." slams in with a shake; "Proof checked on Solana" |
| 6 | 19.9–23.27 | **End card → loop** | The particles form the mark; blue floods out of its dot on the last big beat; "In development", Morse, tagline, "Join the waitlist · morseapp.io". Then the words blur away, the dash retracts, the blue drains back into the dot and the dot closes, leaving the drifting paper field the video opens on |

**Loop:** one pass is exactly 38 beats (698 frames), so the beat grid carries across the seam. Every animated value returns to its frame-0 state: the light drifts on sin/cos of the loop phase, particle speeds are quarter steps and the field travels exactly four depths per pass, the motion-blur shutter wraps around the seam. The soundtrack's fade-out and every effect tail past the end wrap onto the start. Frame 0 is therefore the natural first frame (a baked poster would flash on every loop); `brag.jpg` is the thumbnail to upload.

Sound: the user's track (indie.mp3) as the bed. Effects sit ~10–13 dB under it: noise whooshes and reverse swells on the camera moves, sub hits on the three big beats, recorded keypresses for "@ada", soft clicks on the strikes, two card slides for the slips, one soft impact for the verdict. No pitched tones.
