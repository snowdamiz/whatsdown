# Experimental Hybrid Handshake, Version 1

Status: implemented and reachable. Suite `0x0002` is an experimental custom
construction. Release readiness depends on internal behavioral verification
and applicable platform evidence for the exact candidate; outside review is
not a prerequisite and no independent audit is claimed.

Suite `0x0002` combines the four X25519 results from the classical handshake
with one ML-KEM-768 shared secret. A hybrid device credential binds the exact
1,184-byte ML-KEM public key, and the signed prekey bundle advertises suites
`[0x0002, 0x0001]` and repeats that key. The initial message carries the exact
1,088-byte ML-KEM ciphertext.

```text
classical_ikm = DH1 || DH2 || DH3 || DH4
(pq_ciphertext, pq_secret) = ML-KEM-768.Encaps(responder_pq_prekey)
IKM = classical_ikm || pq_secret
```

The existing transcript salt, root-key, initial-message, and ratchet
derivations then consume `IKM`. The canonical transcript binds suite `0x0002`,
the responder ML-KEM public key, both credential/bundle hashes, and all
classical prekeys. Changing the ML-KEM ciphertext derives a different secret
and fails initial AEAD authentication without producing a session.

## Negotiation and migration

- Two hybrid peers select suite `0x0002`.
- A classical peer yields suite `0x0001` only when the remembered authenticated
  floor is at most `0x0001`.
- A peer previously authenticated at suite `0x0002` rejects a later suite
  `0x0001` offer as `DowngradeDetected`.
- Existing classical snapshots and mobile session records remain suite
  `0x0001`; there is no in-place key conversion.
- New development accounts publish hybrid credentials. Existing or linked
  classical devices move to suite `0x0002` only after credential/prekey
  rotation; established classical sessions remain valid until replaced.

Suite 1 wire vectors are unchanged. The compiler proof pins the ML-KEM-768 key
generation result to NIST ACVP FIPS 203 `tcId 26`; messenger tests cover hybrid
establishment, ratcheting, ciphertext alteration, explicit classical fallback,
and downgrade rejection. `mlkem_interop.test.mpl` checks the runtime's ML-KEM,
one Rust crate with no outside audit, against OpenSSL 3.6, which shares no code
with it: a fixed seed gives the same public key byte for byte, a ciphertext
OpenSSL made decapsulates to the same shared secret, and an altered ciphertext
decapsulates to a different one without an error. The shared secret cannot be
read out of the runtime, so it is compared by what it seals. This is agreement
between two implementations on one vector each way, not an audit of either.

## Limits and release verification

Hybrid decoding requires exact 1,184-byte public keys, 1,088-byte ciphertexts,
and 1,395-byte credentials before cryptographic work. Initial plaintext is
limited to 62,899 bytes so the complete canonical message stays within 65,536
bytes. One receive attempt still burns its claimed one-time X25519 prekey.

The M14 proof records compile-inclusive hybrid timing on the arm64 development
host and cross-compiles the iOS library. Physical-device profiling and
dependency findings must be recorded separately; cross-compilation is not a
device result. ML-KEM protects initial establishment only. The ongoing
Double Ratchet is classical, with no continuous post-quantum recovery claim.
