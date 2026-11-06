# Bounded helper disclosures

These helpers admit fifteen specifically reviewed metadata releases while
retaining private content through binary framing, authenticated encryption,
chunked local history, and presentation selection. This is an application
migration checkpoint, not complete field labeling, network closure, an
independent security review, or a release guarantee.

The two inner-envelope sites publish an integer only: 0 means success, and
1..17 classify the original nullary ProtocolError variants. An exhaustive match
converts the error to that integer before disclosure; fixed errors are rebuilt
afterward. No ProtocolError value or arbitrary error text is declassified. A
future variant, including a variant with a payload, must fail compilation until
its disclosure policy is reviewed.

Other permitted values are the fixed framing/integer/history error classes;
one-bit ratchet/initial-handshake capacity and padding failure; history-part
bounds failure; invalid history capacity as 0 or the exact valid encoded size
8..16,794,632; and the three presentation predicates described below. Encoded
message/history bytes, storage context, AEAD nonce, sender identity, database
path, credentials, and authorization policy are not released by these helpers.
Local encrypted history exposes part count and ciphertext lengths. This policy
does not promise to hide message size, acceptance, timing, or local storage
footprint.

Direct and group history updates prepare encryption before observing private
presentation, attachment, encoding or seal outcomes. They then check the original
results in their original order. A failed preparation cannot return a write plan,
publish fallback ciphertext or replace the last committed history. Large history
prepares all chunks and its authenticated root before checking chunk failures;
the existing capacity limit bounds this to 280 chunks and one root. Preparation
can perform extra bounded reads, generate nonces and reserve secure-storage
counters even when an earlier result will fail. Counter gaps are permitted;
rollback or reuse is not. This ordering adds no declassification and does not
hide timing or secure-storage activity.

Presentation releases canonical-record validity, accepted presentation-frame
presence, and nonempty group metadata. Canonical validity is a content-derived
predicate over bounded name/avatar/community syntax, revision, and role framing;
it is not inherently public. These predicates grant no sender or role authority.
Authenticated sender/group/creator state must supply storage keys. Private role
and revision decisions select incoming or previous plaintext before sealing.
Admitted duplicate, older, and unauthorized values consequently reseal the
unchanged record and use the same encrypted write-plan shape. This advances
storage counters and may create an encrypted empty group record when an absent
record receives an unauthorized update. Malformed presentation errors normalize
to `invalid_presentation`. The existing logical role/revision decisions remain.

Run the focused production and adversarial proof after applying these helpers:

```sh
python3 ops/plaintext/prove_helpers.py \
  --compiler /absolute/path/to/pinned/meshc \
  --output /absolute/path/to/new/evidence-directory
```

The runner snapshots the two production packages without changing live sources.
It proves private envelope framing, mutates only the copy to require rejection of
a new payload-bearing ProtocolError, refuses eight private network/metadata
exits with only E0093 diagnostics and no artifact, and runs the affected real
history/presentation/hybrid/recipient transport tests. Known synthetic fixture
comparisons use test-only disclosure reasons. Retained logs/source hashes
identify this bounded checkpoint; authoritative compiler/application/native
pins and complete field/display/network inventories remain separate gates.
