# Local message history storage

Direct-message history keeps the most recent 256 entries. Adding entry 257 drops
only the oldest entry; a large valid message does not reduce that count. The
canonical entry framing is unchanged. The encoder and decoder share one budget:
8 bytes for the count frame plus 256 entry vectors, each containing at most
65,600 bytes. The maximum logical plaintext is 16,794,632 bytes.

The platform storage seal still accepts at most 65,536 plaintext bytes. Small
histories retain their original platform-wrapped representation. Larger
histories use a versioned `HCB2` container holding one sealed manifest followed by
sealed data parts of at most 60,000 plaintext bytes each. This is a product
storage format; it does not enlarge generic cryptographic or network limits.

The manifest authenticates the complete plaintext length and SHA-256 digest,
data-part count, random 32-byte generation, and history-label digest. Its storage
context binds the label and generation. Each data part has a separate context
binding the label, generation, and part index. The reader requires exact part
lengths, an exact manifest, and complete input consumption. Tampering, reordered
parts, missing or trailing data, a different label, or parts from another
generation fail closed. The reader permits at most 281 sealed parts including
the manifest, and at most 16,831,624 container bytes.

All parts remain inside one SQLite BLOB under the existing history label. The
existing transaction replaces that BLOB together with the applicable session
and outbox updates. A failed seal does not write anything. A failed later SQL
write rolls back the replacement; no detached chunk rows or cleanup cursor are
introduced. Sealing may burn platform counter values on failure, which is safe
and does not reuse those values.

The reader accepts genuine legacy platform-wrapped histories using their
original context. The next successful write chooses the representation by
plaintext length, so a growing legacy history moves to `HCB2` without changing
entry semantics or exposing plaintext in the database. Older clients cannot read
the new large-history container. Downgrading a database containing it is not
supported. The logical budgets above bound stored data, rather than claiming an
equal process-memory limit: encoding, authenticated opening, and decoding use
temporary copies. Balanced concatenation avoids retaining every growing prefix.

Group history retains its existing separate policy: at most 256 entries and at
most 65,536 plaintext bytes, dropping older entries to fit. The real maximum
accepted group-message test verifies that the newest 65,237-byte body survives
on sender and both receiving devices; an oversized body is refused.

Focused coverage lives in `tests/history_storage.test.mpl` and the existing
group lifecycle boundary test. It includes a real platform-sealed SQLite
roundtrip above 8 MiB, retention after entry 257, rollback of a failed outbox
transaction, legacy migration, and malformed container refusal.
