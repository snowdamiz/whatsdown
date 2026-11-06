# Account-bound sealed journals

The app passes its captured public account profile with every journal read and
write. `journal_load_bound` accepts three ordinary length vectors: database path
(4096 bytes), expected profile (36134), and key (256). `journal_save_bound` adds
a nonempty value up to 262144 bytes. A single zero byte removes the record.
Native hosts pin the database path and reject extra fields and trailing bytes.
The old unbound journal entries are unavailable through generic app dispatch.

Account/device identities and keys must still match; routine credential renewal
is allowed. Native code captures both encrypted custody and the previous record
before encryption. A guarded transaction compares both before committing.
Reads also recheck their captured basis. Queued work cannot borrow a replacement
account, and competing prepared writers cannot silently overwrite one another.

Existing records up to 64 KiB keep their original storage encoding. Larger
records use a fresh generation, an independently sealed manifest and up to four
independently sealed 64 KiB chunks. Authenticated contexts bind the journal key,
generation and chunk index. The manifest binds exact size and the plaintext
digest; decoding rejects missing, reordered, extra or corrupt chunks. The
entire encoded record remains one SQLite value.

Read-receipt and notification-preview choices use the fixed keys
`preferences/read-receipts` and `preferences/notification-preview`. Native code
accepts only `on`/`off` and `full`/`sender`/`none`, respectively. The UI migrates
old clear settings after successful native account validation and removes them
only after a sealed commit. Failed migrations retain the old value for retry.
Journal queues and caches are scoped to account/device identity; queued values
and profiles are copied before waiting.

Both native platform proofs cover 64 KiB, 64 KiB + 1 and 256 KiB records across
restart, malformed inputs, preference validation and account replacement.
Rendered checks cover receipt opt-out and redacted notification previews after
restart. These are local simulator/emulator and UI checks, not physical-device
performance or a complete application plaintext-flow claim.
