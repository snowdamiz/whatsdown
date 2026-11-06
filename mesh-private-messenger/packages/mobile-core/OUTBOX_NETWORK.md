# Native ordinary outbox transport

`Mobile.OutboxNetwork.native_outbox_drain` selects saved envelopes and sends their
privacy submissions to the immutable native `NetworkPins.edge_origin` at
`/v1/envelopes/batch`. The UI supplies no endpoint, headers, envelope or payment
material. Privacy sealing and proof of work remain in Mesh.

The request consists of two ordinary length-prefixed vectors, without a count
prefix: UTF-8 database path (1–4096 bytes, no NUL) and one mode byte. Mode `0`
drains normally; mode `1` explicitly retries ordinary free delivery after a
postage refusal. The maximum request is 4105 bytes.

The result has a raw u32BE count of six followed by six length-prefixed vectors:

| Field | Encoding |
| --- | --- |
| Version | `01 4f 42 58` |
| Status | u8: 0 complete, 1 recipient unavailable, 2 unknown transport outcome, 3 time budget exhausted |
| Acknowledged frames | u16BE, at most 256 |
| Remaining ordinary frames | u16BE, at most 256 |
| Postage triggers | Counted list of at most 256 exact 16-byte saved envelope IDs |
| Permanent refusals | Counted list of at most 256 rows, each status u16BE (400 or 410) followed by queued-at milliseconds u64BE |

The maximum result is 8749 bytes. These are local progress and presentation
fields. Acknowledgement means the service accepted the saved frame, not that a
recipient has read it.

A 402 never authorizes a payment. It seals a recipient pause before returning;
subsequent ordinary calls reopen that pause from SQLite. Only explicit mode `1`
clears pauses. A full 256-recipient pause history may drop only entries with no
queued frames. Current queued recipients are never evicted to cause another
free probe. Pending kind-8 postage intents retain ownership of their exact
frames and are excluded regardless of whether spending is currently enabled.

A 429 stops later frames for that recipient during this pass while allowing
other recipients to proceed. A 410, or a 400 after the saved expiration, settles
the frame as permanently refused. Other refusals, redirects, oversized replies,
HTTP failures and unknown outcomes keep the saved frame. Retries reuse its exact
bytes and ID; privacy wrapping may be regenerated. No retry silently selects
credits or creates a paid intent.

Every local settlement compares the exact sealed profile, index, delivery links,
postage ownership and removed records in one SQLite transaction. Enqueue writers
carry the same basis through their atomic session/history/outbox commit. Stale
writers fail without partial session or index updates. A late refusal cannot
delete a newly rotated contact address. Paid-postage creation guards its exact
outbox and delivery basis in the wallet/ownership transaction; saved paid intents
still recover without trying to create new ownership.

The operation processes at most the 256 IDs present at its start. It checks a
30-second monotonic budget between operations, including after proof work, and
uses HTTP timeouts of at most eight seconds, no redirects and a 1024-byte reply
cap. The budget is not a hard preemption boundary for arbitrary native storage
or cryptographic work. Native pin changes, erasure and profile replacement abort
without accepting a late response into another account.

Focused tests use synthetic identities and owned local HTTP peers. They exercise
canonical privacy work/sealing, a maximum-size saved outer, durable pause reopening,
unknown replay, ordering, alias rotation and concurrent guarded writers. They do
not replace native platform execution or the full production service qualification.
