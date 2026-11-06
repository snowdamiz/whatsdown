# Relay cryptographic preflight

`morse-fork-verifier` is the Mesh verification boundary for the
JavaScript relay. It verifies canonical FRK and authenticates registered log
and ring accounts through the existing two-of-three finalized RPC reader.
It has no wallet or transaction writer. It also exposes custody/age admission,
unsigned settlement plans, Stage recovery and lookup activation/cooldown reads.
The standalone relay HTTP endpoint, durable scheduler and manual wallet command
remain pending; the journal, signer and RPC adapter are tested locally in `ops/relay`.

```sh
meshc build mesh-private-messenger/tools/fork-verifier --opt-level 2 --output ./morse-fork-verifier
export MESSENGER_SECURITY_CONFIG="$(cat /path/to/security-config-v4.txt)"
./morse-fork-verifier --input evidence.frk
```

The release frame must identify the monitored log's program, ring and service
key. `MORSE_RELAY_LOG_VERSION` defaults to `2`; an operator can explicitly
select `1` for that frame's legacy log. `MORSE_RELAY_MIN_CONTEXT_SLOT` is a
canonical unsigned decimal RPC floor, default `0`; a durable relay must carry
its persisted agreed context floor into later calls. The file is capped at 8 KiB and
the canonical FRK decoder applies its narrower format bounds. Malformed
frames, incorrect signatures, wrong log/version and honest signed pairs are
rejected before RPC I/O.

On success stdout is one JSON object containing the unchanged proof bytes,
finder, finder-independent proof hash, verdict, context slot and authenticated
account observations. Failure returns exit 1 and an error on stderr without a
verified stdout result. A submitter-supplied ACV3 context is never a trusted
input. An anchor reference is re-read at its index from a stable authenticated
snapshot; a missing or invalid reference cannot be treated as verified.

For a referenced anchor, `witness_scope` is `historical-anchor` and attribution
uses that entry's immutable generation, including the native/C2SP distinction.
For two signed checkpoints it is `current-generation` when witnesses were
checked against the Log's active generation, or `none` for service-only
verification. Historical keys in signed-only evidence still need an additional
authenticated registry/account resolver. Unknown attestations are retained in
the canonical bytes and do not automatically implicate a witness.

`verified` means cryptographically proved against this independent chain view.
It does not mean paid, within the judge's 28-day window, bonded, or admitted
on-chain. The `--submitter PUBKEY --mint MINT` admission mode adds those custody,
destination and age checks and returns either a ready plan or an authenticated
existing receipt. Ready reports include conservative per-step rent allocation
sizes; the JavaScript writer queries current rent prices and fees. The judge
independently enforces age, bonded state, destination ownership and pay-once
PDAs. `service_slashed` describes only the directory: it is not a reason to
skip potential witness claims. The finder is passed through exactly, including
zero; choosing the submitter's payout when zero belongs to the judge/writer.

The live Mesh monitor test submits F1/F2/F3 from both hash profiles to this
preflight, with signed and independently resolved anchor targets and preserved
finder bytes. `scripts/relay-preflight-command.test.mjs` builds the optimized
native executable, rejects tampering before any RPC connection, and refuses a
positive result when independent chain authentication is unavailable.

`ops/relay/verifier.mjs` is the production subprocess wrapper. It bounds input,
outputs, runtime and concurrency, binds fixed configuration/arguments, omits
wallet credentials from the environment, and removes its private temporary
evidence files after process termination. It also carries persisted minimum
context slots into Stage and lookup reads. It does not reimplement Mesh
cryptographic, custody or account-decoding decisions.

Additional recovery commands preserve quorum context for both presence and
absence, without requiring current custody to remain slashable:

```sh
morse-fork-verifier --receipt-state --input evidence.frk --submitter PUBKEY --mint MINT
morse-fork-verifier --destinations-state --input evidence.frk --submitter PUBKEY --mint MINT
```

Receipt state binds the log, mint and proof PDA and returns `missing` or `settled`.
A settled result includes the actual finder; it can differ from the evidence's
finder when someone else filed the same proof first. Destination state binds the
finder and locked token accounts, including the zero-finder fallback to the
submitter, and reports `missing` or `ready` for each. Malformed or unsafe custody,
stale contexts and inconsistent providers are errors. These commands supply
recovery observations; the writer still requires finality or an expiry barrier
before it resolves a pending signature.
