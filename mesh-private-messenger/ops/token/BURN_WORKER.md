# Bounded burn worker

This worker executes an already funded, explicitly selected week. It does not
fund weeks, maintain price observations, operate rewards, install a service or
start automatically. Its only signing authority is the configured opaque payer.
All transaction accounts and instruction bytes come from the existing canonical
burn/close builders.

Build with `meshc build ops/token --opt-level 2 -o burn-worker`, then run
`burn-worker CONFIG.json`. The local qualification pins compiler25a8 and runtime347d;
their exact paths and hashes are in the accompanying proof manifest.

The required configuration fields are:

| Field | Meaning |
|---|---|
| `schema_version` | String `"1"` |
| `pins` | Program, governance, program_slot, USDC, treasury and factory read pins |
| `payer` | Canonical public key matching the opaque local signer |
| `epoch`, `minimum_slot` | Exact decimal strings |
| `rpc_urls` | Exactly three distinct, explicitly chosen HTTPS provider URLs |
| `test_mode` | False for ordinary operation; true permits only owned127.0.0.1 HTTP fixtures in this CLI |
| `replace_expired` | Explicit opt-in to the replacement transition; false keeps expired packets reconciliation-only |
| `routes_hex` | Exactly24 candidate supported39-byte ExactIn routes, one for each immutable row |
| `journal_path` | Persistent local SQLite path |
| `storage_key_directory` | Absolute canonical directory for `StorageKey.file`; native0700/symlink checks apply |
| `ticks`, `interval_ms` | Decimal strings:1..64 ticks,1000..60000ms between ticks |

The signer enters through `MORSE_BURN_WORKER_PAYER_SEED_HEX` using
`Env.get_secret_hex` and `Crypto.signing_from_secret`. Mesh verifies the public
payer before requesting any RPC data. Key material is never accepted in config,
printed in reports or returned to a shell helper. Keep the key directory and
database private and durable. Config URLs may contain credentials; CLI errors
are fixed sanitized strings and do not echo configuration or RPC bodies.

Each tick visits at most24 rows and signs at most one transaction. It performs
at most three authenticated bank reads and one send. Each bank read makes up to
three bounded provider attempts, with three ordinary RPC calls per provider and
one additional old-hash validity call for an expiry proof,3s timeouts,
no redirects and fixed response limits. Submission uses the existing5s bounded
exact-packet sender. A run terminates after the configured number of ticks;
there is no daemon or scheduler registration.

## Authentication and recovery

One31-account finalized request contains the19 market roles followed by the12
custody roles. The custody projection uses the real returned prefix, capped at
2240 bytes, and retains original account space, owner, funding and executable
metadata. Active v1/v2 week bytes use the qualified carry decoder; the market
reader continues to refuse closed frames. Close planning remains independent of
oracle and DEX availability.

`getBlock` is requested for exactly the returned account context slot. Numeric
block height, parent slot, block hash and time are checked, including time equal
to the authenticated Clock. A standalone `getBlockHeight` result cannot approve
replacement. The latest blockhash is read first; its context is a lower bound on
the account bank, and the same bank height must still be inside its lifetime.
Two selected providers must agree on the complete observation, including all31
account metadata/prefix hashes and the lifetime/block fields. Different URL
strings cannot prove real operator independence. Missing blocks, null height,
stale context, changed code, malformed values and disagreement stop signing.
Ordinary operation also refuses Clock time more than120s old or30s ahead of the
local clock. Local time never releases custody.

A committed operation always retries its exact packet after an unknown result.
The operator must enable replacement explicitly. Replacement requires a newer
authenticated bank with height strictly greater than the retired packet's
lastValidBlockHeight, two matching `isBlockhashValid(old signed hash)=false`
responses at exactly that same finalized bank context, the same unexecuted row and immutable canonical
instruction, unchanged code, and a fresh hash while still inside the original
execution window. The route is rechecked against the fresh independent oracle
floor; replacement never lowers its original minimum or shifts its window.
Effective execution validity remains the intersection of the blockhash lifetime
and the program's immutable time window.

The current sealed entry and retired evidence change in one SQLite transaction
with an exact-ciphertext compare-and-swap. There is no intermediate unsigned
state. A retired record retains the complete old signed packet, original sealed
entry, replacement signature and observed bank digest/slot/height/time. Stale
signing callbacks cannot reintroduce it. At most64 packets may be retired per
operation; reaching that bound requires reconciliation. Retired evidence is not
automatically deleted.

An authenticated missed row receives a durable, idempotent missed marker. That
marker blocks replacement even if a later stale read claims time is earlier.
It does not release money, create a new budget or change accounting. At the
original week boundary the worker uses the existing kind13 close-to-carry
instruction and confirms its canonical close receipt. Expired close packets
use the same explicit same-intent recovery boundary. Existing unfunded expiry
tombstones and issuer reallocation are unchanged.

Reports distinguish waiting, reconciliation, pending unknown, RPC acknowledgement,
completed chunk and completed carry. An RPC acknowledgement is not finality.
Earlier rows are reconciled on later ticks, so a late observed receipt is not
stranded after the scheduler advances to another window. A zero process exit
only means the bounded CLI ran; inspect each JSON status for its actual result.

## Local proof limits

The owned HTTP fixture tests strict framing, provider disagreement, replacement,
restart and races. The optional SBF handoff executes exact Mesh-signed packets
against the genuine router/DEX/SPL programs and checks old blockhash refusal,
replacement burn and close/carry. LiteSVM controls Clock/slot/height; it does not
simulate ledger finality or independent providers. All funds and identities are
synthetic. These checks authorize no deployment or production operation.

## Reproduce the isolated tests

`python3 ops/token/prove_burn_worker.py --compiler /absolute/path/to/meshc
--runtime /absolute/path/to/libmesh_rt.a --test-runtime
/absolute/path/to/libmesh_test_rt.a --proof-dir /absolute/new/proof-directory`
(collapse this command to one line). The driver copies the declared local Mesh
packages, materializes only its fixture-suffixed tests, records source/tool hashes,
and leaves the source tree untouched. The committed public corpus has adjacent
provenance and represents prior controlled local SBF observations, not current
production state. No `.morse` path is a default dependency.

For fresh exact-packet SBF coupling, additionally supply `--hook-dir` and
`--key-path` for the separately launched optional retained-bank hook in
`programs/morse-token/tests/support/burn_worker.rs`. Enable that hook's existing
close handoff flag. The ephemeral key must be outside both proof directories and
is read only in memory. The driver tests a genuine still-live legacy packet with
an understated imported lifetime, unknown/restart recovery, four competing
workers, exact replacement execution, late receipt recovery and exact Mesh
close/carry. It probes the encrypted journals from a fresh Mesh process before
removing its private wrapping state; ciphertext copies and public packet evidence
remain in the proof. The SBF runner separately seals its exact source/ELF inputs.
Fixture-only Python HTTP servers are owned peers; all actual worker protocol,
network authentication, signing decisions and journal state remain in Mesh.
