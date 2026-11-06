# Owned shared conversion bank proof

This fixture joins existing SOL and BTC Mesh conversion journals to the existing
one-off burn funding/expiry handoff. It is not a service, signer or keeper.
No default setup, public RPC, live provider credentials, real funds or deployment.

`prove.py --help` requires explicit tools/ELFs, immutable BTC fixture executables
and local Bitcoin/LND paths. Cargo is offline/jobs1; Mesh builds are sequential.
The token ELF must contain qualified tag15 (f01a5e15...), rather than the earlier
c19f3d74 artifact. No accounting/program handler is changed.

One fresh owner/mint/payer/provider set stays inside Rust. Actual instructions
initialize the token/profile and Ray pools. The existing 14-day profile gate is
satisfied by explicit backdated test-genesis initialization, followed by a fresh
host observation time. This is not elapsed production maturity evidence.
The owned genesis identifier commits the new public keys. Historical receipts,
keys, scopes and timestamps are never relabeled. Provider genesis liquidity and
ordinary 300-unit USDC coverage are explicit, distinct from conversion output.

The actual 1.5 SOL swap runs from a durable exact Mesh packet. An owned RPC drops
its reply after execution; fresh processes reconcile its actual output. BTC's
separate Mesh adapter uses real regtest LND, authenticated owned provider fixtures
and its three-origin output reader, admitting one actual SPL TransferChecked into
the pre-bound custody. The full chain scope is fixed before either reservation.
SOL keeps its two-origin treasury binding; BTC read origins are separately bound.

Six prepare processes must persist one tag14 intent for IDs 1, 2 and
9223372036854775809, totaling299003525 micro-units. Rust checks the entire canonical
Mesh message, roles, instruction bytes and schedule before in-memory signing.
Mesh verifies and sends the durable exact packet. Lost acknowledgement leaves
storage pending until authenticated week-frame reads after process restart.
Fresh-hash exact-intent replay must cause no second debit.

A cloned genuine pre-funding bank and database form a separately named expiry
branch. Time and absence cannot release members. Only actual tag15 execution and
authenticated MBX/MBU reads release the original reservation idempotently. Original
SOL lamport and BTC msat20/30/50 allocations/carry retain their denominations.

Fresh manifests pin source/tool/ELF bodies and each outcome; source-before/after
must match. All earlier proofs/failures remain preserved. No live Kraken credit,
public USDC, guardian, production-finality, provider-independence or deployment
claim is made. BTC/SOL originally qualified separate banks remain historical.
