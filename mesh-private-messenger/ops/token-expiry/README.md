# Unfunded burn-week expiry

`Transparency.TokenBurnExpiry` provides strict raw MBX1/MBU1 codecs and the
rent-only tag15 builder. `Transparency.TokenBurnExpiryRead` authenticates the
nine-account finalized custody bank. The issuer requires two independently
configured valid banks with the same immutable footprint; canonical absence
permits preparation only. Neither decoder nor a timeout is release proof.

Run `scripts/prove-token-expiry.sh` with `MESHC`, `MESH_LANG_ROOT`, the matching
`MESH_RT_LIB_PATH`/`MESH_TEST_RT_LIB_PATH`, `CARGO_BUILD_SBF`, and qualified
`MORSE_TOKEN_DEX_BIN_DIR`. The gate creates a fresh private proof directory,
rebuilds token SBF, freezes exact source bodies and binaries, retains functional
red logs, and rejects changed inputs. PostgreSQL and loopback RPC instances are
owned disposable fixtures. Set `PG_BIN` for PostgreSQL tools if needed.

The actual service operator workflow is:

1. Keep the old pending intent and its exact members.
2. Run `treasury burn-expire-request <epoch>` after both pinned chain banks
   reach the funding deadline and prove the canonical pair absent.
3. Review and sign the returned instruction with the external rent payer.
   The issuer never receives this secret or broadcasts the request.
4. Run `treasury burn-reconcile <intent-id-hex>` after the permanent pair is
   finalized and agrees across both providers. Only this proof can release
   the old members; state becomes `expired_unfunded` with no funding instruction.
5. Prepare a new eligible future epoch with `burn-request`. The old immutable
   history remains; its receipt cannot affect the new reservation or funding.

`cli.test.mjs` builds the real issuer unless `CREDIT_ISSUER_BIN` is supplied.
`prove.py` owns a fresh PostgreSQL instance and all migrations. A test-only
compiled Mesh seeder creates synthetic prior accounting and a persisted old
reservation, without bypassing production reads. The real operator then reads
actual SBF banks, holds on absence/provider ambiguity, emits an exact tag15
instruction, and observes its locally signed SBF result. After release, six
processes converge on one new randomized schedule. Its exact instruction
executes 24 Jupiter/Raydium/SPL chunks in SBF with 120,000,000 USDC base units.
An old receipt replay leaves the new funded liabilities unchanged. The issuer
makes zero `sendTransaction` calls.

`BURN_EXPIRY_ARTIFACT_DIR` retains public requests, complete account snapshots
and execution logs; `BURN_EXPIRY_CLI_REPORT` writes the structured result. Clear
old fixture-output environment variables when running test binaries directly;
never point an export at an archived checkpoint.

See [the wire contract](../../protocol/token-burn-expiry-v1.md) for offsets,
canonical absence, prefunding, rollback and terminal replay rules. These are
local compiled/SBF and loopback proofs. They do not establish live consensus,
independent production providers, a MORSE price feed, liquid markets,
continuous funded operations, conversion or the live four-week Phase5 gate.
No live funds, production deployment or activation are authorized by this proof.
