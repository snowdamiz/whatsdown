# Native network-counter qualification

This is an unsigned, read-only local replay. `prove.sh` compiles the real Mesh
reader and serves exact accounts/absences from one actual LiteSVM bank per
response over three owned HTTPS origins. The 24-bank corpus was produced with
`MORSE_NETWORK_COUNTER_FIXTURE_LOG=morse-main` by the genuine judge custody SBF
integration, using the unchanged pinned judge/token/rewards ELFs. No accepted
account bytes were renamed, synthesized, or combined across banks. Its optional
export has no effect on the default `custody-test` harness.

Set `MESH_COMPILER_BIN`, `MESH_RT_LIB_PATH`, and a new
`MORSE_NETWORK_COUNTER_OUTPUT`, then run `./prove.sh`. Default optimization is
explicitly 0. The executable accepts a fixture observation clock so immutable
2024 banks can exercise decoding/accounting. This is **replay**, not a fresh
network or independent-provider claim. Production `network_counter_export`
always uses its native current clock and refuses those old banks.

The test covers owner/PDA/Clock/layout/code/min-context/order/partial/mint and
liability mutations, real legacy and v2 banks, absent and donated vaults,
asset-separated accounting, authenticated seven-day TWAP, exact 2-of-3 agreement,
stale/future refusals, immutable slash history, process restart, cache freshness,
concurrent cache CAS, configuration isolation and corrupted display-cache
recovery. Private temporary wrapping keys and SQLite databases are deleted.

The native proof uses the same production dependencies plus one explicit,
test-only replay-clock export: production ABI 163, proof ABI 164. That extra
export and its header are never production dispatch targets. The retained iOS,
Android and desktop proof records separately document real native current-clock
refusal and replay-clock accepted banks. Public snapshots are display evidence,
not monetary authority or a complete account/history discovery mechanism.
