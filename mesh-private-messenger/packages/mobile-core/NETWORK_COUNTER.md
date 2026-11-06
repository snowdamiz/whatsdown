# Optional native Settings network counter

`network_counter_export` (`mesh_messenger_network_counter`) accepts only the
native UTF-8 database path, at most 4096 bytes. Host dispatch pins that path to
the app's database. It returns `NCR1` followed by bounded JSON, at most 32768
bytes. All amounts and slots are canonical decimal strings. Registered records
have null principal, not an invented zero. USDC, MORSE and explicit legacy-token
amounts remain separate; donations and pending liabilities are not principal.

The counter is default-off and cannot change checkpoint/session admission.
Opening Settings → Network → Bonds and slashes mounts it; refreshing is explicit
and cached for at least 60 seconds. The checkpoint-age timer never requests it.
A current bank must be finalized, at least the pinned/cached minimum slot, and
have its same-bank Clock within 120 seconds of native time. Three configured
origins must agree in a 2-of-3 exact account digest. Every account's owner,
canonical address, layout/padding, executable release slot, binding, mint and
vault accounting is checked. Changed code, partial responses, canary identity,
future/stale banks and disagreement are unavailable. MORSE USD valuation is
optional and requires the explicitly pinned authentic fresh 168-hour oracle;
there is no fallback price or assumed USDC USD valuation.

The release-owned companion `Host.push_get_token("messenger/network-counter/v1")`
contains 17 canonical lines. `network-counter-config.cjs` creates it from
`MESSENGER_NETWORK_COUNTER_CONFIG` (schema_version 1) and the exact native
SecurityConfig frame. It binds SHA256 of that frame, current morse-main witness
set/RPCs/service/judge, explicit v2 or legacy layout, minimum context slot,
program release slots and asset/config addresses. `MESSENGER_NETWORK_COUNTER_TLS_ROOT_PATH`
is optional explicit PEM trust only for these requests; it requires counter
configuration and does not alter other HTTP clients. Missing configuration is
`unconfigured`. OTA/JS cannot supply replacement pins. Native resources are
`MeshMessengerNetworkCounterConfig` on Apple and
`app.morse.mesh.NETWORK_COUNTER_CONFIG` on Android; desktop bundles the same
`networkCounterFrame` through its signed release configuration.

Current observations are replaceable OS-sealed display cache. Proven service
and current-pinned-witness slash facts are immutable, individually authenticated
records scoped by the exact companion identity, at most 17 per configuration.
They survive later failed/contradictory reads and process restart. Conflicting
new status/accounting is discarded; retained slash evidence is explicitly
historical, never a claim of a current bank. Cache corruption can recover valid
facts independently. This is OS-sealed integrity, not a claim that an attacker
cannot roll back the whole application database. Historical configurations are
never combined. There is no signer, transaction builder, funds movement or
complete-history discovery.
