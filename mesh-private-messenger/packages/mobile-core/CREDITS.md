# Native credit custody

Credits require both the signed native security frame's HTTPS issuer origin and
`MESSENGER_CREDIT_PURPOSE=live|test`. Missing purpose or `issuer_origin=-` disables
new credit operations. `messenger/credits/v1` is a native resource containing
`[1,purpose]`; it is not an OTA JavaScript setting. The encrypted profile supplies
account and device identity. Signup and postage use native-verified policy and
durable action builders described below; server feature activation remains
separate. Existing free operations keep their current PWR flow.

All `mesh_messenger_credit_*` requests use a big-endian u32 field count followed
by u32-length byte vectors. The first field is the UTF-8 app database path. Native
responses use the same framing. Request limit is 1,100,000 bytes; extra fields,
trailing bytes and caller-selected account/device/service pins are rejected.

| Export suffix | Fields after database | Result |
| --- | --- | --- |
| `discovery` | none | MCD: origin, `/v1/credits/issuer`, exact CIK |
| `admit` | witnessed evidence | MCA: authenticated issuer key ID |
| `discover_online` | none | discovers and admits issuer evidence through native Mesh HTTPS |
| `prepare` | pack u32, asset byte | MCP purchase plan |
| `prepare_again` | pack u32, asset byte | distinct MCP only after signed quote expiry and no signed payment; old journal remains recoverable |
| `quote` | purchase ID, signed quote envelope | MCP after witnessed quote-signing key and prepayment commitment verification; CSQ292 for Solana, signed Lightning quote for BTC |
| `purchase_continue` | purchase ID | native HTTPS quote/issuance or signed cancellation, recovering the exact journal first |
| `payment` | purchase ID, transaction signature64 | MCP with durable CIQ |
| `payment_signature` | purchase ID, canonical base58 signature text | MCP with durable CIQ |
| `payment_url` | purchase ID | UTF-8 Solana Pay URL from verified pending quote and native mint/purpose |
| `payment_handoff` | purchase ID | verified Solana Pay or Lightning URI; Lightning claim is sealed before returning to the native OS launcher |
| `wallet_quote` | purchase ID | privileged wrapper reads authenticated raw CQT224 before native signing |
| `finalize` | purchase ID, CIS | MCP after one atomic pending-to-tokens commit |
| `recover` | purchase ID | identical saved MCP request body |
| `purchases` | none | MCL followed by recoverable purchase IDs |
| `balance` | none | MCB v3: available, delayed, reserved, expired, pending u32 counts, native purpose and Lightning-network bytes |
| `reserve` | action117, exact body | MCR attachment reservation; retention uses its own builder |
| `reservation` | operation ID | identical saved MCR action/body/CRD |
| `retention` | total days u32 | MCT with device-signed RET and durable exact CAP |
| `retention_recover` | operation ID | identical saved MCT, including unknown outcomes |
| `receipt` | signed CAR | MCR completed only after pinned core and RTE verification |

Except the raw URL/quote exports, each response's first field is its four-byte tag.
Balance strictly uses `03 || ASCII(MCB)` and exactly eight fields: the tag, five
u32 counts, native purpose byte (0 live, 1 test), then Lightning network (0 mainnet,
1 testnet, 2 regtest, 3 signet, 4 simnet, 255 unavailable). Live purpose permits
only mainnet; test purpose excludes mainnet. This purpose controls the localized
test-credit label before any quote exists. Purchase plans use `02 || ASCII(MCP)`;
the other MC responses listed here use `01 || ASCII(MC*)`.
The wallet network plan/status tags are documented separately
in [WALLET_NETWORK.md](WALLET_NETWORK.md).
MCP fields: tag, purchase ID32, stage1, credits2, revision8, origin, route, body,
verified quote (or empty), asset1 (0 USDC, 1 SOL, 2 BTC). Stages are 0 awaiting
quote, 1 awaiting payment, 2 awaiting issuance, 3 complete, and 4 authenticated
Lightning cancellation. Stages 1/3/4 have no network route/body. Solana quotes
have 224 bytes; Lightning quote size depends on the verified invoice.
MCR fields: tag, operation ID32, status1, credits2, revision8, action117, original
request body, CRD. Status0 includes expired or unknown requests; status1 is
completed; status2 is a verified cancellation. MCT fields: tag, operation ID32,
status1, revision8, origin, route, CAP. Terminal MCT has an empty route/body.
Integers use big-endian encoding, including
exact U64 revisions. Discovery/admission tags contain no account or device IDs.

Mesh admits issuer keys through the existing global checkpoint cursor and native
witness policy. Wallet, checkpoint, witnesses, leaf proof and view advance in one
SQLite transaction guarded against concurrent changes. A legacy cursor requires
the existing migration flow first. A raw SPKI never admits a network issuer.

Before the quote POST, Mesh seals every blinding inverse and journals the complete
batch and CQR commitment. Quote responses require a CSQ signature under the separate
Ed25519 quote key in the witnessed 02IKY issuer leaf. Recovery retains and
reverifies that signed envelope; unsigned raw quotes never become payable.
Quote recovery reuses these exact bytes. Finalization
replaces all pending states with sealed tokens in one FULL-synchronous SQLite
commit. Completed purchase markers make response replay idempotent after tokens
have been spent. Tokens wait 600 seconds from the client's local completion time;
this timestamp is not sent to the issuer or represented as a server anonymity
guarantee. Token choice uses cryptographic random ranks.

The wrappers in `apps/mobile/src/credits.ts` call native Mesh operations. Each
purchase/action network attempt first recovers its native journal entry. Native
requests omit cookies/authentication, disallow redirects and send binary bodies
with `Cache-Control: no-store`. Purchase endpoints require 200; retention accepts
200/201 only as transport outcomes and then verifies CAR in Mesh.
A timeout, 425, forged receipt or unknown result never releases/reselects tokens.

The `action_recovery` export takes counted `[database, operation_id]` and returns
MCE: `01 4d 43 45`, operation-ID32, status-u8, kind-u8, revision-u64, pinned edge
origin, route and exact saved CAP. Pending actions use `/v1/credits/reconcile`;
terminal actions have no route/body. The generic `receipt` export accepts either
the exact action-specific CAR or a core-signed CCR cancellation. CCR verification
binds the stored action/frame and requires its signed cancellation time to be at
least the action expiry. The same CAS commit restores only its still-reserved
tokens and preserves terminal status2; replay cannot release tokens reserved by
a later operation, and stale completion cannot delete them.

Priority signup policy uses an account-free native MCY network plan, with tag
`01 4d 43 59`, origin, `/v1/credits/signup-policy` and empty body. Its verified
SPV view is `01 53 50 56`, enabled-u8, purpose-u8, base-difficulty-u8,
current-difficulty-u8, price-u16 and expiry-u64. The view is computed only after
checking the pinned signature, purpose and current 60-second policy window.
JavaScript can present it but cannot supply an authoritative price to custody.

Paid account creation uses a separate native draft export, atomically storing
the profile, sealed account/device/prekey material and encrypted signup intent.
The normal account creation path remains unchanged. The native free-registration
export refuses a paid draft, including after restart, so startup cannot register
it implicitly while a paid action is unresolved. The draft state export returns
one byte:0 legacy,1 paid draft,2 explicitly selected free registration,3 completed.
Username changes preserve the account, device and wallet and CAS both the draft
and profile. Any unresolved signup reservation blocks rename/free selection even
after expiry until signed reconciliation resolves it. A signed CAR atomically
completes the wallet and marker. Free completion requires the exact live own
entry in the verified witnessed cache; a JavaScript success flag cannot mark a
draft complete. The native completion guards those proof records against changes
in the same transaction. Startup and onboarding integration use these states.

`signup` takes counted `[database, SPY]`; `signup_recover` takes `[database]`.
Both return MCS: `01 4d 43 53`, operation-ID32, status-u8, revision-u64, edge
origin, route and CAP. Only status0 carries `/v1/credits/signup` and a body.
`signup_draft_rename` takes `[database, username]`, while `signup_draft_free` and
`signup_draft_free_complete` take `[database]`, returning the native profile.
`register_signup_policy` takes `[database, SPY]`, verifies current policy and
mints the free registration work at its authenticated current difficulty even
when the server has disabled paid signup. Policy request/view works before
profile creation; a locally disabled credit build refuses paid draft creation
before writing the profile.

An unresolved retention request protects retired decryption keys through its latest
possible requested horizon plus four days. A pinned-core CAR binds the exact
action, CRD, nonzero effect ID, authorization window and mailbox result; its saved
bytes then set the signed paid horizon plus the same safety margin. Native cleanup
checks both purpose wallets even while new purchases are disabled. Without a
retention reservation, the existing 35-day cleanup remains unchanged. Unexpired
paid protection cannot be evicted by the 16-bundle cap; renewal fails closed.

Wallet snapshots are encrypted manifests plus individually bound 60KB chunks.
Capacity is 4,096 tokens, 2,048 recoverable purchase markers and 2,176 exact
reservation records, of which at most 128 may remain unresolved, within a
15.36MB snapshot. Capacity failures happen before a request
plan is returned. Starting a distinct purchase while one remains current is
blocked; explicit Buy again may leave an expired unsigned quote recoverable.
Account erasure deletes these encrypted records with existing
app storage. Paid retention UI/server activation remains a separate joint gate.

New reservations and explicit balance refreshes advance a sealed maintenance
cursor. Each pass examines at most 64 token/reservation records; balance refresh
also advances one attachment cleanup cursor by at most 128 staged parts. Part
deletion and cursor advancement share the wallet transaction. Pending reservations
and their tokens are never evicted. Signed exact receipts and spent nullifiers
remain until the selected tokens' two-epoch-plus-seven-day deadline, or a longer
paid attachment/parking horizon. Parking includes its four-day key safety margin.
Successful signup retains its local completion fence. A stored clock watermark
prevents recreating a pruned expired operation after clock rollback.

Attachment inventory keeps all unresolved intents and recent terminal rows within
its existing 128-row bound. Postage keeps at most 16 unresolved batches plus 128
recent terminal rows; completed batches discard their delivery ciphertexts only
after exact outbox acknowledgement or signed cancellation. Exact receipt recovery
remains available through the retention window even when a recent list omits it.
Native preview nonces remain opaque 32-byte values: an eight-byte issue time and
192 random bits. A new intent must use a preview no older than fifteen minutes;
every exact saved retry, including legacy random nonces, remains recoverable.

Snapshot encryption and revision CAS detect corruption and concurrent updates.
They do not provide an OS-backed highwater mark for the SQLite database. A hostile
same-app caller restoring an older valid database can regress local purchase or
reservation history; the core still rejects duplicate token spends. This is
distinct from the native wallet counter, whose platform credential anchor rejects
app-file rollback.


Native local wallet operations are separate from Mesh token custody. Both an
explicit native purpose and `MESSENGER_CREDIT_USDC_MINT_ADDRESS` are required.
The native wallet exposes create/address, purchase Pay/Recover by durable ID,
and bounty-address reservation. The complete network and durable packet
contract is in [WALLET_NETWORK.md](WALLET_NETWORK.md). Native dialogs show the
payment intent and cancel when the app leaves the foreground. The wallet has
no seed export or recovery flow; losing OS credential storage can lose funds.

The Credits screen is reached from You. It reads the sealed local balance and
purchase history only when opened, offers the fixed packs and USDC/SOL choices,
and recovers the exact saved request after unknown outcomes. External payments
use the native Solana Pay URL and canonical pasted transaction signatures.
In-app Pay/Recover send only app database and purchase ID to the native host.
Native Pay obtains its payer privately, prepares the pinned RPC intent, requests
system confirmation, commits the exact packet, then submits. Native Recover
submits an existing packet without opening or signing with the wallet. Neither
operation accepts a JavaScript blockhash, provider URL, raw quote, or packet.
RPC acknowledgment is not payment finality; credits are displayed only after
the issuer response verifies and is durably finalized in Mesh.


The onboarding profile form keeps free account creation primary. An explicit
signup-options check verifies the current signed policy before offering a
local priority draft. Saving that draft does not spend credits. Its screen can
open Credits before registration, show native available/delayed balances, and
reserve 20 credits only after an explicit spend action. Startup reads the native
draft marker before enabling mailbox synchronization or push registration.
A pending CAP exposes exact retry and signed reconciliation; cancellation is
terminal without implying signup success. Username conflicts preserve the same
account, wallet and purchased credits. An explicit free transition registers
with verified current work, resolves its own witnessed directory entry, and
asks native code to complete the draft against that authenticated cache.

Normal mailbox reconnect also refreshes the native-verified signup policy.
Only an explicit native `credits_disabled` plan result permits configured base
work; malformed, stale, forged and unavailable policies remain errors. Policy
queries carry no account/device identity. All onboarding copy is translated in
the six shipped languages. `npm run test:credit-signup` exercises six rendered
flows with IPC/network fixtures; native proof tests verify the cryptography,
atomic transitions and witnessed completion independently.

Postage transport uses `credit_postage_continue([database, nonce32])` and
`postage_policy_publish([database, revision8, device_set_revision8, level1])`.
Both calls use immutable native issuer resources. The mobile and desktop host
boundaries require the app-owned database; Mesh validates the saved operation.
Policy publication loads an authenticated persisted PPY, so a retry does not
re-sign it. `postage_policy_view` returns MPVv2 with an optional pending MPP plan
for UI restart recovery. Acknowledgements do not replace witnessed admission.
See `protocol/credits-postage-v1.md` for framing and verification details.
