# wallet-core

Morse's in-app Solana wallet core (plan §6.13). It holds the seed, derives keys and signs
transfers. Nothing else: no networking, no persistence, no global state, no async runtime.
Rust is an approved exception to the Mesh-first rule for wallet signing only.

It is used to pay credit quotes (§6.10, §6.11), to make one-time bounty addresses for fork
proofs (§6.3) and to move a bounty out afterwards.

## Rules

- **Non-custodial.** The seed exists only on the user's device: in the platform keystore at
  rest, and in memory for the length of one call. Morse never holds it and can't recover it.
- **Wallet addresses never reach Morse servers** (directory, delivery core, privacy edge).
  The host must never put an account or bounty address in a request to them. A bounty address
  appears only in the `FRK` finder field of the one proof it was made for.
- **The wallet never sees a credit token.** Blinding and unblinding happen in mobile-core
  (`Crypto.BlindRsa`). wallet-core only signs the payment to the quote's deposit address.
- **Payments are public.** A purchase or a bounty move is as visible on-chain as any transfer,
  and the RPC provider the host submits through sees the addresses. The app says so before the
  first purchase and the first bounty move.
- Secrets are wiped (`zeroize`) when dropped: seed, derived keys, phrases, entropy, and every
  response buffer when the host frees it.

## Seed and storage

- BIP39, English, 12 or 24 words, **no passphrase** (so the phrase restores the same accounts in
  Phantom, Solflare and `solana-keygen`).
- The host stores the mnemonic **entropy** (16 bytes for 12 words, 32 for 24): the smallest form
  of the seed, and the app can still show the recovery phrase again (op 3).
  - iOS: Keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (never iCloud-synced).
  - Android: the app's secure store (AES-GCM under a non-exportable Android Keystore key,
    ciphertext in app-private preferences excluded from backups and device transfer).
  - Desktop: the OS credential store (the same secure-store path the Mesh host callbacks use).
  - Never in app databases, backups, logs, crash reports, analytics, or anything sent to a server.
- The crate never persists anything. Every call that needs keys takes the entropy in its request
  frame; the host wipes its copy of the frame afterwards.
- Entropy comes from the OS (`getrandom`).

## Derivation (SLIP-0010 Ed25519, hardened only)

| Use | Path | Notes |
|---|---|---|
| Account `i` | `m/44'/501'/i'/0'` | Phantom, Solflare, `solana-keygen --derivation-path`; account 0 is the default. `i < 2147483646` |
| Bounty address `n` | `m/44'/501'/2147483646'/n'` | One per fork proof, never reused. `n < 2^31` |

**Why `2147483646'` for bounties.** It is the second-highest hardened index at the account level
of the standard Solana tree, so bounty keys come from the same phrase and the same backup, yet:

- wallets scan accounts from 0 upward and stop after a few empty ones, so no wallet (Morse
  included) ever offers a bounty address as an account or a receive address, which would link it
  to the user's main address;
- no account path can collide: wallet-core refuses account indexes `>= 2147483646`, and paths of
  other shapes (`m/44'/501'/i'`, Solflare's legacy form and `solana-keygen ?key=i`) have a
  different depth, so they are different keys;
- `2147483647'` stays free for a future reserved branch.

A user can recover a bounty without Morse:
`solana-keygen recover 'prompt://?full-path=m/44/501/2147483646/<n>'` (tested against this crate).

**Bounty index rule (host).** Keep a local counter `next_bounty_index`, starting at 0. To make a
finder address: read `n`, persist `n + 1` **before** the address is used, then derive
`Bounty(n)`. Never derive a bounty address for an index already handed out. The counter is
private, local-only state (not synced to a server). To show bounty balances, scan `0..n`.

## Transactions

Legacy message format, the caller supplies the recent blockhash. The host fetches the blockhash,
submits the base64 transaction (`sendTransaction`, `encoding: "base64"`) and waits for
`finalized` itself.

Instruction order, as Solana Pay requires (transfer last, memo immediately before it):

1. `SetComputeUnitLimit` (optional), 2. `SetComputeUnitPrice` in micro-lamports (optional),
3. SPL only, on request: Associated Token Account `CreateIdempotent` for the recipient (paid by the
   fee payer; a fresh quote deposit address has no USDC account yet),
4. SPL Memo v2 with no accounts (optional),
5. the transfer: System `Transfer`, or SPL Token `TransferChecked` from the owner's associated
   token account to the recipient's, followed by the Solana Pay references as read-only
   non-signer accounts, in order.

Accounts are ordered as the Solana Rust SDK orders them (fee payer, then writable signers,
read-only signers, writable and read-only non-signers, each sorted by key bytes), so output is
byte-identical to `solana`/`spl-token` CLI output for the same inputs.

The fee payer and the owner may differ: a **bounty move** signs with the bounty key as the token
owner and an account key as fee payer (a fresh bounty address holds no SOL). That links the two
addresses on-chain, which is why the app warns before the first move.

Refused: amount 0; account creation for SOL; a reference that is the fee payer or already an
account of the transfer, or repeated; anything over 1,232 bytes serialized.

## Solana Pay transfer requests

`parse_pay_url` accepts `solana:<recipient>?amount=&spl-token=&reference=&label=&message=&memo=`
and refuses everything else:

- another scheme or case, non-ASCII, spaces, a `#` fragment;
- unknown parameters, empty keys or values, a raw `=` in a value, empty `&` segments;
- a repeated parameter (only `reference` may repeat, with distinct values, kept in order);
- base58 that is invalid or not 32 bytes (recipient, `spl-token`, `reference`);
- malformed percent-encoding or invalid UTF-8 (`+` decodes to a space, as in `URLSearchParams`);
- non-canonical amounts: the amount must match `0|[1-9][0-9]*` optionally followed by `.` and
  digits not ending in `0` (so `1.5`, `0.01`; never `01`, `1.`, `.5`, `1.50`, `1e3`, `+1`), must
  fit in a u64 mantissa, and SOL amounts have at most 9 decimals;
- control characters and bidirectional overrides/isolates in `label`, `message`, `memo`.

The amount is returned as `mantissa / 10^scale`; `Amount::base_units(decimals)` converts it
(refusing more decimals than the mint has). Issuers that build these URLs must emit canonical
amounts.

## Rust API

```rust
generate_entropy(words: u8) -> Result<Zeroizing<Vec<u8>>, Error>        // 12 | 24
phrase(entropy: &[u8]) -> Result<Zeroizing<String>, Error>
entropy_from_phrase(phrase: &str) -> Result<Zeroizing<Vec<u8>>, Error>  // forgives case/spacing
Seed::from_entropy(entropy: &[u8]) -> Result<Seed, Error>
keypair(seed: &Seed, path: KeyPath) -> Result<ed25519_dalek::SigningKey, Error>
associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey
sign_transfer(owner: &SigningKey, fee_payer: &SigningKey, t: &Transfer) -> Result<Signed, Error>
parse_pay_url(url: &str) -> Result<PayRequest, Error>
```

`Error::code()` gives a stable snake_case code (the C ABI's error body): `bad_word_count`,
`bad_entropy`, `bad_mnemonic`, `random_unavailable`, `bad_index`, `bad_amount`,
`account_creation_needs_spl`, `bad_reference`, `transaction_too_large`, `bad_url`,
`unknown_param`, `duplicate_param`, `bad_base58`, `too_many_decimals`, `bad_text`, `bad_frame`.

## C ABI

Header: [`include/morse_wallet.h`](include/morse_wallet.h). Built as `staticlib` (for the iOS,
Android and desktop hosts) and `rlib`. Same shape as the Mesh mobile library boundary.

```c
int32_t morse_wallet_call(const uint8_t *request, uint64_t request_len, MorseWalletBytes *response);
void morse_wallet_free_bytes(MorseWalletBytes *bytes);   /* wipes, frees, sets NULL/0 */
```

Stateless and thread-safe. Status: `0` OK (response = the op's response body), `9` application
error (response = the UTF-8 error code), `1` invalid argument (null pointers, request over
65,536 bytes; no response), `4` a caught panic (no response). Always call
`morse_wallet_free_bytes` on the response; freeing null or twice is harmless.

**Request frame:** `u8 version = 1 ‖ u8 op ‖ body`. Integers big-endian (Morse wire convention),
`vec32(x)` = `u32 length ‖ x`, `key` = `u8 kind (1 account | 2 bounty) ‖ u32 index`, pubkeys and
hashes are 32 raw bytes. Every body must be consumed exactly (no trailing bytes), otherwise
`bad_frame`.

| Op | Request body | Response body |
|---|---|---|
| 1 generate | `u8 words (12 \| 24)` | `vec32(entropy) ‖ vec32(phrase UTF-8)` |
| 2 restore | `vec32(phrase UTF-8)` | entropy (16 or 32 bytes) |
| 3 phrase | `vec32(entropy)` | phrase (UTF-8) |
| 4 address | `vec32(entropy) ‖ key` | public key (32) — also the `FRK` finder address for kind 2 |
| 5 transfer | see below | `vec32(signature base58) ‖ vec32(transaction base64)` |
| 6 parse Solana Pay URL | `vec32(url UTF-8)` | see below |

Op 5 body:

```text
vec32(entropy) ‖ key owner ‖ key fee_payer
‖ u8 asset: 1 SOL | 2 SPL, then for SPL only: mint32 ‖ u8 decimals
‖ u64 amount (base units) ‖ recipient32 (wallet address)
‖ u8 create_recipient_account (0 | 1)
‖ u8 reference count r ‖ r × 32
‖ vec32(memo UTF-8; empty = no memo)
‖ u32 compute unit limit (0 = none) ‖ u64 compute unit price, micro-lamports (0 = none)
‖ recent_blockhash32
```

Op 6 response:

```text
recipient32
‖ u8 has_amount (0 | 1), then if 1: u64 mantissa ‖ u8 scale
‖ u8 has_spl_token (0 | 1), then if 1: mint32
‖ u8 reference count r ‖ r × 32
‖ vec32(label) ‖ vec32(message) ‖ vec32(memo)      (empty = absent)
```

## Host integration

Three hosts link this crate; each keeps the seed native and exposes the same small API
(`apps/mobile/modules/mesh-messenger/wallet.ts`), and `apps/mobile/src/wallet.ts` builds
the frames that follow the seed:

| Host | Linking | Seed at rest | Owner check for the phrase |
|---|---|---|---|
| iOS | `MorseWalletCore.xcframework` (device + simulator static libraries), vendored by the `MeshMessenger` pod; `MorseWalletModule.swift` | Keychain, service `app.morse.wallet`, `WhenUnlockedThisDeviceOnly` | `LAContext` `.deviceOwnerAuthentication` |
| Android | `native/android/<abi>/libmorse_wallet_core.a` linked into `libmessenger_mobile.so` (CMake); JNI in `MorseWalletHost.cpp`, module `MorseWalletModule.kt` | `MeshMessengerSecureStore` (Keystore AES-GCM) | `BiometricPrompt` (strong biometrics or screen lock); the lock-screen confirmation on Android 6–9 |
| Desktop | path dependency of `apps/desktop/src-tauri`; `src/wallet.rs` calls `morse_wallet_call` in-process | OS credential store (`keyring`), the Mesh keys' service | none yet |

`scripts/build-mobile-native.sh` builds the archives (`cargo build --locked --release`
with rustup's toolchain, `IPHONEOS_DEPLOYMENT_TARGET=16.4` for iOS) next to the Mesh core's,
and checks that the module's copy `generated/morse_wallet.h` equals `include/morse_wallet.h`.
Both Rust static libraries (this one and the Mesh runtime inside the Mesh core) link into one
binary: built with the same toolchain their standard libraries are the same objects, so the
linker takes one copy (checked for the iOS simulator and both Android ABIs).

Host API (errors are wallet-core's codes or `wallet_exists`, `wallet_missing`,
`wallet_locked`, `bounty_not_issued`, `fee_payer_not_account`, `authentication_failed`,
`bad_op`):

| Call | Does |
|---|---|
| `walletExists()` | whether a seed is stored |
| `walletCreate(words)` | op 1, stores the entropy (refused if one exists) and the bounty index 0, returns the phrase to show once |
| `walletRestore(phrase)` | op 2, stores the entropy and the bounty index 0 |
| `walletPhrase()` | op 3, after the owner check |
| `walletWipe()` | deletes the seed and the bounty index |
| `walletCall(op, body)` | op 4, 5 or 6 with the body after the seed; the host inserts `vec32(entropy)` for 4 and 5, refuses a bounty key whose index was not handed out yet, and refuses a transfer whose fee payer is not an account key |
| `walletNextBountyAddress()` | reads `n`, derives `Bounty(n)`, persists `n + 1`, then returns `u32 n ‖ pubkey` |
| `walletBountyIndex(atLeast)` | raises the next index to at least `atLeast` (a restored wallet scans the chain for bounty addresses it handed out before, issuing each index before deriving it) and returns it |

Every request frame holding the seed is wiped after the call, and so is every response
holding a secret. On iOS the seed is readable only while the device is unlocked, so the
host also keeps the next bounty address's public key (never a secret) in a Keychain item
readable after first unlock: the anchor check can name a finder address in the
background.

## Build and test

Homebrew's cargo shadows rustup here; use the rustup toolchain:

```sh
TC=$(dirname "$(rustup which --toolchain stable rustc)")
PATH="$TC:$PATH" cargo test
PATH="$TC:$PATH" cargo clippy --all-targets -- -D warnings
PATH="$TC:$PATH" cargo fmt --check
PATH="$TC:$PATH" cargo build --release --target aarch64-apple-ios       # and aarch64-apple-ios-sim
PATH="$TC:$PATH" cargo build --release --target aarch64-linux-android   # needs the target and an NDK
```

Dependencies are pinned exactly (`Cargo.toml`, `Cargo.lock`): `ed25519-dalek` 2.2,
`curve25519-dalek` 4.1 (off-curve check for token account addresses), `sha2`, `hmac`, `bip39`
2.2 (its PBKDF2), `zeroize`, `getrandom`, `bs58`, `base64`.

Known-answer vectors in the tests:

- BIP39 seeds for "abandon ×11 about" and "legal winner … title" (seeds cross-checked with
  Python's `hashlib.pbkdf2_hmac`);
- the SLIP-0010 Ed25519 test vectors 1 and 2 (chain code, private and public key at every step);
- `solana-keygen recover` (solana-cli 4.1.1) for accounts 0 and 1 and bounty addresses 0 and 7 of
  "abandon ×11 about";
- signed transactions compared byte for byte with `solana transfer` / `spl-token transfer`
  `--sign-only --dump-transaction-message` (SOL; USDC with a reference; a two-signer bounty move),
  and with the Solana Rust SDK 5.0 plus the SPL interface crates for a full quote payment (compute
  budget, `CreateIdempotent`, memo, `TransferChecked`, two references). The commands are in the
  comments of `src/tx.rs`.
