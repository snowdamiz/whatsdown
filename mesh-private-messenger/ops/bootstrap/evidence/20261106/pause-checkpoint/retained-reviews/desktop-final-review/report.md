# Desktop final review — admission recheck after erasure cleanup

Reviewed frozen owner `3713c59af773c88b7c1650b338ad1fea0ed4df00` in `/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-7a47bb71` (base `f4fdf69fdf62c2776d1d185be6925e8db83b3fde`). Read-only. No production or git edits. No rebuild, tests, UI, or child agents.

Parent `311146f61fb89569989735f992d475122c02a6f3` has the same blobs for the two files in the last diff (`private_commands.rs` `3b32b2a9c99a01868de3c9ef8bf9e801fca5f74f`, `account_transition_tests.rs` `5dc37ad7837ebf01ef0f541adfe565c7fe4fb70e`). Those paths are clean in the parent worktree. This review does not cover later parent edits outside that pair.

## Verdict

No verified source defect in `3713c59` versus `a04f95a0671f8d73d92142e4007b0ce4eae57d01`.

The round-4 race is closed on the macOS `mesh_invoke` path. A private command that waits inside legacy-key cleanup cannot start a Core mutation after lock/unlock has retired its epoch. Failed mutations still keep that epoch. A committed identity change retires it, and a committed erase keeps the finite cleanup obligation without adopting a replacement page or a restored account's keys. Admission failure wipes result bytes and error text before IPC publication.

## Last diff

`3713c59` changes only:

- `mesh-private-messenger/apps/desktop/src-tauri/src/desktop_lock/private_commands.rs`
- `mesh-private-messenger/apps/desktop/src-tauri/src/desktop_lock/tests/account_transition_tests.rs`

`drain_before_core` is `check(call)`, then `drain`, then `check(call)`. The production mutation closure is `check(call)?; library.invoke(...)`, immediately before Core. The new test section is the barrier inside `actual_core_identity_changes_retire_once_and_failed_mutations_keep_admission`.

Owner evidence, not re-run here:

- Red, against the pre-fix tree: child panic at the new assertion, `stale Core operation must not run after cleanup resumes` (`drain-readmission-red.log`). The parent harness line is the child-process status assert.
- Green: that test `ok`, suite `121 passed` (`drain-readmission-green.log`).

## Production call graph

macOS registers `desktop_lock::private_commands::mesh_invoke`. The non-macOS `mesh_invoke` in `main.rs` is not in the invoke handler. Windows and Linux register only appearance and update commands.

`mesh_invoke` holds the Core mutex across the drain and the invoke.

1. `execute_checked` admits the lease.
2. Fork symbols `mesh_messenger_transparency_fork` and `mesh_messenger_fork_filing` return through `core()` (lock, `check(call)`, invoke) and `bounty::invoke_proof`. They do not drain and they are not identity transitions.
3. Every other symbol: `check`, `drain_before_core`, mailbox-ticket ownership check, then `observe_identity_transition`.
4. For a transition symbol, `identity()` reads `mesh_messenger_load_profile` before the mutation closure. The closure checks the lease again, then invokes the caller symbol.
5. If the loaded profile changed, `controller.account_changed` rotates the epoch and `NativeProtection`'s cover calls `Resources::retire`. Success bytes stay in `Zeroizing` and are dropped. The function returns `app_lock_account_changed`.
6. If the profile went from `Some` to `None`, the callback stores the pre-invoke `ProfileIdentity` and the post-change account generation, then drains. Drain failure leaves the obligation. The original call still returns an error, and `execute_checked`'s second check zeroizes it because the epoch already rotated.
7. `execute_checked` checks again and zeroizes either the body or the error string. `publish_result` checks once more before IPC.

Transition symbols: `create_account`, `create_signup_draft`, `complete_device_link`, `directory_register`, `devices_renew`, `account_delete`, `account_discard`, `erase_account`.

`LegacyRemovals::drain` reads the profile once, then either drops the obligation or removes the six captured keys. Removal waits on the main queue and WebKit (`removeItem` in content world `MorseNativePrivateStorage.v1`). `RetiredCleanup::check` follows account generation and page liveness, not the private-command epoch, so lock/unlock does not cancel key removal. `localStorage.removeItem` of a missing key completes as JSON `null`, which `LegacyStorage.m` maps to status 2, so a retry of an already-removed key is idempotent at that source. This review did not re-execute WebKit.

Other live Core reads and writes, each checking its own admission after it takes the Core mutex and before `invoke`:

- `core()` from `wallet_invoke`, `credit_open_payment`, and the fork branch
- `legacy_commands::current_account` (`load_profile` only), with checks on both sides of the WebKit wait
- `notification_commands::preference` and `fresh_notice_preference` (`load_profile`, `journal_load_bound`, `journal_save_bound`)

The mailbox-stream cancel path invokes `mesh_messenger_mailbox_stream_close` for the exact 32-byte ticket already issued to that epoch. `Resources::register` calls that same cancel if the epoch was retired before registration. It does not read or publish mailbox bytes.

Lock, unlock, and page replacement take the controller lock only. They can run during a cleanup wait. They cannot run a second Core mutation while `mesh_invoke` holds the Core mutex.

## Round-4 barrier

`Controller::lifecycle` rotates the epoch on `Inactive` when policy is enabled. The barrier fixture is enabled. During the first cleanup key it goes inactive, active, unlocks, and activates the new epoch. `RetiredCleanup` still succeeds because the account generation did not change. `drain_before_core`'s second `check` then fails the old lease.

The test sets `attempted` only after `drain_before_core` returns, then calls `invoke_identity_transition`, which does not itself check the lease. The assertions that matter are `attempted == false`, profile still `None`, and the fresh epoch still admitted. `execute_checked`'s trailing check would refuse publication even if Core had already run; those two assertions are what prove Core did not run. The red log failed the `attempted` assertion. The fixed source does not reach it.

The production mutation has a further `check(call)` immediately before `library.invoke`. The test does not call that closure. Removing only that inner check would leave the cleanup-wait case protected by `drain_before_core` and would still pass this test. The inner check covers the straight-line gap after the drain returns (mailbox ticket parse). There is no await between the post-drain check and the mutation check. A transition symbol's `load_profile` sits in that gap; it is a read, and the mutation is still checked. This is not a second cleanup-wait route.

## Properties

| Property | Result |
| --- | --- |
| No Core mutation on a stale epoch after cleanup resumes | Holds for `mesh_invoke`. The command that waited is rechecked before invoke. A successor blocked on the Core mutex uses its own lease and `core()` / `preference()` / `current_account` check after the lock. |
| No replacement-account cleanup | Holds. Drain deletes only when the generation still matches and the loaded account is not the captured account. Keys are `{database}/{kind}/v1/{account}` plus one notification key that also includes the device. Page replacement fails `require_open` and keeps the obligation. A restored same account hits `same_account` and does not remove. |
| Failed Core mutation keeps admission | Holds when the follow-up profile load matches the pre-image. `account_changed` runs only if that comparison says the profile changed. Invalid `create_account` and `create_signup_draft` keep the epoch in the test. |
| Committed replacement or remote erase retires the old scope | Holds when the Core call is one of the eight transition symbols and the profile actually changes. `account_changed` rotates the epoch and retires `Resources`. Erase to `None` captures cleanup from the pre-invoke identity. |
| No private error or stale bytes on that refusal | Holds on the admission fence. `execute_checked` zeroizes the body or the error string when the second check fails. Profile parse errors are static strings. `identity()` maps a foreign Core error to `account_state_unavailable`. An identity change drops the `Zeroizing` body and returns a fixed string, which the second check also wipes, so IPC sees `app_lock_stale_epoch`. |

Adjacent, not a verified defect: `wallet_invoke`, `credit_open_payment`, the fork/filing branch, and notification journal writes do not drain a pending obligation before their own Core call. Their epoch check is still immediately before `invoke`, so they are not the stale-command continuation. If erase cleanup stopped on page replacement, those commands can run on the new epoch while the isolated-world keys wait for a later ordinary `mesh_invoke`. That matches the already stated process-lifetime obligation, not a cross-account delete and not a stale-epoch admit. The comment "retries before any Core use" is broader than this call graph.

`backup_import` checks the current profile before import. It is not an account switch and does not need to be in the transition set for this race.

If the post-invoke `load_profile` fails, `observe_identity_transition` treats that as a change and rotates the epoch even when the mutation itself failed. No concrete case of a rejected mutation followed by an unreadable profile was reproduced. Fail-closed, not filed as a bug.

## Prior findings

1. Backup native framing and epoch context — **resolved**. `createBackupServices` asserts the session before encode, after invoke, and after decode, and clears undelivered decoded bytes. Desktop transport sends `X-Morse-Lock-Owner` and `X-Morse-Lock-Epoch` into `mesh_invoke`. Export and import file contexts are bound to `wire::epoch`. Not re-run; outside the `3713` diff.
2. Remote account removal must retire native resources — **resolved** for the desktop reaction. `directory_register` and `devices_renew` are transition symbols. A profile that becomes `None` takes `account_changed` and `Resources::retire`. The test names those symbols and invokes `mesh_messenger_erase_account` at the seam. **Unverified**, and not promoted: no HTTP 410 execution of the real symbol.
3. Legacy-key ownership must be captured before Core erase — **resolved**. The profile snapshot is taken before `invoke`. `capture` uses that snapshot and the post-`account_changed` generation only after the profile is `None`.
4. Cleanup must survive page replacement and must not delete the new account's prefs — **resolved**. A drain error does not call `finish`. The same test removes two keys, replaces the page, then the successor removes all six. A restored identity is spared. Obligation storage is the in-memory `LegacyRemovals` slot only.
5. Lock/unlock during cleanup still reached Core — **resolved** by `3713c59`. See the barrier above. This was the unreviewed fix; it is reviewed here.

## Limits, not filed as bugs

- Native UI on this host is fail-closed (`errSecMissingEntitlement` / `-34018`). Unlocked WebKit, chooser, clipboard, export, and backup UX were not exercised.
- Windows and Linux do not register private IPC.
- Cleanup is process-lifetime only. There is no crash journal.
- Remote-removal coverage is the erase seam, not a live 410.
- Owner build, typecheck, ABI, and the 121-test log were read as existing evidence and were not regenerated.
- `mesh::invoke` still formats an admitted Core failure as `Mesh {status}: {body}`. The cleanup and account-change refusals do not publish that string. No private payload was shown in this path.
