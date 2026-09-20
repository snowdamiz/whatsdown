# Morse security hardening and verification plan

Status: implementation in progress. The acceptance criteria below remain the target;
passing a subset does not establish release readiness. Local results are recorded
in `.security-evidence/local/manifest.json` and its command logs (ignored by Git).

Implemented and locally exercised so far: exact-revision publication checks,
versioned group sender chains and update-only epochs, independent schedule oracle
and bounded symbolic model, retained-key negative control, direct hostile vectors,
OTA signing configuration, Windows signing configuration, separate witness
deployment configuration, and durable witness checkpointing before signature
publication. Shared Mesh fixes cover secret-map forks, moved-resource cleanup,
and string ownership across service calls/casts/replies. Directory freshness,
account-ID lookup, recipient-confidential group transport, and live marker scans
have focused local coverage. Native storage now migrates complete legacy key/counter
pairs to one atomic version-2 record, preserving incomplete legacy records on error.

Still outstanding: the full crash/restore matrix, already-encrypted outbox
revocation handling, cross-epoch queued-message migration coverage, the complete
extended fuzz/state-machine/mutation campaign, and final
candidate verification and publication. Physical/native checks and live witness
permission-isolation checks unavailable on this host are recorded **not run**, as
requested. No live witness cutover has been performed.

## Comparison-driven hardening (2026-09-19)

A review against Signal's design found defects outside the slices below. Each
fix has a regression that fails without it; commit messages record what was
run. Status is per fix, not overall readiness.

| Finding | Status | Evidence |
| --- | --- | --- |
| The published mailbox token was the only credential for fetch, stream, and acknowledgement, so anyone who resolved a username could read and silently delete that device's queue | Fixed. Version-2 requests are signed by the device key in the account-signed credential; the token is only a deposit address | `delivery_wire.test`, `api.test` takeover proof (fails when verification is bypassed), `stream.test`, `directory_mailbox.test`, M8 live proof |
| The unauthenticated single-device directory was still public | Removed (routes, storage, table; migration `011`); the CLI registers as a real device and verifies transparency evidence | `routing.test`, M8 |
| Bare ratchet packets showed delivery a session ID shared by both peers, enough to reconstruct who talks to whom; outer suite and wrapper magic named the packet kind | Fixed. One recipient-sealed transport and one outer suite for every packet ([spec](mesh-private-messenger/protocol/recipient-transport-v1.md)) | `recipient_transport.test` reproduces the leak, `cli_mobile.test`, `fanout.test`, M8 database assertion |
| The privacy edge and the delivery core were one Worker holding the unsealing seed | Code and build fixed: the edge deploys alone with one secret; both Workers strip client headers. **No live cutover or permission-isolation check has run**, and one operator can still correlate | `edge.test`, `witness.test`, smoke test |
| Expo received the public protocol device ID with the push token | Fixed: a random sealed installation ID | `push_binding.test` records what the provider is told |
| An append past 4,096 transparency entries made every lookup fail | Fails safe: appends stop at the ceiling and new accounts at 3,584, reserving room to revoke. The ceiling itself remains; see [key transparency](mesh-private-messenger/protocol/key-transparency-v1.md#proof-representation-and-its-ceiling) | `transparency_capacity.test` |
| Envelopes could be parked with no expiry, holding an offline mailbox full | Fixed: at most 31 days ahead, never already expired | `api.test` |
| Android backup and device transfer, iOS backup, screen capture, app-switcher snapshot, stale decrypted previews | Android plugin verified by config introspection; Swift type-checked; desktop config tested. **The Kotlin change and native wiring were not compiled, and nothing ran on a device** | `data-protection.test`, `window-security.test` |
| Mesh integer division was undefined behaviour; runtime tests, sanitizers, and fuzzing never ran on a change | Fixed in the Mesh hardening branch; **the sanitizer and fuzz jobs have not executed** | `e2e_division_guard`, workflow validated as YAML |

Resolved since:

- **Last-resort prekey.** A drained pool now returns the device's reusable
  last-resort key instead of `409`, so it no longer blocks new sessions; the
  responder refuses a replayed first message (`prekey_pool.test`,
  `last_resort_prekey.test`, M8).
- **Cost of anonymous requests.** Registration, lookup and prekey claim require
  proof of work bound to the endpoint, the request and a five-minute window,
  and each stamp is admitted once (`privacy_edge.test` pinned against an
  independent vector, `admission.test`, `request_stamps.test`, M8). This raises
  the cost of draining pools, filling the log and scraping; it is not a hard
  limit. **The two native dispatch lines for the new exports (Kotlin, Swift)
  were not compiled here.**

- **Strangers crowding out contacts.** A device publishes the hash of a secret
  second deposit address and hands the address to contacts inside the encrypted
  channel; envelopes sent to the public address may hold three quarters of a
  mailbox, the rest is kept for contacts. No wire format changed. A mailbox is
  also bounded by bytes now (4 MiB, 4,096 envelopes) instead of 64 envelopes
  (`contact_address.test` on the server and in the core, `prekey_pool.test`,
  `storage.test`). Not covered: group members who are not direct contacts still
  use the public address, rotation only happens on blocking, and a contact who
  turns hostile can fill the mailbox until blocked.

- **A mailbox that a few envelopes could freeze.** A fetch always began at the
  oldest unacknowledged envelope, and one that could not be opened yet was
  never acknowledged, so eight of them, which any contact can send, were all a
  device received until they expired. A pass now asks past what it has set
  aside; a message numbered more than 64 ahead is refused for good instead of
  being tried again; and an envelope is given up on only after sixteen tries
  and a day, so the device's own passing trouble cannot lose a message
  (`inbox_poison.test`, `network.test.ts`).
- **Skipped message keys never aged out.** A session now lists the keys it
  keeps and forgets one five receiving chains after it was set aside; ratchet
  snapshot `2` stores the list (the direct-security ratchet proof, which also
  covers reading a version `1` snapshot through a frozen version `1` writer).
- **What a notification shows** is the user's choice: name and message, name
  only, or neither (`message-notifications.test.ts`).
- **The read, notification and receipt journals** were plain JSON beside the
  database (files on a phone, `localStorage` on the desktop). The core now
  seals them in the database, one record per chat, under labels only it can
  name; the clear copies are imported once and removed (`journal.test`,
  `journal-store.test.ts`, and the unread and receipts browser checks).
  **The two native dispatch lines for the new exports (Kotlin, Swift) were not
  compiled here.**

Still open from that review, in priority order:

4. Signed prekeys are issued for a year and never rotated, and the ML-KEM key
   is fixed for the life of a credential; there is no post-quantum ratchet.
   The last-resort prekey, the one prekey secret that use does not destroy, is
   now replaced weekly and its old secret destroyed 35 days after the directory
   confirms the new key (`last_resort_prekey.test`); that needed no wire change.
   Both keys sit inside the transparency-logged device set, and a client
   matches a claimed bundle to a logged device by the bytes of the bundle, so
   rotating them means publishing them outside the log, as one-time prekeys
   already are.
5. Compact transparency proofs, and independently operated witnesses. The
   second is operational, not code: `services/transparency-witness` already
   keeps its own key and last checkpoint, checks the log's signature and a
   consistency proof against that checkpoint, and refuses a conflict before it
   co-signs, but every witness in use today is run by the log's own operator.
   A user's own key history is already watched: at every sync a device
   resolves its own account with transparency evidence, treats a rollback or
   two different sets at one sequence as an error, and warns when the set
   advances (`cached_device_set_changed`). There is no view of past changes.
6. Group application messages are signed with the long-term device key and are
   therefore non-repudiable.
7. HPKE is composed by hand in the runtime. It is single-shot, so its one
   RFC 9180 vector (A.2.1, sequence zero) does cover the whole key schedule it
   uses. The ML-KEM crate is unaudited; it is now checked against OpenSSL for
   key generation from a seed and for decapsulation (`mlkem_interop.test`),
   which is agreement on a vector, not an audit. Secrets are not memory-locked.
8. App lock, incognito keyboard, view-once, delete-for-everyone, and
   disappearing messages in groups.

Audience: engineers implementing Morse and its shared Mesh runtime, and a future outside auditor. The deliverable is a reproducible security evidence package for a specific release, backed by implemented controls and adversarial tests.

## 1. Release policy decision

**An outside audit is not a prerequisite for production use, enabling a protocol suite, or publishing a release.** Do not introduce an audit-approval flag, an external signoff requirement, or a test that requires documentation to prohibit production use.

Release readiness will depend on observable internal criteria: the tests below pass for the actual release revision and artifacts; applicable platform checks are complete; and known security failures are fixed or the affected feature is excluded. External review remains valuable additional scrutiny that can happen afterward. Its absence is reported as a fact, not used as a release prohibition.

Remove the contradictory external-review requirements from the security policy, contributor guidance where applicable, protocol profiles, compatibility matrix, security visualization, original roadmap, and milestone scripts. Preserve accurate statements about implemented features, experimental constructions, limitations, and which reviews have actually occurred. Removing a prohibition does not mean relabeling the current implementation as independently audited.

Tests can demonstrate specified behavior, detect attacks, and validate bounded security properties. They cannot prove the absence of every vulnerability. The target claim is **“internally verified against this threat model at this revision,”** with the evidence attached—not an unrestricted claim that the software is proven secure.

This decision supersedes the older plan's external-audit prerequisite. Updating the other documents and scripts is part of S1 below; this planning change alone does not change their contents or the application.

## 2. Starting point and scope

Source inspection established the following baseline. Existing tests were inspected, not executed as part of writing this plan.

| Existing capability | Reuse and strengthen |
| --- | --- |
| Direct-message prekey handshakes, Double Ratchet, hybrid ML-KEM establishment, encrypted device fanout | Existing protocol, mobile-core, and CLI interoperability tests |
| Custom MLS-inspired groups with signed membership transitions and encrypted snapshots | Existing group tree, wire, lifecycle, invitation, removal, and consistency tests |
| Account signatures, device linking/revocation, safety numbers, two-witness transparency checks | Existing device-set, linking, fanout, and transparency tests |
| Encrypted local blobs, platform key storage, transactional outbox and delivery | Existing storage-wrapping, initial-session, prekey-pool, database-failure, and retry tests |
| Sealed delivery, recipient-encrypted initial packets, padding, generic push | Existing transport privacy, privacy-edge, push, and live-service checks |
| Pinned Mesh revision, native bindings, Node test runner, Mesh test runner, Maestro flows | Existing CI and release workflows; extend them rather than add a second test platform |

Confirmed weaknesses or assurance gaps to address:

1. Group message keys can be reconstructed from the retained epoch secret; advancing a generation counter does not provide per-message forward secrecy.
2. Two witness keys currently share an operator/account. Service separation does not establish independent trust against that operator.
3. Group identifiers and membership/control metadata remain visible to delivery. Source addresses and timing remain observable at ingress.
4. Hybrid and group code is callable despite documentation saying production activation is disabled. Existing “review gate” checks only search documentation for that prohibition.
5. The mobile release workflow can publish a native build or OTA update after its JavaScript checks without waiting for the full protocol CI result for the same revision.
6. Some native security checks inspect source strings or compilation rather than exercise the OS behavior. Successful builds and shared-code round trips are useful but insufficient evidence of security.

Scope covers currently exposed direct/group messaging, linking, storage, services, push, desktop/native boundaries, and release/update delivery. Attachment and backup primitives must keep passing their existing tests; additional product integration is not part of this plan. Any such feature exposed in a release must receive the same end-to-end, restore, and leak checks before it ships.

## 3. Security contract

Use these IDs in test names and evidence. Each property needs a positive control and an attack or failure case.

| ID | Required behavior | Important boundary |
| --- | --- | --- |
| C1 | Message content and private protocol keys stay unavailable to delivery, directory, object storage, and push providers | Compromised endpoints and intentional recipient disclosure remain outside confidentiality guarantees |
| C2 | Forged identities, changed transcripts, replay, and suite downgrade are rejected | Rejection must not commit unauthenticated session/history changes; reserved nonces and deliberately consumed one-time prekeys may remain consumed |
| C3 | Current ratchet state cannot recover erased past message keys; fresh authenticated entropy permits recovery after a temporary compromise | Retained history, skipped keys, stolen old snapshots, and continuing endpoint control must be treated separately |
| C4 | Removed devices cannot decrypt messages encrypted after senders adopt the new device set/group epoch | Previously delivered content cannot be recalled; offline senders cannot instantly know a revocation |
| C5 | Restart, retry, concurrent calls, and partial restore never reuse a key/nonce pair or silently lose an acknowledged message | Complete rollback of every trust anchor cannot be assumed detectable |
| C6 | Servers see only the metadata documented for their role | Timing correlation and collusion remain explicit residual risks |
| C7 | Untrusted inputs have bounded decoding, cryptographic work, memory, queue growth, and network effects | Use actual protocol ceilings and measured operating limits |
| C8 | Published native binaries, UI bundles, backend images, and configuration correspond to the revision and dependency set that passed verification | Build provenance and signing do not establish cryptographic correctness by themselves |

## 4. Implementation slices

Implement one failing behavioral test, its smallest correct fix, then refactor while green. Extend existing tests when they already cover the scenario. For an already-correct property, demonstrate that a narrowly weakened implementation makes the new test fail; do not deliberately break production code merely to manufacture a red test.

Protocol transitions remain in Mesh. Generic resource, cryptographic, or fault-injection capabilities belong in the separate Mesh repository and are consumed through a pinned revision. Production secrets never use ordinary byte exports. Any state inspection or compromise injection needed for testing must be confined to the test runtime and absent from release artifacts.

### S1 — Replace external approval with actual release verification

**Priority:** first. **Properties:** C8.

Changes:

- Apply the release-policy decision throughout the existing documentation. Remove the M14/M15 assertions that require production-prohibition text and their “externally gated” success messages. Retain meaningful cryptographic, interoperability, and compatibility tests.
- Make mobile native builds, OTA publication, desktop publication, and backend deployment depend on successful applicable verification for the exact Morse commit and pinned Mesh commit. Manual release paths must follow the same rule.
- Reuse a shared verification workflow or the existing dependency chain. Do not accept the latest green result from a branch if it belongs to another commit.
- Record the suites actually enabled in each artifact. Enabling a suite depends on its behavior checks, not an external review flag.

Tests and acceptance:

- A disposable release rehearsal with protocol CI failed, absent, canceled, or from another commit cannot reach publication; the same candidate with successful applicable checks can.
- Verify the OTA-only path too. A UI change can exfiltrate displayed plaintext even when keys remain native.
- Demonstrate that no outside-audit credential or approval record is needed. Preserve existing code-signing and deployment credentials.
- Documentation and compatibility status match reachable code and evidence; no claim of a software-enforced disable exists without one.

### S2 — Give group messages real key erasure and compromise recovery

**Priority:** highest protocol fix. **Properties:** C2–C5. **Depends on:** S1's test/evidence conventions; S4 for durable completion.

Changes:

- Replace direct derivation of every message key from a retained epoch root with per-sender one-way message-key evolution and bounded skipped-key handling. Use the secret-tree/deletion principles in [RFC 9420 sections 9 and 16.6](https://www.rfc-editor.org/rfc/rfc9420.html#section-9) as a reference; keep the custom protocol label and do not claim MLS interoperability.
- Remove retained ancestors that can regenerate erased application keys. Merely adding a chain while persisting the original epoch secret does not fix the weakness. Separate the material needed for future epoch transitions from application-key derivation, including in snapshots and backups.
- Add an authenticated update-only epoch transition so a group can inject fresh entropy without adding or removing a member. Trigger it on recovery and define a tested, bounded refresh policy.
- Version changed wire semantics and snapshots. Existing queued ciphertext remains interpretable under its original version; new sends use the new version. Require an authenticated group transition when members upgrade; never reinterpret old state or silently downgrade. Old messages do not acquire retroactive forward secrecy.

Tests and acceptance:

- First reproduce recovery of an earlier ciphertext using today's retained epoch secret. After the change, an attacker holding only current protocol state and captured traffic cannot recover a consumed message key. Exclude deliberately retained plaintext history and account for still-valid skipped keys.
- Include every live TreeKEM/HPKE private key and captured welcome/commit in that attacker state. Erasing an epoch root is insufficient if retained transport or tree keys can recover it from an earlier packet; update key lifetimes and the epoch schedule wherever that trace succeeds.
- Cover two senders, duplicates, out-of-order messages, skipped-key expiration, generation limits, restart, and snapshot restore. Authenticated messages remain readable within the documented reordering window.
- Capture a compromised state, end attacker access, perform the specified fresh-key update, and show that the old state cannot decrypt subsequent traffic. State exactly which members/keys were compromised and which honest refresh is necessary; do not claim recovery while an attacker still controls a member.
- A removed member cannot decrypt the new epoch; an added member cannot decrypt earlier epochs. Malicious commits, welcomes, conflicting epochs, and sender impersonation leave committed state unchanged.
- Use an independent derivation oracle and a small symbolic model of the changed key schedule/membership exchange to check secrecy, authentication, and compromise assumptions. Pin the model, tool version, assumptions, and results; a bounded model result is not a proof of the entire app.

### S3 — Expand direct-session and hybrid attack coverage

**Properties:** C1–C3, C7. **Depends on:** S1; may precede S2's full migration.

Changes and tests:

- Extend the existing independent known-answer vectors at the Mesh primitive boundary: X25519, Ed25519, HKDF, AEAD, HPKE, and ML-KEM. Include invalid inputs and boundary lengths, not just encrypt/decrypt round trips through the same code.
- Bind both identities, both device credentials, prekeys, versions, suites, and transcript context. Test substitution of each authenticated field, low-order/all-zero DH results, malformed signatures, modified KEM ciphertext, and cross-session ciphertext swaps.
- Cover hybrid/hybrid, hybrid/classical, existing classical sessions, and a peer previously authenticated as hybrid. A bad hybrid handshake must not trigger a classical retry that bypasses the remembered suite floor.
- Reconcile signed-prekey lifetime and rotation with the documented contract. Exercise expiration, overlap for queued initial messages, replenishment, duplicate claims, concurrent claims, and crash recovery. One-time keys must never become reusable after an error.
- Exercise skipped-key bounds, duplicate initial packets, replay after restart, simultaneous starts, and maximum counter jumps. Test failure behavior through the real core entry points.
- Run temporary-compromise traces against the Double Ratchet: past consumed keys remain unavailable; future confidentiality resumes only after the necessary fresh DH exchange and loss of attacker access. [Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/) supplies the property vocabulary, not an assertion that Morse is Signal-compatible.

**Acceptance:** all supported suite combinations have successful interop and hostile traces; mutation of identity verification, transcript binding, or downgrade enforcement is detected. Describe hybrid protection accurately: ML-KEM-assisted establishment with a classical ongoing ratchet, not continuous post-quantum recovery.

### S4 — Verify encryption state under crash, concurrency, and restore

**Properties:** C2–C5. **Depends on:** the existing transaction boundaries; complete jointly with S2.

Changes and tests:

- Inject process termination and I/O failure before/after nonce reservation, sealing, SQLite commit, network submission, receive commit, and acknowledgement. Exercise real SQLite/WAL and PostgreSQL paths, not only mocked transactions.
- Instrument the test runtime to track key/nonce identity without logging secrets. Repeated delivery of identical ciphertext is valid; a new encryption operation reusing its pair is not.
- Retry committed ciphertext from the outbox rather than encrypting it again. Assert that session advancement, history, deduplication, and outbox updates commit together. A receive ACK must follow durable acceptance or a defined permanent rejection.
- Exercise concurrent foreground/background sync and native bridge calls, storage full, database busy, interrupted OS-key-store writes, unavailable keys, and counter exhaustion.
- Restore an old database with the current key record, an old key record with a new database, swapped account/device blobs, and a complete old backup. Reject detectable rollback/context mismatch without destroying recoverable data.
- If continuity cannot be established, require fresh outbound session/group state and a new storage-key generation before encryption resumes. Preserve readable history and any required old wrapping key until resealing succeeds atomically. Do not pretend an OS key store guarantees rollback resistance on every platform.
- Test prekey/session/group schema migrations on copied fixture stores. Unsupported versions and interrupted migrations must fail safely and remain recoverable.

**Acceptance:** every enumerated interruption point has a deterministic result; no nonce reuse, uncommitted ACK, duplicate display, silent identity reset, or lost committed outbox entry. Explicitly document what full-device rollback and previously stolen snapshots can still reveal.

### S5 — Tighten identity, revocation, and witness operation

**Properties:** C2, C4, C7.

Changes and tests:

- Extend existing linking/revocation tests with an expired or replayed link code, different requesting keys, unauthorized linking from a secondary device, stale sequences, conflicting device sets, revoked-device re-registration, and safety-number changes across linked devices.
- Document and exercise loss of the original account-authorizing device. Do not silently grant secondary devices account authority or add server-held recovery keys. Permanent signing-key compromise requires identity/device replacement and renewed peer verification; a session ratchet alone cannot repair it.
- Bind trust-on-first-use and out-of-band verification to the account key. A fresh client cannot discover the real-world owner of a substituted first-contact key merely because witnesses signed a directory entry; test verified QR/safety-number mismatches separately.
- Define device-set/checkpoint freshness. Start with a five-minute maximum age for authorizing new outbound encryption, with bounded clock tolerance. Offline/stale clients may retain pending plaintext only in encrypted local storage, but must refresh authorization before creating new recipient ciphertext. Do not drop an existing message to simulate revocation safety.
- Specify treatment of already-encrypted outbox items when revocation is learned. Exclude revoked destinations and re-encrypt/requeue under current membership where necessary; do not promise to revoke ciphertext already delivered.
- Test valid conflicting signed checkpoints, missing/duplicate/wrong witnesses, rollback, stale/future timestamps, witness restart, checkpoint CAS conflicts, and all publication/fanout paths. A broken transparency path must not silently bypass verification.
- Isolate witness signing credentials and durable stores from delivery deployments, with separate deployment permissions. Verify access denial using least-privilege test credentials. Separate accounts improve containment but do not create independent operators.

**Acceptance:** an untrusted directory cannot silently change an already verified identity, stale authorization does not create new ciphertext, and witness failure has a visible retry/error path. Independent operation is a deployment improvement, not outside-audit approval; until present, retain the honest collusion limitation.

### S6 — Reduce metadata exposure and test hostile services

**Properties:** C1, C6, C7.

Changes:

- Extend recipient-confidential transport to group membership/control records and, where needed, application frames so delivery does not receive clear group IDs and rosters. Prefer reuse of existing authenticated per-device sessions over a new cryptographic primitive or anonymity network. Keep group membership authentication and account-change checks inside that transport.
- Version the payload change and account for complete framing/padding overhead at each size limit. Test offline group joins and delivery to every authorized device without creating unintended visible direct conversations.
- Make the visibility contract distinguish sending, directory/prekey lookup, mailbox fetch/stream, object access, and push registration. Sending through the privacy edge does not automatically hide the other paths.
- Preserve private internal routes, independent service credentials, TLS endpoint restrictions, redirect rejection, opaque object capabilities, generic push, request bounds, and queue/rate limits.

Tests and acceptance:

- Extend the existing live test with synthetic marker messages, names, group IDs, rosters, filenames, and test-only secret markers. Capture service-visible request bodies/headers, databases, object bytes, push payloads, logs, and local database/WAL/temp files. Check appropriate UTF-8/UTF-16/hex/base64 forms. Plant a deliberate leak in the harness to demonstrate that the scanner detects it.
- At the privacy edge, the destination mailbox remains sealed; at delivery, content and the newly protected group fields remain encrypted. Test each visibility boundary after that component has performed its legitimate decryption, not merely packet capture outside TLS.
- Exercise the actual Worker route allowlist, public access to internal endpoints, credential misuse, redirect/origin manipulation, cross-account object capabilities, oversized requests, replay storms, unavailable dependencies, and partial uploads.
- Measure work and queue bounds during unauthenticated traffic, malicious senders, and proof-of-work replay. Invalid traffic must not grow storage or expensive work without a defined bound.
- Do not equate marker absence with anonymity. Record remaining destination/timing/size-bucket visibility and the shared-infrastructure correlation risk.

### S7 — Exercise real native storage and secure the update chain

**Properties:** C1, C5, C7, C8.

Changes and tests:

- Replace security-relevant source-string checks with OS adapter behavior tests where possible. Keep inexpensive static checks as supplementary checks, not proof of runtime behavior.
- Exercise iOS Keychain, Android Keystore, macOS Keychain, and Windows Credential Manager through the real application bridge. Cover first unlock, lock/background transitions, restart, denied access, key invalidation, reinstall/restore behavior, and application identity/signing changes.
- Private key exports and test-only secret-revelation functions must be unavailable in release builds. Message plaintext intentionally reaches the UI; do not make the impossible assertion that no plaintext ever crosses into TypeScript.
- Test Tauri IPC with malformed input, unsupported commands, cross-origin requests, and untrusted content. Preserve its restrictive CSP and native URL validation. Confirm debug tooling and sample/test data are excluded from release exports.
- Authenticate OTA updates with the platform's supported signing mechanism and verify rejection of altered, wrong-key, incompatible-runtime, and obsolete-policy updates. Native fingerprints alone are compatibility checks, not update authentication. Keep signing-key custody separate from routine publish tokens.
- Pin build inputs and action revisions, verify downloaded toolchain checksums, scan Rust and JavaScript dependencies, and inspect generated bindings. Record exploitability for dependency findings; unresolved high/critical findings reachable in shipped code or privileged release tooling prevent that candidate from publishing.
- Verify macOS signing/notarization and add Windows release signing. Keep distribution signatures and the unsigned build inputs/digests needed for reproducibility comparisons.

**Acceptance:** platform rows have actual executed results, not only cross-compilation. A missing device check is “not run,” never “passed.” Native/ABI/key-store changes require physical iOS and Android checks; unaffected revisions may reuse evidence only with an explicit dependency/content comparison. A substituted update or release artifact is rejected.

### S8 — Run an adversarial system campaign and assemble evidence

**Properties:** C1–C8. **Depends on:** relevant earlier slices.

- Add seeded state-machine scenarios to the existing Mesh tests: multiple devices/accounts, two simultaneous senders, offline periods, duplicates, reordering, revocation, group membership changes, service restarts, and storage faults. Print a seed and minimized action trace on failure.
- Fuzz public binary decoders and state transitions, including native ABI frames, handshakes, ratchet messages, group commits/welcomes/snapshots, transparency evidence, push tokens, and exposed object/backup formats. Bound input sizes and retain failing inputs as regression fixtures.
- Run memory/undefined-behavior instrumentation at supported native/runtime boundaries. Check resource ownership and zeroization in Mesh runtime tests. Timing smoke tests may reveal regressions, but cannot certify constant-time cryptography.
- Add targeted negative-control mutations: bypass AEAD verification, omit identity binding, permit downgrade, reuse a reserved nonce, retain a group message root, ignore revocation, accept one witness twice, expose an internal route, and publish without successful protocol verification. Each must be caught by its owning test.
- Use real local services and disposable databases for multi-client acceptance flows. Keep fault injection and destructive tests away from production data and credentials.

**Acceptance:** all required properties link to an executed test, all discovered failures have a fix plus regression, and an engineer can reproduce the campaign from recorded commits, toolchains, commands, fixtures, and seeds.

## 5. CI execution and evidence

Keep existing Mesh, Rust, Node, and Maestro runners. Add only the smallest orchestration needed to produce a shared result manifest and avoid recompiling/rerunning identical suites through nested milestone scripts.

| Lane | Required work | Initial execution budget |
| --- | --- | --- |
| Pull request | Existing behavioral suites; new focused regressions; golden/hostile vectors; changed native boundaries; corpus replay; relevant service integration | Deterministic checks on every change; measure duration before reorganizing jobs |
| Nightly or manual extended run | Seeded state machines, process-kill matrices, fuzzing, native instrumentation, targeted security mutations | Start with 1,000 seeds of up to 200 operations per state-machine family and 15 minutes per fuzz target; record actual executions and enforce per-case limits |
| Release candidate | Full applicable checks for the candidate, current corpus, migration/restore exercises, artifact/config verification, platform acceptance and publication rehearsal | At least one completed extended campaign on the exact candidate; missing evidence fails readiness |

These counts are starting test budgets, not security thresholds. Increase them based on discovered failures and reachable state/branch coverage. Never substitute an arbitrary coverage percentage or a fuzzing time total for a missing attack scenario.

Existing entry points include the M10/M13/M14/M15 milestone scripts, mobile and desktop `npm test`, mobile typechecking, Cloudflare `npm test`, and the Maestro flows. Their current prerequisites and nesting differ. S1/S8 should expose one documented security-verification entry point over those checks; `node mesh-private-messenger/scripts/verify-security.mjs` now records local checks and missing acceptance rows; it does not yet replace the extended release campaign.

Every evidence manifest must record:

- Morse commit and clean-tree status; Mesh commit; dependency lockfile and toolchain digests; enabled suites and wire/snapshot versions.
- Platform/OS/architecture and artifact hashes, including the native library and OTA bundle/runtime fingerprint.
- Commands, test IDs mapped to C1–C8, pass/fail/not-run status, durations, seeds, minimized fixtures, and modeled threat assumptions.
- Crash/fuzz/mutation results, release rehearsal results, and dependency findings with disposition.
- Known limitations, supported rollback/migration range, and operator instructions for key loss, revocation, and failed updates.

Store synthetic traces and manifests as CI artifacts. Exclude real credentials, private keys, production user data, and unreduced sensitive dumps. Reproduce the same unsigned application inputs where possible; document nondeterministic signing/notarization metadata rather than claiming signed packages must be byte-identical.

## 6. Completion criteria and order

Recommended order: **S1 → S2/S4 together → S3 → S5 → S6 → S7 → S8**. Add each slice's adversarial checks as it lands; do not postpone testing until S8. Parts of native and release verification can proceed independently once S1 establishes the shared contract.

Implementation is complete when:

1. Outside-audit approval is absent from production enablement and release requirements, and documentation accurately describes the resulting policy.
2. The group root-retention weakness is fixed with a versioned, tested migration and explicit erasure/compromise assumptions.
3. Every required property has successful behavioral and adversarial evidence for the candidate; no applicable required test is skipped or replaced by a string search.
4. Release workflows cannot publish a different or unverified revision, including OTA and manual paths.
5. Known high-impact confidentiality, authentication, nonce-reuse, key-substitution, and data-loss failures are resolved in shipped features. Other residual risks have concrete scope and operating guidance.
6. A fresh engineer can replay the evidence and hand the same package to an outside auditor without reconstructing the project history.

Do not expand this effort into a new test framework, a second production cryptographic implementation, a full rewrite to standard MLS, or a general anonymity network. Those require separate demonstrated needs. Preserve existing feature limits until measurements or product requirements justify changing them.

## 7. Implementation starting points

These links identify the code inspected for this plan; module names and behavior above remain the contract if files move.

- [Group message derivation](mesh-private-messenger/packages/messenger-protocol/groups/group_messages.mpl), [group key schedule](mesh-private-messenger/packages/messenger-protocol/groups/key_schedule.mpl), [group snapshots](mesh-private-messenger/packages/messenger-protocol/groups/group_snapshot.mpl), and [group contract](mesh-private-messenger/protocol/mls-groups-v1.md).
- [Direct ratchet](mesh-private-messenger/packages/messenger-protocol/session/ratchet.mpl), [handshake](mesh-private-messenger/packages/messenger-protocol/session/handshake.mpl), [account creation](mesh-private-messenger/packages/mobile-core/mobile/account.mpl), and [device fanout](mesh-private-messenger/packages/mobile-core/mobile/fanout.mpl).
- [Local transactions](mesh-private-messenger/packages/mobile-core/storage/records.mpl), [storage wrapping contract](mesh-private-messenger/protocol/storage-wrapping-v1.md), and [client transparency enforcement](mesh-private-messenger/packages/mobile-core/mobile/transparency.mpl).
- [Privacy contract](mesh-private-messenger/protocol/privacy-contract.md), [Worker routing](mesh-private-messenger/ops/cloudflare/worker.mjs), and [deployment limitations](mesh-private-messenger/ops/cloudflare/README.md).
- [Core CI](.github/workflows/ci.yml), [mobile release](.github/workflows/mobile-release.yml), [desktop release](.github/workflows/desktop-release.yml), [M14 checks](mesh-private-messenger/scripts/prove-m14.sh), [M15 checks](mesh-private-messenger/scripts/prove-m15.sh), and [device acceptance flows](mesh-private-messenger/apps/mobile/tests/e2e/README.md).
