Verdict: REQUEST_CHANGES / HOLD. The exact proposal remains UNAPPLIED, UNCOMPILED and UNAPPROVED. Its single private release is a plausible place for an explicitly authorized mailbox-outcome policy, and I found no execution-order change in the exact diff. It is not sufficient evidence that decoded receive privacy is closed. Correct the policy description, compose against the parent's actual receive source, and satisfy the compiler/runtime controls below before approval. No arbitrary String/Result release or public classifier declassification is justified by this review.

Scope and evidence

This was a read-only source/policy review. No Git commands, builds, compiler invocations, application/test execution, network calls, children, source edits, production changes, or patch application occurred. Writes are confined to this review directory. Source diff comparison and SHA-256 calculations were performed in Python; those are artifact checks, not compiler/runtime controls.

The owner's checkpoint record claims dd1b11a852b97581abb9b83ec55f8f24868312e9 and a clean worktree. Proposal metadata names base 56148470ca80bc3a87fa31c158a1d7156c7223d8. These commit/cleanliness claims were not independently checked with Git. The review pins the actual copied bytes instead. The supplied base and proposed inbox copies reproduce the patch exactly, and the owner's captured inbox equals the supplied base. All three declared proposal hashes match. The parent inbox differs from that base.

1,456 inputs were copied and hashed. Before/immediate-after/final-live hashes and snapshot hashes agree for all captured files; no source drift was observed during this review. See manifest.before.json, manifest.after.json and source-pins.tsv for full original paths and SHA-256 pins. This captures relevant source in the two worktrees, not an atomic repository commit or a claimed full compiler dependency closure.

Paths below are relative to inputs/owner/mesh-private-messenger/packages/ unless prefixed P: (inputs/parent/mesh-private-messenger/packages/) or C: (inputs/compiler/). “Proposed Inbox” means the frozen proposed file under inputs/owner/.morse/decoded-body-labels/inbox-disposition-proposal/proposed/mesh-private-messenger/packages/mobile-core/mobile/inbox.mpl. Inbox lines 1–172 match base; subsequent proposed lines are base +7. All retained evidence is explicitly distinguished from this review's static observations.

Required corrections and approval blockers

1. Correct the policy to cover routing rejection/unknown kind and direct-only deferral. Proposed Inbox:119–145 can return 1 or 0 from delivery_kind Err, or 1 from Ok(0), without calling either direct or group receive. The reason's “after actual direct or group receive” omits these real paths. The proposal's blanket control that pending/capacity/account-state-change errors never age out is also too broad: only DirectReceiveRetry consults header_selection_unfinished. GroupReceiveRetry("account_state_changed") maps to 0. This is reachable through group snapshot/commit guards (mobile/groups.mpl:980–988, 1053–1098; storage/group_records.mpl:97–118; storage/fanout_commit.mpl:21–54). Do not silently change group behavior to fit the prose. Narrow the prose/control requirement and explicitly retain the current group retry policy. A direct deferral leaves the first-attempt timestamp unchanged; it does not pause wall-clock age. A later ordinary retry may therefore age out.

2. Compose and review the actual parent source. P:mobile-core/mobile/inbox.mpl:53 additionally recognizes view_once_reference_refused as permanent. The proposal base does not. P:mobile-core/mobile/messages.mpl:555–562 and 1241–1265 can produce that error from decoded attachment/control content before gossip/invitation work. Applying only the proposed hunk should preserve that parent's list addition; replacing the entire supplied proposed file would lose it and turn a permanent refusal into retry/age-out. Do not treat the old matrix as exhaustive for the composed candidate. snapshot-comparison.json lists 32 differing captured MPL files, including Messages, Groups, Types, history, receive guards and protocol decoding. This is an integration boundary, not a demonstrated regression in the unapplied hunk.

3. Establish provenance and refusal on the final call graph. A private function and a literal reason do not constitute compiler authority. This artifact has no fresh positive/negative compiler evidence or runtime comparison. The frozen compiler source suggests caller-PC protection at checked call boundaries, but this does not prove the selected compiler artifact or the composed app honors the required controls. Earlier receive/gossip/invitation effects also occur before the new release; approving this release cannot authorize them retroactively. The self-sync trusted account/key and restored sibling-session issue is separately owned by the parent and remains an explicit prerequisite. Nothing in this report closes authentication, view-once, invitation, gossip, full Main/receive/history, or deployment gates.

Exact authority and caller provenance

The proposed site is private settle_delivery:178. Its only production call in the captured package is private process_deliveries:233, after canonical_outer succeeds. Its input “observed” is computed by private acknowledge_delivery:172 from the same encoded envelope, decoded outer and loaded profile. It accepts no caller-supplied decoded InnerEnvelope, arbitrary error String, receive outcome, classification Int, or prior success certificate. Canonicalization maps only 1 -> 1, 2 -> 2, everything else -> 0. Both public classifiers remain ordinary pure String -> Bool functions, with no new release. receive_mobile_direct_classified and acknowledge_delivery remain private; receive_mobile_group_classified remains public and contains no new release.

The public entrance is process_delivery_batch(MobileBatchRequest), also exposed through MobileCore.process_delivery_batch_export (mobile_core.mpl:705–706 and mobile/requests.mpl:241–249). Native request parsing accepts a path and encoded batch. Mobile.MailboxSync.receive_pass also invokes it with fetched bytes (mobile/mailbox_sync.mpl:84–106). Loading profile is actual local sealed storage access (mobile/profile.mpl:54–60), and signing later opens local device keys. The batch is nevertheless caller-supplied wire data at the public API: the settlement site does not prove it came from an authenticated mailbox fetch. canonical_outer proves decoding/re-encoding equality, not sender authorization. Recipient HPKE opening likewise does not establish an authenticated peer; anyone with the recipient public key can seal a packet.

That distinction is necessary, not an automatic rejection of this policy. A poisoned mailbox must settle malformed/unauthenticated packets too. In particular, routing failures, wrong mailbox, replay, bad handshake/signature, unknown opened packet kind and pre-decryption group epoch checks are part of the existing outcome surface. Never rename the entire surface “authenticated outcomes.” In the owner snapshot, direct receive performs handshake/ratchet and identity checks before content dispatch (mobile/messages.mpl:418–501, 859–896); those checks do not resolve the separately held same-account/key provenance flaw.

Nested public entry points remain important: received_invitation_writes, observe_gossip, observe_group_gossip, history/presentation helpers, parse_sync_payload[_typed], receive_initial_message, receive_message, receive_mobile_group_classified, process_delivery_batch and the native wrappers. A caller may construct InnerEnvelope with public claimed identities and an explicit Plaintext<Bytes> body. The new private settlement site must not be used to add releases inside those public helpers, and cannot be invoked directly with a constructed Result/Int. A public batch selected using a private bit, private path/sequence/ID, or private branch is a separate caller-provenance control even when the contained ciphertexts are valid.

C:compiler/mesh-typeck/src/plaintext.rs:2980–3014 implements ordinary declassify as a dependency-free value; the reason is recorded, not validated as an authentication proof. The same source at 2659–2680 unions caller PC into summarized effects and output. Thus the limited source-based expectation is that public batch calls under private control remain refused at their storage/effect exits. That expectation needs an actual import/build control. Do not infer it merely from a successful static library build or a declassification inventory. No binary/source correspondence was established for this compiler snapshot.

Exhaustive settlement classification for the exact base

Let D be these 21 exact direct-permanent strings (Inbox:39–61):

wrong_mailbox; invalid_recipient_packet; invalid_outer_envelope; noncanonical_outer_envelope; invalid_initial_packet; invalid_initial_message; outer_suite_mismatch; invalid_initiator_account; invalid_initiator_credential; initial_receive_failed; invalid_initial_plaintext; invalid_peer_profile; invalid_inner_envelope; initial_identity_mismatch; invalid_sync_payload; invalid_ratchet_packet; invalid_ratchet_message; message_rejected; one_time_prekey_not_found; replayed_initial_message; blocked_message.

Let H be {header_selection_pending, header_selection_capacity, account_state_changed} (Inbox:68–72). D and H are disjoint in the frozen base. Let G be these 13 exact group-permanent strings (mobile/groups.mpl:1154–1168):

wrong_group_delivery; invalid_recipient_packet; invalid_outer_envelope; noncanonical_outer_envelope; invalid_group_packet; invalid_group_welcome; group_welcome_rejected; invalid_group_commit; group_commit_rejected; group_stale_epoch; invalid_group_message; group_message_rejected; group_limit_reached.

The complete classifier is:

- delivery_kind Err(e): 1 iff e is in D; otherwise 0. H is not consulted on this path.
- delivery_kind Ok(0): 1, with no direct/group receive. This is an unknown opened sealed packet kind.
- delivery_kind Ok(3): actual group receive; Applied -> 1; Err(e) in G -> Rejected -> 1; every other Err(e) -> Retry -> 0. H is not consulted here either.
- Other successful kinds: kind 1 invokes receive_initial_message; all remaining kinds invoke receive_message. Ok(any output) -> 1. Err(e) in D -> 1. Only a non-D error then consults H: e in H -> 2, otherwise 0.
- The new canonicalization maps every other possible observed Int to 0. Current acknowledge_delivery itself returns only 0, 1 or 2, so this fallback is defensive and behavior-preserving, not a new current route.

These sets plus their complements classify every String, including unknown/future error text. No arbitrary error bytes become the released value. The sets do not attest to the error's origin; a matching propagated error is classified identically wherever it was produced. In a future D/H overlap, permanent rejection wins because it is tested first. The composed parent needs D plus view_once_reference_refused, at minimum; do not broaden D with all parser failures simply to make builds pass.

Outer/batch errors precede this matrix. process_delivery_batch loads profile before decoding the whole batch. Protocol.MailboxWire.decode_delivery_batch parses every outer and rejects the batch on a malformed member before any receive (protocol/mailbox_wire.mpl:150–181). The later per-envelope canonical_outer failure is skipped with the old InboxPass: no ACK, attempt, highest-sequence update or settle release (Proposed Inbox:227–238). Thus an invalid_outer_envelope string being in D does not mean malformed wire always receives an ACK.

First-error precedence is unchanged throughout:

- Initial receive: schema/profile/canonical outer; wrong mailbox; local policy/device/seal/packet decode; initial message/suite/account; captured admission/session state and header capacity; prekey selection/replay; credential/suite/bundle/key opening; handshake; decoded plaintext/profile/inner; previous-session lookup; identity/kind/conversation checks; contact/gossip work; session/prekey preparation; blocked/self-sync/invitation/history branch; guarded commit; returned output. Every ? returns the first encountered error; classification happens only afterward. A persistence failure during a blocked receive wins over the later blocked_message rejection.
- Ratchet receive: schema/profile/canonical outer and mailbox; seal/packet/message/transport checks; header routing or legacy basis; session and peer policy lookup; restore/decrypt; inner decode/identity; session sealing and contact/gossip; blocked, gossip-only, invitation, self-sync, or normal-history branch; commit; returned output. Header selection is before body decryption and may itself persist a header cursor. The parent has changed this content-dispatch order; it must be separately qualified.
- Group receive: schema/sealed profile/profile/canonical outer; suite/mailbox; seal/packet decode; welcome/commit/message route. Welcome and commit prerequisites can fail before cryptographic verification. Message snapshot/index/load and future/stale-epoch checks precede decrypt; decoded payload/time/gossip/history and guarded commit follow it. An earlier snapshot/storage error therefore wins over a later permanent payload rejection. A group guard account_state_changed remains retry.
- Nested crypto classifiers are preserved: recipient opening maps retryable verification failures to recipient_crypto_failed (0) and rejection/padding failure to invalid_recipient_packet (1); handshake maps retryable SessionError to initial_crypto_failed (0), otherwise initial_receive_failed (1); ratchet CryptoFailure -> ratchet_retryable (0), every other rejection -> message_rejected (1). See transport/recipient.mpl:61–84, identity/device.mpl:31–46, session/handshake.mpl:58–71, session/ratchet.mpl:21–25, and mobile/messages.mpl:433–437, 860–864.
- Errors in attempt bookkeeping or final batch work are not classified by the new site. They escape process_delivery_batch through the existing Result path. Final order is inbox-state preparation/persistence, clock, direct expiry, group expiry, gossip flush, then optional key-open/time/signing. An earlier failure wins and prevents ACK return even after earlier receive writes succeeded.

Content-derived disclosures the policy must explicitly accept

The release is three-valued per reached settlement, not proof of content noninterference. Private message content, local state and operational errors can determine its value. The current public outcomes reveal at least ACK membership, retry/deferral effects and later fetch behavior; repeated delivery attempts can reveal a sequence of outcomes. The bound is on the newly released value for one invocation, not a global bound on timing, error inference, all network effects or an entire session.

Concrete source cases:

- Self-sync payload errors differ. The private sync parser returns invalid_sync_payload for malformed required fields, but invalid_store_request for malformed optional safety framing and invalid_safety_number for a nonempty non-64-byte safety value (mobile/sessions.mpl:75–140, 229–240). The first is in D and ACKs; the others retry. Optional safety parsing precedes final finish/username/required-field validation, so a malformed optional safety field can win over another defect. This is a content/error-class oracle on an actual receive, not a public classifier invocation. A valid admitted sibling-session fixture is needed to test it; this example does not approve the held self-sync authorization gate.
- An invalid invitation control is ignored by received_invitation_writes and can still commit the ratchet and ACK; a structurally valid body enters receive_control and loads invitations (mobile/group_invites_state.mpl:281–313, 204–210). With a failing invitation-state read and otherwise successful receive, the invalid case bypasses that read and can ACK while the valid case retries. Likewise valid gossip controls/hints enter additional state/network paths whereas malformed controls/hints can be ignored (mobile/gossip.mpl:185–201, 291–315, 393–409). These earlier effects need their own policy, beyond final settlement.
- Group v5/v6 plaintext decoding failure becomes group_message_rejected and ACKs (mobile/groups.mpl:945–956). Valid content that reaches a failing guarded history/state commit retries. Private expiry/kind/addressing selects whether gossip/history processing runs (1033–1098); a content-dependent failure there may alter the settlement. A group retry does not get the direct H exemption.
- Blocked status returns blocked_message only after the relevant session/admission commit succeeds (mobile/messages.mpl:517–531, 897–903); commit failure can instead defer/retry. Observing ACK must never be described as proof that a message was displayed, accepted as peer-authentic, or even durably stored as history.
- In the parent, unsupported view-once carriers on control messages produce view_once_reference_refused and ACK through the extra D entry. That is another bounded content-derived decision requiring the parent's own reviewed policy and current-source qualification.

A precise policy is: for a canonical wire envelope submitted to this local mailbox operation, release only the existing routing/receive settlement choice (1 = applied/permanently rejected/unknown-kind ACK eligibility; 2 = the exact direct unfinished set; 0 = remaining retry eligibility), including choices influenced by decoded content, local state and unauthenticated rejection. Permit the existing downstream ACK-ID selection, retry bookkeeping and cursor behavior. No arbitrary body, String, Result payload, caller-supplied classification, unrelated caller PC, or earlier receive effect is authorized by that release. This policy releases a classification; it cannot promise no observer can infer a particular error in a context with only one possible cause. If the intended privacy requirement forbids even that classification oracle, the proposal is blocked by design and preserving the old ACK behavior cannot satisfy it.

Ordering and durable effects

The diff replaces one binding with the same acknowledge_delivery call, a pure case, and declassify. It does not move a receive, seal, persistence, clock, cursor operation or ACK signature. Proposed Inbox:167 computes max(sequence, prior highest) before receive, exactly as before. The result then does:

- 2: leave ACK IDs and attempts byte-for-byte unchanged; set set_aside=true; retain max sequence.
- 1: append this outer.envelope_id; remove its attempts; preserve prior set_aside; retain max sequence.
- 0: consult prior attempts using the batch's fixed now. If current try reaches 16 and first attempt is at least 86,400,000 ms old, append ID/remove attempts; otherwise record a retry, set set_aside, and retain max sequence. Counts saturate at 255; at 256 retained records an older record can be evicted. The exact attempt rules are mobile/inbox_state.mpl:93–130.

“Defer without aging” means no attempt increment or age-out evaluation on that pass. It neither clears an earlier retry record nor advances its first-attempt timestamp. Header routing may already have written its own cursor before returning pending/capacity. That behavior is unchanged.

After all members, any set-aside causes cursor=max canonical-settled sequence for the batch, including successful envelopes after the skipped one; otherwise cursor=0. Empty batches reset cursor and still run expiry/gossip. Attempts and cursor are sealed/stored before expiry/gossip and before signature generation. Failures can occur after receive or inbox writes: the batch is not an all-or-nothing transaction, and the release must not be moved ahead of durable receive completion to hide such failures.

The ACK wire contains version, mailbox-token hash, issued-at, envelope IDs and signature, not a receive error/body (protocol/mailbox_wire.mpl:207–253). process_delivery_batch only returns these bytes; Mobile.MailboxSync.receive_pass posts them afterward and performs its identity checks (mobile/mailbox_sync.mpl:92–113). Failed ACK network submission does not roll back receive state. Replays, mixed batches, duplicate IDs and earlier-packet side effects must preserve old behavior.

Smallest concrete changes

Keep the one private Int site and the pure public predicates. Edit the release reason and proposal.json to cover routing failures/unknown kind, state direct-only H handling, and acknowledge content/local-state-derived disposition. Replace the blanket no-aging control with separate direct, routing and group expectations and the retry/defer/retry transition. Add the complete D/H/G matrix and first-error examples to the proposal's policy record. Do not add releases to public String/error/outcome helpers or broaden permanent errors.

Recreate the candidate by adding just the settlement hunk to a pinned, approved parent composition, retaining its view_once_reference_refused entry and receive changes. Rehash that source closure and update the matrix. No speculative refactor, new public API, ABI change or classifier enum is required for this proposal.

Meaningful compiler controls required before approval (NOT RUN)

Use the exact chosen compiler/runtime artifacts and final source closure; pin compiler binary, runtime archives, package manifests/resolution and source hashes before/after. Each negative must fail for the intended E0093 at the intended effect/native/HTTP exit, not for missing imports, syntax/type errors, earlier unrelated build failures, or link failures. Include a matched public/no-label positive so a generally broken program cannot pass the negative test. Inspect the successful plaintext report tied to that build to establish exactly one added site, rather than only a clean build status.

- Compile actual public permanent_direct_delivery_error and header_selection_unfinished imports with explicit Plaintext<String>, both returned Bool and branch-controlled HTTP/log/native effect sinks. Include nested Result/struct/list payload and private error-selection inputs. They must retain labels; public-string counterparts must compile. Test known permanent, H and unknown text without declassifying a test result.
- Compile actual process_delivery_batch under a private Bool branch; also pass a public-looking batch/path/ID/sequence selected by a private Bool. Check native-export return and effect closures, not only a local Bool. Keep a public actual-batch positive. The new gate must not clear unrelated selection/caller PC or prior private early-return control.
- Compile explicit-private constructed InnerEnvelope body/attachment/control fields into received_invitation_writes, observe_gossip/group variants, history/presentation and sync helpers, with claimed identities public and caller PC public. Also check direct/group receive Results, payload bytes, error strings and public classified group outcomes at sinks. Nested helper/closure/aggregate paths must retain provenance. An authenticated reason in source is not evidence of these checks.
- Test explicit-private outer/batch bytes separately from a public ciphertext legitimately produced by an approved seal; test whole-value labels, private result tag selection and private decoded payload. The legitimate seal/body flow may yield only the authorized mailbox classification. Unrelated labeled batch metadata and arbitrary private errors must not become external payloads.
- Compare candidate versus gate-removed/previous source on a well-typed real mailbox caller. Demonstrate the permitted bounded settlement compiles where the new site is actually needed, while exact body/error exits and raw public receive APIs remain refused. A stub replacing acknowledge_delivery with arbitrary Int is not a substitute for the public receive call graph. Any test-only fault seam must be confined to the private receiver path and absent from shipped API.
- Build the full composed Main/native receive/history caller closure after the separate auth/view-once/invitation/gossip prerequisites. Prior broken prerequisites cannot serve as negative privacy evidence; a staticlib passing alone cannot approve the policy.

Meaningful runtime controls required before approval (NOT RUN)

Run real local secure-store/database/crypto fixtures against old and candidate sources with equivalent initial state and controlled clocks. Compare decoded ACK ID order/membership, signature verification against the expected local device key, mailbox hash and timestamp, exact returned errors, decrypted attempts/cursor, durable ratchet/history/prekey/invitation/gossip rows and side-effect order. Random ciphertext bytes themselves need not match across independent seal operations.

- Initial/ratchet/group applied; permanent failures including unauthenticated invalid recipient/seal/signature packets and unknown opened kind; retryable recipient/handshake/ratchet failures; stale vs future group epochs. Cover every D/G member where reachable, with transparent private fault injection for otherwise hard operational paths, plus an arbitrary unknown error complement. Pure predicate tests alone are insufficient.
- Direct H pending/capacity/account-state-change with existing aged retry records must neither ACK nor modify attempts. Contrast the same strings at routing/group boundaries: existing default retry must remain. Exercise retry -> long deferral -> retry, exact 15/16-try and one-day boundaries, >255 count saturation, 256-record eviction and eventual age-out ACK.
- Multi-defect precedence controls: optional safety parse vs another sync defect; blocked-message commit failure vs permanent blocked status; valid invitation with failed state load vs ignored invalid control; malformed group payload vs earlier failed snapshot; group future/stale epoch vs decrypt failure; parent control view-once refusal vs later gossip/storage error. Use legitimately admitted peer/sibling/group fixtures so the intended content path is reached.
- Mixed out-of-order sequences, success after a deferred envelope, empty batch reset, duplicate/replayed deliveries, malformed batch member (whole-batch rejection), and later canonicality failure (skip if a valid fixture is constructible). Verify highest/cursor/attempts precisely, not ACK count alone.
- Fault receive commit, inbox-state seal/write, direct expiry, group expiry, gossip flush, key opening, signing and ACK transport separately. Confirm earlier errors win, failed commits never yield successful application ACK, and failures after earlier durable writes preserve the same redelivery semantics. Include unknown packet routing with no receive call, and header cursor writes before deferred settlement.

Retained evidence (inspected, NOT rerun)

Frozen invitation-authority-historical/evidence.json records the actual-public-API control at baseline a48963b4918f5fc39981176d4e46069b78dfeebb: original-refuses exited 1 with 19 E0093 diagnostics; held-prototype-admits exited 0 with none. Its probe/main.mpl:6–11 passes explicit Plaintext<Bytes> inside a constructed InnerEnvelope to public received_invitation_writes with no private caller branch. That is evidence of the historical helper-policy failure, not proof against or approval of this new settlement site. Retained compiler SHA-256 is 19ef395b701a3c76ff006956597b6ec176810c78a6d07271a253199911ea4e85. The earlier authority-probe/results.json records one unrelated diagnostic and no probe diagnostic in both variants; those runs are inconclusive, not successful refusal controls.

Existing source tests inspected include inbox_poison.test.mpl:113–149 (retry/cursor/day/16-try behavior), header_receive.test.mpl:183–197 and 263–270 (pending cursor and unchanged attempts), and initial_session.test.mpl:172–229 (malformed sealed traffic, injected receive failure, successful/replayed ACK). These are retained test source, not executions for this proposal, and do not cover the whole matrix or caller-provenance controls.

Full source/input pins

The complete original-path-to-snapshot pin set is in source-pins.tsv and both manifests. The concise pins below identify the exact proposal and major owning sources; every other cited source also appears in the full manifests.

- inputs/owner/.morse/decoded-body-labels/inbox-disposition-proposal/inbox-disposition.patch — SHA-256 3be7359980ac07e479cde48fe2d6bdc0948d01db19c7213e4f6e1fcbe2996f97

- inputs/owner/.morse/decoded-body-labels/inbox-disposition-proposal/proposal.json — SHA-256 49d69bfcebcb37c5c4ffe84eb556c05418e26e10c01fe5b71011086612f9696d

- inputs/owner/.morse/decoded-body-labels/inbox-disposition-proposal/base/mesh-private-messenger/packages/mobile-core/mobile/inbox.mpl — SHA-256 aad83bedb0de121f10df6867e61a66242c50cb75ef51a127e54fe599ff3a3dd3

- inputs/owner/.morse/decoded-body-labels/inbox-disposition-proposal/proposed/mesh-private-messenger/packages/mobile-core/mobile/inbox.mpl — SHA-256 5f0a4949b0b3284458b3264ca07a816863071bd22943bdf9aa35207d226d1f2a

- inputs/parent/mesh-private-messenger/packages/mobile-core/mobile/inbox.mpl — SHA-256 7abbf6ecb5d031cf7cc56955df0cae93dc041148537a2be38de92529b4f22811

- inputs/owner/mesh-private-messenger/packages/mobile-core/mobile/messages.mpl — SHA-256 592843a76f3253abde64f2224611f55c9bc885291014d5cc236517d6b5782c68

- inputs/parent/mesh-private-messenger/packages/mobile-core/mobile/messages.mpl — SHA-256 4f0d42f6badd824cb543a23a2f26026e850d9bfa7c8817514619d74868b769a0

- inputs/owner/mesh-private-messenger/packages/mobile-core/mobile/groups.mpl — SHA-256 a3f0c858a0c5a9020f297882bdf9110aa1bd4104e24ae481826452f47631b02d

- inputs/owner/mesh-private-messenger/packages/mobile-core/mobile/inbox_state.mpl — SHA-256 ef7479a0dd3f73fbecdd16977ea814363b901ae690ddd422efe247f84eeb2c66

- inputs/owner/mesh-private-messenger/packages/mobile-core/mobile/mailbox_sync.mpl — SHA-256 47597d8df766942b588ab17fc910df18132a4be4121adb61549f42a87e847e48

- inputs/owner/mesh-private-messenger/packages/mobile-core/mobile/group_invites_state.mpl — SHA-256 f33ab23ba61a52f18105d204893b4d67792a60f5669460706b41aef6626427be

- inputs/owner/mesh-private-messenger/packages/mobile-core/mobile/gossip.mpl — SHA-256 1ef24ef74ae4c05a6178f459194acbad234c5fd7a65194acc533f4714f3d3925

- inputs/owner/mesh-private-messenger/packages/mobile-core/mobile/sessions.mpl — SHA-256 6bdbfe46e6b8b5dcd3bd71e1dd189d84756d1ddac1cdc9e304d56c7744dabee3

- inputs/owner/mesh-private-messenger/packages/messenger-protocol/protocol/mailbox_wire.mpl — SHA-256 414db5bb762d245aeec91868c202c79b5f11edbcc070ed8e28c52d820f50e645

- inputs/compiler/compiler/mesh-typeck/src/plaintext.rs — SHA-256 691c1fb4c8702e072b7cc34bfceb6aac2fe380e543ae24dc37d8e812e6a461d1

- inputs/owner/.morse/decoded-body-labels/invitation-authority-historical/evidence.json — SHA-256 dffb8693f9c8f17e5c486eac8e72736ec3ff4c508a29d81ea34dee1494e10f6e
