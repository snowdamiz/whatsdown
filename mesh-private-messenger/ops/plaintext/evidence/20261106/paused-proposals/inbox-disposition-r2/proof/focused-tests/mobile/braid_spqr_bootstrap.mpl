##! Inactive real handshake-backed durable C1 bootstrap. No application route.
from Session.Handshake import (
  C1Initiated,
  C1Received,
  initiate_braid_spqr_at_minimum_suite,
  receive_initial_braid_spqr_at_minimum_suite
)
from Session.BraidResponder import (
  BraidScope,
  braid_valid_scope
)
from Session.BraidBilateralStore import (
  BraidBilateralSaved,
  save_alice_idle,
  restore_alice_idle
)
from Session.BraidStore import (
  BraidSaved,
  seal_await,
  restore_await
)
from Session.Spqr import (
  SpqrState
)
from Session.SpqrStore import (
  SpqrSaved,
  SpqrStoreIdentity,
  seal_spqr,
  restore_spqr
)
from Identity.Device import (
  DeviceKeys,
  verify_device_credential
)
from Prekeys.Bundle import (
  SignedPrekeySecrets,
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets
)
from Protocol.HandshakeWire import (
  decode_initial_message,
  encode_initial_message
)
from Protocol.IdentityWire import (
  encode_device_credential,
  decode_device_credential
)
from Mobile.Profile import (
  policy
)
from Mobile.BraidSpqrState import (
  BraidSpqrMetadata,
  BraidSpqrPending,
  braid_spqr_labels,
  braid_spqr_metadata_bytes,
  decode_braid_spqr_metadata,
  braid_spqr_descriptor,
  braid_spqr_transition,
  split_braid_spqr_pending,
  join_braid_spqr_pending
)
from Mobile.BraidJournal import (
  braid_labels
)
from Mobile.BraidAliceState import (
  alice_header_labels
)
from Mobile.Prekeys import (
  open_captured_prekey_pools,
  find_prekey,
  remove_prekey,
  remove_prekey_id,
  seal_prekey_pool,
  seal_active_prekey_pool
)
from Mobile.Types import (
  MobileLoadedSession
)
from Mobile.Sessions import (
  decode_session_ids,
  parse_session_record,
  seal_session_ids,
  seal_session,
  restore_session,
  parse_sealed_initial_packet
)
from Mobile.SessionPolicy import (
  NativeSessionPolicy,
  capture_native_session_policy,
  native_session_minimum
)
from Mobile.HeaderCapabilities import (
  require_header_profile,
  require_new_header_capacity
)
from Mobile.Transport import (
  sealed_outer_bytes,
  open_outer_packet
)
from Mobile.Codec import (
  current_time,
  canonical_outer,
  mobile_byte,
  mobile_vector,
  mobile_write_u64
)
from Mobile.Outbox import (
  ids_from_basis,
  prepare_outbox_writes
)
from Transport.Packet import (
  ClientProfile,
  decode_client_profile,
  TransportPacket,
  encode_packet
)
from Storage.Keys import (
  platform_key,
  local_context,
  context,
  open_local,
  seal_local,
  open_signing,
  open_x25519,
  open_mlkem,
  one_time_prekey_label,
  one_time_prekey_context
)
from Storage.AccountGuard import (
  load_account_basis,
  account_basis_current
)
from Storage.FanoutCommit import (
  FanoutSnapshot,
  capture_fanout_snapshot,
  combine_fanout_snapshots,
  commit_fanout_records_at_policy
)
from Storage.OutboxGuard import (
  OutboxBasis
)

pub struct BootstrapResult do
  kind :: Int
  scope :: BraidScope
  revision :: U64
  transition :: Bytes
  envelope_id :: Bytes
  envelope :: Bytes
end

struct BootstrapSources do
  before :: FanoutSnapshot
  profile :: ClientProfile
  ids :: List<Bytes>
  existing :: Bool
  native :: NativeSessionPolicy
  outbox :: OutboxBasis
end

struct BootstrapAttempt do
  direction :: Int
  scope :: BraidScope
  intent :: Bytes
  input_hash :: Bytes
  envelope_hash :: Bytes
  transition :: Bytes
  conversation :: Bytes
end

fn check(value :: Bool, reason :: String) -> Unit!String do
  if value do
    Ok(nil)
  else
    Err(reason)
  end
end

fn number(text :: String) -> U64!String do
  U64.parse(text)
end

fn zero(count :: Int) -> Bytes!String do
  case Bytes.repeat(0, count) do
    Ok(v)
    Err(_) -> Err("invalid_c1_bootstrap")
  end
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 131072) do
    Ok(v)
    Err(_) -> Err("invalid_c1_bootstrap")
  end
end

fn attempt_label(configuration :: Bytes, account :: Bytes, device :: Bytes) -> String do
  "c1/bootstrap/v1/#{Bytes.to_hex(configuration)}/#{Bytes.to_hex(account)}/#{Bytes.to_hex(device)}"
end

fn session_label(scope :: BraidScope) -> String do
  "session/v1/#{Bytes.to_hex(scope.session_id)}"
end

fn scope_for(local :: ClientProfile,
  peer_account :: Bytes,
  peer_device :: Bytes,
  configuration :: Bytes,
  session :: Bytes) -> BraidScope!String do
  let value = BraidScope {
    protocol_info: join([
      Bytes.from_utf8("mesh-msg/braid/v1"),
      mobile_byte(0)?,
      configuration,
      session
    ])?,
    configuration: configuration,
    session_id: session,
    account_id: local.account_id,
    device_id: local.device_id,
    peer_account_id: peer_account,
    peer_device_id: peer_device
  }
  check(braid_valid_scope(value, number("1")?), "invalid_c1_bootstrap_scope")?
  Ok(value)
end

fn captured(before :: FanoutSnapshot, name :: String) -> Bytes!String do
  for basis in before.bases do
    for i in 0..List.length(basis.labels) do
      if List.get(basis.labels, i) == name do
        return Ok(List.get(basis.records, i))
      end
    end
  end
  Err("invalid_c1_bootstrap_sources")
end

fn current(path :: String, before :: FanoutSnapshot) -> Unit!String do
  check(List.all(before.bases, fn(v) -> account_basis_current(path, v) end),
    "account_state_changed")
end

fn extended(path :: String,
  source :: BootstrapSources,
  labels :: List<String>) -> BootstrapSources!String do
  let extra = capture_fanout_snapshot(path, source.outbox.profile, labels)?
  let before = combine_fanout_snapshots(source.before, extra)?
  current(path, before)?
  Ok(%{source | before: before})
end

fn sources(path :: String,
  expected :: Bytes,
  peer_account :: Bytes,
  peer_device :: Bytes,
  configuration :: Bytes,
  conversation :: Bytes,
  key :: borrow StorageKey) -> BootstrapSources!String do
  check(Bytes.length(configuration) == 32
      && Bytes.length(peer_account) == 32
      && Bytes.length(peer_device) == 16
      && (Bytes.length(conversation) == 0 || Bytes.length(conversation) == 16),
    "invalid_c1_bootstrap_request")?
  let custody = load_account_basis(path, [])?
  let before = capture_fanout_snapshot(path,
    custody.profile,
    [
      "sessions/v1",
      "header-routing/v1",
      "device-signing-key/v1",
      "device-identity-key/v1",
      "outbox/v1",
      "postage-queue/v1",
      "delivery/v1",
      attempt_label(configuration, peer_account, peer_device)
    ]
      ++ (if Bytes.length(conversation) == 16 do
        ["history/v1/#{Bytes.to_hex(conversation)}"]
      else
        []
      end))?
  let public = open_local(custody.profile, key, local_context("profile/v1")?)?
  check(Bytes.secure_equals(public, expected), "account_state_changed")?
  let profile = decode_client_profile(public)?
  require_header_profile(profile)?
  check(profile.bundle.suite == 2
      && profile.credential.suite == 2
      && !(Bytes.secure_equals(peer_account, profile.account_id)
        && Bytes.secure_equals(peer_device, profile.device_id)),
    "invalid_c1_bootstrap_profile")?
  let verified = case verify_device_credential(profile.account,
    profile.credential,
    current_time()?,
    profile.account.directory_sequence) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_bootstrap_profile")
  end
  check(verified, "invalid_c1_bootstrap_profile")?
  let index = captured(before, "sessions/v1")?
  let ids = if Bytes.length(index) == 0 do
    []
  else
    decode_session_ids(open_local(index, key, local_context("sessions/v1")?)?)?
  end
  # Preserve the existing bounded capture: no truncation of an inspected index.
  check(List.length(ids) <= 192, "c1_bootstrap_capture_limit")?
  let inspected = if List.length(ids) == 0 do
    before
  else
    combine_fanout_snapshots(before,
      capture_fanout_snapshot(path,
        custody.profile,
        for id in ids do
          "session/v1/#{Bytes.to_hex(id)}"
        end)?)?
  end
  let existing = List.any(for id in ids do
      let name = "session/v1/#{Bytes.to_hex(id)}"
      let record = parse_session_record(open_local(captured(inspected, name)?,
        key,
        local_context(name)?)?)?
      check(Bytes.secure_equals(record.local_account_id, profile.account_id)
          && Bytes.secure_equals(record.local_device_id, profile.device_id),
        "account_state_changed")?
      Bytes.secure_equals(record.peer_account_id, peer_account)
        && Bytes.secure_equals(record.peer_device_id, peer_device)
    end,
    fn(v) -> v end)
  current(path, inspected)?
  let native = capture_native_session_policy()?
  native_session_minimum(native)?
  Ok(BootstrapSources {
    before: inspected,
    profile: profile,
    ids: ids,
    existing: existing,
    native: native,
    outbox: OutboxBasis {
      profile: custody.profile,
      index: captured(before, "outbox/v1")?,
      postage: captured(before, "postage-queue/v1")?,
      delivery: captured(before, "delivery/v1")?
    }
  })
end

fn device(source :: BootstrapSources, key :: borrow StorageKey) -> DeviceKeys!String do
  let p = source.profile
  let signing = open_signing(captured(source.before, "device-signing-key/v1")?,
    key,
    context(p.account_id, p.device_id, "device-signing-key/v1", 7)?)?
  let identity = open_x25519(captured(source.before, "device-identity-key/v1")?,
    key,
    context(p.account_id, p.device_id, "device-identity-key/v1", 8)?)?
  Ok(DeviceKeys {
    device_id: p.device_id,
    signing_private_key: signing,
    signing_public_key: SigningPublicKey { bytes: p.credential.signing_public_key },
    identity_private_key: identity,
    identity_public_key: X25519PublicKey { bytes: p.credential.dh_public_key }
  })
end

fn verify_peer(peer :: ClientProfile) -> Unit!String do
  require_header_profile(peer)?
  check(peer.bundle.suite == 2 && peer.credential.suite == 2, "invalid_c1_bootstrap_peer")?
  let valid = case verify_device_credential(peer.account,
    peer.credential,
    current_time()?,
    peer.account.directory_sequence) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_bootstrap_peer")
  end
  check(valid, "invalid_c1_bootstrap_peer")
end

fn attempt_bytes(value :: BootstrapAttempt) -> Bytes!String do
  join([
    Bytes.from_utf8("CBI1"),
    mobile_byte(1)?,
    mobile_byte(value.direction)?,
    value.scope.configuration,
    value.scope.session_id,
    value.scope.peer_account_id,
    value.scope.peer_device_id,
    value.intent,
    value.input_hash,
    value.envelope_hash,
    value.transition,
    value.conversation
  ])
end

fn read_attempt(source :: BootstrapSources,
  configuration :: Bytes,
  peer_account :: Bytes,
  peer_device :: Bytes,
  key :: borrow StorageKey) -> BootstrapAttempt!String do
  let name = attempt_label(configuration, peer_account, peer_device)
  let bytes = open_local(captured(source.before, name)?, key, local_context(name)?)?
  check(Bytes.length(bytes) == 262
      && Bytes.secure_equals(Bytes.slice(bytes, 0, 4)?, Bytes.from_utf8("CBI1"))
      && Bytes.get(bytes, 4)? == 1
      && Bytes.get(bytes, 5)? <= 1
      && Bytes.secure_equals(Bytes.slice(bytes, 6, 32)?, configuration)
      && Bytes.secure_equals(Bytes.slice(bytes, 70, 32)?, peer_account)
      && Bytes.secure_equals(Bytes.slice(bytes, 102, 16)?, peer_device),
    "invalid_c1_bootstrap_attempt")?
  let value = BootstrapAttempt {
    direction: Bytes.get(bytes, 5)?,
    scope: scope_for(source.profile,
      peer_account,
      peer_device,
      configuration,
      Bytes.slice(bytes, 38, 32)?)?,
    intent: Bytes.slice(bytes, 118, 32)?,
    input_hash: Bytes.slice(bytes, 150, 32)?,
    envelope_hash: Bytes.slice(bytes, 182, 32)?,
    transition: Bytes.slice(bytes, 214, 32)?,
    conversation: Bytes.slice(bytes, 246, 16)?
  }
  check(Bytes.secure_equals(bytes, attempt_bytes(value)?), "invalid_c1_bootstrap_attempt")?
  Ok(value)
end

fn targets(path :: String,
  source :: BootstrapSources,
  scope :: BraidScope,
  absent :: Bool) -> BootstrapSources!String do
  let labels = [session_label(scope)]
    ++ braid_spqr_labels(scope)
    ++ braid_labels(scope)
    ++ alice_header_labels(scope)
  let value = extended(path, source, labels)?
  for name in braid_labels(scope) ++ alice_header_labels(scope) do
    check(Bytes.length(captured(value.before, name)?) == 0, "c1_bootstrap_legacy_conflict")?
  end
  if absent do
    for name in [session_label(scope)] ++ braid_spqr_labels(scope) do
      check(Bytes.length(captured(value.before, name)?) == 0, "c1_bootstrap_target_exists")?
    end
  end
  Ok(value)
end

fn pending_hash(head :: Bytes, tail :: Bytes) -> Bytes!String do
  if Bytes.length(head) == 0 && Bytes.length(tail) == 0 do
    Ok(Crypto.sha256(Bytes.empty()))
  else
    Ok(Crypto.sha256(join([mobile_vector(head)?, mobile_vector(tail)?])?))
  end
end

fn initial_metadata(scope :: BraidScope,
  direction :: Int,
  pq :: borrow SpqrState,
  intent :: Bytes,
  envelope :: Bytes,
  id :: Bytes) -> BraidSpqrMetadata!String do
  let empty = Bytes.empty()
  let outgoing = direction == 0
  Ok(BraidSpqrMetadata {
    scope: scope,
    direction: direction,
    phase: if outgoing do
      0
    else
      4
    end,
    kernel_tag: if outgoing do
      2
    else
      0
    end,
    epoch: number("1")?,
    revision: number("1")?,
    transition: zero(32)?,
    local_epoch: pq.epoch,
    knowledge: pq.knowledge,
    cursors: [0, 0, 0, 0],
    partial_kind: if outgoing do
      0
    else
      1
    end,
    partial_indices: [],
    partial_words: [],
    header: empty,
    vector: empty,
    first: empty,
    second: empty,
    local_receipt: zero(73)?,
    peer_ack: zero(105)?,
    hashes: for i in 0..7 do
      zero(32)?
    end,
    pending_identity: if outgoing do
      join([id, Crypto.sha256(envelope), zero(32)?])?
    else
      zero(80)?
    end,
    slots: pq.slots,
    skipped_index: pq.skipped_index,
    local_attempt: if outgoing do
      join([mobile_byte(1)?, mobile_write_u64(number("0")?)?, intent, Crypto.sha256(envelope)])?
    else
      zero(73)?
    end,
    inbound_result: zero(82)?
  })
end

fn result(m :: BraidSpqrMetadata, kind :: Int, id :: Bytes, envelope :: Bytes) -> BootstrapResult do
  BootstrapResult {
    kind: kind,
    scope: m.scope,
    revision: m.revision,
    transition: m.transition,
    envelope_id: id,
    envelope: envelope
  }
end

fn sealed_metadata(m :: BraidSpqrMetadata,
  auth :: Bytes,
  chains :: Bytes,
  skipped :: Bytes,
  session :: Bytes,
  head :: Bytes,
  tail :: Bytes,
  key :: borrow StorageKey) -> Bytes!String do
  let filled = %{m |
    hashes: [
      Crypto.sha256(auth),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(chains),
      Crypto.sha256(skipped),
      Crypto.sha256(session),
      pending_hash(head, tail)?
    ]
  }
  let name = List.get(braid_spqr_labels(m.scope), 0)
  seal_local(braid_spqr_metadata_bytes(filled)?, key, local_context(name)?)
end

fn initialized(path :: String,
  source :: BootstrapSources,
  attempt :: BootstrapAttempt,
  key :: borrow StorageKey,
  kind :: Int) -> BootstrapResult!String do
  let scope = attempt.scope
  let source = targets(path, source, scope, false)?
  check(List.any(source.ids, fn(id) -> Bytes.secure_equals(id, scope.session_id) end),
    "invalid_c1_bootstrap_index")?
  let ls = braid_spqr_labels(scope)
  let m = decode_braid_spqr_metadata(open_local(captured(source.before, List.get(ls, 0))?,
      key,
      local_context(List.get(ls, 0))?)?,
    scope)?
  check(m.direction == attempt.direction
      && U64.compare(m.revision, number("1")?) == 0
      && U64.compare(m.epoch, number("1")?) == 0
      && U64.compare(m.local_epoch, number("0")?) == 0
      && U64.compare(m.knowledge, number("0")?) == 0
      && Bytes.secure_equals(m.transition, attempt.transition)
      && m.phase == (if attempt.direction == 0 do
          0
        else
          4
        end)
      && List.length(m.partial_indices) == 0,
    "c1_bootstrap_attempt_retired")?
  let auth = captured(source.before, List.get(ls, 1))?
  let epoch_private = captured(source.before, List.get(ls, 2))?
  let continuation = captured(source.before, List.get(ls, 3))?
  let chains = captured(source.before, List.get(ls, 4))?
  let skipped = captured(source.before, List.get(ls, 5))?
  let session = captured(source.before, session_label(scope))?
  let head = captured(source.before, List.get(ls, 6))?
  let tail = captured(source.before, List.get(ls, 7))?
  let expected = [
    Crypto.sha256(auth),
    Crypto.sha256(epoch_private),
    Crypto.sha256(continuation),
    Crypto.sha256(chains),
    Crypto.sha256(skipped),
    Crypto.sha256(session),
    pending_hash(head, tail)?
  ]
  for i in 0..7 do
    check(Bytes.secure_equals(List.get(m.hashes, i), List.get(expected, i)),
      "invalid_c1_bootstrap_component")?
  end
  check(Bytes.length(epoch_private) == 0 && Bytes.length(continuation) == 0,
    "invalid_c1_bootstrap_component")?
  let record = parse_session_record(open_local(session,
    key,
    local_context(session_label(scope))?)?)?
  check(Bytes.secure_equals(record.local_account_id, scope.account_id)
      && Bytes.secure_equals(record.local_device_id, scope.device_id)
      && Bytes.secure_equals(record.peer_account_id, scope.peer_account_id)
      && Bytes.secure_equals(record.peer_device_id, scope.peer_device_id)
      && Bytes.secure_equals(record.conversation_id, attempt.conversation)
      && !record.blocked
      && !record.key_changed,
    "c1_bootstrap_session_changed")?
  let he = restore_session(MobileLoadedSession {
      session_id: scope.session_id,
      label: session_label(scope),
      record: record
    },
    key)?
  check(he.version == 2 && he.suite == 2 && Bytes.secure_equals(he.session_id, scope.session_id),
    "c1_bootstrap_session_changed")?
  let saved = SpqrSaved {
    scope: scope,
    direction: m.direction,
    epoch: m.local_epoch,
    knowledge: m.knowledge,
    slots: m.slots,
    skipped_index: m.skipped_index,
    revision: m.revision,
    transition: m.transition,
    descriptor: braid_spqr_descriptor(m)?,
    chains: chains,
    skipped: skipped
  }
  let _pq = restore_spqr(saved, saved, key)?
  if attempt.direction == 0 do
    let saved = BraidBilateralSaved {
      scope: scope,
      role: 1,
      substate: 0,
      epoch: m.epoch,
      revision: m.revision,
      transition: m.transition,
      output_epoch: number("0")?,
      header: Bytes.empty(),
      vector: Bytes.empty(),
      first: Bytes.empty(),
      wire: Bytes.empty(),
      secrets: auth,
      epoch_key: Bytes.empty(),
      continuation: Bytes.empty()
    }
    let _alice = case restore_alice_idle(saved, saved, key) do
      Ok(v) -> v
      Err(_) -> return Err("c1_bootstrap_kernel_open_failed")
    end
    check(Bytes.length(head) > 0 && Bytes.secure_equals(attempt.input_hash, zero(32)?),
      "invalid_c1_bootstrap_pending")?
    let opened_head = open_local(head, key, local_context(List.get(ls, 6))?)?
    let opened_tail = if Bytes.length(tail) == 0 do
      Bytes.empty()
    else
      open_local(tail, key, local_context(List.get(ls, 7))?)?
    end
    let pending = join_braid_spqr_pending(opened_head, opened_tail)?
    let outer = canonical_outer(pending.envelope)?
    check(Bytes.secure_equals(pending.transition, m.transition)
        && Bytes.secure_equals(pending.envelope_id, outer.envelope_id)
        && Bytes.secure_equals(pending.recipient, record.peer_mailbox)
        && Bytes.secure_equals(outer.mailbox_token, record.peer_mailbox)
        && Bytes.secure_equals(Crypto.sha256(pending.envelope), attempt.envelope_hash)
        && Bytes.secure_equals(m.pending_identity,
          join([outer.envelope_id, attempt.envelope_hash, m.transition])?)
        && Bytes.secure_equals(m.local_attempt,
          join([
            mobile_byte(1)?,
            mobile_write_u64(number("0")?)?,
            attempt.intent,
            attempt.envelope_hash
          ])?),
      "invalid_c1_bootstrap_pending")?
    current(path, source.before)?
    Ok(result(m, kind, outer.envelope_id, pending.envelope))
  else
    let saved = BraidSaved {
      scope: scope,
      epoch: m.epoch,
      revision: m.revision,
      transition: m.transition,
      phase: 0,
      header: Bytes.empty(),
      first: Bytes.empty(),
      secrets: auth,
      continuation: Bytes.empty()
    }
    let _bob = case restore_await(saved, key) do
      Ok(v) -> v
      Err(_) -> return Err("c1_bootstrap_kernel_open_failed")
    end
    check(Bytes.length(head) == 0
        && Bytes.length(tail) == 0
        && Bytes.secure_equals(attempt.intent, zero(32)?)
        && Bytes.secure_equals(attempt.envelope_hash, zero(32)?),
      "invalid_c1_bootstrap_pending")?
    current(path, source.before)?
    Ok(result(m, kind, Bytes.empty(), Bytes.empty()))
  end
end

pub fn recover_braid_spqr_initial(path :: String,
  expected_local :: Bytes,
  peer_account :: Bytes,
  peer_device :: Bytes,
  configuration :: Bytes,
  intent :: Bytes) -> BootstrapResult!String do
  check(Bytes.length(intent) == 32, "invalid_c1_bootstrap_intent")?
  let key = platform_key()?
  let source = sources(path,
    expected_local,
    peer_account,
    peer_device,
    configuration,
    Bytes.empty(),
    key)?
  let attempt = read_attempt(source, configuration, peer_account, peer_device, key)?
  check(attempt.direction == 0 && Bytes.secure_equals(attempt.intent, intent),
    "c1_bootstrap_intent_changed")?
  initialized(path, source, attempt, key, 3)
end

pub fn start_braid_spqr_once(path :: String,
  expected_local :: Bytes,
  expected_peer :: Bytes,
  conversation :: Bytes,
  configuration :: Bytes,
  intent :: Bytes) -> BootstrapResult!String do
  check(Bytes.length(intent) == 32 && Bytes.length(conversation) == 16,
    "invalid_c1_bootstrap_request")?
  let peer = decode_client_profile(expected_peer)?
  verify_peer(peer)?
  let key = platform_key()?
  let source = sources(path,
    expected_local,
    peer.account_id,
    peer.device_id,
    configuration,
    conversation,
    key)?
  let name = attempt_label(configuration, peer.account_id, peer.device_id)
  if Bytes.length(captured(source.before, name)?) != 0 do
    let attempt = read_attempt(source, configuration, peer.account_id, peer.device_id, key)?
    check(attempt.direction == 0
        && Bytes.secure_equals(attempt.intent, intent)
        && Bytes.secure_equals(attempt.conversation, conversation),
      "c1_bootstrap_intent_changed")?
    return initialized(path, source, attempt, key, 3)
  end
  check(!source.existing, "c1_bootstrap_peer_exists")?
  require_new_header_capacity(List.length(source.ids), 1)?
  check(Bytes.length(captured(source.before, "history/v1/#{Bytes.to_hex(conversation)}")?) == 0,
    "c1_bootstrap_conversation_exists")?
  let own = device(source, key)?
  let C1Initiated { he, spqr, braid, initial } = case initiate_braid_spqr_at_minimum_suite(own,
    source.profile.credential,
    peer.account,
    peer.bundle,
    policy(peer, current_time()?),
    0,
    native_session_minimum(source.native)?,
    Bytes.empty(),
    configuration) do
    Ok(v) -> v
    Err(_) -> return Err("c1_bootstrap_handshake_failed")
  end
  let scope = scope_for(source.profile,
    peer.account_id,
    peer.device_id,
    configuration,
    initial.transcript_hash)?
  check(Bytes.secure_equals(he.session_id, scope.session_id)
      && Bytes.secure_equals(spqr.scope.session_id, scope.session_id)
      && Bytes.secure_equals(braid.scope.session_id, scope.session_id),
    "invalid_c1_bootstrap_owner")?
  let message = case encode_initial_message(initial) do
    Ok(v) -> v
    Err(_) -> return Err("c1_bootstrap_initial_encoding_failed")
  end
  let envelope = sealed_outer_bytes(peer.entry.mailbox_token,
    encode_packet(InitialPacket(source.profile.entry.account_identity, message))?,
    peer.credential.dh_public_key,
    current_time()?)?
  let outer = canonical_outer(envelope)?
  let source = targets(path, source, scope, true)?
  let (outbox_labels, outbox_blobs, index) = prepare_outbox_writes(key,
    ids_from_basis(source.outbox, key)?,
    [envelope],
    path,
    Bytes.empty(),
    0,
    0,
    source.profile)?
  check(Bytes.secure_equals(index.before.profile, source.outbox.profile)
      && Bytes.secure_equals(index.before.index, source.outbox.index)
      && Bytes.secure_equals(index.before.postage, source.outbox.postage)
      && Bytes.secure_equals(index.before.delivery, source.outbox.delivery),
    "outbox_state_changed")?
  let source = extended(path, source, outbox_labels)?
  for label in outbox_labels do
    check(Bytes.length(captured(source.before, label)?) == 0, "c1_bootstrap_outbox_target_exists")?
  end
  let m = initial_metadata(scope, 0, spqr, intent, envelope, outer.envelope_id)?
  let transition = braid_spqr_transition(m,
    source.before,
    2,
    Crypto.sha256(join([intent, Crypto.sha256(envelope)])?))?
  let m = %{m |
    transition: transition,
    pending_identity: join([outer.envelope_id, Crypto.sha256(envelope), transition])?
  }
  let kernel = case save_alice_idle(braid, key, m.revision, m.transition) do
    Ok(v) -> v
    Err(_) -> return Err("c1_bootstrap_kernel_seal_failed")
  end
  let pq = seal_spqr(spqr,
    key,
    SpqrStoreIdentity {
      revision: m.revision,
      transition: transition,
      descriptor: braid_spqr_descriptor(m)?
    })?
  let (_id, label, session) = seal_session(he, key, source.profile, peer, conversation, 1, false)?
  check(label == session_label(scope), "invalid_c1_bootstrap_session")?
  let (head, tail) = split_braid_spqr_pending(BraidSpqrPending {
    transition: transition,
    envelope_id: outer.envelope_id,
    recipient: peer.entry.mailbox_token,
    envelope: envelope
  })?
  let ls = braid_spqr_labels(scope)
  let head = seal_local(head, key, local_context(List.get(ls, 6))?)?
  let tail = if Bytes.length(tail) == 0 do
    Bytes.empty()
  else
    seal_local(tail, key, local_context(List.get(ls, 7))?)?
  end
  let metadata = sealed_metadata(m,
    kernel.secrets,
    pq.chains,
    pq.skipped,
    session,
    head,
    tail,
    key)?
  let attempt = BootstrapAttempt {
    direction: 0,
    scope: scope,
    intent: intent,
    input_hash: zero(32)?,
    envelope_hash: Crypto.sha256(envelope),
    transition: transition,
    conversation: conversation
  }
  let attempt_blob = seal_local(attempt_bytes(attempt)?, key, local_context(name)?)?
  let labels = [
    label,
    "sessions/v1",
    List.get(ls, 0),
    List.get(ls, 1),
    List.get(ls, 4),
    List.get(ls, 5),
    List.get(ls, 6),
    name,
    "outbox/v1"
  ]
    ++ outbox_labels
    ++ (if Bytes.length(tail) == 0 do
      []
    else
      [List.get(ls, 7)]
    end)
  let blobs = [
    session,
    seal_session_ids(source.ids ++ [scope.session_id], key)?,
    metadata,
    kernel.secrets,
    pq.chains,
    pq.skipped,
    head,
    attempt_blob,
    index.value
  ]
    ++ outbox_blobs
    ++ (if Bytes.length(tail) == 0 do
      []
    else
      [tail]
    end)
  current(path, source.before)?
  commit_fanout_records_at_policy(path, source.before, source.native, labels, blobs, [])?
  Ok(result(m, 1, outer.envelope_id, envelope))
end

fn captured_secret(source :: BootstrapSources,
  generation :: String,
  fixed :: String) -> (Bytes, String)!String do
  let current = captured(source.before, generation)?
  if Bytes.length(current) > 0 do
    Ok((current, generation))
  else
    let fallback = captured(source.before, fixed)?
    check(Bytes.length(fallback) > 0, "c1_bootstrap_prekey_missing")?
    Ok((fallback, fixed))
  end
end

pub fn receive_braid_spqr_initial(path :: String,
  expected_local :: Bytes,
  expected_peer :: Bytes,
  conversation :: Bytes,
  configuration :: Bytes,
  outer :: Bytes) -> BootstrapResult!String do
  check(Bytes.length(conversation) == 16, "invalid_c1_bootstrap_request")?
  let peer = decode_client_profile(expected_peer)?
  verify_peer(peer)?
  let key = platform_key()?
  let source = sources(path,
    expected_local,
    peer.account_id,
    peer.device_id,
    configuration,
    conversation,
    key)?
  let name = attempt_label(configuration, peer.account_id, peer.device_id)
  let raw_hash = Crypto.sha256(outer)
  if Bytes.length(captured(source.before, name)?) != 0 do
    let attempt = read_attempt(source, configuration, peer.account_id, peer.device_id, key)?
    check(attempt.direction == 1
        && Bytes.secure_equals(attempt.input_hash, raw_hash)
        && Bytes.secure_equals(attempt.conversation, conversation),
      "c1_bootstrap_initial_changed")?
    return initialized(path, source, attempt, key, 4)
  end
  check(!source.existing, "c1_bootstrap_peer_exists")?
  require_new_header_capacity(List.length(source.ids), 1)?
  check(Bytes.length(captured(source.before, "history/v1/#{Bytes.to_hex(conversation)}")?) == 0,
    "c1_bootstrap_conversation_exists")?
  let own = device(source, key)?
  let frame = canonical_outer(outer)?
  check(Bytes.secure_equals(frame.mailbox_token, source.profile.entry.mailbox_token),
    "invalid_c1_bootstrap_recipient")?
  let opened = open_outer_packet(frame, own.identity_private_key)?
  check(opened.sealed, "invalid_c1_bootstrap_recipient")?
  let (account_wire, message) = parse_sealed_initial_packet(opened.packet)?
  check(Bytes.secure_equals(account_wire, peer.entry.account_identity),
    "c1_bootstrap_peer_changed")?
  let initial = case decode_initial_message(message) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_bootstrap_initial")
  end
  let credential = case decode_device_credential(initial.initiator_credential) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_bootstrap_initial")
  end
  let expected_credential = case encode_device_credential(peer.credential) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_bootstrap_peer")
  end
  check(Bytes.secure_equals(initial.initiator_credential, expected_credential)
      && Bytes.secure_equals(credential.account_id, peer.account_id)
      && initial.version == 2
      && initial.suite == 2
      && U64.compare(initial.signed_prekey_id, source.profile.bundle.signed_prekey_id) == 0,
    "c1_bootstrap_peer_or_generation_changed")?
  let generation = U64.to_string(initial.signed_prekey_id)
  let signed_name = "signed-prekey/v1/#{generation}"
  let pq_name = "post-quantum-prekey/v1/#{generation}"
  let otp_name = one_time_prekey_label(initial.one_time_prekey_id)
  let source = extended(path,
    source,
    [
      "one-time-prekeys/v1",
      "one-time-prekey-active/v1",
      "signed-prekey/v1",
      signed_name,
      "post-quantum-prekey/v1",
      pq_name,
      otp_name
    ])?
  let (entries, active) = open_captured_prekey_pools(captured(source.before,
      "one-time-prekeys/v1")?,
    captured(source.before, "one-time-prekey-active/v1")?,
    key)?
  let selected = find_prekey(entries, initial.one_time_prekey_id, 0)?
  check(List.any(active, fn(id) -> U64.compare(id, selected.id) == 0 end),
    "c1_bootstrap_prekey_inactive")?
  let bundle = %{source.profile.bundle |
    one_time_prekey_id: selected.id,
    one_time_prekey: selected.public_key
  }
  let (signed_blob, signed_label) = captured_secret(source, signed_name, "signed-prekey/v1")?
  let signed = SignedPrekeySecrets {
    id: initial.signed_prekey_id,
    private_key: open_x25519(signed_blob,
      key,
      context(source.profile.account_id, source.profile.device_id, signed_label, 9)?)?,
    public_key: X25519PublicKey { bytes: bundle.signed_prekey },
    signature: Signature { bytes: bundle.signed_prekey_signature },
    expires_at: bundle.expires_at
  }
  let (pq_blob, pq_label) = captured_secret(source, pq_name, "post-quantum-prekey/v1")?
  let pq = PostQuantumPrekeySecrets {
    private_key: open_mlkem(pq_blob,
      key,
      context(source.profile.account_id, source.profile.device_id, pq_label, 15)?)?,
    public_key: MlKemPublicKey { bytes: bundle.post_quantum_prekey }
  }
  let otp = OneTimePrekeySecrets {
    id: selected.id,
    private_key: open_x25519(captured(source.before, otp_name)?,
      key,
      one_time_prekey_context(source.profile, selected.id)?)?,
    public_key: X25519PublicKey { bytes: selected.public_key }
  }
  let C1Received {
    he,
    spqr,
    braid,
    plaintext: _clear
  } = case receive_initial_braid_spqr_at_minimum_suite(own,
    source.profile.account,
    bundle,
    signed,
    otp,
    pq,
    peer.account,
    policy(source.profile, current_time()?),
    policy(peer, current_time()?),
    0,
    native_session_minimum(source.native)?,
    message,
    configuration) do
    Ok(v) -> v
    Err(_) -> return Err("c1_bootstrap_handshake_failed")
  end
  # Private initial body is dropped after the actual whole-handshake AEAD.
  let scope = scope_for(source.profile,
    peer.account_id,
    peer.device_id,
    configuration,
    initial.transcript_hash)?
  check(Bytes.secure_equals(he.session_id, scope.session_id)
      && Bytes.secure_equals(spqr.scope.session_id, scope.session_id)
      && Bytes.secure_equals(braid.scope.session_id, scope.session_id),
    "invalid_c1_bootstrap_owner")?
  let source = targets(path, source, scope, true)?
  let m = initial_metadata(scope, 1, spqr, zero(32)?, Bytes.empty(), Bytes.empty())?
  let transition = braid_spqr_transition(m, source.before, 1, raw_hash)?
  let m = %{m | transition: transition}
  let kernel = case seal_await(braid, key, m.revision, transition) do
    Ok(v) -> v
    Err(_) -> return Err("c1_bootstrap_kernel_seal_failed")
  end
  let saved = seal_spqr(spqr,
    key,
    SpqrStoreIdentity {
      revision: m.revision,
      transition: transition,
      descriptor: braid_spqr_descriptor(m)?
    })?
  let (_id, label, session) = seal_session(he, key, source.profile, peer, conversation, 0, false)?
  check(label == session_label(scope), "invalid_c1_bootstrap_session")?
  let metadata = sealed_metadata(m,
    kernel.secrets,
    saved.chains,
    saved.skipped,
    session,
    Bytes.empty(),
    Bytes.empty(),
    key)?
  let attempt = BootstrapAttempt {
    direction: 1,
    scope: scope,
    intent: zero(32)?,
    input_hash: raw_hash,
    envelope_hash: zero(32)?,
    transition: transition,
    conversation: conversation
  }
  let attempt_blob = seal_local(attempt_bytes(attempt)?, key, local_context(name)?)?
  let ls = braid_spqr_labels(scope)
  let labels = [
    label,
    "sessions/v1",
    List.get(ls, 0),
    List.get(ls, 1),
    List.get(ls, 4),
    List.get(ls, 5),
    name,
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1"
  ]
  let blobs = [
    session,
    seal_session_ids(source.ids ++ [scope.session_id], key)?,
    metadata,
    kernel.secrets,
    saved.chains,
    saved.skipped,
    attempt_blob,
    seal_prekey_pool(remove_prekey(entries, selected.id, 0, []), key)?,
    seal_active_prekey_pool(remove_prekey_id(active, selected.id, 0, []), key)?
  ]
  current(path, source.before)?
  commit_fanout_records_at_policy(path, source.before, source.native, labels, blobs, [otp_name])?
  Ok(result(m, 2, Bytes.empty(), Bytes.empty()))
end
