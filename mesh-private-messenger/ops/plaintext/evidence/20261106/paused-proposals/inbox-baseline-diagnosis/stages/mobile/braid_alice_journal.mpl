##! Inactive account-bound Alice header-only fixture coordinator. No native route,
##! public prepared authority, epoch output, root mixing or capability change.
from Session.BraidResponder import BraidScope, braid_valid_scope
from Session.BraidInitiator import BraidAliceIdle, BraidAliceHeaderSent, send_header
from Session.BraidBilateralStore import (
  BraidBilateralSaved,
  bilateral_saved_shape,
  save_alice_idle,
  restore_alice_idle,
  save_alice_header,
  restore_alice_header
)
from Session.State import RatchetState
from Session.Ratchet import encrypt_sealed
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  encode_packet,
  session_aad
)
from Mobile.Codec import (
  current_time,
  mobile_join,
  mobile_vector,
  mobile_write_u64,
  mobile_wide,
  canonical_outer
)
from Mobile.Sessions import (
  decode_session_ids,
  parse_session_record,
  restore_session,
  seal_updated_session,
  session_uses_headers,
  ratchet_bytes
)
from Mobile.Types import MobileLoadedSession, MobilePreparedSend
from Mobile.Transport import sealed_outer_bytes
from Mobile.Outbox import ids_from_basis, prepare_outbox_writes
from Mobile.BraidJournal import braid_labels, braid_header_carrier
from Mobile.BraidAliceState import (
  AliceHeaderMetadata,
  alice_header_labels,
  alice_captured,
  alice_check,
  alice_metadata_bytes,
  decode_alice_metadata
)
from Storage.Keys import platform_key, seal_local, open_local, local_context
from Storage.AccountGuard import account_basis_current, load_account_basis
from Storage.OutboxGuard import OutboxBasis
from Storage.FanoutCommit import (
  FanoutSnapshot,
  capture_fanout_snapshot,
  combine_fanout_snapshots,
  commit_fanout_records,
  commit_fanout_snapshot
)

pub struct BraidAliceHeaderOutcome do
  # 1 newly prepared;2 exact recovered. No epoch output or private handle.
  kind :: Int
  epoch :: U64
  sending_epoch :: U64
  transition :: Bytes
  envelope_id :: Bytes
  envelope :: Bytes
end

struct AliceHeaderSources do
  before :: FanoutSnapshot
  profile :: ClientProfile
  loaded :: MobileLoadedSession
  outbox :: OutboxBasis
end

fn no_pending_id() -> Bytes!String do
  case Bytes.repeat(0, 16) do
    Ok(v)
    Err(_) -> Err("invalid_c1_alice_journal")
  end
end

fn validate_he(state :: consume RatchetState, session_id :: Bytes) -> Result<(), String> do
  alice_check(state.version == 2
      && state.suite == 2
      && Bytes.secure_equals(state.session_id, session_id),
    "c1_alice_session_changed")
end

fn session_label(scope :: BraidScope) -> String do
  "session/v1/#{Bytes.to_hex(scope.session_id)}"
end

fn current(path :: String, before :: FanoutSnapshot) -> Result<(), String> do
  alice_check(List.all(before.bases, fn(basis) -> account_basis_current(path, basis) end),
    "account_state_changed")
end

fn sources(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  key :: borrow StorageKey) -> AliceHeaderSources!String do
  alice_check(braid_valid_scope(scope, mobile_wide("1")?), "invalid_c1_alice_scope")?
  let custody = load_account_basis(path, [])?
  let first = capture_fanout_snapshot(path,
    custody.profile,
    [
      "sessions/v1",
      session_label(scope),
      "header-routing/v1",
      "outbox/v1",
      "postage-queue/v1",
      "delivery/v1"
    ]
      ++ braid_labels(scope)
      ++ alice_header_labels(scope))?
  let public = open_local(custody.profile, key, local_context("profile/v1")?)?
  alice_check(Bytes.secure_equals(public, expected_profile), "account_state_changed")?
  let profile = decode_client_profile(public)?
  alice_check(Bytes.secure_equals(profile.account_id, scope.account_id)
      && Bytes.secure_equals(profile.device_id, scope.device_id),
    "account_state_changed")?
  let ids = decode_session_ids(open_local(alice_captured(first, "sessions/v1")?,
    key,
    local_context("sessions/v1")?)?)?
  alice_check(List.any(ids, fn(id) -> Bytes.secure_equals(id, scope.session_id) end),
    "unknown_session")?
  let label = session_label(scope)
  let record = parse_session_record(open_local(alice_captured(first, label)?,
    key,
    local_context(label)?)?)?
  alice_check(Bytes.secure_equals(record.local_account_id, scope.account_id)
      && Bytes.secure_equals(record.local_device_id, scope.device_id)
      && Bytes.secure_equals(record.peer_account_id, scope.peer_account_id)
      && Bytes.secure_equals(record.peer_device_id, scope.peer_device_id)
      && !record.blocked
      && record.request_state == 1
      && session_uses_headers(record.snapshot),
    "c1_alice_session_changed")?
  let history = capture_fanout_snapshot(path,
    custody.profile,
    ["history/v1/#{Bytes.to_hex(record.conversation_id)}"])?
  let before = combine_fanout_snapshots(first, history)?
  current(path, before)?
  for old in braid_labels(scope) do
    alice_check(Bytes.length(alice_captured(before, old)?) == 0, "c1_alice_legacy_conflict")?
  end
  let loaded = MobileLoadedSession { session_id: scope.session_id, label: label, record: record }
  validate_he(restore_session(loaded, key)?, scope.session_id)?
  current(path, before)?
  Ok(AliceHeaderSources {
    before: before,
    profile: profile,
    loaded: loaded,
    outbox: OutboxBasis {
      profile: custody.profile,
      index: alice_captured(before, "outbox/v1")?,
      postage: alice_captured(before, "postage-queue/v1")?,
      delivery: alice_captured(before, "delivery/v1")?
    }
  })
end

fn metadata(source :: AliceHeaderSources,
  scope :: BraidScope,
  key :: borrow StorageKey) -> AliceHeaderMetadata!String do
  let labels = alice_header_labels(scope)
  let meta = decode_alice_metadata(open_local(alice_captured(source.before, List.get(labels, 0))?,
      key,
      local_context(List.get(labels, 0))?)?,
    scope)?
  let secrets = alice_captured(source.before, List.get(labels, 1))?
  let epoch_key = alice_captured(source.before, List.get(labels, 2))?
  let pending = alice_captured(source.before, List.get(labels, 3))?
  alice_check(Bytes.secure_equals(Crypto.sha256(secrets), meta.secrets_hash)
      && Bytes.secure_equals(Crypto.sha256(epoch_key), meta.epoch_key_hash)
      && Bytes.secure_equals(Crypto.sha256(pending), meta.pending_hash),
    "invalid_c1_alice_journal")?
  let saved = %{meta.saved | secrets: secrets, epoch_key: epoch_key}
  alice_check(bilateral_saved_shape(saved), "invalid_c1_alice_journal")?
  if saved.substate == 0 do
    alice_check(Bytes.length(pending) == 0
        && Bytes.secure_equals(meta.pending_id, no_pending_id()?)
        && Bytes.secure_equals(meta.envelope_hash, Crypto.sha256(Bytes.empty())),
      "invalid_c1_alice_journal")?
  else
    alice_check(Bytes.length(pending) > 0, "invalid_c1_alice_journal")?
  end
  Ok(%{meta | saved: saved})
end

fn transition(before :: FanoutSnapshot,
  scope :: BraidScope,
  revision :: U64,
  transcript :: Bytes) -> Bytes!String do
  let rows = List.flatten(for basis in before.bases do
    for i in 0..List.length(basis.labels) do
      mobile_join([
          mobile_vector(Bytes.from_utf8(List.get(basis.labels, i)))?,
          Crypto.sha256(List.get(basis.records, i))
        ],
        0,
        Bytes.empty())?
    end
  end)
  Ok(Crypto.sha256(mobile_join([
      Bytes.from_utf8("morse/c1/braid-alice-header-transition/v1"),
      scope.configuration,
      mobile_vector(scope.protocol_info)?,
      scope.account_id,
      scope.device_id,
      scope.peer_account_id,
      scope.peer_device_id,
      scope.session_id,
      mobile_write_u64(revision)?,
      Crypto.sha256(List.head(before.bases).profile)
    ]
      ++ rows
      ++ [transcript],
    0,
    Bytes.empty())?))
end

fn sealed_meta(saved :: BraidBilateralSaved,
  pending :: Bytes,
  id :: Bytes,
  envelope :: Bytes,
  key :: borrow StorageKey) -> Bytes!String do
  seal_local(alice_metadata_bytes(AliceHeaderMetadata {
      saved: saved,
      secrets_hash: Crypto.sha256(saved.secrets),
      epoch_key_hash: Crypto.sha256(saved.epoch_key),
      pending_hash: Crypto.sha256(pending),
      pending_id: id,
      envelope_hash: Crypto.sha256(envelope)
    })?,
    key,
    local_context(List.head(alice_header_labels(saved.scope)))?)
end

## Fixture-only independent initializer, epoch1; absence guards forbid replacement.
pub fn initialize_braid_alice_fixture(path :: String,
  expected_profile :: Bytes,
  state :: consume BraidAliceIdle) -> Result<(), String> do
  alice_check(U64.compare(state.epoch, mobile_wide("1")?) == 0, "invalid_c1_alice_initializer")?
  let key = platform_key()?
  let source = sources(path, expected_profile, state.scope, key)?
  let labels = alice_header_labels(state.scope)
  for label in labels do
    alice_check(Bytes.length(alice_captured(source.before, label)?) == 0,
      "c1_alice_already_initialized")?
  end
  let revision = mobile_wide("1")?
  let saved = case save_alice_idle(state,
    key,
    revision,
    transition(source.before, state.scope, revision, Bytes.empty())?) do
    Ok(v) -> v
    Err(_) -> return Err("c1_alice_storage_failed")
  end
  let meta = sealed_meta(saved, Bytes.empty(), no_pending_id()?, Bytes.empty(), key)?
  commit_fanout_records(path, source.before, List.take(labels, 2), [meta, saved.secrets], [])
end

fn drop_header(state :: consume BraidAliceHeaderSent) do
  nil
end

fn recover_from(path :: String,
  source :: AliceHeaderSources,
  meta :: AliceHeaderMetadata,
  key :: borrow StorageKey) -> BraidAliceHeaderOutcome!String do
  alice_check(meta.saved.substate == 1, "c1_alice_no_pending_header")?
  # Expected identity comes only from the authenticated, captured guarded row.
  let restored = case restore_alice_header(meta.saved, meta.saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("c1_alice_storage_failed")
  end
  let label = List.get(alice_header_labels(meta.saved.scope), 3)
  let envelope = open_local(alice_captured(source.before, label)?, key, local_context(label)?)?
  let outer = canonical_outer(envelope)?
  alice_check(Bytes.secure_equals(outer.envelope_id, meta.pending_id)
      && Bytes.secure_equals(Crypto.sha256(envelope), meta.envelope_hash)
      && Bytes.secure_equals(outer.mailbox_token, source.loaded.record.peer_mailbox),
    "invalid_c1_alice_journal")?
  current(path, source.before)?
  drop_header(restored)
  Ok(BraidAliceHeaderOutcome {
    kind: 2,
    epoch: meta.saved.epoch,
    sending_epoch: meta.saved.output_epoch,
    transition: meta.saved.transition,
    envelope_id: meta.pending_id,
    envelope: envelope
  })
end

pub fn recover_braid_header(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope) -> BraidAliceHeaderOutcome!String do
  let key = platform_key()?
  let source = sources(path, expected_profile, scope, key)?
  recover_from(path, source, metadata(source, scope, key)?, key)
end

pub fn prepare_braid_header_once(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  before_commit :: Fun() -> Result<(), String>) -> BraidAliceHeaderOutcome!String do
  prepare_braid_header_fault(path, expected_profile, scope, before_commit, fn() -> Ok(nil) end)
end

## Hooks carry no data or authority. The after hook models a lost commit reply.
pub fn prepare_braid_header_fault(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  before_commit :: Fun() -> Result<(), String>,
  after_commit :: Fun() -> Result<(), String>) -> BraidAliceHeaderOutcome!String do
  let key = platform_key()?
  let source = sources(path, expected_profile, scope, key)?
  let old = metadata(source, scope, key)?
  if old.saved.substate == 1 do
    return recover_from(path, source, old, key)
  end
  let idle = case restore_alice_idle(old.saved, old.saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("c1_alice_storage_failed")
  end
  let (candidate, complete) = case send_header(idle) do
    Ok(v) -> v
    Err(_) -> return Err("c1_alice_prepare_failed")
  end
  let state = restore_session(source.loaded, key)?
  alice_check(state.version == 2
      && state.suite == 2
      && Bytes.secure_equals(state.session_id, scope.session_id),
    "c1_alice_session_changed")?
  let payload = braid_header_carrier(scope, candidate.epoch, complete)?
  let (next_he, message) = case encrypt_sealed(state, payload, session_aad(scope.session_id)?) do
    Ok(v) -> v
    Err(_) -> return Err("c1_alice_he_encryption_failed")
  end
  let envelope = sealed_outer_bytes(source.loaded.record.peer_mailbox,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    source.loaded.record.peer_transport_key,
    current_time()?)?
  let revision = U64.add(old.saved.revision, mobile_wide("1")?)?
  let id = transition(source.before,
    scope,
    revision,
    Crypto.sha256(mobile_join([
        candidate.header.bytes,
        candidate.vector.bytes,
        Crypto.sha256(envelope)
      ],
      0,
      Bytes.empty())?))?
  let saved = case save_alice_header(candidate, key, revision, id) do
    Ok(v) -> v
    Err(_) -> return Err("c1_alice_storage_failed")
  end
  let session = seal_updated_session(next_he, source.loaded, key)?
  let ids = ids_from_basis(source.outbox, key)?
  let (outbox_labels, outbox_blobs, index) = prepare_outbox_writes(key,
    ids,
    [envelope],
    path,
    Bytes.empty(),
    0,
    0,
    source.profile)?
  alice_check(Bytes.secure_equals(index.before.profile, source.outbox.profile)
      && Bytes.secure_equals(index.before.index, source.outbox.index)
      && Bytes.secure_equals(index.before.postage, source.outbox.postage)
      && Bytes.secure_equals(index.before.delivery, source.outbox.delivery),
    "outbox_state_changed")?
  let extra = capture_fanout_snapshot(path, source.outbox.profile, outbox_labels)?
  for label in outbox_labels do
    alice_check(Bytes.length(alice_captured(extra, label)?) == 0, "c1_alice_outbox_target_exists")?
  end
  let before = combine_fanout_snapshots(source.before, extra)?
  current(path, before)?
  let labels = alice_header_labels(scope)
  let pending = seal_local(envelope, key, local_context(List.get(labels, 3))?)?
  let envelope_id = canonical_outer(envelope)?.envelope_id
  let meta = sealed_meta(saved, pending, envelope_id, envelope, key)?
  let prepared = MobilePreparedSend {
    envelope: envelope,
    session_id: scope.session_id,
    session_label: source.loaded.label,
    session_blob: session,
    new_session: false
  }
  before_commit()?
  commit_fanout_snapshot(path,
    before,
    [prepared],
    [],
    alice_captured(source.before, "sessions/v1")?,
    [],
    [],
    outbox_labels ++ labels,
    outbox_blobs ++ [meta, saved.secrets, saved.epoch_key, pending],
    index)?
  after_commit()?
  Ok(BraidAliceHeaderOutcome {
    kind: 1,
    epoch: saved.epoch,
    sending_epoch: saved.output_epoch,
    transition: saved.transition,
    envelope_id: envelope_id,
    envelope: envelope
  })
end
