##! Inactive standalone first-output and bootstrap-backed fragment coordinators.
##! Actual output is consumed in the same CAS; no output input, authority receipt or active route.
from Session.BraidResponder import (
  BraidError,
  BraidScope,
  BraidAwaitHeader,
  BraidHeaderReady,
  braid_valid_scope,
  admit_complete_header
)
from Session.BraidStore import BraidSaved, restore_await, restore_header, seal_await, seal_header
from Session.BraidInitiator import BraidAliceIdle, BraidAliceHeaderSent, send_header
from Session.BraidComplete import (
  BraidBobCt1Sent,
  BraidBobEkReceived,
  BraidBobCt2Sent,
  send_ct1,
  receive_vector,
  send_ct2
)
from Session.BraidBilateralStore import (
  BraidBilateralSaved,
  save_bob_first,
  restore_bob_first,
  save_alice_idle,
  restore_alice_idle,
  save_alice_header,
  restore_alice_header,
  save_bob_vector,
  restore_bob_vector,
  save_bob_second,
  restore_bob_second
)
from Session.Spqr import SpqrState, incorporate_spqr_epoch
from Session.SpqrStore import SpqrSaved, SpqrStoreIdentity, seal_spqr, restore_spqr
from Session.BraidFragment import (
  BraidFragment,
  BraidFragmentKind,
  decode_braid_fragment,
  encode_braid_fragment
)
from Session.BraidFragmentWords import emit_braid_fragment, recover_braid_carrier
from Session.State import RatchetState, DecryptOutcome
from Session.Ratchet import decrypt, decode_ratchet_message, encrypt_sealed
from Session.HeaderRatchet import he_encrypt_hybrid, he_decrypt_hybrid
from Session.TripleWire import decode_triple_message, encode_triple_message, encode_triple_header
from Transport.Packet import ClientProfile, decode_client_profile, encode_packet, session_aad
from Mobile.BraidSpqrState import (
  BraidSpqrMetadata,
  BraidSpqrPending,
  braid_spqr_labels,
  braid_spqr_bootstrap_scope,
  braid_spqr_metadata_bytes,
  decode_braid_spqr_metadata,
  braid_spqr_descriptor,
  braid_spqr_transition,
  split_braid_spqr_pending,
  join_braid_spqr_pending
)
from Mobile.BraidJournal import braid_labels
from Mobile.BraidAliceState import alice_header_labels
from Mobile.Codec import (
  canonical_outer,
  current_time,
  mobile_byte,
  mobile_write_u32,
  mobile_write_u64,
  mobile_read_u64,
  mobile_vector
)
from Mobile.Sessions import (
  decode_session_ids,
  parse_session_record,
  restore_session,
  seal_updated_session,
  updated_session_record,
  parse_ratchet_packet,
  ratchet_bytes
)
from Mobile.Types import MobileLoadedSession, MobilePreparedSend
from Mobile.Transport import open_outer_packet, sealed_outer_bytes
from Mobile.Outbox import ids_from_basis, prepare_outbox_writes
from Storage.Keys import platform_key, local_context, context, open_x25519, open_local, seal_local
from Storage.AccountGuard import load_account_basis, account_basis_current
from Storage.OutboxGuard import OutboxBasis
from Storage.FanoutCommit import (
  FanoutSnapshot,
  capture_fanout_snapshot,
  combine_fanout_snapshots,
  commit_fanout_records,
  commit_fanout_snapshot,
  commit_fanout_records_at_policy,
  commit_fanout_snapshot_at_policy
)
from Mobile.SessionPolicy import (
  NativeSessionPolicy,
  capture_native_session_policy,
  native_session_minimum,
  require_current_session_policy
)

pub struct BraidSpqrOutcome do
  kind :: Int
  revision :: U64
  transition :: Bytes
  epoch :: U64
  local_epoch :: U64
  knowledge :: U64
  envelope_id :: Bytes
  envelope :: Bytes
end

struct BraidSpqrSources do
  before :: FanoutSnapshot
  profile :: ClientProfile
  loaded :: MobileLoadedSession
  outbox :: OutboxBasis
end

fn check(value :: Bool, reason :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(reason)
  end
end

fn zero(n :: Int) -> Bytes!String do
  case Bytes.repeat(0, n) do
    Ok(v)
    Err(_) -> Err("invalid_c1_spqr_journal")
  end
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 131072) do
    Ok(v)
    Err(_) -> Err("invalid_c1_spqr_journal")
  end
end

fn one() -> U64!String do
  U64.parse("1")
end

fn same_scope(a :: BraidScope, b :: BraidScope) -> Bool do
  Bytes.secure_equals(a.protocol_info, b.protocol_info)
    && Bytes.secure_equals(a.configuration, b.configuration)
    && Bytes.secure_equals(a.account_id, b.account_id)
    && Bytes.secure_equals(a.device_id, b.device_id)
    && Bytes.secure_equals(a.peer_account_id, b.peer_account_id)
    && Bytes.secure_equals(a.peer_device_id, b.peer_device_id)
    && Bytes.secure_equals(a.session_id, b.session_id)
end

fn label(scope :: BraidScope) -> String do
  "session/v1/#{Bytes.to_hex(scope.session_id)}"
end

fn captured(before :: FanoutSnapshot, name :: String) -> Bytes!String do
  for b in before.bases do
    for i in 0..List.length(b.labels) do
      if List.get(b.labels, i) == name do
        return Ok(List.get(b.records, i))
      end
    end
  end
  Err("invalid_c1_spqr_sources")
end

fn current(path :: String, before :: FanoutSnapshot) -> Result<(), String> do
  check(List.all(before.bases, fn(b) -> account_basis_current(path, b) end),
    "account_state_changed")
end

fn checked_he(state :: consume RatchetState, session :: Bytes) -> RatchetState!String do
  check(state.version == 2 && state.suite == 2 && Bytes.secure_equals(state.session_id, session),
    "c1_spqr_session_changed")?
  Ok(state)
end

fn discard_he(state :: consume RatchetState) do
  nil
end

fn source_basis(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  key :: borrow StorageKey) -> BraidSpqrSources!String do
  check(braid_valid_scope(scope, one()?), "invalid_c1_spqr_scope")?
  let custody = load_account_basis(path, [])?
  let first = capture_fanout_snapshot(path,
    custody.profile,
    [
      "sessions/v1",
      label(scope),
      "header-routing/v1",
      "device-identity-key/v1",
      "outbox/v1",
      "postage-queue/v1",
      "delivery/v1"
    ]
      ++ braid_spqr_labels(scope)
      ++ braid_labels(scope)
      ++ alice_header_labels(scope))?
  let public = open_local(custody.profile, key, local_context("profile/v1")?)?
  check(Bytes.secure_equals(public, expected_profile), "account_state_changed")?
  let profile = decode_client_profile(public)?
  check(Bytes.secure_equals(profile.account_id, scope.account_id)
      && Bytes.secure_equals(profile.device_id, scope.device_id),
    "account_state_changed")?
  let ids = decode_session_ids(open_local(captured(first, "sessions/v1")?,
    key,
    local_context("sessions/v1")?)?)?
  check(List.any(ids, fn(id) -> Bytes.secure_equals(id, scope.session_id) end), "unknown_session")?
  let record = parse_session_record(open_local(captured(first, label(scope))?,
    key,
    local_context(label(scope))?)?)?
  check(Bytes.secure_equals(record.local_account_id, scope.account_id)
      && Bytes.secure_equals(record.local_device_id, scope.device_id)
      && Bytes.secure_equals(record.peer_account_id, scope.peer_account_id)
      && Bytes.secure_equals(record.peer_device_id, scope.peer_device_id)
      && !record.blocked,
    "c1_spqr_session_changed")?
  let history = capture_fanout_snapshot(path,
    custody.profile,
    ["history/v1/#{Bytes.to_hex(record.conversation_id)}"])?
  let before = combine_fanout_snapshots(first, history)?
  current(path, before)?
  for name in braid_labels(scope) ++ alice_header_labels(scope) do
    check(Bytes.length(captured(before, name)?) == 0, "c1_spqr_legacy_conflict")?
  end
  let loaded = MobileLoadedSession {
    session_id: scope.session_id,
    label: label(scope),
    record: record
  }
  discard_he(checked_he(restore_session(loaded, key)?, scope.session_id)?)
  current(path, before)?
  Ok(BraidSpqrSources {
    before: before,
    profile: profile,
    loaded: loaded,
    outbox: OutboxBasis {
      profile: custody.profile,
      index: captured(before, "outbox/v1")?,
      postage: captured(before, "postage-queue/v1")?,
      delivery: captured(before, "delivery/v1")?
    }
  })
end

# All existing entry points retain accepted-only semantics. Only explicit local
# acceptance can inspect a pending request through the private captured basis.
fn sources(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  key :: borrow StorageKey) -> BraidSpqrSources!String do
  let source = source_basis(path, expected_profile, scope, key)?
  check(source.loaded.record.request_state == 1, "c1_spqr_session_changed")?
  Ok(source)
end

fn pending_hash(head :: Bytes, tail :: Bytes) -> Bytes!String do
  if Bytes.length(head) == 0 && Bytes.length(tail) == 0 do
    Ok(Crypto.sha256(Bytes.empty()))
  else
    Ok(Crypto.sha256(join([mobile_vector(head)?, mobile_vector(tail)?])?))
  end
end

fn metadata(source :: BraidSpqrSources,
  scope :: BraidScope,
  key :: borrow StorageKey) -> BraidSpqrMetadata!String do
  let ls = braid_spqr_labels(scope)
  let m = decode_braid_spqr_metadata(open_local(captured(source.before, List.get(ls, 0))?,
      key,
      local_context(List.get(ls, 0))?)?,
    scope)?
  let values = for i in 1..6 do
    captured(source.before, List.get(ls, i))?
  end
  let expected = (for v in values do
    Crypto.sha256(v)
  end)
    ++ [
      Crypto.sha256(captured(source.before, source.loaded.label)?),
      pending_hash(captured(source.before, List.get(ls, 6))?,
        captured(source.before, List.get(ls, 7))?)?
    ]
  for i in 0..7 do
    check(Bytes.secure_equals(List.get(m.hashes, i), List.get(expected, i)),
      "invalid_c1_spqr_component")?
  end
  check(U64.compare(m.epoch, one()?) == 0
      && U64.compare(m.knowledge, U64.parse("0")?) == 0
      && U64.compare(m.local_epoch,
        if m.phase == 6 do
          one()?
        else
          U64.parse("0")?
        end) == 0,
    "invalid_c1_spqr_milestone")?
  check(Bytes.length(List.get(values, 1)) == 0, "invalid_c1_spqr_component")?
  if m.phase == 10 do
    for i in 1..8 do
      check(Bytes.length(captured(source.before, List.get(ls, i))?) == 0,
        "invalid_c1_spqr_component")?
    end
    nil
  else
    check(Bytes.length(List.get(values, 0)) > 0
        && Bytes.length(List.get(values, 3)) > 0
        && Bytes.length(List.get(values, 4)) > 0,
      "invalid_c1_spqr_component")?
    if m.phase == 6 do
      check(Bytes.length(List.get(values, 2)) > 0
          && Bytes.length(captured(source.before, List.get(ls, 6))?) > 0,
        "invalid_c1_spqr_component")?
    else
      check(Bytes.length(List.get(values, 2)) == 0
          && Bytes.length(captured(source.before, List.get(ls, 6))?) == 0
          && Bytes.length(captured(source.before, List.get(ls, 7))?) == 0,
        "invalid_c1_spqr_component")?
    end
  end
  Ok(m)
end

fn bob_saved(source :: BraidSpqrSources, m :: BraidSpqrMetadata) -> BraidBilateralSaved!String do
  let ls = braid_spqr_labels(m.scope)
  Ok(BraidBilateralSaved {
    scope: m.scope,
    role: 2,
    substate: 1,
    epoch: m.epoch,
    revision: m.revision,
    transition: m.transition,
    output_epoch: m.local_epoch,
    header: Bytes.slice(m.header, 0, 64)?,
    vector: Bytes.empty(),
    first: m.first,
    wire: Bytes.empty(),
    secrets: captured(source.before, List.get(ls, 1))?,
    epoch_key: Bytes.empty(),
    continuation: captured(source.before, List.get(ls, 3))?
  })
end

fn header_saved(source :: BraidSpqrSources, m :: BraidSpqrMetadata) -> BraidSaved!String do
  Ok(BraidSaved {
    scope: m.scope,
    epoch: m.epoch,
    revision: m.revision,
    transition: m.transition,
    phase: if m.phase == 4 do
      0
    else
      1
    end,
    header: if m.phase == 4 do
      Bytes.empty()
    else
      Bytes.slice(m.header, 0, 64)?
    end,
    first: Bytes.empty(),
    secrets: captured(source.before, List.get(braid_spqr_labels(m.scope), 1))?,
    continuation: Bytes.empty()
  })
end

fn consumer(source :: BraidSpqrSources,
  m :: BraidSpqrMetadata,
  key :: borrow StorageKey) -> SpqrState!String do
  check(m.phase != 10, "c1_spqr_terminal_generation")?
  # Restore and drop the scoped kernel too, including recovery and raw duplicates.
  if m.phase == 6 do
    let saved = bob_saved(source, m)?
    let bob = case restore_bob_first(saved, saved, key) do
      Ok(v) -> v
      Err(_) -> return Err("c1_spqr_kernel_storage_failed")
    end
    check(!SecretMap.contains(bob.secrets, Bytes.from_utf8("output")), "invalid_c1_spqr_component")?
  else if m.phase == 4 do
    case restore_await(header_saved(source, m)?, key) do
      Ok(_) -> nil
      Err(_) -> return Err("c1_spqr_kernel_storage_failed")
    end
  else
    case restore_header(header_saved(source, m)?, key) do
      Ok(_) -> nil
      Err(_) -> return Err("c1_spqr_kernel_storage_failed")
    end
  end
  let ls = braid_spqr_labels(m.scope)
  let saved = SpqrSaved {
    scope: m.scope,
    direction: m.direction,
    epoch: m.local_epoch,
    knowledge: m.knowledge,
    slots: m.slots,
    skipped_index: m.skipped_index,
    revision: m.revision,
    transition: m.transition,
    descriptor: braid_spqr_descriptor(m)?,
    chains: captured(source.before, List.get(ls, 4))?,
    skipped: captured(source.before, List.get(ls, 5))?
  }
  restore_spqr(saved, saved, key)
end

fn outcome(m :: BraidSpqrMetadata,
  kind :: Int,
  id :: Bytes,
  envelope :: Bytes) -> BraidSpqrOutcome do
  BraidSpqrOutcome {
    kind: kind,
    revision: m.revision,
    transition: m.transition,
    epoch: m.epoch,
    local_epoch: m.local_epoch,
    knowledge: m.knowledge,
    envelope_id: id,
    envelope: envelope
  }
end

fn authenticated(source :: BraidSpqrSources,
  key :: borrow StorageKey,
  wire :: Bytes) -> (RatchetState, Bytes)!String do
  let outer = canonical_outer(wire)?
  check(Bytes.secure_equals(outer.mailbox_token, source.profile.entry.mailbox_token),
    "invalid_c1_spqr_recipient")?
  let identity = open_x25519(captured(source.before, "device-identity-key/v1")?,
    key,
    context(source.profile.account_id, source.profile.device_id, "device-identity-key/v1", 8)?)?
  let packet = open_outer_packet(outer, identity)?
  check(packet.sealed, "invalid_c1_spqr_recipient")?
  let message = case decode_ratchet_message(parse_ratchet_packet(packet.packet)?) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_packet")
  end
  check(message.version == 4, "invalid_c1_spqr_packet")?
  let he = checked_he(restore_session(source.loaded, key)?, source.loaded.session_id)?
  case decrypt(he, message, session_aad(source.loaded.session_id)?) do
    Opened(next, clear) -> Ok((next, clear))
    Rejected(_, _) -> Err("c1_spqr_body_authentication_failed")
  end
end

fn received_candidate(old :: BraidSpqrMetadata,
  hash :: Bytes,
  kind :: Int,
  phase :: Int,
  tag :: Int,
  fragments :: List<BraidFragment>,
  header :: Bytes) -> BraidSpqrMetadata!String do
  Ok(%{old |
    revision: U64.add(old.revision, one()?)?,
    transition: zero(32)?,
    phase: phase,
    kernel_tag: tag,
    partial_kind: if phase == 4 do
      1
    else
      0
    end,
    partial_indices: for f in fragments do
      f.index
    end,
    partial_words: for f in fragments do
      f.word
    end,
    header: header,
    inbound_result: join([
      mobile_byte(1)?,
      hash,
      mobile_write_u64(old.revision)?,
      mobile_byte(kind)?,
      zero(32)?,
      mobile_write_u64(old.epoch)?
    ])?
  })
end

fn received_transition(m :: BraidSpqrMetadata,
  before :: FanoutSnapshot,
  hash :: Bytes) -> BraidSpqrMetadata!String do
  let id = braid_spqr_transition(m, before, 1, hash)?
  Ok(%{m |
    transition: id,
    inbound_result: join([
      Bytes.slice(m.inbound_result, 0, 42)?,
      id,
      Bytes.slice(m.inbound_result, 74, 8)?
    ])?
  })
end

fn commit_received(path :: String,
  source :: BraidSpqrSources,
  m :: BraidSpqrMetadata,
  auth :: Bytes,
  session :: Bytes,
  pq :: borrow SpqrState,
  key :: borrow StorageKey) -> BraidSpqrOutcome!String do
  let saved = seal_spqr(pq,
    key,
    SpqrStoreIdentity {
      revision: m.revision,
      transition: m.transition,
      descriptor: braid_spqr_descriptor(m)?
    })?
  let filled = %{m |
    hashes: [
      Crypto.sha256(auth),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(saved.chains),
      Crypto.sha256(saved.skipped),
      Crypto.sha256(session),
      Crypto.sha256(Bytes.empty())
    ]
  }
  let ls = braid_spqr_labels(m.scope)
  let meta = seal_local(braid_spqr_metadata_bytes(filled)?, key, local_context(List.get(ls, 0))?)?
  commit_fanout_records(path,
    source.before,
    [List.get(ls, 0), List.get(ls, 1), List.get(ls, 4), List.get(ls, 5), source.loaded.label],
    [meta, auth, saved.chains, saved.skipped, session],
    [List.get(ls, 2), List.get(ls, 3), List.get(ls, 6), List.get(ls, 7)])?
  Ok(outcome(filled,
    if m.phase == 4 do
      1
    else
      2
    end,
    Bytes.empty(),
    Bytes.empty()))
end

fn terminal(path :: String,
  source :: BraidSpqrSources,
  old :: BraidSpqrMetadata,
  hash :: Bytes,
  session :: Bytes,
  key :: borrow StorageKey) -> BraidSpqrOutcome!String do
  let m = %{old |
    phase: 10,
    kernel_tag: 0,
    revision: U64.add(old.revision, one()?)?,
    transition: zero(32)?,
    partial_kind: 0,
    partial_indices: [],
    partial_words: [],
    header: Bytes.empty(),
    first: Bytes.empty(),
    slots: [],
    skipped_index: Bytes.empty(),
    inbound_result: zero(82)?,
    hashes: [
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(session),
      Crypto.sha256(Bytes.empty())
    ]
  }
  let next = %{m | transition: braid_spqr_transition(m, source.before, 3, hash)?}
  let ls = braid_spqr_labels(old.scope)
  let sealed = seal_local(braid_spqr_metadata_bytes(next)?, key, local_context(List.get(ls, 0))?)?
  commit_fanout_records(path,
    source.before,
    [List.get(ls, 0), source.loaded.label],
    [sealed, session],
    List.drop(ls, 1))?
  Err("c1_spqr_terminal_generation")
end

pub fn receive_braid_spqr_control(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  outer :: Bytes) -> BraidSpqrOutcome!String do
  check(!braid_spqr_bootstrap_scope(scope), "c1_spqr_profile_mode")?
  let key = platform_key()?
  let source = sources(path, expected_profile, scope, key)?
  let old = metadata(source, scope, key)?
  let pq = consumer(source, old, key)?
  let hash = Crypto.sha256(outer)
  if Bytes.get(old.inbound_result, 0)? == 1
    && Bytes.secure_equals(Bytes.slice(old.inbound_result, 1, 32)?, hash) do
    current(path, source.before)?
    return Ok(BraidSpqrOutcome {
      kind: 5,
      revision: U64.add(mobile_read_u64(Bytes.slice(old.inbound_result, 33, 8)?)?, one()?)?,
      transition: Bytes.slice(old.inbound_result, 42, 32)?,
      epoch: old.epoch,
      local_epoch: U64.parse("0")?,
      knowledge: U64.parse("0")?,
      envelope_id: Bytes.empty(),
      envelope: Bytes.empty()
    })
  end
  check(old.phase == 4, "c1_spqr_header_already_accepted")?
  let (next_he, clear) = authenticated(source, key, outer)?
  let fragment = case decode_braid_fragment(clear, scope.configuration, scope.session_id) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_fragment")
  end
  check(fragment.kind == BraidHeaderFragment && U64.compare(fragment.epoch, old.epoch) == 0,
    "invalid_c1_spqr_fragment")?
  let existing = for i in 0..List.length(old.partial_indices) do
    %{fragment | index: List.get(old.partial_indices, i), word: List.get(old.partial_words, i)}
  end
  for f in existing do
    check(f.index != fragment.index || Bytes.secure_equals(f.word, fragment.word),
      "c1_spqr_fragment_conflict")?
  end
  let distinct = if List.any(existing, fn(f) -> f.index == fragment.index end) do
    existing
  else
    List.append(existing, fragment)
  end
  let ordered = List.sort(distinct, fn(a, b) -> a.index - b.index end)
  let complete = case recover_braid_carrier(BraidHeaderFragment,
    scope.configuration,
    scope.session_id,
    old.epoch,
    ordered) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_fragment")
  end
  let session = seal_updated_session(next_he, source.loaded, key)?
  let owner = case restore_await(header_saved(source, old)?, key) do
    Ok(v) -> v
    Err(_) -> return Err("c1_spqr_kernel_storage_failed")
  end
  case complete do
    None -> do
      let m = received_transition(received_candidate(old, hash, 1, 4, 0, ordered, Bytes.empty())?,
        source.before,
        hash)?
      let saved = case seal_await(owner, key, m.revision, m.transition) do
        Ok(v) -> v
        Err(_) -> return Err("c1_spqr_kernel_storage_failed")
      end
      commit_received(path, source, m, saved.secrets, session, pq, key)
    end
    Some(header) -> case admit_complete_header(owner, old.epoch, header) do
      BraidHeaderAccepted(ready) -> do
        let m = received_transition(received_candidate(old, hash, 2, 5, 1, [], header)?,
          source.before,
          hash)?
        let saved = case seal_header(ready, key, m.revision, m.transition) do
          Ok(v) -> v
          Err(_) -> return Err("c1_spqr_kernel_storage_failed")
        end
        commit_received(path, source, m, saved.secrets, session, pq, key)
      end
      BraidHeaderFatal(BraidAuthenticationRejected) -> terminal(path,
        source,
        old,
        hash,
        session,
        key)
      BraidHeaderFatal(_) -> Err("c1_spqr_kernel_unavailable")
      BraidHeaderIgnored(_, _) -> Err("invalid_c1_spqr_header")
    end
  end
end

fn control(m :: BraidSpqrMetadata) -> Bytes!String do
  let fragment = case emit_braid_fragment(BraidFirstFragment,
    m.scope.configuration,
    m.scope.session_id,
    m.epoch,
    m.first,
    0) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_control")
  end
  case encode_braid_fragment(fragment) do
    Ok(v)
    Err(_) -> Err("invalid_c1_spqr_control")
  end
end

fn recover_from(path :: String,
  source :: BraidSpqrSources,
  m :: BraidSpqrMetadata,
  key :: borrow StorageKey,
  expected_revision :: U64,
  intent :: Bytes) -> BraidSpqrOutcome!String do
  check(m.phase == 6
      && Bytes.length(intent) == 32
      && U64.compare(mobile_read_u64(Bytes.slice(m.local_attempt, 1, 8)?)?, expected_revision) == 0
      && Bytes.secure_equals(Bytes.slice(m.local_attempt, 9, 32)?, intent)
      && Bytes.secure_equals(Bytes.slice(m.local_attempt, 41, 32)?, Crypto.sha256(control(m)?)),
    "c1_spqr_attempt_changed")?
  let ls = braid_spqr_labels(m.scope)
  let head = open_local(captured(source.before, List.get(ls, 6))?,
    key,
    local_context(List.get(ls, 6))?)?
  let tail_blob = captured(source.before, List.get(ls, 7))?
  let tail = if Bytes.length(tail_blob) == 0 do
    Bytes.empty()
  else
    open_local(tail_blob, key, local_context(List.get(ls, 7))?)?
  end
  let pending = join_braid_spqr_pending(head, tail)?
  let outer = canonical_outer(pending.envelope)?
  check(Bytes.secure_equals(pending.transition, m.transition)
      && Bytes.secure_equals(pending.envelope_id, Bytes.slice(m.pending_identity, 0, 16)?)
      && Bytes.secure_equals(pending.transition, Bytes.slice(m.pending_identity, 48, 32)?)
      && Bytes.secure_equals(Crypto.sha256(pending.envelope),
        Bytes.slice(m.pending_identity, 16, 32)?)
      && Bytes.secure_equals(outer.envelope_id, pending.envelope_id)
      && Bytes.secure_equals(outer.mailbox_token, pending.recipient)
      && Bytes.secure_equals(pending.recipient, source.loaded.record.peer_mailbox),
    "invalid_c1_spqr_pending")?
  current(path, source.before)?
  Ok(outcome(m, 4, pending.envelope_id, pending.envelope))
end

pub fn recover_braid_spqr_pending(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  expected_revision :: U64,
  intent :: Bytes) -> BraidSpqrOutcome!String do
  check(!braid_spqr_bootstrap_scope(scope), "c1_spqr_profile_mode")?
  let key = platform_key()?
  let source = sources(path, expected_profile, scope, key)?
  let m = metadata(source, scope, key)?
  let _restored = consumer(source, m, key)?
  recover_from(path, source, m, key, expected_revision, intent)
end

pub fn prepare_braid_spqr_ct1_once(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  expected_revision :: U64,
  intent :: Bytes) -> BraidSpqrOutcome!String do
  check(!braid_spqr_bootstrap_scope(scope), "c1_spqr_profile_mode")?
  let key = platform_key()?
  let source = sources(path, expected_profile, scope, key)?
  let old = metadata(source, scope, key)?
  let pq = consumer(source, old, key)?
  if old.phase == 6 do
    return recover_from(path, source, old, key, expected_revision, intent)
  end
  check(old.phase == 5
      && Bytes.length(intent) == 32
      && U64.compare(old.revision, expected_revision) == 0,
    "c1_spqr_attempt_changed")?
  let header = case restore_header(header_saved(source, old)?, key) do
    Ok(v) -> v
    Err(_) -> return Err("c1_spqr_kernel_storage_failed")
  end
  let (bob, output) = case send_ct1(header) do
    Ok(v) -> v
    Err(_) -> return Err("c1_spqr_kernel_failed")
  end
  check(same_scope(bob.scope, scope)
      && U64.compare(bob.epoch, old.epoch) == 0
      && U64.compare(output.epoch, old.epoch) == 0,
    "invalid_c1_spqr_output")?
  # C1_SPQR_AFTER_ACTUAL_OUTPUT
  let pq = case incorporate_spqr_epoch(pq, output) do
    SpqrEpochAccepted(v) -> v
    SpqrEpochRefused(_, _) -> return Err("c1_spqr_output_refused")
  end
  check(U64.compare(pq.epoch, old.epoch) == 0 && U64.compare(pq.knowledge, U64.parse("0")?) == 0,
    "invalid_c1_spqr_output")?
  # C1_SPQR_AFTER_ACTUAL_ADD
  let candidate = %{old |
    phase: 6,
    kernel_tag: 6,
    revision: U64.add(old.revision, one()?)?,
    transition: zero(32)?,
    local_epoch: pq.epoch,
    knowledge: pq.knowledge,
    slots: pq.slots,
    skipped_index: pq.skipped_index,
    first: bob.first.bytes,
    cursors: [0, 0, 1, 0],
    local_attempt: join([mobile_byte(1)?, mobile_write_u64(expected_revision)?, intent, zero(32)?])?
  }
  let plaintext = control(candidate)?
  let he = checked_he(restore_session(source.loaded, key)?, scope.session_id)?
  let (next_he, message) = case encrypt_sealed(he, plaintext, session_aad(scope.session_id)?) do
    Ok(v) -> v
    Err(_) -> return Err("c1_spqr_he_encryption_failed")
  end
  let envelope = sealed_outer_bytes(source.loaded.record.peer_mailbox,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    source.loaded.record.peer_transport_key,
    current_time()?)?
  let id = canonical_outer(envelope)?.envelope_id
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
  let extra = capture_fanout_snapshot(path, source.outbox.profile, outbox_labels)?
  for name in outbox_labels do
    check(Bytes.length(captured(extra, name)?) == 0, "c1_spqr_outbox_target_exists")?
  end
  let before = combine_fanout_snapshots(source.before, extra)?
  current(path, before)?
  let m = %{candidate |
    pending_identity: join([id, Crypto.sha256(envelope), zero(32)?])?,
    local_attempt: join([
      mobile_byte(1)?,
      mobile_write_u64(expected_revision)?,
      intent,
      Crypto.sha256(plaintext)
    ])?
  }
  let transition = braid_spqr_transition(m,
    before,
    2,
    Crypto.sha256(join([intent, mobile_write_u64(expected_revision)?, Crypto.sha256(plaintext)])?))?
  let m = %{m |
    transition: transition,
    pending_identity: join([id, Crypto.sha256(envelope), transition])?
  }
  let kernel = case save_bob_first(bob, key, m.revision, m.transition) do
    Ok(v) -> v
    Err(_) -> return Err("c1_spqr_kernel_storage_failed")
  end
  # C1_SPQR_AFTER_KERNEL_SEALS
  let saved = seal_spqr(pq,
    key,
    SpqrStoreIdentity {
      revision: m.revision,
      transition: m.transition,
      descriptor: braid_spqr_descriptor(m)?
    })?
  # C1_SPQR_AFTER_MAP_SEALS
  let session = seal_updated_session(next_he, source.loaded, key)?
  let (head, tail) = split_braid_spqr_pending(BraidSpqrPending {
    transition: m.transition,
    envelope_id: id,
    recipient: source.loaded.record.peer_mailbox,
    envelope: envelope
  })?
  let ls = braid_spqr_labels(scope)
  let head_blob = seal_local(head, key, local_context(List.get(ls, 6))?)?
  let tail_blob = if Bytes.length(tail) == 0 do
    Bytes.empty()
  else
    seal_local(tail, key, local_context(List.get(ls, 7))?)?
  end
  # C1_SPQR_AFTER_PENDING_SEALS
  let filled = %{m |
    hashes: [
      Crypto.sha256(kernel.secrets),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(kernel.continuation),
      Crypto.sha256(saved.chains),
      Crypto.sha256(saved.skipped),
      Crypto.sha256(session),
      pending_hash(head_blob, tail_blob)?
    ]
  }
  let meta = seal_local(braid_spqr_metadata_bytes(filled)?, key, local_context(List.get(ls, 0))?)?
  let labels = [
    List.get(ls, 0),
    List.get(ls, 1),
    List.get(ls, 3),
    List.get(ls, 4),
    List.get(ls, 5),
    List.get(ls, 6)
  ]
    ++ (if Bytes.length(tail_blob) == 0 do
      []
    else
      [List.get(ls, 7)]
    end)
  let blobs = [meta, kernel.secrets, kernel.continuation, saved.chains, saved.skipped, head_blob]
    ++ (if Bytes.length(tail_blob) == 0 do
      []
    else
      [tail_blob]
    end)
  let removed = [List.get(ls, 2)]
    ++ (if Bytes.length(tail_blob) == 0 do
      [List.get(ls, 7)]
    else
      []
    end)
  let prepared = MobilePreparedSend {
    envelope: envelope,
    session_id: scope.session_id,
    session_label: source.loaded.label,
    session_blob: session,
    new_session: false
  }
  # C1_SPQR_BEFORE_GUARDED_COMMIT
  commit_fanout_snapshot(path,
    before,
    [prepared],
    removed,
    captured(source.before, "sessions/v1")?,
    [],
    [],
    outbox_labels ++ labels,
    outbox_blobs ++ blobs,
    index)?
  # C1_SPQR_AFTER_GUARDED_COMMIT
  Ok(outcome(filled, 3, id, envelope))
end

## Bootstrap-backed finite continuation. No caller authority or live activation.
pub struct BraidSpqrStepOutcome do
  kind :: Int
  phase :: Int
  current_revision :: U64
  current_transition :: Bytes
  epoch :: U64
  local_epoch :: U64
  knowledge :: U64
  pending_source_revision :: U64
  pending_source_transition :: Bytes
  pending_creation_revision :: U64
  pending_creation_transition :: Bytes
  inbound_revision :: U64
  inbound_transition :: Bytes
  envelope_id :: Bytes
  envelope :: Bytes
end

# All tentative owners are private to this module and originate from captured
# authenticated durable blobs. Public outcomes are never accepted as receipts.
struct B1Sources do
  source :: BraidSpqrSources
  native :: NativeSessionPolicy
end

type B1Kernel do
  B1AliceIdle(owner :: BraidAliceIdle)
  B1AliceHeader(owner :: BraidAliceHeaderSent)
  B1BobAwait(owner :: BraidAwaitHeader)
  B1BobHeader(owner :: BraidHeaderReady)
  B1BobFirst(owner :: BraidBobCt1Sent)
  B1BobVector(owner :: BraidBobEkReceived)
  B1BobSecond(owner :: BraidBobCt2Sent)
end

type B1Admission do
  B1Admitted(kernel :: B1Kernel, metadata :: BraidSpqrMetadata, kind :: Int)
  B1FatalHeader
end

fn b1_attempt_label(scope :: BraidScope) -> String do
  "c1/bootstrap/v1/#{Bytes.to_hex(scope.configuration)}/#{Bytes.to_hex(scope.peer_account_id)}/#{Bytes.to_hex(scope.peer_device_id)}"
end

fn b1_source_basis(path :: String,
  expected :: Bytes,
  scope :: BraidScope,
  key :: borrow StorageKey) -> B1Sources!String do
  check(braid_spqr_bootstrap_scope(scope), "c1_spqr_profile_mode")?
  let native = capture_native_session_policy()?
  native_session_minimum(native)?
  let original = source_basis(path, expected, scope, key)?
  check(!original.loaded.record.key_changed && original.loaded.record.strongest_suite == 2,
    "c1_spqr_session_changed")?
  let name = b1_attempt_label(scope)
  let extra = capture_fanout_snapshot(path, original.outbox.profile, [name])?
  let before = combine_fanout_snapshots(original.before, extra)?
  let source = %{original | before: before}
  let bytes = open_local(captured(before, name)?, key, local_context(name)?)?
  check(Bytes.length(bytes) == 262
      && Bytes.secure_equals(Bytes.slice(bytes, 0, 4)?, Bytes.from_utf8("CBI1"))
      && Bytes.get(bytes, 4)? == 1
      && Bytes.get(bytes, 5)? <= 1
      && Bytes.secure_equals(Bytes.slice(bytes, 6, 32)?, scope.configuration)
      && Bytes.secure_equals(Bytes.slice(bytes, 38, 32)?, scope.session_id)
      && Bytes.secure_equals(Bytes.slice(bytes, 70, 32)?, scope.peer_account_id)
      && Bytes.secure_equals(Bytes.slice(bytes, 102, 16)?, scope.peer_device_id)
      && Bytes.secure_equals(Bytes.slice(bytes, 246, 16)?, source.loaded.record.conversation_id),
    "invalid_c1_bootstrap_attempt")?
  current(path, before)?
  require_current_session_policy(native)?
  Ok(B1Sources { source: source, native: native })
end

fn b1_sources(path :: String,
  expected :: Bytes,
  scope :: BraidScope,
  key :: borrow StorageKey) -> B1Sources!String do
  let source = b1_source_basis(path, expected, scope, key)?
  check(source.source.loaded.record.request_state == 1, "c1_spqr_session_changed")?
  Ok(source)
end

fn b1_metadata(source :: B1Sources,
  scope :: BraidScope,
  key :: borrow StorageKey) -> BraidSpqrMetadata!String do
  let ls = braid_spqr_labels(scope)
  let m = decode_braid_spqr_metadata(open_local(captured(source.source.before, List.get(ls, 0))?,
      key,
      local_context(List.get(ls, 0))?)?,
    scope)?
  let attempt = open_local(captured(source.source.before, b1_attempt_label(scope))?,
    key,
    local_context(b1_attempt_label(scope))?)?
  check(m.direction == Bytes.get(attempt, 5)?, "invalid_c1_bootstrap_attempt")?
  if Bytes.length(m.local_attempt) == 73 do
    check(U64.compare(m.revision, one()?) == 0
        && U64.compare(m.local_epoch, U64.parse("0")?) == 0
        && U64.compare(m.knowledge, U64.parse("0")?) == 0
        && Bytes.secure_equals(m.transition, Bytes.slice(attempt, 214, 32)?)
        && List.length(m.partial_indices) == 0
        && Bytes.length(m.header) == 0
        && ((m.direction == 0 && m.phase == 0 && m.kernel_tag == 2)
          || (m.direction == 1 && m.phase == 4 && m.kernel_tag == 0))
        && List.length(m.slots) == 1
        && U64.compare(List.head(m.slots).send_count, U64.parse("0")?) == 0
        && U64.compare(List.head(m.slots).receive_count, U64.parse("0")?) == 0,
      "c1_spqr_bootstrap_attempt_retired")?
  end
  let values = for i in 1..6 do
    captured(source.source.before, List.get(ls, i))?
  end
  let expected = (for v in values do
    Crypto.sha256(v)
  end)
    ++ [
      Crypto.sha256(captured(source.source.before, source.source.loaded.label)?),
      pending_hash(captured(source.source.before, List.get(ls, 6))?,
        captured(source.source.before, List.get(ls, 7))?)?
    ]
  for i in 0..7 do
    check(Bytes.secure_equals(List.get(m.hashes, i), List.get(expected, i)),
      "invalid_c1_spqr_component")?
  end
  if m.phase == 10 do
    for i in 1..8 do
      check(Bytes.length(captured(source.source.before, List.get(ls, i))?) == 0,
        "invalid_c1_spqr_component")?
    end
    nil
  else
    check(Bytes.length(List.get(values, 0)) > 0
        && Bytes.length(List.get(values, 3)) > 0
        && Bytes.length(List.get(values, 4)) > 0,
      "invalid_c1_spqr_component")?
    check((Bytes.length(List.get(values, 1)) > 0) == (m.kernel_tag == 3)
        && (Bytes.length(List.get(values, 2)) > 0) == (m.phase >= 6 && m.phase <= 8)
        && (Bytes.length(captured(source.source.before, List.get(ls, 6))?) > 0) == (m.direction == 0
            || m.phase >= 6),
      "invalid_c1_spqr_component")?
    if m.direction == 1 && m.phase < 6 do
      check(Bytes.length(captured(source.source.before, List.get(ls, 7))?) == 0,
        "invalid_c1_spqr_component")?
    end
  end
  Ok(m)
end

fn b1_bilateral(source :: B1Sources, m :: BraidSpqrMetadata) -> BraidBilateralSaved!String do
  let ls = braid_spqr_labels(m.scope)
  let substate = if m.direction == 0 do
    if m.kernel_tag == 2 do
      0
    else
      1
    end
  else if m.kernel_tag == 6 do
    1
  else if m.kernel_tag == 7 do
    2
  else
    3
  end
  Ok(BraidBilateralSaved {
    scope: m.scope,
    role: if m.direction == 0 do
      1
    else
      2
    end,
    substate: substate,
    epoch: m.epoch,
    revision: m.revision,
    transition: m.transition,
    output_epoch: m.local_epoch,
    header: if Bytes.length(m.header) == 0 do
      Bytes.empty()
    else
      Bytes.slice(m.header, 0, 64)?
    end,
    vector: m.vector,
    first: m.first,
    wire: m.second,
    secrets: captured(source.source.before, List.get(ls, 1))?,
    epoch_key: captured(source.source.before, List.get(ls, 2))?,
    continuation: captured(source.source.before, List.get(ls, 3))?
  })
end

fn b1_kernel(source :: B1Sources,
  m :: BraidSpqrMetadata,
  key :: borrow StorageKey) -> B1Kernel!String do
  check(m.phase != 10, "c1_spqr_terminal_generation")?
  if m.direction == 0 do
    let saved = b1_bilateral(source, m)?
    if m.kernel_tag == 2 do
      case restore_alice_idle(saved, saved, key) do
        Ok(v) -> Ok(B1AliceIdle(v))
        Err(_) -> Err("c1_spqr_kernel_storage_failed")
      end
    else
      case restore_alice_header(saved, saved, key) do
        Ok(v) -> Ok(B1AliceHeader(v))
        Err(_) -> Err("c1_spqr_kernel_storage_failed")
      end
    end
  else if m.phase == 4 do
    case restore_await(header_saved(source.source, m)?, key) do
      Ok(v) -> Ok(B1BobAwait(v))
      Err(_) -> Err("c1_spqr_kernel_storage_failed")
    end
  else if m.phase == 5 do
    case restore_header(header_saved(source.source, m)?, key) do
      Ok(v) -> Ok(B1BobHeader(v))
      Err(_) -> Err("c1_spqr_kernel_storage_failed")
    end
  else
    let saved = b1_bilateral(source, m)?
    if m.phase == 6 || m.phase == 7 do
      case restore_bob_first(saved, saved, key) do
        Ok(v) -> do
          check(!SecretMap.contains(v.secrets, Bytes.from_utf8("output")),
            "invalid_c1_spqr_component")?
          Ok(B1BobFirst(v))
        end
        Err(_) -> Err("c1_spqr_kernel_storage_failed")
      end
    else if m.phase == 8 do
      case restore_bob_vector(saved, saved, key) do
        Ok(v) -> Ok(B1BobVector(v))
        Err(_) -> Err("c1_spqr_kernel_storage_failed")
      end
    else
      case restore_bob_second(saved, saved, key) do
        Ok(v) -> Ok(B1BobSecond(v))
        Err(_) -> Err("c1_spqr_kernel_storage_failed")
      end
    end
  end
end

fn b1_consumer(source :: B1Sources,
  m :: BraidSpqrMetadata,
  key :: borrow StorageKey) -> SpqrState!String do
  let _validated = b1_kernel(source, m, key)?
  let ls = braid_spqr_labels(m.scope)
  let saved = SpqrSaved {
    scope: m.scope,
    direction: m.direction,
    epoch: m.local_epoch,
    knowledge: m.knowledge,
    slots: m.slots,
    skipped_index: m.skipped_index,
    revision: m.revision,
    transition: m.transition,
    descriptor: braid_spqr_descriptor(m)?,
    chains: captured(source.source.before, List.get(ls, 4))?,
    skipped: captured(source.source.before, List.get(ls, 5))?
  }
  restore_spqr(saved, saved, key)
end

fn b1_bilateral_seal(result :: BraidBilateralSaved!BraidError) -> (Bytes, Bytes, Bytes)!String do
  case result do
    Ok(v) -> Ok((v.secrets, v.epoch_key, v.continuation))
    Err(_) -> Err("c1_spqr_kernel_storage_failed")
  end
end

fn b1_header_seal(result :: BraidSaved!BraidError) -> (Bytes, Bytes, Bytes)!String do
  case result do
    Ok(v) -> Ok((v.secrets, Bytes.empty(), Bytes.empty()))
    Err(_) -> Err("c1_spqr_kernel_storage_failed")
  end
end

fn b1_seal_kernel(kernel :: consume B1Kernel,
  m :: BraidSpqrMetadata,
  key :: borrow StorageKey) -> (Bytes, Bytes, Bytes)!String do
  case kernel do
    B1AliceIdle(v) -> b1_bilateral_seal(save_alice_idle(v, key, m.revision, m.transition))
    B1AliceHeader(v) -> b1_bilateral_seal(save_alice_header(v, key, m.revision, m.transition))
    B1BobAwait(v) -> b1_header_seal(seal_await(v, key, m.revision, m.transition))
    B1BobHeader(v) -> b1_header_seal(seal_header(v, key, m.revision, m.transition))
    B1BobFirst(v) -> b1_bilateral_seal(save_bob_first(v, key, m.revision, m.transition))
    B1BobVector(v) -> b1_bilateral_seal(save_bob_vector(v, key, m.revision, m.transition))
    B1BobSecond(v) -> b1_bilateral_seal(save_bob_second(v, key, m.revision, m.transition))
  end
end

fn b1_outcome(m :: BraidSpqrMetadata,
  kind :: Int,
  id :: Bytes,
  envelope :: Bytes) -> BraidSpqrStepOutcome!String do
  let has_pending = Bytes.length(m.local_attempt) == 105 && Bytes.get(m.local_attempt, 0)? == 1
  let source = if has_pending do
    mobile_read_u64(Bytes.slice(m.local_attempt, 1, 8)?)?
  else
    U64.parse("0")?
  end
  let inbound = Bytes.get(m.inbound_result, 0)? == 1
  Ok(BraidSpqrStepOutcome {
    kind: kind,
    phase: m.phase,
    current_revision: m.revision,
    current_transition: m.transition,
    epoch: m.epoch,
    local_epoch: m.local_epoch,
    knowledge: m.knowledge,
    pending_source_revision: source,
    pending_source_transition: if has_pending do
      Bytes.slice(m.local_attempt, 9, 32)?
    else
      zero(32)?
    end,
    pending_creation_revision: if has_pending do
      U64.add(source, one()?)?
    else
      U64.parse("0")?
    end,
    pending_creation_transition: if has_pending do
      Bytes.slice(m.pending_identity, 48, 32)?
    else
      zero(32)?
    end,
    inbound_revision: if inbound do
      U64.add(mobile_read_u64(Bytes.slice(m.inbound_result, 33, 8)?)?, one()?)?
    else
      U64.parse("0")?
    end,
    inbound_transition: if inbound do
      Bytes.slice(m.inbound_result, 42, 32)?
    else
      zero(32)?
    end,
    envelope_id: id,
    envelope: envelope
  })
end

fn b1_fragment(m :: BraidSpqrMetadata,
  kind :: BraidFragmentKind,
  carrier :: Bytes,
  index :: Int) -> BraidFragment!String do
  check(index >= 0 && index < 65536, "c1_spqr_fragment_exhausted")?
  case emit_braid_fragment(kind,
    m.scope.configuration,
    m.scope.session_id,
    m.epoch,
    carrier,
    index) do
    Ok(v)
    Err(_) -> Err("invalid_c1_spqr_fragment")
  end
end

fn b1_fragment_bytes(fragment :: BraidFragment) -> Bytes!String do
  case encode_braid_fragment(fragment) do
    Ok(v)
    Err(_) -> Err("invalid_c1_spqr_fragment")
  end
end

fn b1_pending_fragment(m :: BraidSpqrMetadata) -> BraidFragment!String do
  if m.direction == 0 do
    b1_fragment(m, BraidHeaderFragment, m.header, List.get(m.cursors, 0) - 1)
  else if List.get(m.cursors, 3) > 0 do
    b1_fragment(m, BraidSecondFragment, m.second, List.get(m.cursors, 3) - 1)
  else
    b1_fragment(m, BraidFirstFragment, m.first, List.get(m.cursors, 2) - 1)
  end
end

fn b1_stored_pending(source :: B1Sources,
  m :: BraidSpqrMetadata,
  key :: borrow StorageKey) -> BraidSpqrPending!String do
  let ls = braid_spqr_labels(m.scope)
  let head = open_local(captured(source.source.before, List.get(ls, 6))?,
    key,
    local_context(List.get(ls, 6))?)?
  let tail_blob = captured(source.source.before, List.get(ls, 7))?
  let tail = if Bytes.length(tail_blob) == 0 do
    Bytes.empty()
  else
    open_local(tail_blob, key, local_context(List.get(ls, 7))?)?
  end
  let pending = join_braid_spqr_pending(head, tail)?
  let outer = canonical_outer(pending.envelope)?
  check(Bytes.secure_equals(pending.transition, Bytes.slice(m.pending_identity, 48, 32)?)
      && Bytes.secure_equals(pending.envelope_id, Bytes.slice(m.pending_identity, 0, 16)?)
      && Bytes.secure_equals(Crypto.sha256(pending.envelope),
        Bytes.slice(m.pending_identity, 16, 32)?)
      && Bytes.secure_equals(outer.envelope_id, pending.envelope_id)
      && Bytes.secure_equals(outer.mailbox_token, pending.recipient)
      && Bytes.secure_equals(pending.recipient, source.source.loaded.record.peer_mailbox),
    "invalid_c1_spqr_pending")?
  Ok(pending)
end

# Bind the current pending envelope's actual queue rows, including absence after
# independent settlement. Recovery never recreates an acknowledged outbox row.
fn b1_pending_sources(path :: String,
  source :: B1Sources,
  m :: BraidSpqrMetadata,
  key :: borrow StorageKey) -> B1Sources!String do
  if Bytes.secure_equals(m.pending_identity, zero(80)?) do
    return Ok(source)
  end
  let pending = b1_stored_pending(source, m, key)?
  let id = pending.envelope_id
  let head_label = "outbox-envelope/v1/#{Bytes.to_hex(id)}"
  let tail_label = "outbox-envelope-tail/v1/#{Bytes.to_hex(id)}"
  let extra = capture_fanout_snapshot(path, source.source.outbox.profile, [head_label, tail_label])?
  let before = combine_fanout_snapshots(source.source.before, extra)?
  let queued = List.any(ids_from_basis(source.source.outbox, key)?,
    fn(value) -> Bytes.secure_equals(value, id) end)
  if queued do
    let n = Bytes.length(pending.envelope)
    let count = if n > 65532 do
      65532
    else
      n
    end
    let expected = join([mobile_write_u32(n)?, Bytes.slice(pending.envelope, 0, count)?])?
    check(Bytes.secure_equals(open_local(captured(before, head_label)?,
          key,
          local_context(head_label)?)?,
        expected),
      "invalid_c1_spqr_outbox")?
    if count == n do
      check(Bytes.length(captured(before, tail_label)?) == 0, "invalid_c1_spqr_outbox")?
    else
      check(Bytes.secure_equals(open_local(captured(before, tail_label)?,
            key,
            local_context(tail_label)?)?,
          Bytes.slice(pending.envelope, count, n - count)?),
        "invalid_c1_spqr_outbox")?
    end
  else
    check(Bytes.length(captured(before, head_label)?) == 0
        && Bytes.length(captured(before, tail_label)?) == 0,
      "invalid_c1_spqr_outbox")?
  end
  current(path, before)?
  Ok(%{source | source: %{source.source | before: before}})
end

fn b1_recover(path :: String,
  source :: B1Sources,
  m :: BraidSpqrMetadata,
  key :: borrow StorageKey,
  revision :: U64,
  transition :: Bytes,
  intent :: Bytes) -> BraidSpqrStepOutcome!String do
  check(Bytes.length(m.local_attempt) == 105
      && Bytes.get(m.local_attempt, 0)? == 1
      && Bytes.length(transition) == 32
      && Bytes.length(intent) == 32
      && U64.compare(mobile_read_u64(Bytes.slice(m.local_attempt, 1, 8)?)?, revision) == 0
      && Bytes.secure_equals(Bytes.slice(m.local_attempt, 9, 32)?, transition)
      && Bytes.secure_equals(Bytes.slice(m.local_attempt, 41, 32)?, intent)
      && Bytes.secure_equals(Bytes.slice(m.local_attempt, 73, 32)?,
        Crypto.sha256(b1_fragment_bytes(b1_pending_fragment(m)?)?)),
    "c1_spqr_attempt_changed")?
  let pending = b1_stored_pending(source, m, key)?
  current(path, source.source.before)?
  require_current_session_policy(source.native)?
  b1_outcome(m, 2, pending.envelope_id, pending.envelope)
end

fn b1_authenticated(source :: B1Sources,
  key :: borrow StorageKey,
  wire :: Bytes,
  pq :: consume SpqrState) -> (RatchetState, SpqrState, BraidFragment, Bytes)!String do
  let outer = canonical_outer(wire)?
  check(Bytes.secure_equals(outer.mailbox_token, source.source.profile.entry.mailbox_token),
    "invalid_c1_spqr_recipient")?
  let identity = open_x25519(captured(source.source.before, "device-identity-key/v1")?,
    key,
    context(source.source.profile.account_id,
      source.source.profile.device_id,
      "device-identity-key/v1",
      8)?)?
  let packet = open_outer_packet(outer, identity)?
  check(packet.sealed, "invalid_c1_spqr_recipient")?
  let message = case decode_triple_message(parse_ratchet_packet(packet.packet)?) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_packet")
  end
  let he = checked_he(restore_session(source.source.loaded, key)?, source.source.loaded.session_id)?
  case he_decrypt_hybrid(he, pq, message, session_aad(source.source.loaded.session_id)?) do
    HybridOpened(next_he, next_pq, header, _clear) -> do
      let encoded = case encode_triple_header(header) do
        Ok(v) -> v
        Err(_) -> return Err("invalid_c1_spqr_packet")
      end
      Ok((next_he, next_pq, header.fragment, Crypto.sha256(encoded)))
    end
    HybridOpenRefused(_, _, _) -> Err("c1_spqr_body_authentication_failed")
  end
end

fn b1_next(old :: BraidSpqrMetadata, pq :: borrow SpqrState) -> BraidSpqrMetadata!String do
  check(same_scope(pq.scope, old.scope)
      && pq.direction == old.direction
      && U64.compare(pq.knowledge, U64.parse("0")?) == 0,
    "invalid_c1_spqr_output")?
  Ok(%{old |
    revision: U64.add(old.revision, one()?)?,
    transition: zero(32)?,
    local_epoch: pq.epoch,
    knowledge: pq.knowledge,
    slots: pq.slots,
    skipped_index: pq.skipped_index,
    local_attempt: if Bytes.length(old.local_attempt) == 73 do
      zero(105)?
    else
      old.local_attempt
    end
  })
end

fn b1_received(m :: BraidSpqrMetadata,
  old :: BraidSpqrMetadata,
  kind :: Int,
  hash :: Bytes,
  before :: FanoutSnapshot) -> BraidSpqrMetadata!String do
  let candidate = %{m |
    inbound_result: join([
      mobile_byte(1)?,
      hash,
      mobile_write_u64(old.revision)?,
      mobile_byte(kind)?,
      zero(32)?,
      mobile_write_u64(old.epoch)?
    ])?
  }
  received_transition(candidate, before, hash)
end

fn b1_records(source :: B1Sources,
  m :: BraidSpqrMetadata,
  kernel :: consume B1Kernel,
  pq :: borrow SpqrState,
  session :: Bytes,
  head :: Bytes,
  tail :: Bytes,
  key :: borrow StorageKey) -> (BraidSpqrMetadata, List<String>, List<Bytes>, List<String>)!String do
  let (auth, epoch_private, continuation) = b1_seal_kernel(kernel, m, key)?
  let saved = seal_spqr(pq,
    key,
    SpqrStoreIdentity {
      revision: m.revision,
      transition: m.transition,
      descriptor: braid_spqr_descriptor(m)?
    })?
  let components = [auth, epoch_private, continuation, saved.chains, saved.skipped]
  let filled = %{m |
    hashes: (for v in components do
      Crypto.sha256(v)
    end)
      ++ [Crypto.sha256(session), pending_hash(head, tail)?]
  }
  let ls = braid_spqr_labels(m.scope)
  let meta = seal_local(braid_spqr_metadata_bytes(filled)?, key, local_context(List.get(ls, 0))?)?
  let labels = [List.get(ls, 0)]
    ++ List.flatten(for i in 0..5 do
      if Bytes.length(List.get(components, i)) == 0 do
        []
      else
        [List.get(ls, i + 1)]
      end
    end)
  let blobs = [meta]
    ++ List.flatten(for v in components do
      if Bytes.length(v) == 0 do
        []
      else
        [v]
      end
    end)
  let removed = List.flatten(for i in 0..5 do
    if Bytes.length(List.get(components, i)) == 0 do
      [List.get(ls, i + 1)]
    else
      []
    end
  end)
  Ok((filled, labels, blobs, removed))
end

fn b1_cursored(kernel :: consume B1Kernel,
  pq :: consume SpqrState,
  m :: BraidSpqrMetadata,
  kind :: BraidFragmentKind,
  carrier :: Bytes,
  slot :: Int) -> (B1Kernel, SpqrState, BraidSpqrMetadata, BraidFragment)!String do
  let index = List.get(m.cursors, slot)
  let fragment = b1_fragment(m, kind, carrier, index)?
  let next = %{m |
    cursors: for i in 0..4 do
      if i == slot do
        index + 1
      else
        List.get(m.cursors, i)
      end
    end
  }
  Ok((kernel, pq, next, fragment))
end

fn b1_prepare_action(kernel :: consume B1Kernel,
  pq :: consume SpqrState,
  old :: BraidSpqrMetadata) -> (B1Kernel, SpqrState, BraidSpqrMetadata, BraidFragment)!String do
  case kernel do
    B1AliceIdle(owner) -> do
      check(old.direction == 0 && old.phase == 0 && List.get(old.cursors, 0) == 0,
        "invalid_c1_spqr_phase")?
      let (next, header) = case send_header(owner) do
        Ok(v) -> v
        Err(_) -> return Err("c1_spqr_kernel_failed")
      end
      let m = %{old |
        kernel_tag: 3,
        header: header,
        vector: next.vector.bytes,
        cursors: [1, 0, 0, 0]
      }
      let fragment = b1_fragment(m, BraidHeaderFragment, header, 0)?
      Ok((B1AliceHeader(next), pq, m, fragment))
    end
    B1AliceHeader(owner) -> b1_cursored(B1AliceHeader(owner),
      pq,
      old,
      BraidHeaderFragment,
      old.header,
      0)
    B1BobHeader(owner) -> do
      check(old.phase == 5, "invalid_c1_spqr_phase")?
      let (bob, output) = case send_ct1(owner) do
        Ok(v) -> v
        Err(_) -> return Err("c1_spqr_kernel_failed")
      end
      check(same_scope(bob.scope, old.scope) && U64.compare(output.epoch, old.epoch) == 0,
        "invalid_c1_spqr_output")?
      let first = bob.first.bytes
      let pq = case incorporate_spqr_epoch(pq, output) do
        SpqrEpochAccepted(v) -> v
        SpqrEpochRefused(_, _) -> return Err("c1_spqr_output_refused")
      end
      let m = %{old | phase: 6, kernel_tag: 6, first: first, partial_kind: 2, cursors: [0, 0, 1, 0]}
      let fragment = b1_fragment(m, BraidFirstFragment, first, 0)?
      Ok((B1BobFirst(bob), pq, m, fragment))
    end
    B1BobFirst(owner) -> b1_cursored(B1BobFirst(owner), pq, old, BraidFirstFragment, old.first, 2)
    B1BobVector(owner) -> b1_cursored(B1BobVector(owner), pq, old, BraidFirstFragment, old.first, 2)
    B1BobSecond(owner) -> b1_cursored(B1BobSecond(owner),
      pq,
      old,
      BraidSecondFragment,
      old.second,
      3)
    B1BobAwait(_) -> Err("c1_spqr_header_not_accepted")
  end
end

fn b1_matches(m :: BraidSpqrMetadata,
  fragment :: BraidFragment,
  kind :: BraidFragmentKind,
  carrier :: Bytes) -> Result<(), String> do
  let expected = b1_fragment(m, kind, carrier, fragment.index)?
  check(Bytes.secure_equals(fragment.word, expected.word), "c1_spqr_fragment_conflict")
end

fn b1_partial(m :: BraidSpqrMetadata,
  fragment :: BraidFragment,
  kind :: BraidFragmentKind) -> (List<BraidFragment>, Bool)!String do
  let existing = for i in 0..List.length(m.partial_indices) do
    %{fragment |
      kind: kind,
      index: List.get(m.partial_indices, i),
      word: List.get(m.partial_words, i)
    }
  end
  for f in existing do
    check(f.index != fragment.index || Bytes.secure_equals(f.word, fragment.word),
      "c1_spqr_fragment_conflict")?
  end
  let duplicate = List.any(existing, fn(f) -> f.index == fragment.index end)
  let combined = if duplicate do
    existing
  else
    List.append(existing, %{fragment | kind: kind})
  end
  Ok((List.sort(combined, fn(a, b) -> a.index - b.index end), duplicate))
end

fn b1_ack(m :: BraidSpqrMetadata, header_hash :: Bytes, raw_hash :: Bytes) -> Bytes!String do
  if Bytes.get(m.peer_ack, 0)? == 1 do
    Ok(m.peer_ack)
  else
    join([
      mobile_byte(1)?,
      mobile_write_u64(m.epoch)?,
      Crypto.sha256(m.first),
      header_hash,
      raw_hash
    ])
  end
end

fn b1_complete_vector(owner :: consume BraidBobEkReceived,
  m :: BraidSpqrMetadata) -> B1Admission!String do
  let candidate = %{m |
    phase: 8,
    kernel_tag: 7,
    partial_kind: 0,
    partial_indices: [],
    partial_words: [],
    vector: owner.vector.bytes
  }
  if Bytes.get(m.peer_ack, 0)? == 0 do
    Ok(B1Admitted(B1BobVector(owner), candidate, 5))
  else
    case send_ct2(owner) do
      BraidCt2Emitted(next, wire) -> Ok(B1Admitted(B1BobSecond(next),
        %{candidate | phase: 9, kernel_tag: 8, second: wire},
        6))
      BraidCt2Refused(_, _) -> Err("c1_spqr_kernel_failed")
    end
  end
end

fn b1_receive_action(kernel :: consume B1Kernel,
  m :: BraidSpqrMetadata,
  fragment :: BraidFragment,
  header_hash :: Bytes,
  raw_hash :: Bytes) -> B1Admission!String do
  check(fragment.kind != NoBraidFragment
      && fragment.kind != BraidFirstFragment
      && fragment.kind != BraidSecondFragment
      && U64.compare(fragment.epoch, m.epoch) == 0,
    "invalid_c1_spqr_fragment")?
  case kernel do
    B1BobAwait(owner) -> do
      check(fragment.kind == BraidHeaderFragment, "invalid_c1_spqr_fragment")?
      let (parts, duplicate) = b1_partial(m, fragment, BraidHeaderFragment)?
      let complete = case recover_braid_carrier(BraidHeaderFragment,
        m.scope.configuration,
        m.scope.session_id,
        m.epoch,
        parts) do
        Ok(v) -> v
        Err(_) -> return Err("invalid_c1_spqr_fragment")
      end
      case complete do
        None -> Ok(B1Admitted(B1BobAwait(owner),
          %{m |
            partial_indices: for f in parts do
              f.index
            end,
            partial_words: for f in parts do
              f.word
            end
          },
          if duplicate do
            7
          else
            3
          end))
        Some(header) -> case admit_complete_header(owner, m.epoch, header) do
          BraidHeaderAccepted(next) -> Ok(B1Admitted(B1BobHeader(next),
            %{m |
              phase: 5,
              kernel_tag: 1,
              header: header,
              partial_kind: 0,
              partial_indices: [],
              partial_words: []
            },
            4))
          BraidHeaderFatal(BraidAuthenticationRejected) -> Ok(B1FatalHeader)
          BraidHeaderFatal(_) -> Err("c1_spqr_kernel_unavailable")
          BraidHeaderIgnored(_, _) -> Err("invalid_c1_spqr_header")
        end
      end
    end
    B1BobHeader(owner) -> do
      check(fragment.kind == BraidHeaderFragment, "invalid_c1_spqr_fragment")?
      b1_matches(m, fragment, BraidHeaderFragment, m.header)?
      Ok(B1Admitted(B1BobHeader(owner), m, 7))
    end
    B1BobFirst(owner) -> do
      if fragment.kind == BraidHeaderFragment do
        b1_matches(m, fragment, BraidHeaderFragment, m.header)?
        return Ok(B1Admitted(B1BobFirst(owner), m, 7))
      end
      if fragment.kind == BraidAckFragment do
        return Ok(B1Admitted(B1BobFirst(owner), m, 7))
      end
      check(fragment.kind == BraidVectorFragment || fragment.kind == BraidVectorAckFragment,
        "invalid_c1_spqr_fragment")?
      let (parts, duplicate) = b1_partial(m, fragment, BraidVectorFragment)?
      let ack = if fragment.kind == BraidVectorAckFragment do
        b1_ack(m, header_hash, raw_hash)?
      else
        m.peer_ack
      end
      let next_m = %{m |
        peer_ack: ack,
        phase: if Bytes.get(ack, 0)? == 1 do
          7
        else
          6
        end,
        partial_indices: for f in parts do
          f.index
        end,
        partial_words: for f in parts do
          f.word
        end
      }
      let complete = case recover_braid_carrier(BraidVectorFragment,
        m.scope.configuration,
        m.scope.session_id,
        m.epoch,
        parts) do
        Ok(v) -> v
        Err(_) -> return Err("invalid_c1_spqr_fragment")
      end
      case complete do
        None -> Ok(B1Admitted(B1BobFirst(owner),
          next_m,
          if duplicate do
            7
          else
            3
          end))
        Some(vector) -> case receive_vector(owner,
          m.epoch,
          MlKemPublicVector1152 { bytes: vector }) do
          BraidVectorAccepted(next) -> b1_complete_vector(next, next_m)
          BraidVectorIgnored(_, _) -> Err("invalid_c1_spqr_vector")
        end
      end
    end
    B1BobVector(owner) -> do
      if fragment.kind == BraidHeaderFragment do
        b1_matches(m, fragment, BraidHeaderFragment, m.header)?
        return Ok(B1Admitted(B1BobVector(owner), m, 7))
      end
      if fragment.kind != BraidAckFragment do
        check(fragment.kind == BraidVectorFragment || fragment.kind == BraidVectorAckFragment,
          "invalid_c1_spqr_fragment")?
        b1_matches(m, fragment, BraidVectorFragment, m.vector)?
      end
      if fragment.kind == BraidAckFragment || fragment.kind == BraidVectorAckFragment do
        b1_complete_vector(owner, %{m | peer_ack: b1_ack(m, header_hash, raw_hash)?})
      else
        Ok(B1Admitted(B1BobVector(owner), m, 7))
      end
    end
    B1BobSecond(owner) -> do
      if fragment.kind == BraidHeaderFragment do
        b1_matches(m, fragment, BraidHeaderFragment, m.header)?
      else if fragment.kind != BraidAckFragment do
        check(fragment.kind == BraidVectorFragment || fragment.kind == BraidVectorAckFragment,
          "invalid_c1_spqr_fragment")?
        b1_matches(m, fragment, BraidVectorFragment, m.vector)?
      end
      Ok(B1Admitted(B1BobSecond(owner), m, 7))
    end
    _ -> Err("invalid_c1_spqr_phase")
  end
end

fn b1_terminal(path :: String,
  source :: B1Sources,
  old :: BraidSpqrMetadata,
  raw_hash :: Bytes,
  session :: Bytes,
  key :: borrow StorageKey) -> BraidSpqrStepOutcome!String do
  let m = %{old |
    phase: 10,
    kernel_tag: 0,
    revision: U64.add(old.revision, one()?)?,
    transition: zero(32)?,
    local_epoch: U64.parse("0")?,
    knowledge: U64.parse("0")?,
    cursors: [0, 0, 0, 0],
    partial_kind: 0,
    partial_indices: [],
    partial_words: [],
    header: Bytes.empty(),
    vector: Bytes.empty(),
    first: Bytes.empty(),
    second: Bytes.empty(),
    peer_ack: zero(105)?,
    pending_identity: zero(80)?,
    local_attempt: zero(105)?,
    inbound_result: zero(82)?,
    slots: [],
    skipped_index: Bytes.empty(),
    hashes: [
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(session),
      Crypto.sha256(Bytes.empty())
    ]
  }
  let next = %{m | transition: braid_spqr_transition(m, source.source.before, 3, raw_hash)?}
  let ls = braid_spqr_labels(old.scope)
  let meta = seal_local(braid_spqr_metadata_bytes(next)?, key, local_context(List.get(ls, 0))?)?
  commit_fanout_records_at_policy(path,
    source.source.before,
    source.native,
    [List.get(ls, 0), source.source.loaded.label],
    [meta, session],
    List.drop(ls, 1))?
  Err("c1_spqr_terminal_generation")
end

pub fn prepare_braid_spqr_fragment_once(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  expected_revision :: U64,
  expected_transition :: Bytes,
  intent :: Bytes) -> BraidSpqrStepOutcome!String do
  check(Bytes.length(expected_transition) == 32 && Bytes.length(intent) == 32,
    "c1_spqr_attempt_changed")?
  let key = platform_key()?
  let source = b1_sources(path, expected_profile, scope, key)?
  let old = b1_metadata(source, scope, key)?
  let source = b1_pending_sources(path, source, old, key)?
  if Bytes.length(old.local_attempt) == 105
    && Bytes.get(old.local_attempt, 0)? == 1
    && U64.compare(mobile_read_u64(Bytes.slice(old.local_attempt, 1, 8)?)?, expected_revision) == 0
    && Bytes.secure_equals(Bytes.slice(old.local_attempt, 9, 32)?, expected_transition)
    && Bytes.secure_equals(Bytes.slice(old.local_attempt, 41, 32)?, intent) do
    let _validated = b1_consumer(source, old, key)?
    return b1_recover(path, source, old, key, expected_revision, expected_transition, intent)
  end
  check(U64.compare(old.revision, expected_revision) == 0
      && Bytes.secure_equals(old.transition, expected_transition),
    "c1_spqr_attempt_changed")?
  let cursor = if old.direction == 0 do
    List.get(old.cursors, 0)
  else if old.phase == 9 do
    List.get(old.cursors, 3)
  else
    List.get(old.cursors, 2)
  end
  check(cursor < 65536, "c1_spqr_fragment_exhausted")?
  let pq = b1_consumer(source, old, key)?
  let kernel = b1_kernel(source, old, key)?
  let (kernel, pq, candidate, fragment) = b1_prepare_action(kernel, pq, old)?
  let fragment_hash = Crypto.sha256(b1_fragment_bytes(fragment)?)
  let he = checked_he(restore_session(source.source.loaded, key)?, scope.session_id)?
  let (he, pq, message) = case he_encrypt_hybrid(he,
    pq,
    Bytes.empty(),
    fragment,
    session_aad(scope.session_id)?) do
    HybridSealed(h, q, v) -> (h, q, v)
    HybridSealRefused(_, _, _) -> return Err("c1_spqr_he_encryption_failed")
  end
  let wire = case encode_triple_message(message) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_spqr_packet")
  end
  let envelope = sealed_outer_bytes(source.source.loaded.record.peer_mailbox,
    encode_packet(RatchetPacket(wire))?,
    source.source.loaded.record.peer_transport_key,
    current_time()?)?
  let id = canonical_outer(envelope)?.envelope_id
  let (outbox_labels, outbox_blobs, index) = prepare_outbox_writes(key,
    ids_from_basis(source.source.outbox, key)?,
    [envelope],
    path,
    Bytes.empty(),
    0,
    0,
    source.source.profile)?
  check(Bytes.secure_equals(index.before.profile, source.source.outbox.profile)
      && Bytes.secure_equals(index.before.index, source.source.outbox.index)
      && Bytes.secure_equals(index.before.postage, source.source.outbox.postage)
      && Bytes.secure_equals(index.before.delivery, source.source.outbox.delivery),
    "outbox_state_changed")?
  let extra = capture_fanout_snapshot(path, source.source.outbox.profile, outbox_labels)?
  for name in outbox_labels do
    check(Bytes.length(captured(extra, name)?) == 0, "c1_spqr_outbox_target_exists")?
  end
  let before = combine_fanout_snapshots(source.source.before, extra)?
  current(path, before)?
  let source = %{source | source: %{source.source | before: before}}
  let next_metadata = b1_next(candidate, pq)?
  let m = %{next_metadata |
    pending_identity: join([id, Crypto.sha256(envelope), zero(32)?])?,
    local_attempt: join([
      mobile_byte(1)?,
      mobile_write_u64(expected_revision)?,
      expected_transition,
      intent,
      fragment_hash
    ])?
  }
  let transition = braid_spqr_transition(m,
    before,
    2,
    Crypto.sha256(join([
      intent,
      mobile_write_u64(expected_revision)?,
      expected_transition,
      fragment_hash
    ])?))?
  let m = %{m |
    transition: transition,
    pending_identity: join([id, Crypto.sha256(envelope), transition])?
  }
  let session = seal_updated_session(he, source.source.loaded, key)?
  let (head, tail) = split_braid_spqr_pending(BraidSpqrPending {
    transition: transition,
    envelope_id: id,
    recipient: source.source.loaded.record.peer_mailbox,
    envelope: envelope
  })?
  let ls = braid_spqr_labels(scope)
  let head_blob = seal_local(head, key, local_context(List.get(ls, 6))?)?
  let tail_blob = if Bytes.length(tail) == 0 do
    Bytes.empty()
  else
    seal_local(tail, key, local_context(List.get(ls, 7))?)?
  end
  let (filled, labels, blobs, removed) = b1_records(source,
    m,
    kernel,
    pq,
    session,
    head_blob,
    tail_blob,
    key)?
  let pending_labels = [List.get(ls, 6)]
    ++ (if Bytes.length(tail_blob) == 0 do
      []
    else
      [List.get(ls, 7)]
    end)
  let pending_blobs = [head_blob]
    ++ (if Bytes.length(tail_blob) == 0 do
      []
    else
      [tail_blob]
    end)
  let removed = removed
    ++ (if Bytes.length(tail_blob) == 0 do
      [List.get(ls, 7)]
    else
      []
    end)
  let prepared = MobilePreparedSend {
    envelope: envelope,
    session_id: scope.session_id,
    session_label: source.source.loaded.label,
    session_blob: session,
    new_session: false
  }
  commit_fanout_snapshot_at_policy(path,
    before,
    source.native,
    [prepared],
    removed,
    captured(before, "sessions/v1")?,
    [],
    [],
    outbox_labels ++ labels ++ pending_labels,
    outbox_blobs ++ blobs ++ pending_blobs,
    index)?
  b1_outcome(filled, 1, id, envelope)
end

pub fn receive_braid_spqr_fragment(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  outer :: Bytes) -> BraidSpqrStepOutcome!String do
  let key = platform_key()?
  let source = b1_sources(path, expected_profile, scope, key)?
  let old = b1_metadata(source, scope, key)?
  let source = b1_pending_sources(path, source, old, key)?
  check(old.direction == 1, "invalid_c1_spqr_phase")?
  let pq = b1_consumer(source, old, key)?
  let hash = Crypto.sha256(outer)
  if Bytes.get(old.inbound_result, 0)? == 1
    && Bytes.secure_equals(Bytes.slice(old.inbound_result, 1, 32)?, hash) do
    current(path, source.source.before)?
    require_current_session_policy(source.native)?
    return b1_outcome(old, 8, Bytes.empty(), Bytes.empty())
  end
  let (he, pq, fragment, header_hash) = b1_authenticated(source, key, outer, pq)?
  let candidate = b1_next(old, pq)?
  let kernel = b1_kernel(source, old, key)?
  let admission = b1_receive_action(kernel, candidate, fragment, header_hash, hash)?
  let session = seal_updated_session(he, source.source.loaded, key)?
  case admission do
    B1FatalHeader -> b1_terminal(path, source, old, hash, session, key)
    B1Admitted(kernel, candidate, kind) -> do
      let m = b1_received(candidate, old, kind, hash, source.source.before)?
      let ls = braid_spqr_labels(scope)
      let head = captured(source.source.before, List.get(ls, 6))?
      let tail = captured(source.source.before, List.get(ls, 7))?
      let (filled, labels, blobs, removed) = b1_records(source,
        m,
        kernel,
        pq,
        session,
        head,
        tail,
        key)?
      commit_fanout_records_at_policy(path,
        source.source.before,
        source.native,
        labels ++ [source.source.loaded.label],
        blobs ++ [session],
        removed)?
      b1_outcome(filled, kind, Bytes.empty(), Bytes.empty())
    end
  end
end

pub fn recover_braid_spqr_fragment(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  source_revision :: U64,
  source_transition :: Bytes,
  intent :: Bytes) -> BraidSpqrStepOutcome!String do
  let key = platform_key()?
  let source = b1_sources(path, expected_profile, scope, key)?
  let m = b1_metadata(source, scope, key)?
  let source = b1_pending_sources(path, source, m, key)?
  let _validated = b1_consumer(source, m, key)?
  b1_recover(path, source, m, key, source_revision, source_transition, intent)
end

## Explicit local C1 request acceptance; no active app policy route.
pub struct BraidSpqrAcceptanceOutcome do
  kind :: Int
  phase :: Int
  current_revision :: U64
  current_transition :: Bytes
  epoch :: U64
  local_epoch :: U64
  knowledge :: U64
end

fn b1_acceptance_outcome(m :: BraidSpqrMetadata, kind :: Int) -> BraidSpqrAcceptanceOutcome do
  BraidSpqrAcceptanceOutcome {
    kind: kind,
    phase: m.phase,
    current_revision: m.revision,
    current_transition: m.transition,
    epoch: m.epoch,
    local_epoch: m.local_epoch,
    knowledge: m.knowledge
  }
end

pub fn accept_braid_spqr_request(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope) -> BraidSpqrAcceptanceOutcome!String do
  let key = platform_key()?
  let source = b1_source_basis(path, expected_profile, scope, key)?
  let old = b1_metadata(source, scope, key)?
  check(old.direction == 1 && old.phase >= 4 && old.phase <= 9, "invalid_c1_spqr_acceptance")?
  let source = b1_pending_sources(path, source, old, key)?
  if source.source.loaded.record.request_state == 1 do
    check(Bytes.length(old.local_attempt) == 105, "invalid_c1_spqr_acceptance")?
    let _validated = b1_consumer(source, old, key)?
    current(path, source.source.before)?
    require_current_session_policy(source.native)?
    return Ok(b1_acceptance_outcome(old, 2))
  end
  # b1_metadata authenticates the untouched v1 revision and CBI1 transition.
  # Operation4 additionally requires the complete empty initial Bob shape.
  check(source.source.loaded.record.request_state == 0 && Bytes.length(old.local_attempt) == 73,
    "invalid_c1_spqr_acceptance")?
  let candidate = %{old |
    revision: U64.add(old.revision, one()?)?,
    transition: zero(32)?,
    local_attempt: zero(105)?
  }
  let commitment = Crypto.sha256(join([
    Bytes.from_utf8("morse/c1/braid-spqr/request-accept/v1"),
    mobile_byte(0)?,
    scope.protocol_info,
    old.transition,
    mobile_write_u64(old.revision)?
  ])?)
  let next = %{candidate |
    transition: braid_spqr_transition(candidate, source.source.before, 4, commitment)?
  }
  let pq = b1_consumer(source, old, key)?
  let kernel = b1_kernel(source, old, key)?
  # Preserve the opaque HE snapshot and every session field except request state.
  let record = %{source.source.loaded.record | request_state: 1}
  let session = seal_local(updated_session_record(record.snapshot, record)?,
    key,
    local_context(source.source.loaded.label)?)?
  let (filled, labels, blobs, removed) = b1_records(source,
    next,
    kernel,
    pq,
    session,
    Bytes.empty(),
    Bytes.empty(),
    key)?
  commit_fanout_records_at_policy(path,
    source.source.before,
    source.native,
    labels ++ [source.source.loaded.label],
    blobs ++ [session],
    removed)?
  Ok(b1_acceptance_outcome(filled, 1))
end
