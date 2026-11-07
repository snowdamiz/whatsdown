##! Inactive C1 complete-message coordinator. No native export or production
##! control routing. Public entry points authenticate real HE input themselves;
##! no caller-supplied Boolean, proof record or prepared plan authorizes commit.
from Session.BraidResponder import (
  BraidScope,
  BraidAwaitHeader,
  BraidCt1Ready,
  BraidHeaderAdmission,
  BraidError,
  admit_complete_header,
  prepare_ct1,
  braid_valid_scope
)
from Session.BraidStore import (
  BraidSaved,
  seal_await,
  seal_header,
  seal_ct1,
  restore_await,
  restore_header,
  restore_ct1,
  braid_storage_context
)
from Session.State import RatchetState, DecryptOutcome
from Session.Ratchet import decode_ratchet_message, decrypt, encrypt_sealed
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  encode_packet,
  session_aad
)
from Binary.Reader import BinaryReader, reader, read_vector, finish
from Mobile.Codec import (
  canonical_outer,
  current_time,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u64,
  mobile_vector,
  mobile_write_u64,
  mobile_wide
)
from Mobile.Profile import open_device
from Mobile.Sessions import (
  decode_session_ids,
  parse_session_record,
  restore_session,
  seal_updated_session,
  session_uses_headers,
  parse_ratchet_packet,
  ratchet_bytes
)
from Mobile.Types import MobileLoadedSession, MobilePreparedSend
from Mobile.Transport import open_outer_packet, sealed_outer_bytes
from Mobile.Outbox import load_outbox_ids, prepare_outbox_writes
from Storage.Keys import platform_key, seal_local, open_local, local_context
from Storage.AccountGuard import account_basis_current, load_account_basis
from Storage.FanoutCommit import (
  FanoutSnapshot,
  capture_fanout_snapshot,
  combine_fanout_snapshots,
  commit_fanout_records,
  commit_fanout_snapshot
)

pub struct BraidJournalOutcome do
  # 1 accepted header/no output;2 new committed output;3 exact recovered output.
  kind :: Int
  epoch :: U64
  sending_epoch :: U64
  output_id :: Bytes
  first :: Bytes
  envelope :: Bytes
end

struct Sources do
  before :: FanoutSnapshot
  profile :: ClientProfile
  loaded :: MobileLoadedSession
end

struct Metadata do
  saved :: BraidSaved
  secrets_hash :: Bytes
  continuation_hash :: Bytes
  pending_hash :: Bytes
  output_id :: Bytes
end

fn error(value :: Bool, name :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(name)
  end
end

fn part(value :: Bytes, start :: Int, count :: Int) -> Bytes!String do
  case Bytes.slice(value, start, count) do
    Ok(v)
    Err(_) -> Err("invalid_c1_journal")
  end
end

pub fn braid_labels(scope :: BraidScope) -> List<String> do
  let prefix = "c1/braid/v1/#{Bytes.to_hex(scope.session_id)}/#{Bytes.to_hex(scope.configuration)}"
  [prefix <> "/metadata", prefix <> "/secrets", prefix <> "/continuation", prefix <> "/pending"]
end

fn session_label(scope :: BraidScope) -> String do
  "session/v1/#{Bytes.to_hex(scope.session_id)}"
end

fn same_scope(a :: BraidScope, b :: BraidScope) -> Bool do
  Bytes.secure_equals(a.configuration, b.configuration)
    && Bytes.secure_equals(a.protocol_info, b.protocol_info)
    && Bytes.secure_equals(a.account_id, b.account_id)
    && Bytes.secure_equals(a.device_id, b.device_id)
    && Bytes.secure_equals(a.peer_account_id, b.peer_account_id)
    && Bytes.secure_equals(a.peer_device_id, b.peer_device_id)
    && Bytes.secure_equals(a.session_id, b.session_id)
end

fn captured(before :: FanoutSnapshot, label :: String) -> Bytes!String do
  for basis in before.bases do
    for i in 0..List.length(basis.labels) do
      if List.get(basis.labels, i) == label do
        return Ok(List.get(basis.records, i))
      end
    end
  end
  Err("invalid_c1_source_set")
end

fn current(path :: String, before :: FanoutSnapshot) -> Result<(), String> do
  error(List.all(before.bases, fn(basis) -> account_basis_current(path, basis) end),
    "account_state_changed")
end

## Decode only the ciphertexts we captured, not a newer row accidentally blessed
## by a later snapshot. No SQLite handle survives into cryptographic work.
fn sources(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  key :: borrow StorageKey) -> Sources!String do
  error(braid_valid_scope(scope, mobile_wide("1")?), "invalid_c1_scope")?
  let profile_only = load_account_basis(path, [])?
  let profile_basis = capture_fanout_snapshot(path,
    profile_only.profile,
    ["sessions/v1", session_label(scope), "header-routing/v1"]
      ++ braid_labels(scope)
      ++ ["outbox/v1", "postage-queue/v1", "delivery/v1"])?
  let public = open_local(List.head(profile_basis.bases).profile,
    key,
    local_context("profile/v1")?)?
  error(Bytes.secure_equals(public, expected_profile), "account_state_changed")?
  let profile = decode_client_profile(public)?
  error(Bytes.secure_equals(profile.account_id, scope.account_id)
      && Bytes.secure_equals(profile.device_id, scope.device_id),
    "account_state_changed")?
  let index = decode_session_ids(open_local(captured(profile_basis, "sessions/v1")?,
    key,
    local_context("sessions/v1")?)?)?
  error(List.any(index, fn(id) -> Bytes.secure_equals(id, scope.session_id) end),
    "unknown_session")?
  let label = session_label(scope)
  let record = parse_session_record(open_local(captured(profile_basis, label)?,
    key,
    local_context(label)?)?)?
  error(Bytes.secure_equals(record.local_account_id, profile.account_id)
      && Bytes.secure_equals(record.local_device_id, profile.device_id)
      && Bytes.secure_equals(record.peer_account_id, scope.peer_account_id)
      && Bytes.secure_equals(record.peer_device_id, scope.peer_device_id)
      && !record.blocked
      && record.request_state == 1
      && session_uses_headers(record.snapshot),
    "c1_session_changed")?
  let history = "history/v1/#{Bytes.to_hex(record.conversation_id)}"
  let extra = capture_fanout_snapshot(path, List.head(profile_basis.bases).profile, [history])?
  let before = combine_fanout_snapshots(profile_basis, extra)?
  current(path, before)?
  Ok(Sources {
    before: before,
    profile: profile,
    loaded: MobileLoadedSession { session_id: scope.session_id, label: label, record: record }
  })
end

fn encode_fields(fields :: List<Bytes>) -> Bytes!String do
  mobile_join(for value in fields do
      mobile_vector(value)?
    end,
    0,
    Bytes.empty())
end

fn read_fields(state :: BinaryReader,
  remaining :: Int,
  fields :: List<Bytes>) -> List<Bytes>!String do
  if remaining == 0 do
    case finish(state) do
      Ok(_) -> Ok(fields)
      Err(_) -> Err("invalid_c1_journal")
    end
  else
    let (next, value) = case read_vector(state, 1024) do
      Ok(v) -> v
      Err(_) -> return Err("invalid_c1_journal")
    end
    read_fields(next, remaining - 1, List.append(fields, value))
  end
end

fn meta_bytes(value :: Metadata) -> Bytes!String do
  let s = value.saved
  encode_fields([
    Bytes.from_utf8("CBJ1"),
    s.scope.configuration,
    s.scope.protocol_info,
    s.scope.account_id,
    s.scope.device_id,
    s.scope.peer_account_id,
    s.scope.peer_device_id,
    s.scope.session_id,
    mobile_write_u64(s.epoch)?,
    mobile_write_u64(s.revision)?,
    s.transition,
    mobile_byte(s.phase)?,
    s.header,
    s.first,
    value.secrets_hash,
    value.continuation_hash,
    value.pending_hash,
    value.output_id
  ])
end

fn decode_meta(value :: Bytes, scope :: BraidScope) -> Metadata!String do
  let state = case reader(value, 4096) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_journal")
  end
  let f = read_fields(state, 18, [])?
  error(Bytes.secure_equals(List.get(f, 0), Bytes.from_utf8("CBJ1")), "invalid_c1_journal")?
  for i in [1, 3, 5, 7, 10, 14, 15, 16, 17] do
    error(Bytes.length(List.get(f, i)) == 32, "invalid_c1_journal")?
  end
  error(Bytes.length(List.get(f, 4)) == 16
      && Bytes.length(List.get(f, 6)) == 16
      && Bytes.length(List.get(f, 8)) == 8
      && Bytes.length(List.get(f, 9)) == 8
      && Bytes.length(List.get(f, 11)) == 1,
    "invalid_c1_journal")?
  let actual = BraidScope {
    configuration: List.get(f, 1),
    protocol_info: List.get(f, 2),
    account_id: List.get(f, 3),
    device_id: List.get(f, 4),
    peer_account_id: List.get(f, 5),
    peer_device_id: List.get(f, 6),
    session_id: List.get(f, 7)
  }
  error(same_scope(scope, actual), "c1_scope_changed")?
  let phase = mobile_read_byte(List.get(f, 11))?
  let saved = BraidSaved {
    scope: actual,
    epoch: mobile_read_u64(List.get(f, 8))?,
    revision: mobile_read_u64(List.get(f, 9))?,
    transition: List.get(f, 10),
    phase: phase,
    header: List.get(f, 12),
    first: List.get(f, 13),
    secrets: Bytes.empty(),
    continuation: Bytes.empty()
  }
  if phase == 3 do
    error(Bytes.length(saved.header) == 0
        && Bytes.length(saved.first) == 0
        && U64.compare(saved.epoch, mobile_wide("0")?) > 0
        && U64.compare(saved.revision, mobile_wide("0")?) > 0,
      "invalid_c1_journal")?
  else
    # This checks exact phase/width context before any resource restore.
    case braid_storage_context(saved, 22) do
      Err(_) -> return Err("invalid_c1_journal")
      Ok(_) -> nil
    end
  end
  Ok(Metadata {
    saved: saved,
    secrets_hash: List.get(f, 14),
    continuation_hash: List.get(f, 15),
    pending_hash: List.get(f, 16),
    output_id: List.get(f, 17)
  })
end

fn metadata(before :: FanoutSnapshot,
  scope :: BraidScope,
  key :: borrow StorageKey) -> Metadata!String do
  let labels = braid_labels(scope)
  let meta = decode_meta(open_local(captured(before, List.get(labels, 0))?,
      key,
      local_context(List.get(labels, 0))?)?,
    scope)?
  let secrets = captured(before, List.get(labels, 1))?
  let continuation = captured(before, List.get(labels, 2))?
  let pending = captured(before, List.get(labels, 3))?
  error(Bytes.secure_equals(Crypto.sha256(secrets), meta.secrets_hash)
      && Bytes.secure_equals(Crypto.sha256(continuation), meta.continuation_hash)
      && Bytes.secure_equals(Crypto.sha256(pending), meta.pending_hash),
    "invalid_c1_journal")?
  if meta.saved.phase == 3 do
    error(Bytes.length(secrets) == 0
        && Bytes.length(continuation) == 0
        && Bytes.length(pending) == 0,
      "invalid_c1_journal")?
  else if meta.saved.phase < 2 do
    error(Bytes.length(continuation) == 0 && Bytes.length(pending) == 0, "invalid_c1_journal")?
  end
  if meta.saved.phase != 2 do
    error(Bytes.secure_equals(meta.output_id, none_hash()), "invalid_c1_journal")?
  end
  Ok(%{meta | saved: %{meta.saved | secrets: secrets, continuation: continuation}})
end

fn transition(before :: FanoutSnapshot,
  scope :: BraidScope,
  label :: String,
  revision :: U64,
  transcript :: Bytes) -> Bytes!String do
  Ok(Crypto.sha256(mobile_join([
      Bytes.from_utf8("morse/c1/braid-transition/v1/" <> label),
      scope.configuration,
      scope.session_id,
      mobile_write_u64(revision)?,
      Crypto.sha256(List.head(before.bases).profile),
      Crypto.sha256(captured(before, session_label(scope))?),
      Crypto.sha256(captured(before, List.get(braid_labels(scope), 0))?),
      Crypto.sha256(captured(before, List.get(braid_labels(scope), 1))?),
      Crypto.sha256(captured(before, List.get(braid_labels(scope), 2))?),
      Crypto.sha256(captured(before, List.get(braid_labels(scope), 3))?),
      transcript
    ],
    0,
    Bytes.empty())?))
end

fn sealed_meta(saved :: BraidSaved,
  pending :: Bytes,
  output_id :: Bytes,
  key :: borrow StorageKey) -> Bytes!String do
  seal_local(meta_bytes(Metadata {
      saved: saved,
      secrets_hash: Crypto.sha256(saved.secrets),
      continuation_hash: Crypto.sha256(saved.continuation),
      pending_hash: Crypto.sha256(pending),
      output_id: output_id
    })?,
    key,
    local_context(List.head(braid_labels(saved.scope)))?)
end

fn none_hash() -> Bytes do
  Crypto.sha256(Bytes.empty())
end

## Explicit fixture-only bootstrap from an independent saved-PQ initializer.
## It cannot replace or clear any existing generation.
pub fn initialize_braid_fixture(path :: String,
  expected_profile :: Bytes,
  state :: consume BraidAwaitHeader) -> Result<(), String> do
  let key = platform_key()?
  let source = sources(path, expected_profile, state.scope, key)?
  let labels = braid_labels(state.scope)
  for label in labels do
    error(Bytes.length(captured(source.before, label)?) == 0, "c1_already_initialized")?
  end
  let revision = mobile_wide("1")?
  let saved = case seal_await(state,
    key,
    revision,
    transition(source.before, state.scope, "fixture-init", revision, Bytes.empty())?) do
    Ok(v) -> v
    Err(_) -> return Err("c1_storage_failed")
  end
  let meta = sealed_meta(saved, Bytes.empty(), none_hash(), key)?
  commit_fanout_records(path, source.before, List.take(labels, 2), [meta, saved.secrets], [])
end

## Test-only complete logical header carrier, inside actual recipient+HE AEAD.
pub fn braid_header_carrier(scope :: BraidScope, epoch :: U64, complete :: Bytes) -> Bytes!String do
  error(Bytes.length(complete) == 96, "invalid_c1_carrier")?
  mobile_join([
      Bytes.from_utf8("TEST/C1/HEADER/V1"),
      scope.configuration,
      scope.session_id,
      mobile_write_u64(epoch)?,
      complete
    ],
    0,
    Bytes.empty())
end

fn admitted_header(plaintext :: Bytes, saved :: BraidSaved) -> Bytes!String do
  let prefix = Bytes.from_utf8("TEST/C1/HEADER/V1")
  let n = Bytes.length(prefix)
  error(Bytes.length(plaintext) == n + 168
      && Bytes.secure_equals(part(plaintext, 0, n)?, prefix)
      && Bytes.secure_equals(part(plaintext, n, 32)?, saved.scope.configuration)
      && Bytes.secure_equals(part(plaintext, n + 32, 32)?, saved.scope.session_id)
      && U64.compare(mobile_read_u64(part(plaintext, n + 64, 8)?)?, saved.epoch) == 0,
    "invalid_c1_carrier")?
  part(plaintext, n + 72, 96)
end

fn rejected_he(state :: consume RatchetState) -> Result<(RatchetState, Bytes), String> do
  Err("c1_he_authentication_failed")
end

fn checked_he(state :: consume RatchetState, session_id :: Bytes) -> RatchetState!String do
  error(state.version == 2 && state.suite == 2 && Bytes.secure_equals(state.session_id, session_id),
    "c1_session_changed")?
  Ok(state)
end

fn authenticated_receive(path :: String,
  source :: Sources,
  key :: borrow StorageKey,
  outer_wire :: Bytes) -> Result<(RatchetState, Bytes), String> do
  let outer = canonical_outer(outer_wire)?
  error(Bytes.secure_equals(outer.mailbox_token, source.profile.entry.mailbox_token),
    "invalid_c1_recipient")?
  let device = open_device(source.profile, key, path)?
  let opened = open_outer_packet(outer, device.identity_private_key)?
  error(opened.sealed, "invalid_c1_recipient")?
  let wire = parse_ratchet_packet(opened.packet)?
  let message = case decode_ratchet_message(wire) do
    Ok(v) -> v
    Err(_) -> return Err("invalid_c1_packet")
  end
  error(message.version == 4, "invalid_c1_packet")?
  let state = checked_he(restore_session(source.loaded, key)?, source.loaded.session_id)?
  case decrypt(state, message, session_aad(source.loaded.session_id)?) do
    Opened(next, plaintext) -> Ok((next, plaintext))
    Rejected(old, _) -> rejected_he(old)
  end
end

## Hook is a fixture barrier only. It receives no plaintext, state or admission
## token; callers cannot supply a prepared receive or bypass actual decryption.
pub fn receive_braid_control(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  outer :: Bytes,
  before_commit :: Fun() -> Result<(), String>) -> BraidJournalOutcome!String do
  let key = platform_key()?
  let source = sources(path, expected_profile, scope, key)?
  let old = metadata(source.before, scope, key)?
  if old.saved.phase == 3 do
    return Err("c1_terminal_generation")
  end
  error(old.saved.phase == 0, "c1_header_already_accepted")?
  let (next_he, plaintext) = authenticated_receive(path, source, key, outer)?
  let complete = admitted_header(plaintext, old.saved)?
  let state = case restore_await(old.saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("c1_storage_failed")
  end
  let revision = U64.add(old.saved.revision, mobile_wide("1")?)?
  let id = transition(source.before, scope, "accepted-header", revision, Crypto.sha256(outer))?
  let (saved, terminal) = case admit_complete_header(state, old.saved.epoch, complete) do
    BraidHeaderAccepted(ready) -> do
      let value = case seal_header(ready, key, revision, id) do
        Ok(v) -> v
        Err(_) -> return Err("c1_storage_failed")
      end
      (value, false)
    end
    BraidHeaderIgnored(_, _) -> return Err("invalid_c1_header")
    BraidHeaderFatal(BraidAuthenticationRejected) -> (BraidSaved {
        scope: scope,
        epoch: old.saved.epoch,
        revision: revision,
        transition: id,
        phase: 3,
        header: Bytes.empty(),
        first: Bytes.empty(),
        secrets: Bytes.empty(),
        continuation: Bytes.empty()
      },
      true)
    BraidHeaderFatal(_) -> return Err("c1_authentication_unavailable")
  end
  let session = seal_updated_session(next_he, source.loaded, key)?
  let labels = braid_labels(scope)
  let meta = sealed_meta(saved, Bytes.empty(), none_hash(), key)?
  before_commit()?
  if terminal do
    commit_fanout_records(path,
      source.before,
      [List.head(labels), source.loaded.label],
      [meta, session],
      List.drop(labels, 1))?
    Err("c1_terminal_generation")
  else
    commit_fanout_records(path,
      source.before,
      List.take(labels, 2) ++ [source.loaded.label],
      [meta, saved.secrets, session],
      List.drop(labels, 2))?
    Ok(BraidJournalOutcome {
      kind: 1,
      epoch: saved.epoch,
      sending_epoch: U64.subtract(saved.epoch, mobile_wide("1")?)?,
      output_id: Bytes.empty(),
      first: Bytes.empty(),
      envelope: Bytes.empty()
    })
  end
end

fn drop_candidate(value :: consume BraidCt1Ready) do
  nil
end

fn recover_from(path :: String,
  source :: Sources,
  meta :: Metadata,
  key :: borrow StorageKey) -> BraidJournalOutcome!String do
  if meta.saved.phase == 3 do
    return Err("c1_terminal_generation")
  end
  error(meta.saved.phase == 2, "c1_no_pending_output")?
  let restored = case restore_ct1(meta.saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("c1_storage_failed")
  end
  let expected_id = case braid_storage_context(meta.saved, 22) do
    Ok(v) -> Crypto.sha256(v)
    Err(_) -> return Err("invalid_c1_journal")
  end
  error(Bytes.secure_equals(meta.output_id, expected_id), "invalid_c1_journal")?
  let label = List.get(braid_labels(meta.saved.scope), 3)
  let envelope = open_local(captured(source.before, label)?, key, local_context(label)?)?
  canonical_outer(envelope)?
  current(path, source.before)?
  drop_candidate(restored)
  Ok(BraidJournalOutcome {
    kind: 3,
    epoch: meta.saved.epoch,
    sending_epoch: U64.subtract(meta.saved.epoch, mobile_wide("1")?)?,
    output_id: meta.output_id,
    first: meta.saved.first,
    envelope: envelope
  })
end

pub fn recover_braid_output(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope) -> BraidJournalOutcome!String do
  let key = platform_key()?
  let source = sources(path, expected_profile, scope, key)?
  recover_from(path, source, metadata(source.before, scope, key)?, key)
end

## Explicit Send is distinct from Receive. Its candidate and real pending HE
## envelope commit once, alongside the existing session/outbox guards.
pub fn send_braid_control(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  before_commit :: Fun() -> Result<(), String>) -> BraidJournalOutcome!String do
  send_braid_control_fault(path, expected_profile, scope, before_commit, fn() -> Ok(nil) end)
end

## Fixture-only fault after the durable commit, before returning its outcome.
## It cannot affect admission, produce a second candidate or roll back a commit.
pub fn send_braid_control_fault(path :: String,
  expected_profile :: Bytes,
  scope :: BraidScope,
  before_commit :: Fun() -> Result<(), String>,
  after_commit :: Fun() -> Result<(), String>) -> BraidJournalOutcome!String do
  let key = platform_key()?
  let source = sources(path, expected_profile, scope, key)?
  let old = metadata(source.before, scope, key)?
  if old.saved.phase == 3 do
    return Err("c1_terminal_generation")
  end
  if old.saved.phase == 2 do
    return recover_from(path, source, old, key)
  end
  error(old.saved.phase == 1, "c1_header_not_accepted")?
  let ready = case restore_header(old.saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("c1_storage_failed")
  end
  let candidate = case prepare_ct1(ready) do
    Ok(v) -> v
    Err(_) -> return Err("c1_prepare_failed")
  end
  let revision = U64.add(old.saved.revision, mobile_wide("1")?)?
  let id = transition(source.before,
    scope,
    "explicit-send",
    revision,
    Crypto.sha256(mobile_join([candidate.header, candidate.first.bytes], 0, Bytes.empty())?))?
  let saved = case seal_ct1(candidate, key, revision, id) do
    Ok(v) -> v
    Err(_) -> return Err("c1_storage_failed")
  end
  let payload = mobile_join([
      Bytes.from_utf8("TEST/C1/CT1/V1"),
      scope.configuration,
      scope.session_id,
      mobile_write_u64(candidate.epoch)?,
      candidate.first.bytes
    ],
    0,
    Bytes.empty())?
  let state = checked_he(restore_session(source.loaded, key)?, scope.session_id)?
  let (next_he, message) = case encrypt_sealed(state, payload, session_aad(scope.session_id)?) do
    Ok(v) -> v
    Err(_) -> return Err("c1_he_encryption_failed")
  end
  let envelope = sealed_outer_bytes(source.loaded.record.peer_mailbox,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    source.loaded.record.peer_transport_key,
    current_time()?)?
  let session = seal_updated_session(next_he, source.loaded, key)?
  let pending_ids = load_outbox_ids(path, key)?
  let (outbox_labels, outbox_blobs, index) = prepare_outbox_writes(key,
    pending_ids,
    [envelope],
    path,
    Bytes.empty(),
    0,
    0,
    source.profile)?
  let extra = capture_fanout_snapshot(path, List.head(source.before.bases).profile, outbox_labels)?
  for label in outbox_labels do
    error(Bytes.length(captured(extra, label)?) == 0, "c1_outbox_target_exists")?
  end
  let before = combine_fanout_snapshots(source.before, extra)?
  current(path, before)?
  let labels = braid_labels(scope)
  let pending = seal_local(envelope, key, local_context(List.get(labels, 3))?)?
  let output_id = case braid_storage_context(saved, 22) do
    Ok(v) -> Crypto.sha256(v)
    Err(_) -> return Err("invalid_c1_journal")
  end
  let meta = sealed_meta(saved, pending, output_id, key)?
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
    captured(source.before, "sessions/v1")?,
    [],
    [],
    outbox_labels ++ labels,
    outbox_blobs ++ [meta, saved.secrets, saved.continuation, pending],
    index)?
  after_commit()?
  Ok(BraidJournalOutcome {
    kind: 2,
    epoch: saved.epoch,
    sending_epoch: U64.subtract(saved.epoch, mobile_wide("1")?)?,
    output_id: output_id,
    first: saved.first,
    envelope: envelope
  })
end
