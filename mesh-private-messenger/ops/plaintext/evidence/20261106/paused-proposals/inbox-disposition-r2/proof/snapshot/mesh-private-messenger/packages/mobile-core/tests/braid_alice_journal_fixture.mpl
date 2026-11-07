##! Owned real signed-account/PQ/HE fixtures. All generated files live under the
##! runner's0700 root, which is removed even on early Err, assertion or timeout.
from Binary.Reader import BinaryReader, reader, read_vector
from Tests.BraidJournalFixture import BraidHeFixture, setup
from Tests.GroupLifecycleSupport import GroupAccountFixture
from Tests.Support import repeated
from Session.BraidResponder import BraidScope
from Session.BraidInitiator import BraidAliceIdle, BraidAliceHeaderSent, initialize_initiator
from Session.BraidBilateralStore import restore_alice_header, save_alice_header
from Mobile.BraidAliceJournal import (
  BraidAliceHeaderOutcome,
  initialize_braid_alice_fixture,
  prepare_braid_header_once,
  prepare_braid_header_fault,
  recover_braid_header
)
from Mobile.BraidAliceState import (
  AliceHeaderMetadata,
  alice_header_labels,
  alice_check,
  decode_alice_metadata,
  alice_metadata_bytes
)
from Mobile.BraidJournal import braid_labels, receive_braid_control, braid_header_carrier
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import (
  load_session_ids,
  find_peer_session,
  restore_session,
  seal_updated_session,
  ratchet_bytes,
  parse_ratchet_packet,
  updated_session_record
)
from Mobile.Account import create_account
from Mobile.Outbox import load_outbox_ids, acknowledge_outbox
from Mobile.Types import MobileAccountRequest, MobilePayloadRequest
from Mobile.Codec import (
  canonical_outer,
  current_time,
  mobile_join,
  mobile_vector,
  encode_output_list,
  mobile_write_u64
)
from Mobile.Transport import open_outer_packet, sealed_outer_bytes
from Session.HeaderRatchet import he_initialize_alice
from Session.Ratchet import decode_ratchet_message, decrypt, encrypt_sealed
from Session.State import RatchetState, RatchetMessage, DecryptOutcome
from Storage.Keys import platform_key, open_local, seal_local, local_context
from Storage.AccountGuard import (
  load_account_basis,
  same_account_basis,
  commit_account_changes,
  erase_account_if_current
)
from Storage.Blobs import load_blob
from Storage.Records import erase_local_state, store_updated_blobs, store_record_changes
from Transport.Packet import decode_client_profile, encode_packet, TransportPacket, session_aad
from Protocol.EnvelopeWire import encode_outer_envelope

struct AliceHeaderFixture do
  accounts :: GroupAccountFixture
  alice_profile :: Bytes
  bob_profile :: Bytes
  scope :: BraidScope
  bob_scope :: BraidScope
end

fn drop_header(state :: consume BraidAliceHeaderSent) do
  nil
end

fn report_result(result :: Result<(), String>) -> Result<(), String> do
  case result do
    Ok(_) -> Ok(nil)
    Err(reason) -> do
      println("C1 Alice fixture refusal: #{reason}")
      Err(reason)
    end
  end
end

fn no_fault() -> Result<(), String> do
  Ok(nil)
end

fn fixture() -> AliceHeaderFixture!String do
  let BraidHeFixture {
    accounts,
    alice_profile,
    bob_profile,
    scope,
    alice_auth,
    epoch_private,
    header
  } = setup()?
  # The legacy fixture generated a key for its own tests. It is never adopted.
  Secret.destroy(epoch_private)
  let local = %{scope |
    account_id: scope.peer_account_id,
    device_id: scope.peer_device_id,
    peer_account_id: scope.account_id,
    peer_device_id: scope.device_id
  }
  initialize_braid_alice_fixture(accounts.alice_path,
    alice_profile,
    BraidAliceIdle { scope: local, epoch: alice_auth.epoch, secrets: alice_auth.secrets })?
  Ok(AliceHeaderFixture {
    accounts: accounts,
    alice_profile: alice_profile,
    bob_profile: bob_profile,
    scope: local,
    bob_scope: scope
  })
end

fn cleanup(f :: AliceHeaderFixture) -> Result<(), String> do
  for path in [f.accounts.alice_path, f.accounts.bob_path, f.accounts.linked_path] do
    erase_local_state(path)?
    for suffix in [
      "",
      "-wal",
      "-shm",
      ".1.ready",
      ".2.ready",
      ".go",
      ".1.result",
      ".2.result",
      ".race",
      ".unknown",
      ".recovered",
      ".restart"
    ] do
      if File.exists(path <> suffix) do
        File.delete(path <> suffix)?
      end
    end
  end
  Ok(nil)
end

fn labels(f :: AliceHeaderFixture) -> List<String>!String do
  let key = platform_key()?
  let loaded = find_peer_session(f.accounts.alice_path,
    key,
    f.scope.peer_account_id,
    load_session_ids(f.accounts.alice_path, key)?,
    0)?
  Ok([
    "sessions/v1",
    loaded.label,
    "header-routing/v1",
    "history/v1/#{Bytes.to_hex(loaded.record.conversation_id)}",
    "outbox/v1",
    "postage-queue/v1",
    "delivery/v1"
  ]
    ++ braid_labels(f.scope)
    ++ alice_header_labels(f.scope))
end

fn prepared(f :: AliceHeaderFixture) -> BraidAliceHeaderOutcome!String do
  prepare_braid_header_once(f.accounts.alice_path, f.alice_profile, f.scope, no_fault)
end

fn recovered(f :: AliceHeaderFixture) -> BraidAliceHeaderOutcome!String do
  recover_braid_header(f.accounts.alice_path, f.alice_profile, f.scope)
end

fn metadata(f :: AliceHeaderFixture) -> Result<(), String> do
  let key = platform_key()?
  let ls = alice_header_labels(f.scope)
  let m = decode_alice_metadata(open_local(load_blob(f.accounts.alice_path, List.get(ls, 0))?,
      key,
      local_context(List.get(ls, 0))?)?,
    f.scope)?
  let saved = %{m.saved |
    secrets: load_blob(f.accounts.alice_path, List.get(ls, 1))?,
    epoch_key: load_blob(f.accounts.alice_path, List.get(ls, 2))?
  }
  let state = case restore_alice_header(saved, saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_restore_typed_epoch")
  end
  let (header, vector) = case Crypto.mlkem_public_parts(state.private_key) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_restored_public_parts")
  end
  alice_check(Bytes.length(saved.secrets) == 154
      && Bytes.length(saved.epoch_key) == 131
      && Bytes.secure_equals(header.bytes, saved.header)
      && Bytes.secure_equals(vector.bytes, saved.vector)
      && Bytes.length(vector.bytes) == 1152
      && !SecretMap.contains(state.secrets, Bytes.from_utf8("output")),
    "fixture_exact_header_key")?
  drop_header(state)
  Ok(nil)
end

fn peer_accept(f :: AliceHeaderFixture, sent :: BraidAliceHeaderOutcome) -> Result<(), String> do
  let key = platform_key()?
  let bob = decode_client_profile(f.bob_profile)?
  let loaded = find_peer_session(f.accounts.bob_path,
    key,
    f.scope.account_id,
    load_session_ids(f.accounts.bob_path, key)?,
    0)?
  let history = "history/v1/#{Bytes.to_hex(loaded.record.conversation_id)}"
  let prior = load_account_basis(f.accounts.bob_path, [history])?
  let outcome = receive_braid_control(f.accounts.bob_path,
    f.bob_profile,
    f.bob_scope,
    sent.envelope,
    no_fault)?
  alice_check(outcome.kind == 1
      && Bytes.length(outcome.output_id) == 0
      && Bytes.length(outcome.envelope) == 0,
    "fixture_actual_bob_admission")?
  let peer_label = List.head(braid_labels(f.bob_scope))
  let peer_record = open_local(load_blob(f.accounts.bob_path, peer_label)?,
    key,
    local_context(peer_label)?)?
  let admitted = raw_fields(fixture_reader(peer_record)?, 18, [])?
  let local = full_meta(f)?
  alice_check(Bytes.secure_equals(List.get(admitted, 12), local.saved.header),
    "fixture_emitted_header_matches_restored_epoch_key")?
  alice_check(same_account_basis(prior, load_account_basis(f.accounts.bob_path, [history])?),
    "fixture_no_peer_history")
end

fn exact(f :: AliceHeaderFixture) -> Result<(), String> do
  let key = platform_key()?
  let ids = load_outbox_ids(f.accounts.alice_path, key)?
  let ls = labels(f)?
  let before = load_account_basis(f.accounts.alice_path, ls)?
  let shared = case Secret.random(32) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_repeat_initializer")
  end
  let again = case initialize_initiator(f.scope, shared) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_repeat_initializer")
  end
  alice_check(case initialize_braid_alice_fixture(f.accounts.alice_path, f.alice_profile, again) do
      Err("c1_alice_already_initialized") -> true
      _ -> false
    end,
    "fixture_initializer_never_replaces")?
  Secret.destroy(shared)
  alice_check(same_account_basis(before, load_account_basis(f.accounts.alice_path, ls)?),
    "fixture_repeated_init_no_mutation")?
  let sent = prepared(f)?
  alice_check(sent.kind == 1
      && U64.compare(sent.epoch, U64.parse("1")?) == 0
      && U64.compare(sent.sending_epoch, U64.parse("0")?) == 0
      && Bytes.length(sent.transition) == 32
      && Bytes.length(sent.envelope_id) == 16,
    "fixture_first_prepared_header")?
  alice_check(List.length(load_outbox_ids(f.accounts.alice_path, key)?) == List.length(ids) + 1,
    "fixture_one_outbox_append")?
  let saved = load_account_basis(f.accounts.alice_path, ls)?
  alice_check(!same_account_basis(before, saved), "fixture_committed_generation")?
  metadata(f)?
  for i in 0..List.length(before.labels) do
    let label = List.get(before.labels, i)
    if List.contains(["header-routing/v1", "postage-queue/v1", "delivery/v1"], label)
      || String.starts_with(label, "history/v1/") do
      alice_check(Bytes.secure_equals(List.get(before.records, i), List.get(saved.records, i)),
        "fixture_guard_only_unchanged")?
    end
  end
  let r = recovered(f)?
  let retry = prepared(f)?
  alice_check(r.kind == 2
      && retry.kind == 2
      && Bytes.secure_equals(sent.envelope, r.envelope)
      && Bytes.secure_equals(sent.envelope, retry.envelope)
      && Bytes.secure_equals(sent.transition, r.transition)
      && Bytes.secure_equals(sent.envelope_id, r.envelope_id),
    "fixture_exact_recovery")?
  alice_check(same_account_basis(saved, load_account_basis(f.accounts.alice_path, ls)?),
    "fixture_retry_no_mutation")?
  # Settling the outbox does not authorize requeue or encrypt again.
  acknowledge_outbox(MobilePayloadRequest {
    database_path: f.accounts.alice_path,
    payload: sent.envelope
  })?
  let settled = load_account_basis(f.accounts.alice_path, ls)?
  alice_check(Bytes.secure_equals(prepared(f)?.envelope, sent.envelope)
      && same_account_basis(settled, load_account_basis(f.accounts.alice_path, ls)?),
    "fixture_settled_not_requeued")?
  peer_corruption(f, sent)?
  peer_accept(f, sent)
end

pub fn first_send_and_recovery() -> Result<(), String> do
  let f = fixture()?
  let result = exact(f)
  cleanup(f)?
  report_result(result)
end

fn fixture_slice(value :: Bytes, start :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(value, start, length) do
    Ok(v)
    Err(_) -> Err("fixture_slice")
  end
end

fn fixture_reader(value :: Bytes) -> BinaryReader!String do
  case reader(value, 4096) do
    Ok(v)
    Err(_) -> Err("fixture_reader")
  end
end

fn flipped(value :: Bytes) -> Bytes!String do
  let old = case Bytes.get(value, 0) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_flip_empty")
  end
  mobile_join([
      repeated(if old == 0 do
          1
        else
          0
        end,
        1)?,
      fixture_slice(value, 1, Bytes.length(value) - 1)?
    ],
    0,
    Bytes.empty())
end

fn source_fences(f :: AliceHeaderFixture) -> Result<(), String> do
  let path = f.accounts.alice_path
  let ls = labels(f)?
  for label in ls ++ ["profile/v1"] do
    let original = case load_blob(path, label) do
      Ok(v) -> v
      Err(_) -> Bytes.empty()
    end
    let changed = if Bytes.length(original) == 0 do
      Bytes.from_utf8("fixture appeared")
    else
      flipped(original)?
    end
    let result = prepare_braid_header_once(path,
      f.alice_profile,
      f.scope,
      fn() -> store_updated_blobs(path, [label], [changed]) end)
    alice_check(case result do
        Err("account_state_changed") -> true
        _ -> false
      end,
      "fixture_exact_source_fence")?
    alice_check(Bytes.secure_equals(load_blob(path, label)?, changed), "fixture_winner_preserved")?
    if Bytes.length(original) == 0 do
      store_record_changes(path, [], [], [label])?
    else
      store_updated_blobs(path, [label], [original])?
    end
  end
  # A real valid profile reseal changes ciphertext custody even when public bytes agree.
  let key = platform_key()?
  let old_profile = load_blob(path, "profile/v1")?
  let public = open_local(old_profile, key, local_context("profile/v1")?)?
  let new_profile = seal_local(public, key, local_context("profile/v1")?)?
  alice_check(case prepare_braid_header_once(path,
      f.alice_profile,
      f.scope,
      fn() -> store_updated_blobs(path, ["profile/v1"], [new_profile]) end) do
      Err("account_state_changed") -> true
      _ -> false
    end,
    "fixture_valid_profile_reseal_fence")?
  store_updated_blobs(path, ["profile/v1"], [old_profile])?
  real_session_races(f)
end

pub fn account_source_races() -> Result<(), String> do
  let f = fixture()?
  let result = source_fences(f)
  cleanup(f)?
  report_result(result)
end

fn await_file(path :: String, n :: Int) -> Bool do
  if File.exists(path) do
    case File.read(path) do
      Ok(value) -> if String.length(value) > 0 do
        return true
      end
      Err(_) -> nil
    end
  end
  if n <= 0 do
    false
  else
    Timer.sleep(5)
    await_file(path, n - 1)
  end
end

actor alice_header_racer(path :: String, profile :: Bytes, scope :: BraidScope, n :: Int) do
  let result = prepare_braid_header_once(path,
    profile,
    scope,
    fn() do
      File.write(path <> ".#{n}.ready", "ready")?
      alice_check(await_file(path <> ".go", 2000), "fixture_barrier_timeout")
    end)
  File.write(path <> ".#{n}.result",
    case result do
      Ok(v) -> if v.kind == 1 do
        "new"
      else
        "recovered"
      end
      Err("account_state_changed") -> "changed"
      Err(_) -> "unexpected"
    end)
end

actor alice_header_race_master(path :: String, profile :: Bytes, scope :: BraidScope) do
  let a = spawn(alice_header_racer, path, profile, scope, 1)
  let b = spawn(alice_header_racer, path, profile, scope, 2)
  Process.monitor(a, "a")
  Process.monitor(b, "b")
  if await_file(path <> ".1.ready", 2000) && await_file(path <> ".2.ready", 2000) do
    File.write(path <> ".go", "go")
    let first = receive do
      text -> text
      after 15000 -> "timeout"
    end
    let second = receive do
      text -> text
      after 15000 -> "timeout"
    end
    File.write(path <> ".race",
      if (first == "a" && second == "b") || (first == "b" && second == "a") do
        "ok"
      else
        "timeout"
      end)
  else
    File.write(path <> ".race", "not-prepared")
  end
end

fn race(f :: AliceHeaderFixture) -> Result<(), String> do
  let path = f.accounts.alice_path
  let _master = spawn(alice_header_race_master, path, f.alice_profile, f.scope)
  alice_check(await_file(path <> ".race", 5000) && File.read(path <> ".race")? == "ok",
    "fixture_race_finished")?
  let a = File.read(path <> ".1.result")?
  let b = File.read(path <> ".2.result")?
  alice_check((a == "new" && b == "changed") || (a == "changed" && b == "new"),
    "fixture_single_header_winner")?
  let r = recovered(f)?
  metadata(f)?
  peer_accept(f, r)
end

pub fn competing_prepares() -> Result<(), String> do
  let f = fixture()?
  let result = race(f)
  cleanup(f)?
  report_result(result)
end

actor alice_header_unknown_writer(path :: String, profile :: Bytes, scope :: BraidScope) do
  let result = prepare_braid_header_fault(path,
    profile,
    scope,
    no_fault,
    fn() -> Err("fixture_lost_reply") end)
  File.write(path <> ".unknown",
    case result do
      Err("fixture_lost_reply") -> "unknown"
      _ -> "unexpected"
    end)
end

actor alice_header_fresh_reader(path :: String, profile :: Bytes, scope :: BraidScope) do
  let result = recover_braid_header(path, profile, scope)
  File.write(path <> ".recovered",
    case result do
      Ok(v) -> Bytes.to_hex(v.transition)
        <> ":"
        <> Bytes.to_hex(v.envelope_id)
        <> ":"
        <> Bytes.to_hex(v.envelope)
      Err(_) -> "refused"
    end)
end

actor alice_header_restart_master(path :: String, profile :: Bytes, scope :: BraidScope) do
  let w = spawn(alice_header_unknown_writer, path, profile, scope)
  Process.monitor(w, "writer")
  let a = receive do
    text -> text
    after 15000 -> "timeout"
  end
  if a == "writer" do
    let r = spawn(alice_header_fresh_reader, path, profile, scope)
    Process.monitor(r, "reader")
    let b = receive do
      text -> text
      after 15000 -> "timeout"
    end
    File.write(path <> ".restart",
      if b == "reader" do
        "ok"
      else
        "timeout"
      end)
  else
    File.write(path <> ".restart", "timeout")
  end
end

fn unknown(f :: AliceHeaderFixture) -> Result<(), String> do
  let path = f.accounts.alice_path
  let _master = spawn(alice_header_restart_master, path, f.alice_profile, f.scope)
  alice_check(await_file(path <> ".restart", 5000)
      && File.read(path <> ".restart")? == "ok"
      && File.read(path <> ".unknown")? == "unknown",
    "fixture_lost_reply_committed")?
  let before = load_account_basis(path, labels(f)?)?
  let r = recovered(f)?
  alice_check(File.read(path <> ".recovered")? == Bytes.to_hex(r.transition)
        <> ":"
        <> Bytes.to_hex(r.envelope_id)
        <> ":"
        <> Bytes.to_hex(r.envelope),
    "fixture_fresh_actor_exact")?
  metadata(f)?
  alice_check(same_account_basis(before, load_account_basis(path, labels(f)?)?),
    "fixture_fresh_actor_readonly")?
  peer_accept(f, r)
end

pub fn lost_reply_fresh_actor() -> Result<(), String> do
  let f = fixture()?
  let result = unknown(f)
  cleanup(f)?
  report_result(result)
end

fn full_meta(f :: AliceHeaderFixture) -> AliceHeaderMetadata!String do
  let key = platform_key()?
  let ls = alice_header_labels(f.scope)
  let m = decode_alice_metadata(open_local(load_blob(f.accounts.alice_path, List.get(ls, 0))?,
      key,
      local_context(List.get(ls, 0))?)?,
    f.scope)?
  Ok(%{m |
    saved: %{m.saved |
      secrets: load_blob(f.accounts.alice_path, List.get(ls, 1))?,
      epoch_key: load_blob(f.accounts.alice_path, List.get(ls, 2))?
    }
  })
end

fn write_meta(f :: AliceHeaderFixture, m :: AliceHeaderMetadata) -> Result<(), String> do
  let key = platform_key()?
  let label = List.head(alice_header_labels(f.scope))
  store_updated_blobs(f.accounts.alice_path,
    [label],
    [seal_local(alice_metadata_bytes(m)?, key, local_context(label)?)?])
end

fn refused_unchanged(f :: AliceHeaderFixture) -> Result<(), String> do
  let before = load_account_basis(f.accounts.alice_path, labels(f)?)?
  alice_check(Result.is_err(recovered(f)) && Result.is_err(prepared(f)),
    "fixture_corrupt_refused_no_fallback")?
  alice_check(same_account_basis(before, load_account_basis(f.accounts.alice_path, labels(f)?)?),
    "fixture_corrupt_refusal_no_write")
end

fn raw_fields(r :: BinaryReader, n :: Int, fields :: List<Bytes>) -> List<Bytes>!String do
  if n == 0 do
    Ok(fields)
  else
    let (next, field) = case read_vector(r, 1152) do
      Ok(v) -> v
      Err(_) -> return Err("fixture_raw_fields")
    end
    raw_fields(next, n - 1, List.append(fields, field))
  end
end

fn replace_field(fields :: List<Bytes>, at :: Int, replacement :: Bytes) -> Bytes!String do
  mobile_join(for i in 0..List.length(fields) do
      mobile_vector(if i == at do
        replacement
      else
        List.get(fields, i)
      end)?
    end,
    0,
    Bytes.empty())
end

fn refusals(f :: AliceHeaderFixture) -> Result<(), String> do
  let key = platform_key()?
  let ls = alice_header_labels(f.scope)
  let idle_secrets = load_blob(f.accounts.alice_path, List.get(ls, 1))?
  prepared(f)?
  let m = full_meta(f)?
  let original = load_blob(f.accounts.alice_path, List.head(ls))?
  let plain = open_local(original, key, local_context(List.head(ls))?)?
  let fields = raw_fields(fixture_reader(plain)?, 21, [])?
  let malformed = [
    fixture_slice(plain, 0, Bytes.length(plain) - 1)?,
    mobile_join([plain, repeated(0, 1)?], 0, Bytes.empty())?,
    repeated(0, 4097)?,
    replace_field(fields, 15, repeated(0, 1153)?)?,
    replace_field(fields, 8, repeated(2, 1)?)?,
    replace_field(fields, 9, repeated(2, 1)?)?,
    replace_field(fields, 11, repeated(0, 8)?)?,
    replace_field(fields, 7, repeated(9, 32)?)?,
    replace_field(fields, 1, repeated(9, 32)?)?,
    replace_field(fields, 3, repeated(9, 32)?)?,
    replace_field(fields, 12, repeated(9, 32)?)?,
    replace_field(fields, 18, repeated(9, 32)?)?,
    replace_field(fields, 19, repeated(9, 16)?)?,
    replace_field(fields, 20, repeated(9, 32)?)?
  ]
  for bad in malformed do
    store_updated_blobs(f.accounts.alice_path,
      [List.head(ls)],
      [seal_local(bad, key, local_context(List.head(ls))?)?])?
    refused_unchanged(f)?
  end
  store_updated_blobs(f.accounts.alice_path, [List.head(ls)], [original])?
  for i in [1, 2, 3] do
    let label = List.get(ls, i)
    let blob = load_blob(f.accounts.alice_path, label)?
    store_updated_blobs(f.accounts.alice_path, [label], [flipped(blob)?])?
    refused_unchanged(f)?
    store_updated_blobs(f.accounts.alice_path, [label], [blob])?
  end
  # A valid old phase0 authenticator is not a HeaderSent authenticator.
  store_updated_blobs(f.accounts.alice_path, [List.get(ls, 1)], [idle_secrets])?
  write_meta(f, %{m | secrets_hash: Crypto.sha256(idle_secrets)})?
  refused_unchanged(f)?
  store_updated_blobs(f.accounts.alice_path, List.take(ls, 2), [original, m.saved.secrets])?
  # A valid purpose23 key under another transition context cannot be transplanted.
  let restored = case restore_alice_header(m.saved, m.saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_restore_original")
  end
  let other_saved = case save_alice_header(restored, key, U64.parse("3")?, repeated(8, 32)?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_other_key_context")
  end
  store_updated_blobs(f.accounts.alice_path, [List.get(ls, 2)], [other_saved.epoch_key])?
  write_meta(f, %{m | epoch_key_hash: Crypto.sha256(other_saved.epoch_key)})?
  refused_unchanged(f)?
  drop_header(restored)
  store_updated_blobs(f.accounts.alice_path,
    [List.head(ls), List.get(ls, 2)],
    [original, m.saved.epoch_key])?
  # Local wrapping under another context/key is refused before replacement.
  let wrong = case StorageKey.ephemeral() do
    Ok(v) -> v
    Err(_) -> return Err("fixture_wrong_key")
  end
  for blob in [
    seal_local(plain, key, local_context("wrong-alice-context")?)?,
    seal_local(plain, wrong, local_context(List.head(ls))?)?
  ] do
    store_updated_blobs(f.accounts.alice_path, [List.head(ls)], [blob])?
    refused_unchanged(f)?
  end
  store_updated_blobs(f.accounts.alice_path, [List.head(ls)], [original])?
  metadata(f)?
  session_integrity_refusals(f)
end

pub fn authenticated_storage_refusals() -> Result<(), String> do
  let f = fixture()?
  let result = refusals(f)
  cleanup(f)?
  report_result(result)
end

fn replacement(f :: AliceHeaderFixture) -> Result<(), String> do
  let path = f.accounts.alice_path
  let before = load_account_basis(path, labels(f)?)?
  let result = prepare_braid_header_once(path,
    f.alice_profile,
    f.scope,
    fn() do
      erase_account_if_current(path, before.profile)?
      create_account(MobileAccountRequest {
        database_path: Bytes.from_utf8(path),
        username: Bytes.from_utf8("alicereplacement")
      })?
      Ok(nil)
    end)
  alice_check(case result do
      Err("account_state_changed") -> true
      _ -> false
    end,
    "fixture_replacement_fence")?
  alice_check(!Bytes.secure_equals(load_profile(path)?, f.alice_profile),
    "fixture_real_account_replaced")?
  for label in alice_header_labels(f.scope)
    ++ braid_labels(f.scope)
    ++ ["outbox/v1", "session/v1/#{Bytes.to_hex(f.scope.session_id)}"] do
    alice_check(Result.is_err(load_blob(path, label)), "fixture_no_old_generation_resurrected")?
  end
  Ok(nil)
end

fn failure(f :: AliceHeaderFixture) -> Result<(), String> do
  let path = f.accounts.alice_path
  let before = load_account_basis(path, labels(f)?)?
  alice_check(case prepare_braid_header_once(path,
      f.alice_profile,
      f.scope,
      fn() -> Err("fixture_abort_before_commit") end) do
      Err("fixture_abort_before_commit") -> true
      _ -> false
    end,
    "fixture_abort_refused")?
  alice_check(same_account_basis(before, load_account_basis(path, labels(f)?)?),
    "fixture_abort_all_or_none")?
  let key = platform_key()?
  let original = load_blob(path, "outbox/v1")?
  let full = encode_output_list(for i in 0..256 do
    fixture_slice(Crypto.sha256(Bytes.from_utf8("#{i}")), 0, 16)?
  end)?
  store_updated_blobs(path, ["outbox/v1"], [seal_local(full, key, local_context("outbox/v1")?)?])?
  let full_before = load_account_basis(path, labels(f)?)?
  alice_check(case prepared(f) do
      Err("outbox_full") -> true
      _ -> false
    end,
    "fixture_full_outbox_refused")?
  alice_check(same_account_basis(full_before, load_account_basis(path, labels(f)?)?),
    "fixture_full_outbox_no_partial")?
  store_updated_blobs(path, ["outbox/v1"], [original])?
  replacement(f)
end

pub fn commit_failure_boundaries() -> Result<(), String> do
  let f = fixture()?
  let result = failure(f)
  cleanup(f)?
  report_result(result)
end

fn peer_message(f :: AliceHeaderFixture, wire :: Bytes) -> RatchetMessage!String do
  let key = platform_key()?
  let bob = decode_client_profile(f.bob_profile)?
  let device = open_device(bob, key, f.accounts.bob_path)?
  let outer = canonical_outer(wire)?
  let opened = open_outer_packet(outer, device.identity_private_key)?
  alice_check(opened.sealed, "fixture_recipient_sealed")?
  case decode_ratchet_message(parse_ratchet_packet(opened.packet)?) do
    Ok(v)
    Err(_) -> Err("fixture_ratchet_message")
  end
end

fn peer_corruption(f :: AliceHeaderFixture,
  sent :: BraidAliceHeaderOutcome) -> Result<(), String> do
  let bob_labels = [
    "sessions/v1",
    "session/v1/#{Bytes.to_hex(f.scope.session_id)}",
    "header-routing/v1"
  ]
    ++ braid_labels(f.bob_scope)
  let before = load_account_basis(f.accounts.bob_path, bob_labels)?
  let outer = canonical_outer(sent.envelope)?
  let damaged = case encode_outer_envelope(%{outer | ciphertext: flipped(outer.ciphertext)?}) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_corrupt_outer")
  end
  let bob = decode_client_profile(f.bob_profile)?
  let message = peer_message(f, sent.envelope)?
  let bad_he = sealed_outer_bytes(bob.entry.mailbox_token,
    encode_packet(RatchetPacket(ratchet_bytes(%{message |
      ciphertext: flipped(message.ciphertext)?
    })?))?,
    bob.credential.dh_public_key,
    current_time()?)?
  for wire in [damaged, bad_he] do
    alice_check(Result.is_err(receive_braid_control(f.accounts.bob_path,
        f.bob_profile,
        f.bob_scope,
        wire,
        no_fault)),
      "fixture_actual_authentication_refusal")?
    alice_check(same_account_basis(before, load_account_basis(f.accounts.bob_path, bob_labels)?),
      "fixture_auth_refusal_no_peer_mutation")?
  end
  Ok(nil)
end

fn internal_mac(f :: AliceHeaderFixture) -> Result<(), String> do
  prepared(f)?
  let key = platform_key()?
  let m = full_meta(f)?
  let loaded = find_peer_session(f.accounts.alice_path,
    key,
    f.scope.peer_account_id,
    load_session_ids(f.accounts.alice_path, key)?,
    0)?
  let before = load_account_basis(f.accounts.alice_path, ["sessions/v1", loaded.label])?
  let payload = braid_header_carrier(f.scope,
    m.saved.epoch,
    mobile_join([m.saved.header, repeated(0, 32)?], 0, Bytes.empty())?)?
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    payload,
    session_aad(loaded.session_id)?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_valid_he_bad_mac")
  end
  let bob = decode_client_profile(f.bob_profile)?
  let wire = sealed_outer_bytes(bob.entry.mailbox_token,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    bob.credential.dh_public_key,
    current_time()?)?
  commit_account_changes(f.accounts.alice_path,
    before,
    [loaded.label],
    [seal_updated_session(next, loaded, key)?],
    [])?
  alice_check(case receive_braid_control(f.accounts.bob_path,
      f.bob_profile,
      f.bob_scope,
      wire,
      no_fault) do
      Err("c1_terminal_generation") -> true
      _ -> false
    end,
    "fixture_scoped_bad_mac_terminal")?
  let committed = load_account_basis(f.accounts.bob_path, braid_labels(f.bob_scope))?
  for label in List.drop(braid_labels(f.bob_scope), 1) do
    alice_check(Result.is_err(load_blob(f.accounts.bob_path, label)),
      "fixture_terminal_no_secrets")?
  end
  alice_check(case receive_braid_control(f.accounts.bob_path,
      f.bob_profile,
      f.bob_scope,
      wire,
      no_fault) do
      Err("c1_terminal_generation") -> true
      _ -> false
    end,
    "fixture_terminal_replay_refused")?
  alice_check(same_account_basis(committed,
      load_account_basis(f.accounts.bob_path, braid_labels(f.bob_scope))?),
    "fixture_terminal_stable")
end

pub fn actual_authentication_boundaries() -> Result<(), String> do
  let f = fixture()?
  let result = internal_mac(f)
  cleanup(f)?
  report_result(result)
end

fn session_integrity_refusals(f :: AliceHeaderFixture) -> Result<(), String> do
  let key = platform_key()?
  let path = f.accounts.alice_path
  let loaded = find_peer_session(path,
    key,
    f.scope.peer_account_id,
    load_session_ids(path, key)?,
    0)?
  let original = load_blob(path, loaded.label)?
  let root = case Secret.random(32) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_classical_root")
  end
  let bootstrap = case Crypto.x25519_generate() do
    Ok(v) -> v
    Err(_) -> return Err("fixture_classical_bootstrap")
  end
  let classical = case he_initialize_alice(root,
    1,
    f.scope.session_id,
    bootstrap.public_key,
    U64.parse("1")?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_classical_he")
  end
  Secret.destroy(bootstrap.private_key)
  let blob = seal_updated_session(classical, loaded, key)?
  store_updated_blobs(path, [loaded.label], [blob])?
  refused_unchanged(f)?
  let shared = case Secret.random(32) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_new_initializer")
  end
  let idle = case initialize_initiator(f.scope, shared) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_new_initializer")
  end
  alice_check(case initialize_braid_alice_fixture(path, f.alice_profile, idle) do
      Err("c1_alice_session_changed") -> true
      _ -> false
    end,
    "fixture_classical_init_refused")?
  Secret.destroy(shared)
  let snapshot = loaded.record.snapshot
  let bad = mobile_join([
      fixture_slice(snapshot, 0, Bytes.length(snapshot) - 1)?,
      flipped(fixture_slice(snapshot, Bytes.length(snapshot) - 1, 1)?)?
    ],
    0,
    Bytes.empty())?
  store_updated_blobs(path,
    [loaded.label],
    [seal_local(updated_session_record(bad, loaded.record)?, key, local_context(loaded.label)?)?])?
  refused_unchanged(f)?
  store_updated_blobs(path, [loaded.label], [original])?
  Ok(nil)
end

fn concurrent_he_receive(f :: AliceHeaderFixture) -> Result<(), String> do
  let key = platform_key()?
  let bob = find_peer_session(f.accounts.bob_path,
    key,
    f.scope.account_id,
    load_session_ids(f.accounts.bob_path, key)?,
    0)?
  let bob_basis = load_account_basis(f.accounts.bob_path, ["sessions/v1", bob.label])?
  let (next_bob, message) = case encrypt_sealed(restore_session(bob, key)?,
    Bytes.from_utf8("TEST concurrent HE receive"),
    session_aad(bob.session_id)?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_concurrent_bob_send")
  end
  let bob_blob = seal_updated_session(next_bob, bob, key)?
  commit_account_changes(f.accounts.bob_path, bob_basis, [bob.label], [bob_blob], [])?
  let alice = find_peer_session(f.accounts.alice_path,
    key,
    f.scope.peer_account_id,
    load_session_ids(f.accounts.alice_path, key)?,
    0)?
  let alice_basis = load_account_basis(f.accounts.alice_path, ["sessions/v1", alice.label])?
  let next = case decrypt(restore_session(alice, key)?, message, session_aad(alice.session_id)?) do
    Opened(state, plaintext) -> state
    Rejected(state, _) -> return Err("fixture_concurrent_alice_receive")
  end
  let blob = seal_updated_session(next, alice, key)?
  commit_account_changes(f.accounts.alice_path, alice_basis, [alice.label], [blob], [])
end

fn real_session_races(f :: AliceHeaderFixture) -> Result<(), String> do
  let key = platform_key()?
  let path = f.accounts.alice_path
  let loaded = find_peer_session(path,
    key,
    f.scope.peer_account_id,
    load_session_ids(path, key)?,
    0)?
  let original = load_blob(path, loaded.label)?
  let static_labels = labels(f)?
  for record in [
    %{loaded.record | blocked: true},
    %{loaded.record | peer_account_id: repeated(9, 32)?}
  ] do
    let changed = seal_local(updated_session_record(record.snapshot, record)?,
      key,
      local_context(loaded.label)?)?
    alice_check(case prepare_braid_header_once(path,
        f.alice_profile,
        f.scope,
        fn() -> store_updated_blobs(path, [loaded.label], [changed]) end) do
        Err("account_state_changed") -> true
        _ -> false
      end,
      "fixture_valid_session_update_fence")?
    let changed_basis = load_account_basis(path, static_labels)?
    alice_check(Result.is_err(recovered(f)) && Result.is_err(prepared(f)),
      "fixture_rebound_or_blocked_refused")?
    alice_check(same_account_basis(changed_basis, load_account_basis(path, static_labels)?),
      "fixture_rebound_or_blocked_no_write")?
    store_updated_blobs(path, [loaded.label], [original])?
  end
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    Bytes.from_utf8("TEST concurrent HE send"),
    session_aad(loaded.session_id)?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_concurrent_he_send")
  end
  let changed = seal_updated_session(next, loaded, key)?
  alice_check(case prepare_braid_header_once(path,
      f.alice_profile,
      f.scope,
      fn() -> store_updated_blobs(path, [loaded.label], [changed]) end) do
      Err("account_state_changed") -> true
      _ -> false
    end,
    "fixture_actual_he_send_fence")?
  store_updated_blobs(path, [loaded.label], [original])?
  alice_check(case prepare_braid_header_once(path,
      f.alice_profile,
      f.scope,
      fn() -> concurrent_he_receive(f) end) do
      Err("account_state_changed") -> true
      _ -> false
    end,
    "fixture_actual_he_receive_fence")?
  Ok(nil)
end
