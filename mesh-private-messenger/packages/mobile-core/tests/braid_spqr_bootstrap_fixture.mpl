from Protocol.HandshakeWire import decode_initial_message, encode_initial_message

##! TEST ONLY genuine production-form account/prekey bootstrap fixture.
from Mobile.BraidSpqrBootstrap import (
  BootstrapResult,
  start_braid_spqr_once,
  receive_braid_spqr_initial,
  recover_braid_spqr_initial
)
from Mobile.BraidSpqrState import (
  braid_spqr_labels,
  decode_braid_spqr_metadata,
  braid_spqr_descriptor,
  BraidSpqrMetadata
)
from Mobile.Profile import (
  load_profile,
  open_device,
  open_account,
  policy
)
from Mobile.Prekeys import (
  load_prekey_pool,
  load_active_prekey_pool,
  open_captured_prekey_pools,
  seal_active_prekey_pool,
  find_last_resort_prekey
)
from Mobile.Renewal import open_bundle_prekeys
from Mobile.Sessions import (
  load_session_ids,
  load_session_record,
  restore_session,
  parse_sealed_initial_packet
)
from Mobile.Outbox import (
  load_outbox_ids,
  load_outbox_entry
)
from Mobile.SessionPolicy import (
  capture_native_session_policy,
  native_session_minimum
)
from Mobile.Transport import (
  open_outer_packet,
  sealed_outer_bytes
)
from Mobile.Codec import (
  canonical_outer,
  mobile_join,
  mobile_write_u64,
  mobile_vector,
  current_time
)
from MobileCore import (
  create_account_export,
  create_link_request_export,
  authorize_device_link_export,
  complete_device_link_export,
  directory_entry_export
)
from Storage.Keys import (
  platform_key,
  local_context,
  open_local,
  one_time_prekey_label,
  context,
  open_x25519,
  one_time_prekey_context,
  seal_local,
  seal_x25519,
  seal_mlkem
)
from Storage.Blobs import (
  load_blob
)
from Storage.Records import (
  erase_local_state,
  store_updated_blobs
)
from Session.Spqr import (
  SpqrState
)
from Session.SpqrStore import (
  SpqrSaved,
  restore_spqr
)
from Session.BraidBilateralStore import (
  BraidBilateralSaved,
  restore_alice_idle
)
from Session.BraidStore import (
  BraidSaved,
  restore_await
)
from Session.BraidInitiator import (
  send_header
)
from Session.BraidResponder import (
  admit_complete_header,
  BraidScope,
  BraidHeaderAdmission
)
from Session.BraidFragment import (
  BraidFragmentKind
)
from Session.BraidFragmentWords import (
  emit_braid_fragment
)
from Session.HeaderRatchet import (
  he_encrypt_hybrid,
  he_decrypt_hybrid,
  HybridSendOutcome,
  HybridReceiveOutcome
)
from Transport.Packet import (
  decode_client_profile,
  encode_client_profile,
  session_aad,
  TransportPacket,
  encode_packet
)
from Protocol.DirectoryWire import (
  decode_directory_entry,
  encode_device_set
)
from Protocol.IdentityWire import (
  decode_account_identity,
  decode_device_credential
)
from Protocol.PrekeyWire import (
  decode_prekey_bundle,
  encode_prekey_bundle
)
from Identity.Device import issue_hybrid_device_credential
from Prekeys.Bundle import (
  generate_post_quantum_prekey,
  generate_signed_prekey,
  generate_one_time_prekey,
  build_hybrid_prekey_bundle,
  OneTimePrekeySecrets
)
from Protocol.V1 import (
  DeviceSet
)
from Session.Handshake import receive_initial_braid_spqr_at_minimum_suite
from Transparency.Merkle import (
  leaf_hash
)
from Tests.GroupLifecycleSupport import (
  GroupAccountFixture,
  install_signed_transparency
)
from Tests.GroupConsistencySupport import (
  SignedTransparencyViewFixture,
  signed_transparency_view,
  request
)
from Tests.Support import (
  repeated
)

pub struct BootstrapAccounts do
  accounts :: GroupAccountFixture
  alice_profile :: Bytes
  bob_profile :: Bytes
end

fn config() -> Bytes do
  Crypto.sha256(Bytes.from_utf8("TEST ONLY durable B0 profile"))
end

fn intent() -> Bytes do
  Crypto.sha256(Bytes.from_utf8("TEST ONLY B0 intent"))
end

fn conversation() -> Bytes!String do
  repeated(7, 16)
end

fn accounts() -> BootstrapAccounts!String do
  check(Test.install_in_memory_secure_store(), "fixture_secure_store")?
  let a = owned_accounts()?
  let signed = signed_transparency_view([leaf_hash(a.alice_set)?, leaf_hash(a.bob_set)?])?
  install_policy(signed)?
  for path in [a.alice_path, a.bob_path] do
    check(install_signed_transparency(path, signed, a.alice_set)?, "fixture_alice_transparency")?
    check(install_signed_transparency(path, signed, a.bob_set)?, "fixture_bob_transparency")?
  end
  # Transparency setup installs its own version1 frame. Restore and assert the
  # actual release policy after that helper's final native-config write.
  install_policy(signed)?
  Ok(BootstrapAccounts {
    alice_profile: load_profile(a.alice_path)?,
    bob_profile: load_profile(a.bob_path)?,
    accounts: a
  })
end

fn cleanup(f :: BootstrapAccounts) -> Unit!String do
  for path in [f.accounts.alice_path, f.accounts.bob_path, f.accounts.linked_path] do
    erase_local_state(path)?
  end
  Ok(nil)
end

fn start(f :: BootstrapAccounts) -> BootstrapResult!String do
  start_braid_spqr_once(f.accounts.alice_path,
    f.alice_profile,
    f.bob_profile,
    conversation()?,
    config(),
    intent())
end

fn receive_initial_control(f :: BootstrapAccounts, envelope :: Bytes) -> BootstrapResult!String do
  receive_braid_spqr_initial(f.accounts.bob_path,
    f.bob_profile,
    f.alice_profile,
    conversation()?,
    config(),
    envelope)
end

fn recover(f :: BootstrapAccounts) -> BootstrapResult!String do
  let peer = decode_client_profile(f.bob_profile)?
  recover_braid_spqr_initial(f.accounts.alice_path,
    f.alice_profile,
    peer.account_id,
    peer.device_id,
    config(),
    intent())
end

fn metadata(path :: String, scope :: BraidScope) -> BraidSpqrMetadata!String do
  let key = platform_key()?
  let label = List.get(braid_spqr_labels(scope), 0)
  decode_braid_spqr_metadata(open_local(load_blob(path, label)?, key, local_context(label)?)?,
    scope)
end

fn consumer(path :: String, m :: BraidSpqrMetadata) -> SpqrState!String do
  let key = platform_key()?
  let labels = braid_spqr_labels(m.scope)
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
    chains: load_blob(path, List.get(labels, 4))?,
    skipped: load_blob(path, List.get(labels, 5))?
  }
  restore_spqr(saved, saved, key)
end

## Canonical logical encrypted-row and blob-index metadata comparison, not DB bytes.
fn row_set(path :: String) -> List<Bytes>!String do
  let db = Sqlite.open(path)?
  let rows = Sqlite.query_values(db,
    "SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash",
    [])?
  let indices = Sqlite.query_values(db,
    "SELECT version, database_id, key_check FROM encrypted_blob_index ORDER BY version",
    [])?
  Sqlite.close(db)
  check(List.length(indices) == 1, "fixture_blob_index_count")?
  let index = List.head(indices)
  let version = case Map.get(index, "version") do
    Text(v) -> Bytes.from_utf8(v)
    _ -> return Err("fixture_blob_index_version")
  end
  let database = case Map.get(index, "database_id") do
    Binary(v) -> v
    _ -> return Err("fixture_blob_index_database")
  end
  let key_check = case Map.get(index, "key_check") do
    Binary(v) -> v
    _ -> return Err("fixture_blob_index_key")
  end
  let header = mobile_join([
      Bytes.from_utf8("IDX2"),
      mobile_vector(version)?,
      mobile_vector(database)?,
      mobile_vector(key_check)?
    ],
    0,
    Bytes.empty())?
  let result = for row in rows do
    let name = case Map.get(row, "record_hash") do
      Text(v) -> Bytes.from_utf8(v)
      _ -> return Err("fixture_record_hash")
    end
    let ciphertext = case Map.get(row, "ciphertext") do
      Binary(v) -> v
      _ -> return Err("fixture_ciphertext_row")
    end
    mobile_join([Bytes.from_utf8("ROW2"), mobile_vector(name)?, mobile_vector(ciphertext)?],
      0,
      Bytes.empty())?
  end
  Ok([header] ++ result)
end

fn equal_rows(a :: List<Bytes>, b :: List<Bytes>) -> Bool do
  List.length(a) == List.length(b)
    && List.all(for i in 0..List.length(a) do
        Bytes.secure_equals(List.get(a, i), List.get(b, i))
      end,
      fn(v) -> v end)
end

fn actual_pair(f :: BootstrapAccounts) -> Unit!String do
  let sent = start(f)?
  let accepted = receive_initial_control(f, sent.envelope)?
  check(Bytes.secure_equals(sent.scope.session_id, accepted.scope.session_id),
    "fixture_real_session_agreement")?
  let schema_key = platform_key()?
  let attempt_label = "c1/bootstrap/v1/#{Bytes.to_hex(config())}/#{Bytes.to_hex(sent.scope.peer_account_id)}/#{Bytes.to_hex(sent.scope.peer_device_id)}"
  let attempt = open_local(load_blob(f.accounts.alice_path, attempt_label)?,
    schema_key,
    local_context(attempt_label)?)?
  check(Bytes.length(attempt) == 262
      && Bytes.secure_equals(Bytes.slice(attempt, 0, 4)?, Bytes.from_utf8("CBI1"))
      && Bytes.get(attempt, 4)? == 1
      && Bytes.get(attempt, 5)? == 0
      && Bytes.secure_equals(Bytes.slice(attempt, 6, 32)?, config())
      && Bytes.secure_equals(Bytes.slice(attempt, 38, 32)?, sent.scope.session_id)
      && Bytes.secure_equals(Bytes.slice(attempt, 70, 32)?, sent.scope.peer_account_id)
      && Bytes.secure_equals(Bytes.slice(attempt, 102, 16)?, sent.scope.peer_device_id)
      && Bytes.secure_equals(Bytes.slice(attempt, 118, 32)?, intent())
      && Bytes.secure_equals(Bytes.slice(attempt, 150, 32)?, repeated(0, 32)?)
      && Bytes.secure_equals(Bytes.slice(attempt, 182, 32)?, Crypto.sha256(sent.envelope))
      && Bytes.secure_equals(Bytes.slice(attempt, 214, 32)?, sent.transition)
      && Bytes.secure_equals(Bytes.slice(attempt, 246, 16)?, conversation()?),
    "fixture_independent_CBI1_schema")?
  let ma = metadata(f.accounts.alice_path, sent.scope)?
  let mb = metadata(f.accounts.bob_path, accepted.scope)?
  check(ma.phase == 0
      && ma.kernel_tag == 2
      && mb.phase == 4
      && mb.kernel_tag == 0
      && ma.direction == 0
      && mb.direction == 1
      && U64.compare(ma.local_epoch, U64.parse("0")?) == 0
      && U64.compare(mb.knowledge, U64.parse("0")?) == 0,
    "fixture_epoch_zero_metadata")?
  let key = platform_key()?
  let pa = consumer(f.accounts.alice_path, ma)?
  let pb = consumer(f.accounts.bob_path, mb)?
  let la = load_session_record(f.accounts.alice_path, key, sent.scope.session_id)?
  let lb = load_session_record(f.accounts.bob_path, key, accepted.scope.session_id)?
  let a = restore_session(la, key)?
  let b = restore_session(lb, key)?
  let empty = Bytes.empty()
  let saved_a = BraidBilateralSaved {
    scope: ma.scope,
    role: 1,
    substate: 0,
    epoch: ma.epoch,
    revision: ma.revision,
    transition: ma.transition,
    output_epoch: U64.parse("0")?,
    header: empty,
    vector: empty,
    first: empty,
    wire: empty,
    epoch_key: empty,
    continuation: empty,
    secrets: load_blob(f.accounts.alice_path, List.get(braid_spqr_labels(ma.scope), 1))?
  }
  let ai = case restore_alice_idle(saved_a, saved_a, key) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_actual_braid_alice_restore")
  end
  let saved_b = BraidSaved {
    scope: mb.scope,
    epoch: mb.epoch,
    revision: mb.revision,
    transition: mb.transition,
    phase: 0,
    header: empty,
    first: empty,
    continuation: empty,
    secrets: load_blob(f.accounts.bob_path, List.get(braid_spqr_labels(mb.scope), 1))?
  }
  let bi = case restore_await(saved_b, key) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_actual_braid_bob_restore")
  end
  let (ah, header) = case send_header(ai) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_actual_header")
  end
  let fragment = case emit_braid_fragment(BraidHeaderFragment,
    ah.scope.configuration,
    ah.scope.session_id,
    ah.epoch,
    header,
    0) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_actual_fragment")
  end
  let (_a, _pa, msg) = case he_encrypt_hybrid(a,
    pa,
    empty,
    fragment,
    session_aad(ah.scope.session_id)?) do
    HybridSealed(h, q, v) -> (h, q, v)
    _ -> return Err("fixture_actual_hybrid_send")
  end
  case he_decrypt_hybrid(b, pb, msg, session_aad(ah.scope.session_id)?) do
    HybridOpened(_b, _pb, got, _clear) -> do
      check(Bytes.secure_equals(got.fragment.word, fragment.word), "fixture_actual_hybrid_peer")?
      nil
    end
    _ -> return Err("fixture_actual_hybrid_open")
  end
  let _ready = case admit_complete_header(bi, ah.epoch, header) do
    BraidHeaderAccepted(v) -> v
    _ -> return Err("fixture_actual_braid_peer")
  end
  let bob_profile = decode_client_profile(f.bob_profile)?
  check(case load_blob(f.accounts.bob_path,
      one_time_prekey_label(bob_profile.bundle.one_time_prekey_id)) do
      Err("local_state_not_found") -> true
      _ -> false
    end,
    "fixture_actual_otp_deleted")?
  check(List.length(load_prekey_pool(bob_profile, key, f.accounts.bob_path)?) == 0
      && List.length(load_active_prekey_pool(f.accounts.bob_path, [], key)?) == 0,
    "fixture_pool_and_active_consumed")?
  let ids = load_outbox_ids(f.accounts.alice_path, key)?
  check(List.length(ids) == 1
      && Bytes.secure_equals(load_outbox_entry(f.accounts.alice_path, key, sent.envelope_id)?,
        sent.envelope),
    "fixture_exact_initial_outbox")
end

pub fn b0_mobile_durable_pair() -> Unit!String do
  let f = accounts()?
  let result = actual_pair(f)
  cleanup(f)?
  result
end

fn recovery_inner(f :: BootstrapAccounts) -> Unit!String do
  let sent = start(f)?
  let a = row_set(f.accounts.alice_path)?
  let again = start(f)?
  let recovered = recover(f)?
  check(Bytes.secure_equals(sent.envelope, again.envelope)
      && Bytes.secure_equals(sent.envelope, recovered.envelope)
      && equal_rows(a, row_set(f.accounts.alice_path)?),
    "fixture_no_prepare_replay_or_requeue")?
  let wrong = start_braid_spqr_once(f.accounts.alice_path,
    f.alice_profile,
    f.bob_profile,
    conversation()?,
    config(),
    Crypto.sha256(Bytes.from_utf8("different intent")))
  check(Result.is_err(wrong) && equal_rows(a, row_set(f.accounts.alice_path)?),
    "fixture_different_intent_rollback")?
  check(case start_braid_spqr_once(f.accounts.alice_path,
      f.alice_profile,
      f.bob_profile,
      conversation()?,
      Crypto.sha256(Bytes.from_utf8("different profile C")),
      intent()) do
      Err("c1_bootstrap_peer_exists") -> true
      _ -> false
    end,
    "fixture_existing_peer_refused")?
  check(equal_rows(a, row_set(f.accounts.alice_path)?), "fixture_existing_peer_no_write")?
  let accepted = receive_initial_control(f, sent.envelope)?
  let b = row_set(f.accounts.bob_path)?
  let duplicate = receive_initial_control(f, sent.envelope)?
  check(Bytes.secure_equals(accepted.scope.session_id, duplicate.scope.session_id)
      && equal_rows(b, row_set(f.accounts.bob_path)?),
    "fixture_exact_initial_duplicate")
end

pub fn b0_mobile_exact_recovery() -> Unit!String do
  let f = accounts()?
  let result = recovery_inner(f)
  cleanup(f)?
  result
end

fn b0_mobile_refusals_inner(f :: BootstrapAccounts) -> Unit!String do
  let sent = start(f)?
  let before = row_set(f.accounts.bob_path)?
  check(Result.is_err(receive_braid_spqr_initial(f.accounts.bob_path,
      f.bob_profile,
      f.alice_profile,
      conversation()?,
      Crypto.sha256(Bytes.from_utf8("wrong config")),
      sent.envelope))
      && equal_rows(before, row_set(f.accounts.bob_path)?),
    "fixture_wrong_config_rollback")?
  let profile = decode_client_profile(f.bob_profile)?
  let key = platform_key()?
  let recipient = open_device(profile, key, f.accounts.bob_path)?
  let opened = open_outer_packet(canonical_outer(sent.envelope)?, recipient.identity_private_key)?
  let (account, hello) = parse_sealed_initial_packet(opened.packet)?
  let initial = case decode_initial_message(hello) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_initial_decode")
  end
  let damaged = %{initial | ciphertext: repeated(0, Bytes.length(initial.ciphertext))?}
  let encoded = case encode_initial_message(damaged) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_initial_encode")
  end
  let tampered = sealed_outer_bytes(profile.entry.mailbox_token,
    encode_packet(InitialPacket(account, encoded))?,
    profile.credential.dh_public_key,
    case U64.parse("1700000000000") do
      Ok(v) -> v
      Err(_) -> return Err("fixture_time")
    end)?
  check(Result.is_err(receive_initial_control(f, tampered))
      && equal_rows(before, row_set(f.accounts.bob_path)?),
    "fixture_real_body_auth_rollback")?
  let pool = load_blob(f.accounts.bob_path, "one-time-prekeys/v1")?
  let active = load_blob(f.accounts.bob_path, "one-time-prekey-active/v1")?
  let (entries, ids) = open_captured_prekey_pools(pool, active, key)?
  check(List.length(entries) == 1 && List.length(ids) == 1, "fixture_real_active_pool")?
  check(Result.is_err(open_captured_prekey_pools(active, pool, key)),
    "fixture_captured_pool_contexts")?
  let removed = one_time_prekey_label(profile.bundle.one_time_prekey_id)
  let bad = Crypto.sha256(Bytes.from_utf8("invalid typed secret ciphertext"))
  store_updated_blobs(f.accounts.bob_path, [removed], [bad])?
  let changed = row_set(f.accounts.bob_path)?
  check(Result.is_err(receive_initial_control(f, sent.envelope))
      && equal_rows(changed, row_set(f.accounts.bob_path)?),
    "fixture_selected_key_rollback")
end

pub fn b0_mobile_refusals() -> Unit!String do
  let f = accounts()?
  let result = b0_mobile_refusals_inner(f)
  cleanup(f)?
  result?
  for mode in 0..5 do
    let f = accounts()?
    let result = bounded_policy_inner(f, mode)
    cleanup(f)?
    result?
  end
  Ok(nil)
end

## Actually sign a successor current generation and retain old ciphertexts.
fn next_generation(f :: BootstrapAccounts) -> BootstrapAccounts!String do
  let path = f.accounts.bob_path
  let p = decode_client_profile(f.bob_profile)?
  let key = platform_key()?
  let account = open_account(p, key, path)?
  let device = open_device(p, key, path)?
  let pq = case generate_post_quantum_prekey() do
    Ok(v) -> v
    Err(_) -> return Err("fixture_generation_pq")
  end
  let credential = case issue_hybrid_device_credential(account,
    device,
    pq.public_key,
    p.credential.capabilities,
    p.credential.created_at,
    p.credential.expires_at,
    p.credential.directory_sequence) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_generation_credential")
  end
  let id = U64.add(p.bundle.signed_prekey_id, U64.parse("1")?)?
  let signed = case generate_signed_prekey(device, credential, id, p.bundle.expires_at) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_generation_signed")
  end
  let otp = OneTimePrekeySecrets {
    id: p.bundle.one_time_prekey_id,
    public_key: X25519PublicKey { bytes: p.bundle.one_time_prekey },
    private_key: open_x25519(load_blob(path, one_time_prekey_label(p.bundle.one_time_prekey_id))?,
      key,
      one_time_prekey_context(p, p.bundle.one_time_prekey_id)?)?
  }
  let bundle = case build_hybrid_prekey_bundle(credential, signed, otp, pq) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_generation_bundle")
  end
  let encoded = case encode_prekey_bundle(bundle) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_generation_encoding")
  end
  let wire = encode_client_profile(%{p.entry | prekey_bundle: encoded}, p.account_id, p.device_id)?
  let signed_name = "signed-prekey/v1/#{U64.to_string(id)}"
  let pq_name = "post-quantum-prekey/v1/#{U64.to_string(id)}"
  store_updated_blobs(path,
    ["profile/v1", signed_name, pq_name],
    [
      seal_local(wire, key, local_context("profile/v1")?)?,
      seal_x25519(signed.private_key, key, context(p.account_id, p.device_id, signed_name, 9)?)?,
      seal_mlkem(pq.private_key, key, context(p.account_id, p.device_id, pq_name, 15)?)?
    ])?
  Ok(%{f | bob_profile: wire})
end

fn bounded_policy_inner(f :: BootstrapAccounts, mode :: Int) -> Unit!String do
  if mode == 4 do
    return reusable_refusal_inner(f)
  end
  if mode == 3 do
    let next = next_generation(f)?
    let sent = start(next)?
    let accepted = receive_initial_control(next, sent.envelope)?
    return check(Bytes.secure_equals(accepted.scope.session_id, sent.scope.session_id),
      "fixture_keyed_current_generation_accepted")
  end
  let sent = start(f)?
  let profile = decode_client_profile(f.bob_profile)?
  let key = platform_key()?
  if mode == 0 do
    store_updated_blobs(f.accounts.bob_path,
      ["one-time-prekey-active/v1"],
      [seal_active_prekey_pool([], key)?])?
    let winner = row_set(f.accounts.bob_path)?
    check(case receive_initial_control(f, sent.envelope) do
        Err("c1_bootstrap_prekey_inactive") -> true
        _ -> false
      end,
      "fixture_inactive_otp_refusal")?
    check(equal_rows(winner, row_set(f.accounts.bob_path)?), "fixture_inactive_otp_no_write")
  else if mode == 1 do
    let next = next_generation(f)?
    let winner = row_set(f.accounts.bob_path)?
    check(case receive_initial_control(next, sent.envelope) do
        Err("c1_bootstrap_peer_or_generation_changed") -> true
        _ -> false
      end,
      "fixture_real_old_generation_refusal")?
    check(equal_rows(winner, row_set(f.accounts.bob_path)?), "fixture_old_generation_no_write")
  else
    let scope = %{sent.scope |
      account_id: profile.account_id,
      device_id: profile.device_id,
      peer_account_id: sent.scope.account_id,
      peer_device_id: sent.scope.device_id
    }
    let label = List.get(braid_spqr_labels(scope), 4)
    store_updated_blobs(f.accounts.bob_path,
      [label],
      [seal_local(Bytes.from_utf8("TEST ONLY partial target"), key, local_context(label)?)?])?
    let winner = row_set(f.accounts.bob_path)?
    check(case receive_initial_control(f, sent.envelope) do
        Err("c1_bootstrap_target_exists") -> true
        _ -> false
      end,
      "fixture_authenticated_partial_target_refusal")?
    check(equal_rows(winner, row_set(f.accounts.bob_path)?), "fixture_partial_target_no_write")
  end
end

pub fn b0_mobile_actual_api_preflight() -> Unit!String do
  let f = accounts()?
  let key = platform_key()?
  let profile = decode_client_profile(f.bob_profile)?
  let device = open_device(profile, key, f.accounts.bob_path)?
  let entries = load_prekey_pool(profile, key, f.accounts.bob_path)?
  let active = load_active_prekey_pool(f.accounts.bob_path, entries, key)?
  check(Bytes.secure_equals(device.identity_public_key.bytes, profile.credential.dh_public_key)
      && List.length(entries) == 1
      && List.length(active) == 1
      && List.length(load_session_ids(f.accounts.bob_path, key)?) == 0,
    "fixture_actual_account_prekey_api")?
  print("B0_ACTUAL_MOBILE_API_PREFLIGHT_EXECUTED")
  cleanup(f)
end

pub fn b0_mobile_report(value :: Unit!String) -> Bool do
  case value do
    Ok(_) -> true
    Err(reason) -> do
      print("B0 fixture refusal: " <> reason)
      false
    end
  end
end

fn check(ok :: Bool, reason :: String) -> Unit!String do
  if ok do
    Ok(nil)
  else
    Err(reason)
  end
end

fn install_policy(signed :: SignedTransparencyViewFixture) -> Result<(), String> do
  let bare = "1\n"
    <> Bytes.to_hex(signed.service_public_key)
    <> "\n"
    <> Bytes.to_hex(signed.witness_a_public_key)
    <> "\n"
    <> Bytes.to_hex(signed.witness_b_public_key)
    <> "\n8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a\n1"
  check(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
      Bytes.from_utf8("6\n2\n" <> bare)),
    "fixture_native_config")?
  check(native_session_minimum(capture_native_session_policy()?)? == 2,
    "fixture_current_suite_floor")
end

fn owned_path(name :: String) -> String!String do
  let nonce = case Crypto.random_bytes(8) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_path")
  end
  Ok(Env.get("MORSE_C1_FIXTURE_ROOT", "/tmp")
    <> "/c1-braid-"
    <> name
    <> "-"
    <> Bytes.to_hex(nonce)
    <> ".db")
end

## Same genuine account/link/export operations as GroupLifecycleSupport
## Only caller-owned filenames differ. No accepted account/credential bytes are made up.
fn owned_accounts() -> GroupAccountFixture!String do
  let alice_path = owned_path("alice")?
  let bob_path = owned_path("bob")?
  let linked_path = owned_path("linked")?
  create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")])?)?
  create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")])?)?
  let link_request = create_link_request_export(Bytes.from_utf8(linked_path))?
  let authorization = authorize_device_link_export(request([
    Bytes.from_utf8(alice_path),
    link_request
  ])?)?
  complete_device_link_export(request([Bytes.from_utf8(linked_path), authorization])?)?
  let alice = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(alice_path))?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_alice_entry")
  end
  let bob = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(bob_path))?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_bob_entry")
  end
  let linked = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(linked_path))?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_linked_entry")
  end
  let account = case decode_account_identity(alice.account_identity) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_alice_account")
  end
  let bob_account = case decode_account_identity(bob.account_identity) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_bob_account")
  end
  let linked_bundle = case decode_prekey_bundle(linked.prekey_bundle) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_linked_bundle")
  end
  let linked_credential = case decode_device_credential(linked_bundle.device_credential) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_linked_credential")
  end
  let alice_set = case encode_device_set(DeviceSet {
    version: 1,
    username: "alice",
    account_identity: alice.account_identity,
    sequence: U64.parse("2")?,
    devices: [alice, linked],
    revoked_device_ids: []
  }) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_alice_set")
  end
  let bob_set = case encode_device_set(DeviceSet {
    version: 1,
    username: "bob",
    account_identity: bob.account_identity,
    sequence: bob_account.directory_sequence,
    devices: [bob],
    revoked_device_ids: []
  }) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_bob_set")
  end
  Ok(GroupAccountFixture {
    alice_path: alice_path,
    bob_path: bob_path,
    linked_path: linked_path,
    alice_entry: alice,
    bob_entry: bob,
    linked_entry: linked,
    alice_account: account,
    linked_credential: linked_credential,
    alice_set: alice_set,
    bob_set: bob_set
  })
end

fn reusable_refusal_inner(f :: BootstrapAccounts) -> Unit!String do
  let p = decode_client_profile(f.bob_profile)?
  let alice = decode_client_profile(f.alice_profile)?
  let key = platform_key()?
  let entries = load_prekey_pool(p, key, f.accounts.bob_path)?
  let (signed, _old, pq) = open_bundle_prekeys(p,
    key,
    f.accounts.bob_path,
    p.bundle,
    List.head(entries))?
  let id = U64.parse("4611686018427387905")?
  let reusable = case generate_one_time_prekey(id) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_reusable_generate")
  end
  let bundle = case build_hybrid_prekey_bundle(p.credential, signed, reusable, pq) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_reusable_bundle")
  end
  let encoded = case encode_prekey_bundle(bundle) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_reusable_encoding")
  end
  let peer = encode_client_profile(%{p.entry | prekey_bundle: encoded}, p.account_id, p.device_id)?
  store_updated_blobs(f.accounts.bob_path,
    [one_time_prekey_label(id), "last-resort-prekey/v1"],
    [
      seal_x25519(reusable.private_key, key, one_time_prekey_context(p, id)?)?,
      seal_local(mobile_join([
            mobile_write_u64(id)?,
            reusable.public_key.bytes,
            mobile_write_u64(current_time()?)?
          ],
          0,
          Bytes.empty())?,
        key,
        local_context("last-resort-prekey/v1")?)?
    ])?
  check(Option.is_some(find_last_resort_prekey(f.accounts.bob_path, key, id)?),
    "fixture_actual_reusable_stored")?
  let sent = start_braid_spqr_once(f.accounts.alice_path,
    f.alice_profile,
    peer,
    conversation()?,
    config(),
    intent())?
  let device = open_device(p, key, f.accounts.bob_path)?
  let opened = open_outer_packet(canonical_outer(sent.envelope)?, device.identity_private_key)?
  let (_account, hello) = parse_sealed_initial_packet(opened.packet)?
  let selected = case find_last_resort_prekey(f.accounts.bob_path, key, id)? do
    Some(v) -> v
    None -> return Err("fixture_reusable_missing")
  end
  let (signed, one_time, pq) = open_bundle_prekeys(p, key, f.accounts.bob_path, bundle, selected)?
  check(case receive_initial_braid_spqr_at_minimum_suite(device,
      p.account,
      bundle,
      signed,
      one_time,
      pq,
      alice.account,
      policy(p, current_time()?),
      policy(alice, current_time()?),
      0,
      2,
      hello,
      config()) do
      Ok(_) -> true
      Err(_) -> false
    end,
    "fixture_reusable_initial_actually_authenticates")?
  let before = row_set(f.accounts.bob_path)?
  check(case receive_initial_control(f, sent.envelope) do
      Err("one_time_prekey_not_found") -> true
      _ -> false
    end,
    "fixture_reusable_not_active_otp_refused")?
  check(equal_rows(before, row_set(f.accounts.bob_path)?), "fixture_reusable_no_write")
end
