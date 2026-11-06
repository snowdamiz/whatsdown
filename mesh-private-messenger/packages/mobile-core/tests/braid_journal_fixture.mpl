##! Owned real-profile/HE fixtures. No network service, production endpoint,
##! capability, wire parser, cold-process or native-storage claim.
from Mobile.BraidJournal import (
  BraidJournalOutcome,
  braid_labels,
  braid_header_carrier,
  initialize_braid_fixture,
  receive_braid_control,
  send_braid_control,
  send_braid_control_fault,
  recover_braid_output
)
from Session.BraidResponder import BraidScope, BraidAwaitHeader, initialize_responder
from Session.Ratchet import encrypt_sealed, decrypt, decode_ratchet_message
from Session.State import RatchetState, RatchetMessage, DecryptOutcome
from Mobile.Account import create_account
from Mobile.Messages import start_conversation, receive_initial_message
from Mobile.Profile import load_profile, open_post_quantum_prekey, open_device
from Mobile.Sessions import (
  load_session_ids,
  find_peer_session,
  restore_session,
  seal_updated_session,
  ratchet_bytes,
  parse_ratchet_packet
)
from Mobile.Types import MobileAccountRequest, MobileStartRequest, MobileReceiveRequest
from Mobile.Transport import sealed_outer_bytes, open_outer_packet
from Mobile.Codec import current_time, mobile_join, mobile_write_u64, canonical_outer
from MobileCore import (
  update_conversation_export,
  create_account_export,
  create_link_request_export,
  authorize_device_link_export,
  complete_device_link_export,
  directory_entry_export
)
from Storage.Keys import platform_key, local_context, seal_local
from Storage.AccountGuard import (
  load_account_basis,
  same_account_basis,
  commit_account_changes,
  erase_account_if_current
)
from Storage.Records import store_updated_blobs, store_record_changes, erase_local_state
from Storage.Blobs import load_blob
from Transport.Packet import TransportPacket, decode_client_profile, encode_packet, session_aad
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import DeviceSet
from Transparency.Merkle import leaf_hash
from Tests.GroupLifecycleSupport import GroupAccountFixture, install_signed_transparency
from Tests.GroupConsistencySupport import signed_transparency_view, request
from Tests.Support import repeated, write_u32

pub resource struct BraidHeFixture do
  accounts :: GroupAccountFixture
  alice_profile :: Bytes
  bob_profile :: Bytes
  scope :: BraidScope
  alice_auth :: BraidAwaitHeader
  epoch_private :: MlKemPrivateKey
  header :: MlKemHeader64
end

fn check(value :: Bool, reason :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(reason)
  end
end

fn no_fault() -> Result<(), String> do
  Ok(nil)
end

## Explicitly owned paths let the outer qualifier remove all generated files
## after an assertion/timeout/setup failure, even before setup returns a value.
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

## Same genuine account/link/export operations as GroupLifecycleSupport; only
## caller-owned filenames differ. No accepted account/credential bytes are made up.
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

fn labels(f :: borrow BraidHeFixture) -> List<String>!String do
  let key = platform_key()?
  let loaded = find_peer_session(f.accounts.bob_path,
    key,
    f.scope.peer_account_id,
    load_session_ids(f.accounts.bob_path, key)?,
    0)?
  Ok([
    "sessions/v1",
    "session/v1/#{Bytes.to_hex(f.scope.session_id)}",
    "header-routing/v1",
    "history/v1/#{Bytes.to_hex(loaded.record.conversation_id)}",
    "outbox/v1",
    "postage-queue/v1",
    "delivery/v1"
  ]
    ++ braid_labels(f.scope))
end

pub fn setup() -> BraidHeFixture!String do
  check(Test.install_in_memory_secure_store(), "fixture_platform_store")?
  let accounts = owned_accounts()?
  let signed = signed_transparency_view([
    leaf_hash(accounts.alice_set)?,
    leaf_hash(accounts.bob_set)?
  ])?
  for path in [accounts.alice_path, accounts.bob_path] do
    check(install_signed_transparency(path, signed, accounts.alice_set)?, "fixture_transparency")?
    check(install_signed_transparency(path, signed, accounts.bob_set)?, "fixture_transparency")?
  end
  let alice_wire = load_profile(accounts.alice_path)?
  let bob_wire = load_profile(accounts.bob_path)?
  let hello = start_conversation(MobileStartRequest {
    database_path: accounts.alice_path,
    peer_profile: bob_wire,
    body: Bytes.from_utf8("TEST ONLY real HE initializer"),
    attachment: Bytes.empty()
  })?
  check(Bytes.secure_equals(receive_initial_message(MobileReceiveRequest {
        database_path: accounts.bob_path,
        outer: hello
      })?,
      Bytes.from_utf8("TEST ONLY real HE initializer")),
    "fixture_he_setup")?
  update_conversation_export(request([
    Bytes.from_utf8(accounts.bob_path),
    alice_wire,
    repeated(1, 1)?,
    write_u32(0)?
  ])?)?
  let alice = decode_client_profile(alice_wire)?
  let bob = decode_client_profile(bob_wire)?
  let key = platform_key()?
  let loaded = find_peer_session(accounts.bob_path,
    key,
    alice.account_id,
    load_session_ids(accounts.bob_path, key)?,
    0)?
  let scope = BraidScope {
    protocol_info: Bytes.from_utf8("MorseBraid_MLKEM768_SHA-256"),
    configuration: Crypto.sha256(Bytes.from_utf8("TEST ONLY C1 complete header carrier v1")),
    account_id: bob.account_id,
    device_id: bob.device_id,
    peer_account_id: alice.account_id,
    peer_device_id: alice.device_id,
    session_id: loaded.session_id
  }
  # Establish a separate actual shared key through Bob's saved PQ prekey.
  # Neither this key nor the fresh epoch key is the HE root or HE header key.
  let saved = open_post_quantum_prekey(bob, key, accounts.bob_path)?
  check(Bytes.secure_equals(saved.public_key.bytes, bob.bundle.post_quantum_prekey),
    "fixture_real_saved_pq")?
  let (ciphertext, left) = case Crypto.mlkem_encapsulate(saved.public_key) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_initializer_encaps")
  end
  let right = case Crypto.mlkem_decapsulate(saved.private_key, ciphertext) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_initializer_decaps")
  end
  let alice_auth = case initialize_responder(scope, left) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_auth_init")
  end
  let responder = case initialize_responder(scope, right) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_auth_init")
  end
  initialize_braid_fixture(accounts.bob_path, bob_wire, responder)?
  Secret.destroy(left)
  Secret.destroy(right)
  Secret.destroy(saved.private_key)
  Secret.destroy(key)
  let epoch_key = case Crypto.mlkem_generate() do
    Ok(v) -> v
    Err(_) -> return Err("fixture_epoch_key")
  end
  check(!Bytes.secure_equals(epoch_key.public_key.bytes, bob.bundle.post_quantum_prekey),
    "fixture_distinct_epoch_key")?
  let (header, _vector) = case Crypto.mlkem_public_parts(epoch_key.private_key) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_epoch_parts")
  end
  Ok(BraidHeFixture {
    accounts: accounts,
    alice_profile: alice_wire,
    bob_profile: bob_wire,
    scope: scope,
    alice_auth: alice_auth,
    epoch_private: epoch_key.private_key,
    header: header
  })
end

fn complete_header(f :: borrow BraidHeFixture) -> Bytes!String do
  let mac = case SecretMap.copy(f.alice_auth.secrets, Bytes.from_utf8("mac")) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_mac_key")
  end
  let tag = case Crypto.hmac_sha256_tag(mac,
    mobile_join([
        f.scope.protocol_info,
        Bytes.from_utf8(":ekheader"),
        mobile_write_u64(f.alice_auth.epoch)?,
        f.header.bytes
      ],
      0,
      Bytes.empty())?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_header_mac")
  end
  Secret.destroy(mac)
  mobile_join([f.header.bytes, tag], 0, Bytes.empty())
end

## Real sending HE state is committed under its captured account/session basis.
## Only the complete logical carrier is synthetic; its authentication is not.
fn incoming(f :: borrow BraidHeFixture, plaintext :: Bytes) -> Bytes!String do
  let key = platform_key()?
  let peer = decode_client_profile(f.bob_profile)?
  let loaded = find_peer_session(f.accounts.alice_path,
    key,
    peer.account_id,
    load_session_ids(f.accounts.alice_path, key)?,
    0)?
  check(Bytes.secure_equals(loaded.session_id, f.scope.session_id), "fixture_he_session")?
  let before = load_account_basis(f.accounts.alice_path, ["sessions/v1", loaded.label])?
  let state = restore_session(loaded, key)?
  let (next, message) = case encrypt_sealed(state, plaintext, session_aad(loaded.session_id)?) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_he_encrypt")
  end
  let outer = sealed_outer_bytes(peer.entry.mailbox_token,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    peer.credential.dh_public_key,
    current_time()?)?
  let blob = seal_updated_session(next, loaded, key)?
  commit_account_changes(f.accounts.alice_path, before, [loaded.label], [blob], [])?
  Ok(outer)
end

fn correct_incoming(f :: borrow BraidHeFixture) -> Bytes!String do
  incoming(f, braid_header_carrier(f.scope, f.alice_auth.epoch, complete_header(f)?)?)
end

fn accept(f :: borrow BraidHeFixture) -> Result<(), String> do
  let received = receive_braid_control(f.accounts.bob_path,
    f.bob_profile,
    f.scope,
    correct_incoming(f)?,
    no_fault)?
  check(received.kind == 1
      && Bytes.length(received.output_id) == 0
      && Bytes.length(received.envelope) == 0
      && U64.compare(received.epoch, f.alice_auth.epoch) == 0,
    "fixture_receive_without_output")?
  check(case recover_braid_output(f.accounts.bob_path, f.bob_profile, f.scope) do
      Err("c1_no_pending_output") -> true
      _ -> false
    end,
    "fixture_no_early_output")
end

fn flipped(value :: Bytes) -> Bytes!String do
  check(Bytes.length(value) > 0, "fixture_flip_empty")?
  let old = case Bytes.get(value, 0) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_flip_byte")
  end
  let tail = case Bytes.slice(value, 1, Bytes.length(value) - 1) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_flip_tail")
  end
  mobile_join([
      repeated(if old == 0 do
          1
        else
          0
        end,
        1)?,
      tail
    ],
    0,
    Bytes.empty())
end

fn peer_message(f :: borrow BraidHeFixture, wire :: Bytes) -> RatchetMessage!String do
  let key = platform_key()?
  let alice = decode_client_profile(f.alice_profile)?
  let outer = canonical_outer(wire)?
  check(Bytes.secure_equals(outer.mailbox_token, alice.entry.mailbox_token),
    "fixture_outgoing_recipient")?
  let device = open_device(alice, key, f.accounts.alice_path)?
  let opened = open_outer_packet(outer, device.identity_private_key)?
  check(opened.sealed, "fixture_outgoing_seal")?
  case decode_ratchet_message(parse_ratchet_packet(opened.packet)?) do
    Ok(v)
    Err(_) -> Err("fixture_outgoing_ratchet")
  end
end

fn drop_opened(state :: consume RatchetState, plaintext :: Bytes) -> Bytes!String do
  Ok(plaintext)
end

fn drop_rejected(state :: consume RatchetState) -> Bytes!String do
  Err("fixture_peer_he_refused")
end

## Real peer authentication, deliberately read-only. No HE root/key is exported.
fn peer_plaintext(f :: borrow BraidHeFixture, wire :: Bytes) -> Bytes!String do
  let message = peer_message(f, wire)?
  let key = platform_key()?
  let bob = decode_client_profile(f.bob_profile)?
  let loaded = find_peer_session(f.accounts.alice_path,
    key,
    bob.account_id,
    load_session_ids(f.accounts.alice_path, key)?,
    0)?
  check(Bytes.secure_equals(loaded.session_id, f.scope.session_id), "fixture_peer_session")?
  let state = restore_session(loaded, key)?
  case decrypt(state, message, session_aad(loaded.session_id)?) do
    Opened(next, plaintext) -> drop_opened(next, plaintext)
    Rejected(old, _) -> drop_rejected(old)
  end
end

fn slice(value :: Bytes, offset :: Int, count :: Int) -> Bytes!String do
  case Bytes.slice(value, offset, count) do
    Ok(v)
    Err(_) -> Err("fixture_ct1_frame")
  end
end

fn verify_outgoing(f :: borrow BraidHeFixture,
  sent :: BraidJournalOutcome,
  authenticated :: BraidJournalOutcome) -> Result<(), String> do
  let bob = decode_client_profile(f.bob_profile)?
  let key = platform_key()?
  let loaded = find_peer_session(f.accounts.alice_path,
    key,
    bob.account_id,
    load_session_ids(f.accounts.alice_path, key)?,
    0)?
  let before = load_account_basis(f.accounts.alice_path, ["sessions/v1", loaded.label])?
  let plaintext = peer_plaintext(f, sent.envelope)?
  let prefix = Bytes.from_utf8("TEST/C1/CT1/V1")
  let n = Bytes.length(prefix)
  check(Bytes.length(plaintext) == n + 1032
      && Bytes.secure_equals(slice(plaintext, 0, n)?, prefix)
      && Bytes.secure_equals(slice(plaintext, n, 32)?, f.scope.configuration)
      && Bytes.secure_equals(slice(plaintext, n + 32, 32)?, f.scope.session_id)
      && Bytes.secure_equals(slice(plaintext, n + 64, 8)?, mobile_write_u64(sent.epoch)?)
      && Bytes.length(authenticated.first) == 960
      && Bytes.secure_equals(slice(plaintext, n + 72, 960)?, authenticated.first)
      && Bytes.secure_equals(sent.first, authenticated.first),
    "fixture_actual_peer_ct1")?
  let outer = canonical_outer(sent.envelope)?
  let corrupted_outer = case encode_outer_envelope(%{outer |
    ciphertext: flipped(outer.ciphertext)?
  }) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_corrupt_outgoing")
  end
  check(Result.is_err(peer_plaintext(f, corrupted_outer)), "fixture_corrupt_recipient_refused")?
  # Reseal a changed HE ciphertext using only Alice's public recipient key.
  # Recipient sealing alone must not suffice to pass the HE authentication.
  let message = peer_message(f, sent.envelope)?
  let alice = decode_client_profile(f.alice_profile)?
  let changed_he = sealed_outer_bytes(alice.entry.mailbox_token,
    encode_packet(RatchetPacket(ratchet_bytes(%{message |
      ciphertext: flipped(message.ciphertext)?
    })?))?,
    alice.credential.dh_public_key,
    current_time()?)?
  check(Result.is_err(peer_plaintext(f, changed_he)), "fixture_corrupt_he_refused")?
  check(same_account_basis(before,
      load_account_basis(f.accounts.alice_path, ["sessions/v1", loaded.label])?),
    "fixture_peer_checks_read_only")
end

fn cleanup(f :: consume BraidHeFixture) -> Result<(), String> do
  let BraidHeFixture {
    accounts,
    alice_profile,
    bob_profile,
    scope,
    alice_auth,
    epoch_private,
    header
  } = f
  Secret.destroy(alice_auth.secrets)
  Secret.destroy(epoch_private)
  for path in [accounts.alice_path, accounts.bob_path, accounts.linked_path] do
    erase_local_state(path)?
    for suffix in ["", "-wal", "-shm"] do
      if File.exists(path <> suffix) do
        File.delete(path <> suffix)?
      end
    end
  end
  Ok(nil)
end

fn auth_boundaries(f :: borrow BraidHeFixture) -> Result<(), String> do
  let before = load_account_basis(f.accounts.bob_path, labels(f)?)?
  let outer = canonical_outer(correct_incoming(f)?)?
  let tampered = case encode_outer_envelope(%{outer | ciphertext: flipped(outer.ciphertext)?}) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_tampered_outer")
  end
  check(Result.is_err(receive_braid_control(f.accounts.bob_path,
      f.bob_profile,
      f.scope,
      tampered,
      no_fault)),
    "fixture_outer_refusal")?
  check(same_account_basis(before, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_unauth_no_mutation")?
  for plaintext in [
    Bytes.from_utf8("malformed complete carrier"),
    braid_header_carrier(%{f.scope | configuration: repeated(9, 32)?},
      f.alice_auth.epoch,
      complete_header(f)?)?,
    braid_header_carrier(f.scope,
      U64.add(f.alice_auth.epoch, U64.parse("1")?)?,
      complete_header(f)?)?
  ] do
    let packet = incoming(f, plaintext)?
    check(Result.is_err(receive_braid_control(f.accounts.bob_path,
        f.bob_profile,
        f.scope,
        packet,
        no_fault)),
      "fixture_carrier_refusal")?
    check(same_account_basis(before, load_account_basis(f.accounts.bob_path, labels(f)?)?),
      "fixture_malformed_no_mutation")?
  end
  check(Result.is_err(receive_braid_control(f.accounts.bob_path,
      f.alice_profile,
      f.scope,
      correct_incoming(f)?,
      no_fault)),
    "fixture_stale_ui_profile")?
  check(same_account_basis(before, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_wrong_profile_no_mutation")?
  accept(f)
end

pub fn actual_he_boundary() -> Result<(), String> do
  let f = setup()?
  let result = auth_boundaries(f)
  cleanup(f)?
  result
end

fn exact_send(f :: borrow BraidHeFixture) -> Result<(), String> do
  accept(f)?
  let before = load_account_basis(f.accounts.bob_path, labels(f)?)?
  let sent = send_braid_control(f.accounts.bob_path, f.bob_profile, f.scope, no_fault)?
  check(sent.kind == 2
      && Bytes.length(sent.output_id) == 32
      && Bytes.length(sent.envelope) > 960
      && U64.compare(sent.sending_epoch, U64.parse("0")?) == 0,
    "fixture_new_output")?
  let saved = load_account_basis(f.accounts.bob_path, labels(f)?)?
  check(!same_account_basis(before, saved), "fixture_send_committed")?
  let recovered = recover_braid_output(f.accounts.bob_path, f.bob_profile, f.scope)?
  verify_outgoing(f, sent, recovered)?
  let repeated_send = send_braid_control(f.accounts.bob_path, f.bob_profile, f.scope, no_fault)?
  check(recovered.kind == 3
      && repeated_send.kind == 3
      && Bytes.secure_equals(sent.output_id, recovered.output_id)
      && Bytes.secure_equals(sent.envelope, recovered.envelope)
      && Bytes.secure_equals(sent.envelope, repeated_send.envelope),
    "fixture_exact_recovered_output")?
  check(same_account_basis(saved, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_retry_no_write")
end

pub fn exact_pending_output() -> Result<(), String> do
  let f = setup()?
  let result = exact_send(f)
  cleanup(f)?
  result
end

fn terminal(f :: borrow BraidHeFixture) -> Result<(), String> do
  let before = load_account_basis(f.accounts.bob_path, labels(f)?)?
  let bad = incoming(f,
    braid_header_carrier(f.scope,
      f.alice_auth.epoch,
      mobile_join([f.header.bytes, repeated(0, 32)?], 0, Bytes.empty())?)?)?
  check(case receive_braid_control(f.accounts.bob_path, f.bob_profile, f.scope, bad, no_fault) do
      Err("c1_terminal_generation") -> true
      _ -> false
    end,
    "fixture_internal_mac_terminal")?
  let committed = load_account_basis(f.accounts.bob_path, labels(f)?)?
  check(!same_account_basis(before, committed), "fixture_terminal_committed")?
  for label in List.drop(braid_labels(f.scope), 1) do
    check(Result.is_err(load_blob(f.accounts.bob_path, label)),
      "fixture_terminal_no_active_secret")?
  end
  let later = correct_incoming(f)?
  check(case receive_braid_control(f.accounts.bob_path, f.bob_profile, f.scope, later, no_fault) do
      Err("c1_terminal_generation") -> true
      _ -> false
    end,
    "fixture_no_terminal_resumption")?
  check(case send_braid_control(f.accounts.bob_path, f.bob_profile, f.scope, no_fault) do
      Err("c1_terminal_generation") -> true
      _ -> false
    end,
    "fixture_no_terminal_send")?
  check(same_account_basis(committed, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_terminal_stable")
end

pub fn terminal_lifecycle() -> Result<(), String> do
  let f = setup()?
  let result = terminal(f)
  cleanup(f)?
  result
end

fn source_fences(f :: borrow BraidHeFixture) -> Result<(), String> do
  accept(f)?
  let path = f.accounts.bob_path
  let source_labels = labels(f)?
  for target in source_labels ++ ["profile/v1"] do
    let original = case load_blob(f.accounts.bob_path, target) do
      Ok(v) -> v
      Err(_) -> Bytes.empty()
    end
    let changed = if Bytes.length(original) == 0 do
      Bytes.from_utf8("fixture appeared")
    else
      flipped(original)?
    end
    let refused = send_braid_control(f.accounts.bob_path,
      f.bob_profile,
      f.scope,
      fn() -> store_updated_blobs(path, [target], [changed]) end)
    check(case refused do
        Err("account_state_changed") -> true
        _ -> false
      end,
      "fixture_captured_source_changed")?
    check(Bytes.secure_equals(load_blob(f.accounts.bob_path, target)?, changed),
      "fixture_winner_not_overwritten")?
    if Bytes.length(original) == 0 do
      store_record_changes(f.accounts.bob_path, [], [], [target])?
    else
      store_updated_blobs(f.accounts.bob_path, [target], [original])?
    end
  end
  let before = load_account_basis(f.accounts.bob_path, source_labels)?
  check(case send_braid_control(f.accounts.bob_path,
      f.bob_profile,
      f.scope,
      fn() -> Err("fixture_abort_before_commit") end) do
      Err("fixture_abort_before_commit") -> true
      _ -> false
    end,
    "fixture_precommit_abort")?
  check(same_account_basis(before, load_account_basis(f.accounts.bob_path, source_labels)?),
    "fixture_abort_no_partial_rows")
end

pub fn guarded_sources() -> Result<(), String> do
  let f = setup()?
  let result = source_fences(f)
  cleanup(f)?
  result
end

fn await_file(path :: String, attempts :: Int) -> Bool do
  if File.exists(path) do
    return true
  end
  if attempts <= 0 do
    false
  else
    Timer.sleep(5)
    await_file(path, attempts - 1)
  end
end

actor racer(path :: String, profile :: Bytes, scope :: BraidScope, number :: Int) do
  let result = send_braid_control(path,
    profile,
    scope,
    fn() do
      File.write(path <> ".#{number}.ready", "ready")?
      check(await_file(path <> ".go", 2000), "fixture_barrier_timeout")
    end)
  let text = case result do
    Ok(value) -> if value.kind == 2 do
      "new"
    else
      "unexpected_recovery"
    end
    Err("account_state_changed") -> "changed"
    Err(_) -> "unexpected_error"
  end
  File.write(path <> ".#{number}.result", text)
end

actor race_master(path :: String, profile :: Bytes, scope :: BraidScope) do
  let first = spawn(racer, path, profile, scope, 1)
  let second = spawn(racer, path, profile, scope, 2)
  Process.monitor(first, "first-ended")
  Process.monitor(second, "second-ended")
  if await_file(path <> ".1.ready", 2000) && await_file(path <> ".2.ready", 2000) do
    File.write(path <> ".go", "go")
    let a = receive do
      text -> text
      after 15000 -> "timeout"
    end
    let b = receive do
      text -> text
      after 15000 -> "timeout"
    end
    File.write(path <> ".race",
      if (a == "first-ended" && b == "second-ended")
        || (a == "second-ended" && b == "first-ended") do
        "ok"
      else
        "missing-exit"
      end)
  else
    File.write(path <> ".race", "prepare-timeout")
  end
end

pub fn competing_prepared_sends() -> Result<(), String> do
  let f = setup()?
  accept(f)?
  let _master = spawn(race_master, f.accounts.bob_path, f.bob_profile, f.scope)
  check(await_file(f.accounts.bob_path <> ".race", 4000), "fixture_race_timeout")?
  check(File.read(f.accounts.bob_path <> ".race")? == "ok", "fixture_race_actor_exit")?
  let first = File.read(f.accounts.bob_path <> ".1.result")?
  let second = File.read(f.accounts.bob_path <> ".2.result")?
  check((first == "new" && second == "changed") || (first == "changed" && second == "new"),
    "fixture_single_prepared_winner")?
  check(recover_braid_output(f.accounts.bob_path, f.bob_profile, f.scope)?.kind == 3,
    "fixture_race_exact_recovery")?
  for suffix in [".1.ready", ".2.ready", ".1.result", ".2.result", ".go", ".race"] do
    File.delete(f.accounts.bob_path <> suffix)?
  end
  cleanup(f)
end

actor unknown_writer(path :: String, profile :: Bytes, scope :: BraidScope) do
  let result = send_braid_control_fault(path,
    profile,
    scope,
    no_fault,
    fn() do
      File.write(path <> ".committed", "committed")?
      Err("fixture_lost_reply")
    end)
  File.write(path <> ".unknown",
    case result do
      Err("fixture_lost_reply") -> "unknown"
      _ -> "unexpected"
    end)
end

actor fresh_reader(path :: String, profile :: Bytes, scope :: BraidScope) do
  let result = recover_braid_output(path, profile, scope)
  File.write(path <> ".recovered",
    case result do
      Ok(value) -> if value.kind == 3 do
        Bytes.to_hex(value.output_id) <> ":" <> Bytes.to_hex(value.envelope)
      else
        "unexpected"
      end
      Err(_) -> "refused"
    end)
end

actor restart_master(path :: String, profile :: Bytes, scope :: BraidScope) do
  let writer = spawn(unknown_writer, path, profile, scope)
  Process.monitor(writer, "writer-ended")
  let first = receive do
    text -> text
    after 15000 -> "timeout"
  end
  if first == "writer-ended" do
    let fresh = spawn(fresh_reader, path, profile, scope)
    Process.monitor(fresh, "reader-ended")
    let second = receive do
      text -> text
      after 15000 -> "timeout"
    end
    File.write(path <> ".restart",
      if second == "reader-ended" do
        "ok"
      else
        "reader-timeout"
      end)
  else
    File.write(path <> ".restart", "writer-timeout")
  end
end

pub fn unknown_reply_actor_restart() -> Result<(), String> do
  let f = setup()?
  accept(f)?
  let _master = spawn(restart_master, f.accounts.bob_path, f.bob_profile, f.scope)
  check(await_file(f.accounts.bob_path <> ".restart", 5000), "fixture_restart_timeout")?
  check(File.read(f.accounts.bob_path <> ".restart")? == "ok"
      && File.read(f.accounts.bob_path <> ".unknown")? == "unknown"
      && File.read(f.accounts.bob_path <> ".committed")? == "committed",
    "fixture_committed_unknown")?
  let before = load_account_basis(f.accounts.bob_path, labels(f)?)?
  let recovered = recover_braid_output(f.accounts.bob_path, f.bob_profile, f.scope)?
  check(File.read(f.accounts.bob_path <> ".recovered")? == Bytes.to_hex(recovered.output_id)
        <> ":"
        <> Bytes.to_hex(recovered.envelope),
    "fixture_exact_fresh_actor_recovery")?
  check(same_account_basis(before, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_recovery_no_write")?
  for suffix in [".committed", ".unknown", ".recovered", ".restart"] do
    File.delete(f.accounts.bob_path <> suffix)?
  end
  cleanup(f)
end

pub fn replacement_cannot_be_terminated() -> Result<(), String> do
  let f = setup()?
  let path = f.accounts.bob_path
  let before = load_account_basis(f.accounts.bob_path, labels(f)?)?
  let bad = incoming(f,
    braid_header_carrier(f.scope,
      f.alice_auth.epoch,
      mobile_join([f.header.bytes, repeated(0, 32)?], 0, Bytes.empty())?)?)?
  let result = receive_braid_control(f.accounts.bob_path,
    f.bob_profile,
    f.scope,
    bad,
    fn() do
      erase_account_if_current(path, before.profile)?
      create_account(MobileAccountRequest {
        database_path: Bytes.from_utf8(path),
        username: Bytes.from_utf8("c1replacement")
      })?
      Ok(nil)
    end)
  check(case result do
      Err("account_state_changed") -> true
      _ -> false
    end,
    "fixture_terminal_replacement_fence")?
  check(!Bytes.secure_equals(load_profile(f.accounts.bob_path)?, f.bob_profile),
    "fixture_real_replacement")?
  for label in braid_labels(f.scope) do
    check(Result.is_err(load_blob(f.accounts.bob_path, label)), "fixture_replacement_no_old_rows")?
  end
  cleanup(f)
end
