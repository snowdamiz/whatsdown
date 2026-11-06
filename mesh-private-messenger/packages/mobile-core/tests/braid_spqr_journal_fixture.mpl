##! Source-prepared real account/HE/PQ fixture. No compiler or durability claim.
from Session.BraidResponder import BraidScope, BraidAwaitHeader, initialize_responder
from Session.BraidInitiator import (
  BraidAliceHeaderSent,
  initialize_initiator,
  send_header,
  send_vector,
  receive_ct1,
  receive_ct2
)
from Session.BraidComplete import receive_vector, send_ct2
from Session.BraidBilateralStore import BraidBilateralSaved, restore_bob_first
from Session.BraidStore import seal_await
from Session.Spqr import SpqrState, SpqrSlot, initialize_spqr, incorporate_spqr_epoch
from Session.SpqrStore import SpqrSaved, SpqrStoreIdentity, seal_spqr, restore_spqr
from Session.BraidFragment import (
  BraidFragment,
  BraidFragmentKind,
  encode_braid_fragment,
  decode_braid_fragment
)
from Session.BraidFragmentWords import emit_braid_fragment, recover_braid_carrier
from Session.Ratchet import encrypt_sealed, decrypt, decode_ratchet_message
from Session.State import DecryptOutcome
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
from Mobile.BraidSpqrJournal import (
  BraidSpqrOutcome,
  receive_braid_spqr_control,
  prepare_braid_spqr_ct1_once,
  recover_braid_spqr_pending
)
from Mobile.BraidJournal import braid_labels
from Mobile.BraidAliceState import alice_header_labels
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
from Mobile.Types import MobileStartRequest, MobileReceiveRequest, MobilePayloadRequest
from Mobile.Transport import sealed_outer_bytes, open_outer_packet
from Mobile.Codec import current_time, canonical_outer, mobile_join, mobile_write_u64, mobile_vector
from Mobile.Outbox import (
  load_outbox_ids,
  load_outbox_entry,
  acknowledge_outbox,
  prepare_outbox_writes
)
from Mobile.SessionPolicy import capture_native_session_policy, native_session_minimum
from MobileCore import (
  create_account_export,
  create_link_request_export,
  authorize_device_link_export,
  complete_device_link_export,
  directory_entry_export,
  update_conversation_export
)
from Storage.Keys import platform_key, local_context, seal_local, open_local
from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis,
  same_account_basis,
  commit_account_changes,
  erase_account_if_current
)
from Storage.FanoutCommit import FanoutSnapshot
from Storage.Records import store_updated_blobs, erase_local_state
from Storage.Blobs import load_blob
from Transport.Packet import TransportPacket, decode_client_profile, encode_packet, session_aad
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import DeviceSet
from Transparency.Merkle import leaf_hash
from Tests.GroupLifecycleSupport import GroupAccountFixture, install_signed_transparency
from Tests.GroupConsistencySupport import (
  SignedTransparencyViewFixture,
  signed_transparency_view,
  request
)
from Tests.Support import repeated, write_u32

pub resource struct BraidSpqrFixture do
  accounts :: GroupAccountFixture
  alice_profile :: Bytes
  bob_profile :: Bytes
  scope :: BraidScope
  alice :: BraidAliceHeaderSent
  bob :: BraidAwaitHeader
  header :: Bytes
  seed :: SecretBytes
end

fn fixture_checked_bytes(value :: Result<Bytes, BytesError>) -> Bytes!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_checked_bytes_api")
  end
end

fn fixture_crypto_bytes(value :: Result<Bytes, CryptoError>) -> Bytes!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_public_crypto_api")
  end
end

fn fixture_crypto_secret(value :: consume Result<SecretBytes, CryptoError>) -> SecretBytes!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_public_crypto_api")
  end
end

fn fixture_encapsulation(value :: consume Result<(MlKemCiphertext, SecretBytes), CryptoError>) -> (MlKemCiphertext, SecretBytes)!String do
  case value do
    Ok(value)
    Err(_) -> Err("fixture_public_crypto_api")
  end
end

# Only the assertion outcome for controlled synthetic messages crosses this boundary.
# Observe it before branching so later fixture storage and cleanup stay public.
fn check(value :: Bool, reason :: String) -> Result<(), String> do
  if declassify(value,
    "test-only Boolean assertion of controlled synthetic SPQR journal fixtures; no application disclosure") do
    Ok(nil)
  else
    Err(reason)
  end
end

fn number(text :: String) -> U64!String do
  U64.parse(text)
end

fn zero(count :: Int) -> Bytes!String do
  repeated(0, count)
end

fn flipped(value :: Bytes) -> Bytes!String do
  let old = Bytes.get(value, 0)?
  let changed = if old == 0 do
    1
  else
    0
  end
  fixture_checked_bytes(Bytes.concat_many([
      repeated(changed, 1)?,
      Bytes.slice(value, 1, Bytes.length(value) - 1)?
    ],
    Bytes.length(value)))
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

pub fn make_braid_spqr_fixture() -> BraidSpqrFixture!String do
  check(Test.install_in_memory_secure_store(), "fixture_platform_store")?
  let accounts = owned_accounts()?
  let signed = signed_transparency_view([
    leaf_hash(accounts.alice_set)?,
    leaf_hash(accounts.bob_set)?
  ])?
  install_policy(signed)?
  for path in [accounts.alice_path, accounts.bob_path] do
    check(install_signed_transparency(path, signed, accounts.alice_set)?, "fixture_transparency")?
    check(install_signed_transparency(path, signed, accounts.bob_set)?, "fixture_transparency")?
  end
  let alice_wire = load_profile(accounts.alice_path)?
  let bob_wire = load_profile(accounts.bob_path)?
  let hello = start_conversation(MobileStartRequest {
    database_path: accounts.alice_path,
    peer_profile: bob_wire,
    body: Bytes.from_utf8("TEST ONLY independent HE for SPQR journal"),
    attachment: Bytes.empty()
  })?
  check(Bytes.secure_equals(receive_initial_message(MobileReceiveRequest {
        database_path: accounts.bob_path,
        outer: hello
      })?,
      Bytes.from_utf8("TEST ONLY independent HE for SPQR journal")),
    "fixture_real_he")?
  update_conversation_export(request([
    Bytes.from_utf8(accounts.bob_path),
    alice_wire,
    repeated(1, 1)?,
    write_u32(0)?
  ])?)?
  let alice_profile = decode_client_profile(alice_wire)?
  let bob_profile = decode_client_profile(bob_wire)?
  let key = platform_key()?
  let loaded = find_peer_session(accounts.bob_path,
    key,
    alice_profile.account_id,
    load_session_ids(accounts.bob_path, key)?,
    0)?
  let scope = BraidScope {
    protocol_info: Bytes.from_utf8("MorseBraid_MLKEM768_SHA-256"),
    configuration: Crypto.sha256(Bytes.from_utf8("TEST ONLY C1 same-CAS SPQR consumer v1")),
    account_id: bob_profile.account_id,
    device_id: bob_profile.device_id,
    peer_account_id: alice_profile.account_id,
    peer_device_id: alice_profile.device_id,
    session_id: loaded.session_id
  }
  let he = restore_session(loaded, key)?
  check(he.version == 2 && he.suite == 2 && Bytes.secure_equals(he.session_id, scope.session_id),
    "fixture_real_suite2")?
  let saved = open_post_quantum_prekey(bob_profile, key, accounts.bob_path)?
  check(Bytes.secure_equals(saved.public_key.bytes, bob_profile.bundle.post_quantum_prekey),
    "fixture_real_saved_pq")?
  let (ciphertext, left) = fixture_encapsulation(Crypto.mlkem_encapsulate(saved.public_key))?
  let right = fixture_crypto_secret(Crypto.mlkem_decapsulate(saved.private_key, ciphertext))?
  let alice_scope = %{scope |
    account_id: scope.peer_account_id,
    device_id: scope.peer_device_id,
    peer_account_id: scope.account_id,
    peer_device_id: scope.device_id
  }
  let alice = case initialize_initiator(alice_scope, left) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_braid_seed")
  end
  let bob = case initialize_responder(scope, right) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_braid_seed")
  end
  let (alice, header) = case send_header(alice) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_header")
  end
  Secret.destroy(left)
  Secret.destroy(right)
  Secret.destroy(saved.private_key)
  let seed = fixture_crypto_secret(Env.get_secret_hex("MORSE_C1_SPQR_JOURNAL_SEED"))?
  Ok(BraidSpqrFixture {
    accounts: accounts,
    alice_profile: alice_wire,
    bob_profile: bob_wire,
    scope: scope,
    alice: alice,
    bob: bob,
    header: header,
    seed: seed
  })
end

fn selected(f :: borrow BraidSpqrFixture) -> String!String do
  let key = platform_key()?
  Ok(find_peer_session(f.accounts.bob_path,
    key,
    f.scope.peer_account_id,
    load_session_ids(f.accounts.bob_path, key)?,
    0)?.label)
end

fn labels(f :: borrow BraidSpqrFixture) -> List<String>!String do
  let key = platform_key()?
  let loaded = find_peer_session(f.accounts.bob_path,
    key,
    f.scope.peer_account_id,
    load_session_ids(f.accounts.bob_path, key)?,
    0)?
  Ok([
    "sessions/v1",
    loaded.label,
    "header-routing/v1",
    "device-identity-key/v1",
    "history/v1/#{Bytes.to_hex(loaded.record.conversation_id)}",
    "outbox/v1",
    "postage-queue/v1",
    "delivery/v1"
  ]
    ++ braid_spqr_labels(f.scope)
    ++ braid_labels(f.scope)
    ++ alice_header_labels(f.scope))
end

fn base_metadata(scope :: BraidScope,
  slots :: List<SpqrSlot>,
  index :: Bytes) -> BraidSpqrMetadata!String do
  Ok(BraidSpqrMetadata {
    scope: scope,
    direction: 1,
    phase: 4,
    kernel_tag: 0,
    epoch: number("1")?,
    revision: number("1")?,
    transition: Crypto.sha256(Bytes.from_utf8("TEST ONLY independent fixture bootstrap")),
    local_epoch: number("0")?,
    knowledge: number("0")?,
    cursors: [0, 0, 0, 0],
    partial_kind: 1,
    partial_indices: [],
    partial_words: [],
    header: Bytes.empty(),
    vector: Bytes.empty(),
    first: Bytes.empty(),
    second: Bytes.empty(),
    local_receipt: zero(73)?,
    peer_ack: zero(105)?,
    hashes: for i in 0..7 do
      Crypto.sha256(Bytes.empty())
    end,
    pending_identity: zero(80)?,
    slots: slots,
    skipped_index: index,
    local_attempt: zero(73)?,
    inbound_result: zero(82)?
  })
end

## Fixture bootstrap only. Production journal has no initialization entry point.
fn initialize_fixture(f :: borrow BraidSpqrFixture) -> Result<(), String> do
  let key = platform_key()?
  let all = labels(f)?
  let before = load_account_basis(f.accounts.bob_path, all)?
  let ls = braid_spqr_labels(f.scope)
  for label in ls ++ braid_labels(f.scope) ++ alice_header_labels(f.scope) do
    check(Result.is_err(load_blob(f.accounts.bob_path, label)), "fixture_no_legacy_or_existing_c1")?
  end
  let state = case initialize_spqr(f.scope, 1, f.seed) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_spqr_init")
  end
  let m = base_metadata(f.scope, state.slots, state.skipped_index)?
  let descriptor = braid_spqr_descriptor(m)?
  let auth = case seal_await(f.bob, key, m.revision, m.transition) do
    Ok(value) -> value.secrets
    Err(_) -> return Err("fixture_auth_seal")
  end
  let saved = seal_spqr(state,
    key,
    SpqrStoreIdentity { revision: m.revision, transition: m.transition, descriptor: descriptor })?
  let session = load_blob(f.accounts.bob_path, selected(f)?)?
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
  let encoded = braid_spqr_metadata_bytes(filled)?
  let metadata = seal_local(encoded, key, local_context(List.get(ls, 0))?)?
  commit_account_changes(f.accounts.bob_path,
    before,
    [List.get(ls, 0), List.get(ls, 1), List.get(ls, 4), List.get(ls, 5)],
    [metadata, auth, saved.chains, saved.skipped],
    [])
end

fn metadata(f :: borrow BraidSpqrFixture) -> BraidSpqrMetadata!String do
  let key = platform_key()?
  let label = List.head(braid_spqr_labels(f.scope))
  decode_braid_spqr_metadata(open_local(load_blob(f.accounts.bob_path, label)?,
      key,
      local_context(label)?)?,
    f.scope)
end

fn restore_consumer(f :: borrow BraidSpqrFixture, m :: BraidSpqrMetadata) -> SpqrState!String do
  let key = platform_key()?
  let ls = braid_spqr_labels(f.scope)
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
    chains: load_blob(f.accounts.bob_path, List.get(ls, 4))?,
    skipped: load_blob(f.accounts.bob_path, List.get(ls, 5))?
  }
  restore_spqr(saved, saved, key)
end

fn incoming(f :: borrow BraidSpqrFixture, plaintext :: Bytes) -> Bytes!String do
  let key = platform_key()?
  let peer = decode_client_profile(f.bob_profile)?
  let loaded = find_peer_session(f.accounts.alice_path,
    key,
    peer.account_id,
    load_session_ids(f.accounts.alice_path, key)?,
    0)?
  let before = load_account_basis(f.accounts.alice_path, ["sessions/v1", loaded.label])?
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    plaintext,
    session_aad(loaded.session_id)?) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_real_he_encrypt")
  end
  let outer = sealed_outer_bytes(peer.entry.mailbox_token,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    peer.credential.dh_public_key,
    current_time()?)?
  commit_account_changes(f.accounts.alice_path,
    before,
    [loaded.label],
    [seal_updated_session(next, loaded, key)?],
    [])?
  Ok(outer)
end

fn word(f :: borrow BraidSpqrFixture, header :: Bytes, index :: Int) -> BraidFragment!String do
  case emit_braid_fragment(BraidHeaderFragment,
    f.scope.configuration,
    f.scope.session_id,
    number("1")?,
    header,
    index) do
    Ok(value)
    Err(_) -> Err("fixture_fragment_emit")
  end
end

fn receive_word(f :: borrow BraidSpqrFixture,
  fragment :: BraidFragment) -> BraidSpqrOutcome!String do
  let wire = case encode_braid_fragment(fragment) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_fragment_encode")
  end
  receive_braid_spqr_control(f.accounts.bob_path, f.bob_profile, f.scope, incoming(f, wire)?)
end

fn ready(f :: borrow BraidSpqrFixture) -> BraidSpqrMetadata!String do
  initialize_fixture(f)?
  check(receive_word(f, word(f, f.header, 0)?)?.kind == 1, "fixture_partial_header")?
  check(receive_word(f, word(f, f.header, 1)?)?.kind == 2, "fixture_complete_header")?
  let m = metadata(f)?
  check(m.phase == 5 && m.kernel_tag == 1, "fixture_header_ready")?
  Ok(m)
end

fn intent() -> Bytes!String do
  repeated(17, 32)
end

fn prepare(f :: borrow BraidSpqrFixture, source_revision :: U64) -> BraidSpqrOutcome!String do
  prepare_braid_spqr_ct1_once(f.accounts.bob_path,
    f.bob_profile,
    f.scope,
    source_revision,
    intent()?)
end

fn recover(f :: borrow BraidSpqrFixture, source_revision :: U64) -> BraidSpqrOutcome!String do
  recover_braid_spqr_pending(f.accounts.bob_path,
    f.bob_profile,
    f.scope,
    source_revision,
    intent()?)
end

fn tag(map :: borrow SecretMap, name :: Bytes) -> Bytes!String do
  let key = fixture_crypto_secret(SecretMap.copy(map, name))?
  let result = fixture_crypto_bytes(Crypto.hmac_sha256_tag(key,
    Bytes.from_utf8("TEST ONLY independently completed journal peer")))?
  Secret.destroy(key)
  Ok(result)
end

fn compare_consumer(left :: borrow SpqrState, right :: borrow SpqrState) -> Result<(), String> do
  check(Bytes.secure_equals(tag(left.chains, zero(1)?)?, tag(right.chains, zero(1)?)?),
    "fixture_peer_root_agreement")?
  for e in ["0", "1"] do
    for d in [0, 1] do
      let name = fixture_checked_bytes(Bytes.concat_many([
          repeated(1, 1)?,
          mobile_write_u64(number(e)?)?,
          repeated(d, 1)?
        ],
        10))?
      check(Bytes.secure_equals(tag(left.chains, name)?, tag(right.chains, name)?),
        "fixture_peer_chain_agreement")?
    end
  end
  Ok(nil)
end

## Open the ACTUAL returned transport, not a reconstructed fixture plaintext.
fn peer_accepts_actual_pending(f :: borrow BraidSpqrFixture,
  sent :: BraidSpqrOutcome,
  first :: MlKemCiphertext1_960) -> Result<(), String> do
  let key = platform_key()?
  let alice_profile = decode_client_profile(f.alice_profile)?
  let outer = canonical_outer(sent.envelope)?
  check(Bytes.secure_equals(outer.mailbox_token, alice_profile.entry.mailbox_token)
      && Bytes.secure_equals(outer.envelope_id, sent.envelope_id),
    "fixture_actual_pending_recipient_identity")?
  let device = open_device(alice_profile, key, f.accounts.alice_path)?
  let opened = open_outer_packet(outer, device.identity_private_key)?
  check(opened.sealed, "fixture_actual_pending_recipient_open")?
  let loaded = find_peer_session(f.accounts.alice_path,
    key,
    f.scope.account_id,
    load_session_ids(f.accounts.alice_path, key)?,
    0)?
  let he = restore_session(loaded, key)?
  check(he.version == 2 && he.suite == 2 && Bytes.secure_equals(he.session_id, f.scope.session_id),
    "fixture_actual_pending_peer_suite2")?
  let message = case decode_ratchet_message(parse_ratchet_packet(opened.packet)?) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_actual_pending_ratchet_frame")
  end
  check(message.version == 4, "fixture_actual_pending_he_version")?
  let clear = case decrypt(he, message, session_aad(f.scope.session_id)?) do
    Opened(_, value) -> value
    _ -> return Err("fixture_actual_pending_he_authentication")
  end
  let fragment = case decode_braid_fragment(clear, f.scope.configuration, f.scope.session_id) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_actual_pending_exact_cbf1")
  end
  let expected = case emit_braid_fragment(BraidFirstFragment,
    f.scope.configuration,
    f.scope.session_id,
    number("1")?,
    first.bytes,
    0) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_actual_pending_expected_word")
  end
  let exact = case encode_braid_fragment(expected) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_actual_pending_expected_encoding")
  end
  check(fragment.kind == BraidFirstFragment
      && U64.compare(fragment.epoch, number("1")?) == 0
      && fragment.index == 0
      && Bytes.secure_equals(fragment.word, expected.word)
      && Bytes.secure_equals(clear, exact),
    "fixture_actual_pending_matches_restored_ct1_index0")
end

fn first_output_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  let before = ready(f)?
  let sent = prepare(f, before.revision)?
  let m = metadata(f)?
  check(sent.kind == 3 && m.phase == 6 && m.kernel_tag == 6 && List.get(m.cursors, 2) == 1,
    "fixture_first_ct1_commit")?
  check(U64.compare(m.local_epoch, number("1")?) == 0
      && U64.compare(m.knowledge, number("0")?) == 0,
    "fixture_no_fake_K")?
  let state = restore_consumer(f, m)?
  let ls = braid_spqr_labels(f.scope)
  let key = platform_key()?
  let bob = case restore_bob_first(BraidBilateralSaved {
      scope: f.scope,
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
      secrets: load_blob(f.accounts.bob_path, List.get(ls, 1))?,
      epoch_key: Bytes.empty(),
      continuation: load_blob(f.accounts.bob_path, List.get(ls, 3))?
    },
    BraidBilateralSaved {
      scope: f.scope,
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
      secrets: Bytes.empty(),
      epoch_key: Bytes.empty(),
      continuation: Bytes.empty()
    },
    key) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_restored_real_bob")
  end
  check(!SecretMap.contains(bob.secrets, Bytes.from_utf8("output")), "fixture_no_raw_output")?
  peer_accepts_actual_pending(f, sent, bob.first)?
  let BraidSpqrFixture { accounts, scope, alice, seed } = f
  let (alice, vector) = case send_vector(alice) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_peer_vector")
  end
  let first = bob.first
  let bob = case receive_vector(bob, m.epoch, vector) do
    BraidVectorAccepted(value) -> value
    _ -> return Err("fixture_peer_vector_admission")
  end
  let wire = case send_ct2(bob) do
    BraidCt2Emitted(_, value) -> value
    _ -> return Err("fixture_peer_ct2")
  end
  let alice = case receive_ct1(alice, m.epoch, first) do
    BraidAliceCt1Accepted(value) -> value
    _ -> return Err("fixture_peer_ct1")
  end
  let output = case receive_ct2(alice, m.epoch, wire) do
    BraidAliceCt2Accepted(_, value) -> value
    _ -> return Err("fixture_peer_actual_output")
  end
  let peer_scope = %{scope |
    account_id: scope.peer_account_id,
    device_id: scope.peer_device_id,
    peer_account_id: scope.account_id,
    peer_device_id: scope.device_id
  }
  let peer = case initialize_spqr(peer_scope, 0, seed) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_peer_spqr_init")
  end
  let peer = case incorporate_spqr_epoch(peer, output) do
    SpqrEpochAccepted(value) -> value
    _ -> return Err("fixture_peer_consumer")
  end
  compare_consumer(state, peer)?
  let ids = load_outbox_ids(accounts.bob_path, key)?
  check(List.any(ids, fn(id) -> Bytes.secure_equals(id, sent.envelope_id) end),
    "fixture_pending_in_real_outbox")?
  check(Bytes.secure_equals(load_outbox_entry(accounts.bob_path, key, sent.envelope_id)?,
      sent.envelope),
    "fixture_outbox_exact")
end

fn authenticated_header_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  initialize_fixture(f)?
  let ls = braid_spqr_labels(f.scope)
  let old_chains = load_blob(f.accounts.bob_path, List.get(ls, 4))?
  let old_skips = load_blob(f.accounts.bob_path, List.get(ls, 5))?
  let old_consumer = restore_consumer(f, metadata(f)?)?
  let fragment = word(f, f.header, 0)?
  let encoded = case encode_braid_fragment(fragment) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_word")
  end
  let raw = incoming(f, encoded)?
  let unopened = canonical_outer(raw)?
  let bad_outer = case encode_outer_envelope(%{unopened |
    ciphertext: flipped(unopened.ciphertext)?
  }) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_bad_outer")
  end
  let untouched = load_account_basis(f.accounts.bob_path, labels(f)?)?
  check(Result.is_err(receive_braid_spqr_control(f.accounts.bob_path,
      f.bob_profile,
      f.scope,
      bad_outer)),
    "fixture_real_recipient_tag_refusal")?
  check(same_account_basis(untouched, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_recipient_failure_no_write")?
  let key = platform_key()?
  let profile = decode_client_profile(f.bob_profile)?
  let device = open_device(profile, key, f.accounts.bob_path)?
  let opened = open_outer_packet(unopened, device.identity_private_key)?
  let message = case decode_ratchet_message(parse_ratchet_packet(opened.packet)?) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_bad_body_message")
  end
  let bad_he = sealed_outer_bytes(profile.entry.mailbox_token,
    encode_packet(RatchetPacket(ratchet_bytes(%{message |
      ciphertext: flipped(message.ciphertext)?
    })?))?,
    profile.credential.dh_public_key,
    current_time()?)?
  check(Result.is_err(receive_braid_spqr_control(f.accounts.bob_path,
      f.bob_profile,
      f.scope,
      bad_he)),
    "fixture_real_he_body_tag_refusal")?
  check(same_account_basis(untouched, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_body_failure_no_write")?
  check(Result.is_err(receive_word(f, %{fragment | configuration: repeated(99, 32)?})),
    "fixture_authenticated_wrong_scope")?
  check(same_account_basis(untouched, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_scope_failure_no_write")?
  let a = receive_braid_spqr_control(f.accounts.bob_path, f.bob_profile, f.scope, raw)?
  check(a.kind == 1, "fixture_first_distinct_word")?
  let m = metadata(f)?
  check(m.phase == 4 && List.length(m.partial_indices) == 1, "fixture_rank_from_pairs")?
  check(!Bytes.secure_equals(old_chains, load_blob(f.accounts.bob_path, List.get(ls, 4))?)
      && !Bytes.secure_equals(old_skips, load_blob(f.accounts.bob_path, List.get(ls, 5))?),
    "fixture_partial_reseals_both_maps")?
  let consumer = restore_consumer(f, m)?
  check(U64.compare(consumer.epoch, number("0")?) == 0, "fixture_partial_keeps_secret_epoch")?
  check(Bytes.secure_equals(tag(old_consumer.chains, zero(1)?)?, tag(consumer.chains, zero(1)?)?),
    "fixture_partial_keeps_root")?
  for direction in [0, 1] do
    let name = fixture_checked_bytes(Bytes.concat_many([
        repeated(1, 1)?,
        mobile_write_u64(number("0")?)?,
        repeated(direction, 1)?
      ],
      10))?
    check(Bytes.secure_equals(tag(old_consumer.chains, name)?, tag(consumer.chains, name)?),
      "fixture_partial_keeps_both_chains")?
  end
  let basis = load_account_basis(f.accounts.bob_path, labels(f)?)?
  check(receive_braid_spqr_control(f.accounts.bob_path, f.bob_profile, f.scope, raw)?.kind == 5,
    "fixture_exact_current_receipt")?
  check(same_account_basis(basis, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_exact_duplicate_readonly")?
  receive_word(f, fragment)?
  check(List.length(metadata(f)?.partial_indices) == 1, "fixture_authenticated_duplicate_no_rank")?
  let before = load_account_basis(f.accounts.bob_path, labels(f)?)?
  let conflicting = %{fragment | word: flipped(fragment.word)?}
  check(Result.is_err(receive_word(f, conflicting)), "fixture_same_index_conflict")?
  check(same_account_basis(before, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_conflict_no_write")?
  check(receive_word(f, word(f, f.header, 1)?)?.kind == 2, "fixture_exact_completion")?
  Ok(nil)
end

fn recovery_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  let source = ready(f)?
  let sent = prepare(f, source.revision)?
  let basis = load_account_basis(f.accounts.bob_path, labels(f)?)?
  let recovered = recover(f, source.revision)?
  let repeated_send = prepare(f, source.revision)?
  for value in [recovered, repeated_send] do
    check(Bytes.secure_equals(value.envelope, sent.envelope)
        && Bytes.secure_equals(value.envelope_id, sent.envelope_id)
        && Bytes.secure_equals(value.transition, sent.transition),
      "fixture_exact_saved_attempt")?
  end
  check(same_account_basis(basis, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_recovery_no_reseal_or_key_step")?
  check(Result.is_err(prepare_braid_spqr_ct1_once(f.accounts.bob_path,
      f.bob_profile,
      f.scope,
      source.revision,
      repeated(18, 32)?)),
    "fixture_different_intent_stale")?
  acknowledge_outbox(MobilePayloadRequest {
    database_path: f.accounts.bob_path,
    payload: sent.envelope
  })?
  let settled = load_account_basis(f.accounts.bob_path, labels(f)?)?
  check(Bytes.secure_equals(recover(f, source.revision)?.envelope, sent.envelope),
    "fixture_settled_pending_exact")?
  check(same_account_basis(settled, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_recovery_never_requeues")?
  Ok(nil)
end

fn stale_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  let source = ready(f)?
  let all = labels(f)?
  let key = platform_key()?
  let label = selected(f)?
  let original = load_blob(f.accounts.bob_path, label)?
  store_updated_blobs(f.accounts.bob_path,
    [label],
    [seal_local(Bytes.from_utf8("changed session"), key, local_context(label)?)?])?
  let before = load_account_basis(f.accounts.bob_path, all)?
  check(Result.is_err(prepare(f, source.revision)), "fixture_replaced_session_refused")?
  check(same_account_basis(before, load_account_basis(f.accounts.bob_path, all)?),
    "fixture_replaced_session_no_write")?
  store_updated_blobs(f.accounts.bob_path, [label], [original])?
  let basis = load_account_basis(f.accounts.bob_path, all)?
  erase_account_if_current(f.accounts.bob_path, basis.profile)?
  check(Result.is_err(prepare(f, source.revision)) && Result.is_err(recover(f, source.revision)),
    "fixture_erased_custody_refused")?
  for label in ["profile/v1"] ++ all do
    check(Result.is_err(load_blob(f.accounts.bob_path, label)),
      "fixture_no_erased_account_resurrection")?
  end
  Ok(nil)
end

fn corrupt_and_terminal_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  initialize_fixture(f)?
  let ls = braid_spqr_labels(f.scope)
  let original = load_blob(f.accounts.bob_path, List.get(ls, 5))?
  store_updated_blobs(f.accounts.bob_path, [List.get(ls, 5)], [repeated(1, 71)?])?
  let before = load_account_basis(f.accounts.bob_path, labels(f)?)?
  check(Result.is_err(receive_word(f, word(f, f.header, 0)?)), "fixture_corrupt_component_refused")?
  check(same_account_basis(before, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_component_failure_no_write")?
  store_updated_blobs(f.accounts.bob_path, [List.get(ls, 5)], [original])?
  let bad = fixture_checked_bytes(Bytes.concat_many([
      Bytes.slice(f.header, 0, 64)?,
      flipped(Bytes.slice(f.header, 64, 32)?)?
    ],
    96))?
  receive_word(f, word(f, bad, 0)?)?
  check(Result.is_err(receive_word(f, word(f, bad, 1)?)), "fixture_authenticated_kernel_fatal")?
  check(metadata(f)?.phase == 10, "fixture_terminal_committed")?
  for label in List.drop(ls, 1) do
    check(Result.is_err(load_blob(f.accounts.bob_path, label)), "fixture_terminal_secrets_removed")?
  end
  let terminal = load_account_basis(f.accounts.bob_path, labels(f)?)?
  check(Result.is_err(initialize_fixture(f)) && Result.is_err(prepare(f, number("1")?)),
    "fixture_no_terminal_reset")?
  check(same_account_basis(terminal, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_terminal_refusal_no_write")
end

fn cleanup(accounts :: GroupAccountFixture) -> Result<(), String> do
  for path in [accounts.alice_path, accounts.bob_path, accounts.linked_path] do
    erase_local_state(path)?
    for suffix in [
      "",
      "-wal",
      "-shm",
      ".gate.ready",
      ".gate.go",
      ".gate.result",
      ".reader.result"
    ] do
      if File.exists(path <> suffix) do
        File.delete(path <> suffix)?
      end
    end
  end
  Ok(nil)
end

pub fn authenticated_header() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = authenticated_header_inner(f)
  cleanup(accounts)?
  result
end

pub fn atomic_first_output() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = first_output_inner(f)
  cleanup(accounts)?
  result
end

pub fn exact_recovery() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = recovery_inner(f)
  cleanup(accounts)?
  result
end

pub fn stale_sources() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = stale_inner(f)
  cleanup(accounts)?
  result
end

pub fn corruption_and_terminal() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = corrupt_and_terminal_inner(f)
  cleanup(accounts)?
  result
end

pub fn report(value :: Result<(), String>) -> Bool do
  case value do
    Ok(_) -> true
    Err(reason) -> do
      println("C1 SPQR prepared fixture refusal: #{reason}")
      false
    end
  end
end

pub fn literal_schema() -> Result<(), String> do
  let scope = BraidScope {
    protocol_info: Bytes.from_utf8("Morse"),
    configuration: repeated(17, 32)?,
    account_id: repeated(49, 32)?,
    device_id: repeated(65, 16)?,
    peer_account_id: repeated(50, 32)?,
    peer_device_id: repeated(66, 16)?,
    session_id: repeated(34, 32)?
  }
  let slot = SpqrSlot {
    epoch: number("0")?,
    send_present: true,
    send_count: number("0")?,
    receive_present: true,
    receive_count: number("0")?
  }
  let m = %{base_metadata(scope, [slot], Bytes.empty())? |
    revision: number("7")?,
    transition: repeated(85, 32)?,
    hashes: [
      repeated(97, 32)?,
      Crypto.sha256(Bytes.empty()),
      Crypto.sha256(Bytes.empty()),
      repeated(100, 32)?,
      repeated(101, 32)?,
      repeated(102, 32)?,
      Crypto.sha256(Bytes.empty())
    ]
  }
  let literal = Bytes.from_hex("4346533101054d6f72736511111111111111111111111111111111111111111111111111111111111111113131313131313131313131313131313131313131313131313131313131313131414141414141414141414141414141413232323232323232323232323232323232323232323232323232323232323232424242424242424242424242424242422222222222222222222222222222222222222222222222222222222222222222010400000000000000000100000000000000075555555555555555555555555555555555555555555555555555555555555555000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006161616161616161616161616161616161616161616161616161616161616161e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855646464646464646464646464646464646464646464646464646464646464646465656565656565656565656565656565656565656565656565656565656565656666666666666666666666666666666666666666666666666666666666666666e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000010000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")?
  check(Bytes.secure_equals(braid_spqr_metadata_bytes(m)?, literal), "fixture_literal_cfs1")?
  check(Bytes.secure_equals(braid_spqr_descriptor(m)?,
      Bytes.from_hex("09f21dc038d0f4032ff55593dc0d0d5b6ffb9cb818a626bae6df5fbb54897cb5")?),
    "fixture_literal_descriptor")?
  let basis = FanoutSnapshot {
    bases: [
      AccountBasis {
        profile: Bytes.from_utf8("PROFILE"),
        labels: ["z", "a"],
        records: [Bytes.empty(), Bytes.from_utf8("A")]
      }
    ]
  }
  check(Bytes.secure_equals(braid_spqr_transition(m, basis, 1, repeated(119, 32)?)?,
      Bytes.from_hex("9b21c5883c0e0f98bb2cba7e05d0a784079897c6e23373d7c0162ef5e02a9bf8")?),
    "fixture_literal_transition_sorted_basis")?
  let decoded = decode_braid_spqr_metadata(literal, scope)?
  check(decoded.phase == 4 && U64.compare(decoded.revision, number("7")?) == 0,
    "fixture_literal_decode")?
  for bad in [
    fixture_checked_bytes(Bytes.concat_many([literal, zero(1)?], 8193))?,
    Bytes.slice(literal, 0, Bytes.length(literal) - 1)?,
    zero(8193)?
  ] do
    check(Result.is_err(decode_braid_spqr_metadata(bad, scope)),
      "fixture_canonical_length_refusal")?
  end
  for bad in [
    %{m | direction: 2},
    %{m | slots: []},
    %{m | slots: [slot, slot]},
    %{m | cursors: [0, 0, 65537, 0]},
    %{m | phase: 99}
  ] do
    check(Result.is_err(braid_spqr_metadata_bytes(bad)), "fixture_malformed_metadata_refusal")?
  end
  let p0 = BraidSpqrPending {
    transition: repeated(85, 32)?,
    envelope_id: repeated(68, 16)?,
    recipient: repeated(102, 32)?,
    envelope: repeated(171, 1)?
  }
  let (h0, t0) = split_braid_spqr_pending(p0)?
  check(Bytes.length(h0) == 90 && Bytes.length(t0) == 0, "fixture_pending_split_bound")?
  check(Bytes.secure_equals(Crypto.sha256(h0),
      Bytes.from_hex("c5c2fa7a4bad21d65a66dab1245be407e1ee420b6e6dc43d774895431d7e79a4")?)
      && Bytes.secure_equals(Crypto.sha256(t0),
        Bytes.from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?),
    "fixture_pending_literal_hashes")?
  check(Bytes.secure_equals(join_braid_spqr_pending(h0, t0)?.envelope, p0.envelope),
    "fixture_pending_exact_join")?
  let p1 = BraidSpqrPending {
    transition: repeated(85, 32)?,
    envelope_id: repeated(68, 16)?,
    recipient: repeated(102, 32)?,
    envelope: repeated(171, 65447)?
  }
  let (h1, t1) = split_braid_spqr_pending(p1)?
  check(Bytes.length(h1) == 65536 && Bytes.length(t1) == 0, "fixture_pending_split_bound")?
  check(Bytes.secure_equals(Crypto.sha256(h1),
      Bytes.from_hex("cc6de08c90795146797a0c268471fbb3d99ce37ce074a951b4ee74e5c49dc19a")?)
      && Bytes.secure_equals(Crypto.sha256(t1),
        Bytes.from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?),
    "fixture_pending_literal_hashes")?
  check(Bytes.secure_equals(join_braid_spqr_pending(h1, t1)?.envelope, p1.envelope),
    "fixture_pending_exact_join")?
  let p2 = BraidSpqrPending {
    transition: repeated(85, 32)?,
    envelope_id: repeated(68, 16)?,
    recipient: repeated(102, 32)?,
    envelope: repeated(171, 65448)?
  }
  let (h2, t2) = split_braid_spqr_pending(p2)?
  check(Bytes.length(h2) == 65536 && Bytes.length(t2) == 1, "fixture_pending_split_bound")?
  check(Bytes.secure_equals(Crypto.sha256(h2),
      Bytes.from_hex("590271c4d1a5a28239df2ed9dd66d9e6d75e1ac18a837309f02809d9076daabc")?)
      && Bytes.secure_equals(Crypto.sha256(t2),
        Bytes.from_hex("087d80f7f182dd44f184aa86ca34488853ebcc04f0c60d5294919a466b463831")?),
    "fixture_pending_literal_hashes")?
  check(Bytes.secure_equals(join_braid_spqr_pending(h2, t2)?.envelope, p2.envelope),
    "fixture_pending_exact_join")?
  let p3 = BraidSpqrPending {
    transition: repeated(85, 32)?,
    envelope_id: repeated(68, 16)?,
    recipient: repeated(102, 32)?,
    envelope: repeated(171, 65606)?
  }
  let (h3, t3) = split_braid_spqr_pending(p3)?
  check(Bytes.length(h3) == 65536 && Bytes.length(t3) == 159, "fixture_pending_split_bound")?
  check(Bytes.secure_equals(Crypto.sha256(h3),
      Bytes.from_hex("bef4a0797393e4ed5b2464f4fb2fa295946eab1d2d3aa1fb332c26238774853d")?)
      && Bytes.secure_equals(Crypto.sha256(t3),
        Bytes.from_hex("cb093698b0394bb0a6e667401b9b49aac4820e63810a0c658708f5836cca3543")?),
    "fixture_pending_literal_hashes")?
  check(Bytes.secure_equals(join_braid_spqr_pending(h3, t3)?.envelope, p3.envelope),
    "fixture_pending_exact_join")?
  Ok(nil)
end

pub fn direct_mobile_api_preflight() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = mobile_preflight_inner(f)
  cleanup(accounts)?
  result
end

fn mobile_preflight_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  let key = platform_key()?
  for label in braid_spqr_labels(f.scope)
    ++ braid_labels(f.scope)
    ++ alice_header_labels(f.scope) do
    check(Result.is_err(load_blob(f.accounts.bob_path, label)), "fixture_preflight_no_c1_rows")?
  end
  let a = word(f, f.header, 0)?
  let b = word(f, f.header, 1)?
  check(case recover_braid_carrier(BraidHeaderFragment,
      f.scope.configuration,
      f.scope.session_id,
      number("1")?,
      [a]) do
      Ok(None) -> true
      _ -> false
    end,
    "fixture_real_incomplete")?
  check(case recover_braid_carrier(BraidHeaderFragment,
      f.scope.configuration,
      f.scope.session_id,
      number("1")?,
      [b, a]) do
      Ok(Some(value)) -> Bytes.secure_equals(value, f.header)
      _ -> false
    end,
    "fixture_real_complete")?
  let payload = case encode_braid_fragment(a) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_preflight_encode")
  end
  let raw = incoming(f, payload)?
  let profile = decode_client_profile(f.bob_profile)?
  let device = open_device(profile, key, f.accounts.bob_path)?
  let opened = open_outer_packet(canonical_outer(raw)?, device.identity_private_key)?
  check(opened.sealed, "fixture_preflight_recipient")?
  let loaded = find_peer_session(f.accounts.bob_path,
    key,
    f.scope.peer_account_id,
    load_session_ids(f.accounts.bob_path, key)?,
    0)?
  let message = case decode_ratchet_message(parse_ratchet_packet(opened.packet)?) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_preflight_he_decode")
  end
  let clear = case decrypt(restore_session(loaded, key)?,
    message,
    session_aad(f.scope.session_id)?) do
    Opened(_, value) -> value
    _ -> return Err("fixture_preflight_real_he_authentication")
  end
  check(Bytes.secure_equals(clear, payload), "fixture_preflight_authenticated_exact_cbf1")?
  case decode_braid_fragment(clear, f.scope.configuration, f.scope.session_id) do
    Ok(value) -> check(value.index == 0, "fixture_preflight_word_index")?
    Err(_) -> return Err("fixture_preflight_cbf1_decode")
  end
  let before = load_account_basis(f.accounts.bob_path, labels(f)?)?
  let (_, _, index) = prepare_outbox_writes(key,
    load_outbox_ids(f.accounts.bob_path, key)?,
    [raw],
    f.accounts.bob_path,
    Bytes.empty(),
    0,
    0,
    profile)?
  check(Bytes.secure_equals(before.profile, index.before.profile),
    "fixture_preflight_same_custody_outbox")?
  check(same_account_basis(before, load_account_basis(f.accounts.bob_path, labels(f)?)?),
    "fixture_preflight_no_receiver_commit")
end

## These test-only entry points run only in separately copied source controls.
fn snapshot_rows(path :: String, names :: List<String>) -> List<Bytes>!String do
  let values = for label in names do
    case load_blob(path, label) do
      Ok(value) -> value
      Err("local_state_not_found") -> Bytes.empty()
      Err(reason) -> return Err(reason)
    end
  end
  Ok(values)
end

## Test-only complete ciphertext row set also detects orphan new outbox records.
fn ciphertext_rows(path :: String) -> List<Bytes>!String do
  let database = Sqlite.open(path)?
  let result = Sqlite.query_values(database,
    "SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash",
    [])
  Sqlite.close(database)
  let rows = result?
  let encoded = for row in rows do
    case (Map.get(row, "record_hash"), Map.get(row, "ciphertext")) do
      (Text(name), Binary(blob)) -> mobile_join([
          mobile_vector(Bytes.from_utf8(name))?,
          mobile_vector(blob)?
        ],
        0,
        Bytes.empty())?
      _ -> return Err("fixture_ciphertext_row_schema")
    end
  end
  Ok(encoded)
end

fn same_rows(left :: List<Bytes>, right :: List<Bytes>) -> Bool do
  List.length(left) == List.length(right)
    && List.all(for i in 0..List.length(left) do
        Bytes.secure_equals(List.get(left, i), List.get(right, i))
      end,
      fn(value) -> value end)
end

fn await_file(path :: String, remaining :: Int) -> Bool do
  if File.exists(path) do
    case File.read(path) do
      Ok(value) -> if String.length(value) > 0 do
        return true
      end
      Err(_) -> nil
    end
  end
  if remaining == 0 do
    false
  else
    Timer.sleep(5)
    await_file(path, remaining - 1)
  end
end

actor journal_fault_writer(path :: String,
  profile :: Bytes,
  scope :: BraidScope,
  revision :: U64,
  local_intent :: Bytes) do
  let result = prepare_braid_spqr_ct1_once(path, profile, scope, revision, local_intent)
  File.write(path <> ".gate.result",
    case result do
      Err(reason) -> reason
      Ok(value) -> "committed:" <> Bytes.to_hex(value.transition)
    end)
end

actor journal_fresh_reader(path :: String,
  profile :: Bytes,
  scope :: BraidScope,
  revision :: U64,
  local_intent :: Bytes) do
  let result = recover_braid_spqr_pending(path, profile, scope, revision, local_intent)
  File.write(path <> ".reader.result",
    case result do
      Err(reason) -> "refused:" <> reason
      Ok(value) -> Bytes.to_hex(value.transition)
        <> ":"
        <> Bytes.to_hex(value.envelope_id)
        <> ":"
        <> Bytes.to_hex(value.envelope)
    end)
end

pub fn copied_source_component_abort() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = component_abort_inner(f)
  cleanup(accounts)?
  result
end

fn component_abort_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  let source = ready(f)?
  let names = ["profile/v1"] ++ labels(f)?
  let before = snapshot_rows(f.accounts.bob_path, names)?
  let all_before = ciphertext_rows(f.accounts.bob_path)?
  check(case prepare(f, source.revision) do
      Err("fixture_spqr_boundary_abort") -> true
      _ -> false
    end,
    "fixture_real_component_abort_reached")?
  check(same_rows(before, snapshot_rows(f.accounts.bob_path, names)?),
    "fixture_all_rows_unchanged_after_abort")?
  check(same_rows(all_before, ciphertext_rows(f.accounts.bob_path)?),
    "fixture_complete_ciphertext_set_after_abort")?
  let unchanged = restore_consumer(f, metadata(f)?)?
  check(U64.compare(unchanged.epoch, number("0")?) == 0
      && U64.compare(unchanged.knowledge, number("0")?) == 0,
    "fixture_abort_keeps_old_consumer")
end

pub fn copied_source_unknown_reply() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = unknown_reply_inner(f)
  cleanup(accounts)?
  result
end

fn unknown_reply_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  let source = ready(f)?
  let path = f.accounts.bob_path
  let _writer = spawn(journal_fault_writer,
    path,
    f.bob_profile,
    f.scope,
    source.revision,
    intent()?)
  check(await_file(path <> ".gate.result", 6000)
      && File.read(path <> ".gate.result")? == "fixture_spqr_unknown_reply",
    "fixture_commit_reply_actually_lost")?
  let committed = metadata(f)?
  check(committed.phase == 6 && U64.compare(committed.local_epoch, number("1")?) == 0,
    "fixture_unknown_commit_is_durable")?
  let before = snapshot_rows(path, ["profile/v1"] ++ labels(f)?)?
  let all_before = ciphertext_rows(path)?
  let _reader = spawn(journal_fresh_reader,
    path,
    f.bob_profile,
    f.scope,
    source.revision,
    intent()?)
  check(await_file(path <> ".reader.result", 6000), "fixture_fresh_actor_finished")?
  let recovered = recover(f, source.revision)?
  check(File.read(path <> ".reader.result")? == Bytes.to_hex(recovered.transition)
        <> ":"
        <> Bytes.to_hex(recovered.envelope_id)
        <> ":"
        <> Bytes.to_hex(recovered.envelope),
    "fixture_fresh_actor_exact_pending")?
  check(same_rows(before, snapshot_rows(path, ["profile/v1"] ++ labels(f)?)?),
    "fixture_fresh_actor_does_no_reseal")?
  check(same_rows(all_before, ciphertext_rows(path)?),
    "fixture_complete_ciphertext_set_after_recovery")
end

pub fn copied_source_guard_race() -> Result<(), String> do
  let f = make_braid_spqr_fixture()?
  let accounts = f.accounts
  let result = guard_race_inner(f)
  cleanup(accounts)?
  result
end

fn guard_race_inner(f :: consume BraidSpqrFixture) -> Result<(), String> do
  let source = ready(f)?
  let path = f.accounts.bob_path
  let all = labels(f)?
  let _writer = spawn(journal_fault_writer,
    path,
    f.bob_profile,
    f.scope,
    source.revision,
    intent()?)
  check(await_file(path <> ".gate.ready", 6000), "fixture_prepared_writer_reached_copied_barrier")?
  let mode = Env.get("MORSE_C1_SOURCE_RACE", "history")
  let target = if mode == "session" do
    selected(f)?
  else if mode == "history" do
    List.head(List.filter(all, fn(label) -> String.starts_with(label, "history/v1/") end))
  else if mode == "routing" do
    "header-routing/v1"
  else if mode == "outbox" do
    "outbox/v1"
  else if mode == "postage" do
    "postage-queue/v1"
  else if mode == "delivery" do
    "delivery/v1"
  else if mode == "absent-target" do
    List.get(braid_spqr_labels(f.scope), 6)
  else
    "profile/v1"
  end
  let key = platform_key()?
  if mode == "custody" do
    erase_account_if_current(path, load_account_basis(path, all)?.profile)?
  else
    store_updated_blobs(path,
      [target],
      [
        seal_local(Bytes.from_utf8("TEST ONLY changed during prepared crypto"),
          key,
          local_context(target)?)?
      ])?
  end
  let changed = snapshot_rows(path, ["profile/v1"] ++ all)?
  let all_changed = ciphertext_rows(path)?
  File.write(path <> ".gate.go", "go")?
  check(await_file(path <> ".gate.result", 6000), "fixture_racing_writer_finished")?
  let reason = File.read(path <> ".gate.result")?
  check(reason == "account_state_changed" || reason == "outbox_state_changed",
    "fixture_original_basis_fences_race")?
  check(same_rows(changed, snapshot_rows(path, ["profile/v1"] ++ all)?),
    "fixture_race_publishes_no_other_rows")?
  check(same_rows(all_changed, ciphertext_rows(path)?),
    "fixture_complete_ciphertext_set_after_race")
end
