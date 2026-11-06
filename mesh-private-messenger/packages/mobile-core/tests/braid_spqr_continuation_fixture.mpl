##! TEST ONLY source preparation. Actual B0 peers; no independent seed initializer.
from Mobile.BraidSpqrBootstrap import start_braid_spqr_once, receive_braid_spqr_initial
from Mobile.BraidSpqrJournal import (
  BraidSpqrStepOutcome,
  accept_braid_spqr_request,
  prepare_braid_spqr_fragment_once,
  receive_braid_spqr_fragment,
  recover_braid_spqr_fragment,
  receive_braid_spqr_control,
  prepare_braid_spqr_ct1_once,
  recover_braid_spqr_pending
)
from Mobile.BraidSpqrState import (
  BraidSpqrMetadata,
  braid_spqr_labels,
  braid_spqr_descriptor,
  braid_spqr_metadata_bytes,
  decode_braid_spqr_metadata,
  braid_spqr_transition
)
from Mobile.Profile import load_profile
from Mobile.Sessions import (
  load_session_record,
  restore_session,
  parse_ratchet_packet,
  updated_session_record
)
from Mobile.Outbox import load_outbox_ids, load_outbox_entry
from Mobile.Transport import open_outer_packet, sealed_outer_bytes
from Mobile.Codec import (
  canonical_outer,
  current_time,
  mobile_join,
  mobile_vector,
  mobile_read_u64,
  mobile_write_u64
)
from Mobile.SessionPolicy import capture_native_session_policy, native_session_minimum
from MobileCore import (
  create_account_export,
  create_link_request_export,
  authorize_device_link_export,
  complete_device_link_export,
  directory_entry_export
)
from Storage.Keys import platform_key, local_context, context, open_local, open_x25519, seal_local
from Storage.Blobs import load_blob
from Storage.Records import erase_local_state, store_updated_blobs
from Session.BraidResponder import BraidScope, BraidAwaitHeader, BraidHeaderAdmission
from Session.BraidInitiator import (
  BraidAliceHeaderSent,
  BraidAliceCt1Received,
  send_header,
  send_vector,
  receive_ct1,
  receive_ct2
)
from Session.BraidBilateralStore import (
  BraidBilateralSaved,
  restore_alice_idle,
  restore_alice_header,
  restore_bob_first,
  restore_bob_vector,
  restore_bob_second
)
from Session.BraidFragment import BraidFragment, BraidFragmentKind, encode_braid_fragment
from Session.BraidFragmentWords import emit_braid_fragment, recover_braid_carrier
from Session.Spqr import SpqrState, incorporate_spqr_epoch
from Session.SpqrStore import SpqrSaved, restore_spqr
from Session.State import RatchetState
from Session.HeaderRatchet import he_encrypt_hybrid, he_decrypt_hybrid
from Session.TripleWire import encode_triple_message, decode_triple_message
from Transport.Packet import TransportPacket, decode_client_profile, encode_packet, session_aad
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import DeviceSet
from Transparency.Merkle import leaf_hash
from Tests.GroupLifecycleSupport import GroupAccountFixture, install_signed_transparency
from Tests.GroupConsistencySupport import (
  SignedTransparencyViewFixture,
  signed_transparency_view,
  request
)
from Tests.Support import repeated
from Mobile.ConversationPolicy import prepare_conversation_policy, commit_conversation_policy
from Session.BraidStore import BraidSaved, restore_await
from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.FanoutCommit import FanoutSnapshot, capture_fanout_snapshot
from Mobile.BraidJournal import braid_labels
from Mobile.BraidAliceState import alice_header_labels

struct B1Accounts do
  accounts :: GroupAccountFixture
  alice_profile :: Bytes
  bob_profile :: Bytes
  alice_scope :: BraidScope
  bob_scope :: BraidScope
end

resource struct B1Peer do
  fixture :: B1Accounts
  he :: RatchetState
  pq :: SpqrState
  alice :: BraidAliceCt1Received
  vector :: Bytes
  first :: Bytes
end

fn b1_check(ok :: Bool, reason :: String) -> Unit!String do
  if ok do
    Ok(nil)
  else
    Err(reason)
  end
end

fn b1_num(value :: String) -> U64!String do
  U64.parse(value)
end

fn b1_config() -> Bytes do
  Crypto.sha256(Bytes.from_utf8("TEST ONLY B1 actual bootstrap profile"))
end

fn b1_intent(value :: String) -> Bytes do
  Crypto.sha256(Bytes.from_utf8("TEST ONLY B1 intent " <> value))
end

fn b1_meta(path :: String, scope :: BraidScope) -> BraidSpqrMetadata!String do
  let key = platform_key()?
  let name = List.get(braid_spqr_labels(scope), 0)
  decode_braid_spqr_metadata(open_local(load_blob(path, name)?, key, local_context(name)?)?, scope)
end

fn b1_pq(path :: String, m :: BraidSpqrMetadata) -> SpqrState!String do
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

fn b1_kernel(path :: String, m :: BraidSpqrMetadata) -> BraidBilateralSaved!String do
  let ls = braid_spqr_labels(m.scope)
  let maybe = fn(index) do
    case load_blob(path, List.get(ls, index)) do
      Ok(v)
      Err("local_state_not_found") -> Ok(Bytes.empty())
      Err(error)
    end
  end
  Ok(BraidBilateralSaved {
    scope: m.scope,
    role: if m.direction == 0 do
      1
    else
      2
    end,
    substate: if m.direction == 0 do
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
    end,
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
    secrets: load_blob(path, List.get(ls, 1))?,
    epoch_key: maybe(2)?,
    continuation: maybe(3)?
  })
end

fn b1_prepare(f :: B1Accounts, alice :: Bool, intent :: String) -> BraidSpqrStepOutcome!String do
  let path = if alice do
    f.accounts.alice_path
  else
    f.accounts.bob_path
  end
  let scope = if alice do
    f.alice_scope
  else
    f.bob_scope
  end
  let profile = if alice do
    f.alice_profile
  else
    f.bob_profile
  end
  let old = b1_meta(path, scope)?
  prepare_braid_spqr_fragment_once(path,
    profile,
    scope,
    old.revision,
    old.transition,
    b1_intent(intent))
end

fn b1_receive(f :: B1Accounts, envelope :: Bytes) -> BraidSpqrStepOutcome!String do
  receive_braid_spqr_fragment(f.accounts.bob_path, f.bob_profile, f.bob_scope, envelope)
end

fn b1_bootstrap_initial() -> B1Accounts!String do
  b1_check(Test.install_in_memory_secure_store(), "b1_fixture_secure_store")?
  let accounts = owned_accounts()?
  let signed = signed_transparency_view([
    leaf_hash(accounts.alice_set)?,
    leaf_hash(accounts.bob_set)?
  ])?
  install_policy(signed)?
  for path in [accounts.alice_path, accounts.bob_path] do
    b1_check(install_signed_transparency(path, signed, accounts.alice_set)?,
      "b1_fixture_transparency")?
    b1_check(install_signed_transparency(path, signed, accounts.bob_set)?,
      "b1_fixture_transparency")?
  end
  # Restore canonical policy AFTER the transparency helper's own config write.
  install_policy(signed)?
  let alice = load_profile(accounts.alice_path)?
  let bob = load_profile(accounts.bob_path)?
  let sent = start_braid_spqr_once(accounts.alice_path,
    alice,
    bob,
    repeated(9, 16)?,
    b1_config(),
    b1_intent("initial"))?
  let opened = receive_braid_spqr_initial(accounts.bob_path,
    bob,
    alice,
    repeated(9, 16)?,
    b1_config(),
    sent.envelope)?
  b1_check(Bytes.secure_equals(sent.scope.session_id, opened.scope.session_id),
    "b1_fixture_actual_B0")?
  Ok(B1Accounts {
    accounts: accounts,
    alice_profile: alice,
    bob_profile: bob,
    alice_scope: sent.scope,
    bob_scope: opened.scope
  })
end

# TEST ONLY explicit local user accept; production B0 remains pending.
fn b1_initial() -> B1Accounts!String do
  let f = b1_bootstrap_initial()?
  case accept_braid_spqr_request(f.accounts.bob_path, f.bob_profile, f.bob_scope) do
    Ok(_) -> Ok(f)
    Err(error) -> do
      b1_cleanup(f)?
      Err(error)
    end
  end
end

fn b1_cleanup(f :: B1Accounts) -> Unit!String do
  for path in [f.accounts.alice_path, f.accounts.bob_path, f.accounts.linked_path] do
    erase_local_state(path)?
  end
  Ok(nil)
end

fn b1_with(run :: Fun(B1Accounts) -> Unit!String) -> Unit!String do
  let f = b1_initial()?
  let result = run(f)
  b1_cleanup(f)?
  result
end

fn b1_ready(f :: B1Accounts) -> Unit!String do
  let first = b1_prepare(f, true, "hdr0")?
  let a1 = b1_meta(f.accounts.alice_path, f.alice_scope)?
  b1_check(a1.kernel_tag == 3 && List.get(a1.cursors, 0) == 1, "b1_header_generated_once")?
  let key = platform_key()?
  let saved = b1_kernel(f.accounts.alice_path, a1)?
  let _owner = case restore_alice_header(saved, saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("b1_header_typed_private_restore")
  end
  let partial = b1_receive(f, first.envelope)?
  b1_check(partial.phase == 4, "b1_header_rank_one")?
  let second = b1_prepare(f, true, "hdr1")?
  let a2 = b1_meta(f.accounts.alice_path, f.alice_scope)?
  b1_check(Bytes.secure_equals(a1.header, a2.header)
      && Bytes.secure_equals(a1.vector, a2.vector)
      && List.get(a2.cursors, 0) == 2,
    "b1_header_same_carrier_key")?
  let accepted = b1_receive(f, second.envelope)?
  b1_check(accepted.phase == 5 && U64.compare(accepted.local_epoch, b1_num("0")?) == 0,
    "b1_actual_header_admission")
end

fn install_policy(signed :: SignedTransparencyViewFixture) -> Result<(), String> do
  let bare = "1\n"
    <> Bytes.to_hex(signed.service_public_key)
    <> "\n"
    <> Bytes.to_hex(signed.witness_a_public_key)
    <> "\n"
    <> Bytes.to_hex(signed.witness_b_public_key)
    <> "\n8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a\n1"
  b1_check(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
      Bytes.from_utf8("6\n2\n" <> bare)),
    "fixture_native_config")?
  b1_check(native_session_minimum(capture_native_session_policy()?)? == 2,
    "fixture_current_suite_floor")
end

fn owned_path(name :: String) -> String!String do
  b1_check(String.length(Env.get("MORSE_C1_FIXTURE_ROOT", "")) > 0, "b1_fixture_root_required")?
  let nonce = case Crypto.random_bytes(8) do
    Ok(v) -> v
    Err(_) -> return Err("fixture_path")
  end
  Ok(Env.get("MORSE_C1_FIXTURE_ROOT", "")
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

fn row_set(path :: String) -> List<Bytes>!String do
  let db = Sqlite.open(path)?
  let rows = Sqlite.query_values(db,
    "SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash",
    [])?
  let indices = Sqlite.query_values(db,
    "SELECT version, database_id, key_check FROM encrypted_blob_index ORDER BY version",
    [])?
  Sqlite.close(db)
  b1_check(List.length(indices) == 1, "fixture_blob_index_count")?
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

fn b1_wrap(f :: B1Accounts, message :: Bytes, to_bob :: Bool) -> Bytes!String do
  let target = decode_client_profile(if to_bob do
    f.bob_profile
  else
    f.alice_profile
  end)?
  sealed_outer_bytes(target.entry.mailbox_token,
    encode_packet(RatchetPacket(message))?,
    target.credential.dh_public_key,
    current_time()?)
end

fn b1_unwrap(f :: B1Accounts, envelope :: Bytes, at_alice :: Bool) -> Bytes!String do
  let path = if at_alice do
    f.accounts.alice_path
  else
    f.accounts.bob_path
  end
  let profile = decode_client_profile(if at_alice do
    f.alice_profile
  else
    f.bob_profile
  end)?
  let key = platform_key()?
  let identity = open_x25519(load_blob(path, "device-identity-key/v1")?,
    key,
    context(profile.account_id, profile.device_id, "device-identity-key/v1", 8)?)?
  let packet = open_outer_packet(canonical_outer(envelope)?, identity)?
  b1_check(packet.sealed, "b1_actual_sealed_recipient")?
  parse_ratchet_packet(packet.packet)
end

fn b1_open(f :: B1Accounts,
  he :: consume RatchetState,
  pq :: consume SpqrState,
  envelope :: Bytes) -> (RatchetState, SpqrState, BraidFragment)!String do
  let message = case decode_triple_message(b1_unwrap(f, envelope, true)?) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_CHF1")
  end
  case he_decrypt_hybrid(he, pq, message, session_aad(f.alice_scope.session_id)?) do
    HybridOpened(h, q, header, clear) -> do
      b1_check(Bytes.length(clear) == 0, "b1_actual_empty_control_body")?
      Ok((h, q, header.fragment))
    end
    _ -> Err("b1_fixture_real_combined_body_open")
  end
end

fn b1_collect(f :: B1Accounts,
  he :: consume RatchetState,
  pq :: consume SpqrState,
  kind :: BraidFragmentKind,
  count :: Int,
  index :: Int,
  words :: List<BraidFragment>) -> (RatchetState, SpqrState, Bytes)!String do
  if index == count do
    let complete = case recover_braid_carrier(kind,
      f.alice_scope.configuration,
      f.alice_scope.session_id,
      b1_num("1")?,
      words) do
      Ok(Some(v)) -> v
      _ -> return Err("b1_fixture_actual_complete_carrier")
    end
    return Ok((he, pq, complete))
  end
  let label = if kind == BraidFirstFragment do
    "first"
  else
    "second"
  end
  let prepared = b1_prepare(f, false, "peer-#{label}-#{index}")?
  let (he, pq, fragment) = b1_open(f, he, pq, prepared.envelope)?
  b1_check(fragment.kind == kind
      && fragment.index == index
      && U64.compare(fragment.epoch, b1_num("1")?) == 0,
    "b1_exact_finite_sent_fragment")?
  b1_collect(f, he, pq, kind, count, index + 1, List.append(words, fragment))
end

fn b1_peer(f :: B1Accounts) -> B1Peer!String do
  b1_ready(f)?
  let m = b1_meta(f.accounts.alice_path, f.alice_scope)?
  let key = platform_key()?
  let saved = b1_kernel(f.accounts.alice_path, m)?
  let owner = case restore_alice_header(saved, saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_real_saved_header")
  end
  let (ek, vector) = case send_vector(owner) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_actual_send_vector")
  end
  let he = restore_session(load_session_record(f.accounts.alice_path,
      key,
      f.alice_scope.session_id)?,
    key)?
  let pq = b1_pq(f.accounts.alice_path, m)?
  let (he, pq, first) = b1_collect(f, he, pq, BraidFirstFragment, 15, 0, [])?
  let alice = case receive_ct1(ek, b1_num("1")?, MlKemCiphertext1_960 { bytes: first }) do
    BraidAliceCt1Accepted(v) -> v
    _ -> return Err("b1_fixture_actual_Ct1_admission")
  end
  let bob = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(bob.phase == 6
      && bob.kernel_tag == 6
      && U64.compare(bob.local_epoch, b1_num("1")?) == 0
      && U64.compare(bob.knowledge, b1_num("0")?) == 0
      && List.get(bob.cursors, 2) == 15,
    "b1_actual_ADD1_and_fifteen_sends")?
  let saved_bob = b1_kernel(f.accounts.bob_path, bob)?
  let actual = case restore_bob_first(saved_bob, saved_bob, key) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_actual_bob_first_restore")
  end
  b1_check(!SecretMap.contains(actual.secrets, Bytes.from_utf8("output"))
      && Bytes.secure_equals(actual.first.bytes, first),
    "b1_no_durable_output_exact_Ct1")?
  Ok(B1Peer { fixture: f, he: he, pq: pq, alice: alice, vector: vector.bytes, first: first })
end

fn b1_mutate(bytes :: Bytes) -> Bytes!String do
  let last = Bytes.length(bytes) - 1
  let suffix = case Bytes.from_list([(Bytes.get(bytes, last)? + 1) % 256]) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_byte_literal")
  end
  mobile_join([Bytes.slice(bytes, 0, last)?, suffix], 0, Bytes.empty())
end

fn b1_peer_send(peer :: consume B1Peer,
  kind :: BraidFragmentKind,
  index :: Int,
  conflicting :: Bool) -> (B1Peer, Bytes)!String do
  let B1Peer { fixture, he, pq, alice, vector, first } = peer
  let carrier = if kind == BraidAckFragment do
    Bytes.empty()
  else
    vector
  end
  let fragment = case emit_braid_fragment(kind,
    fixture.alice_scope.configuration,
    fixture.alice_scope.session_id,
    b1_num("1")?,
    carrier,
    index) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_actual_Ek_word")
  end
  let fragment = if conflicting do
    %{fragment | word: b1_mutate(fragment.word)?}
  else
    fragment
  end
  let (he, pq, message) = case he_encrypt_hybrid(he,
    pq,
    Bytes.empty(),
    fragment,
    session_aad(fixture.alice_scope.session_id)?) do
    HybridSealed(h, q, v) -> (h, q, v)
    _ -> return Err("b1_fixture_actual_combined_send")
  end
  let bytes = case encode_triple_message(message) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_encode_CHF1")
  end
  Ok((B1Peer { fixture: fixture, he: he, pq: pq, alice: alice, vector: vector, first: first },
    b1_wrap(fixture, bytes, true)?))
end

fn b1_vectors(peer :: consume B1Peer, index :: Int, stop :: Int) -> B1Peer!String do
  if index == stop do
    return Ok(peer)
  end
  let f = peer.fixture
  let (peer, raw) = b1_peer_send(peer, BraidVectorFragment, index, false)?
  b1_receive(f, raw)?
  b1_vectors(peer, index + 1, stop)
end

fn b1_root_tag(pq :: borrow SpqrState) -> Bytes!String do
  let name = case Bytes.from_list([0]) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_root_name")
  end
  let root = case SecretMap.copy(pq.chains, name) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_root_copy")
  end
  let result = case Crypto.hmac_sha256_tag(root,
    Bytes.from_utf8("TEST ONLY B1 actual SPQR root agreement")) do
    Ok(v)
    Err(_) -> Err("b1_fixture_root_tag")
  end
  Secret.destroy(root)
  result
end

fn b1_finish(peer :: consume B1Peer) -> Unit!String do
  let B1Peer { fixture, he, pq, alice, vector: _vector, first: _first } = peer
  let before = b1_meta(fixture.accounts.bob_path, fixture.bob_scope)?
  b1_check(before.phase == 9 && Bytes.length(before.second) == 160, "b1_actual_Ct2_saved")?
  let key = platform_key()?
  let saved = b1_kernel(fixture.accounts.bob_path, before)?
  let actual = case restore_bob_second(saved, saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("b1_fixture_actual_Ct2_restore")
  end
  b1_check(Bytes.secure_equals(actual.wire, before.second) && Bytes.length(saved.continuation) == 0,
    "b1_continuation_deleted_exact_wire")?
  let (he, pq, wire) = b1_collect(fixture, he, pq, BraidSecondFragment, 3, 0, [])?
  let (next, output) = case receive_ct2(alice, b1_num("1")?, wire) do
    BraidAliceCt2Accepted(v, output) -> (v, output)
    _ -> return Err("b1_fixture_actual_peer_Ct2_auth")
  end
  let pq = case incorporate_spqr_epoch(pq, output) do
    SpqrEpochAccepted(v) -> v
    _ -> return Err("b1_fixture_actual_peer_ADD1")
  end
  let bob = b1_meta(fixture.accounts.bob_path, fixture.bob_scope)?
  let bob_pq = b1_pq(fixture.accounts.bob_path, bob)?
  b1_check(U64.compare(next.epoch, b1_num("2")?) == 0
      && U64.compare(pq.epoch, b1_num("1")?) == 0
      && U64.compare(pq.knowledge, b1_num("0")?) == 0
      && U64.compare(bob_pq.knowledge, b1_num("0")?) == 0
      && Bytes.secure_equals(b1_root_tag(pq)?, b1_root_tag(bob_pq)?),
    "b1_actual_output_agreement_no_fake_K")?
  # A real E2 combined-key message is possible only after this actual output.
  # B1 production receiver must refuse it without advancing durable K0.
  let future = case emit_braid_fragment(NoBraidFragment,
    fixture.alice_scope.configuration,
    fixture.alice_scope.session_id,
    b1_num("2")?,
    Bytes.empty(),
    0) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_actual_future_fragment")
  end
  let (_he, _pq, message) = case he_encrypt_hybrid(he,
    pq,
    Bytes.empty(),
    future,
    session_aad(fixture.alice_scope.session_id)?) do
    HybridSealed(h, q, v) -> (h, q, v)
    _ -> return Err("b1_fixture_actual_future_key")
  end
  let raw = case encode_triple_message(message) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_actual_future_wire")
  end
  let rows = row_set(fixture.accounts.bob_path)?
  b1_check(Result.is_err(b1_receive(fixture, b1_wrap(fixture, raw, true)?))
      && equal_rows(rows, row_set(fixture.accounts.bob_path)?),
    "b1_future_epoch_atomic_refusal")
end

fn b1_header_output_inner(f :: B1Accounts) -> Unit!String do
  let _peer = b1_peer(f)?
  let m = b1_meta(f.accounts.bob_path, f.bob_scope)?
  let key = platform_key()?
  let old = row_set(f.accounts.bob_path)?
  let source = mobile_read_u64(Bytes.slice(m.local_attempt, 1, 8)?)?
  let tr = Bytes.slice(m.local_attempt, 9, 32)?
  let recovered = recover_braid_spqr_fragment(f.accounts.bob_path,
    f.bob_profile,
    f.bob_scope,
    source,
    tr,
    b1_intent("peer-first-14"))?
  b1_check(equal_rows(old, row_set(f.accounts.bob_path)?)
      && Bytes.secure_equals(recovered.envelope,
        load_outbox_entry(f.accounts.bob_path, key, recovered.envelope_id)?)
      && List.length(load_outbox_ids(f.accounts.bob_path, key)?) == 15,
    "b1_exact_first_output_pending_recovery")
end

fn b1_no_ack_inner(f :: B1Accounts) -> Unit!String do
  let peer = b1_peer(f)?
  let (peer, early) = b1_peer_send(peer, BraidAckFragment, 0, false)?
  let ignored = b1_receive(f, early)?
  let m = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(ignored.kind == 7 && m.phase == 6 && Bytes.get(m.peer_ack, 0)? == 0,
    "b1_early_standalone_ack_ignored")?
  let peer = b1_vectors(peer, 0, 18)?
  let m = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(m.phase == 8
      && m.kernel_tag == 7
      && Bytes.get(m.peer_ack, 0)? == 0
      && Bytes.length(m.vector) == 1152
      && Bytes.length(m.second) == 0,
    "b1_complete_vector_without_ACK_waits")?
  let key = platform_key()?
  let saved = b1_kernel(f.accounts.bob_path, m)?
  let _actual = case restore_bob_vector(saved, saved, key) do
    Ok(v) -> v
    Err(_) -> return Err("b1_actual_vector_owner_restore")
  end
  let (peer, ack) = b1_peer_send(peer, BraidAckFragment, 0, false)?
  let accepted = b1_receive(f, ack)?
  b1_check(accepted.phase == 9, "b1_genuine_ack_unblocks_actual_Ct2")?
  b1_finish(peer)
end

fn b1_reordered_inner(f :: B1Accounts) -> Unit!String do
  let peer = b1_peer(f)?
  let (peer, first) = b1_peer_send(peer, BraidVectorFragment, 17, false)?
  b1_receive(f, first)?
  let rows = row_set(f.accounts.bob_path)?
  let (peer, conflict) = b1_peer_send(peer, BraidVectorAckFragment, 17, true)?
  b1_check(Result.is_err(b1_receive(f, conflict))
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_conflict_with_ACK_whole_rollback")?
  let (peer, ack) = b1_peer_send(peer, BraidVectorAckFragment, 17, false)?
  b1_receive(f, ack)?
  let m = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(m.phase == 7
      && List.length(m.partial_indices) == 1
      && Bytes.get(m.peer_ack, 0)? == 1
      && Bytes.secure_equals(Bytes.slice(m.peer_ack, 9, 32)?, Crypto.sha256(m.first)),
    "b1_authenticated_ACKpartial_binds_Ct1")?
  let (peer, duplicate) = b1_peer_send(peer, BraidVectorFragment, 17, false)?
  b1_receive(f, duplicate)?
  let duplicate_m = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(duplicate_m.phase == 7
      && List.length(duplicate_m.partial_indices) == 1
      && Bytes.secure_equals(m.peer_ack, duplicate_m.peer_ack)
      && U64.compare(duplicate_m.revision, m.revision) > 0,
    "b1_fresh_authenticated_duplicate_no_rank_no_ACK_loss")?
  let peer = b1_vectors(peer, 0, 17)?
  b1_check(b1_meta(f.accounts.bob_path, f.bob_scope)?.phase == 9,
    "b1_reordered_bare_Ek_retains_ACK")?
  b1_finish(peer)
end

fn b1_pending_inner(f :: B1Accounts) -> Unit!String do
  let peer = b1_peer(f)?
  let m = b1_meta(f.accounts.bob_path, f.bob_scope)?
  let rev = mobile_read_u64(Bytes.slice(m.local_attempt, 1, 8)?)?
  let source_tr = Bytes.slice(m.local_attempt, 9, 32)?
  let original = recover_braid_spqr_fragment(f.accounts.bob_path,
    f.bob_profile,
    f.bob_scope,
    rev,
    source_tr,
    b1_intent("peer-first-14"))?
  let key = platform_key()?
  let outbox = load_outbox_ids(f.accounts.bob_path, key)?
  let old_maps = [
    load_blob(f.accounts.bob_path, List.get(braid_spqr_labels(f.bob_scope), 4))?,
    load_blob(f.accounts.bob_path, List.get(braid_spqr_labels(f.bob_scope), 5))?
  ]
  let (_peer, raw) = b1_peer_send(peer, BraidVectorFragment, 0, false)?
  let received = b1_receive(f, raw)?
  let changed = b1_meta(f.accounts.bob_path, f.bob_scope)?
  let recovered = recover_braid_spqr_fragment(f.accounts.bob_path,
    f.bob_profile,
    f.bob_scope,
    rev,
    source_tr,
    b1_intent("peer-first-14"))?
  b1_check(Bytes.secure_equals(original.envelope, recovered.envelope)
      && U64.compare(original.pending_creation_revision, recovered.pending_creation_revision) == 0
      && Bytes.secure_equals(original.pending_creation_transition,
        recovered.pending_creation_transition)
      && U64.compare(recovered.current_revision, original.current_revision) > 0
      && !Bytes.secure_equals(recovered.current_transition, recovered.pending_creation_transition)
      && List.length(load_outbox_ids(f.accounts.bob_path, key)?) == List.length(outbox),
    "b1_pending_creation_survives_receive")?
  let bad = SpqrSaved {
    scope: changed.scope,
    direction: changed.direction,
    epoch: changed.local_epoch,
    knowledge: changed.knowledge,
    slots: changed.slots,
    skipped_index: changed.skipped_index,
    revision: changed.revision,
    transition: changed.transition,
    descriptor: braid_spqr_descriptor(changed)?,
    chains: List.get(old_maps, 0),
    skipped: List.get(old_maps, 1)
  }
  let refused = case restore_spqr(bad, bad, key) do
    Err(_) -> true
    Ok(_) -> false
  end
  b1_check(refused, "b1_old_maps_refuse_current_descriptor")?
  let rows = row_set(f.accounts.bob_path)?
  let duplicate = b1_receive(f, raw)?
  b1_check(duplicate.kind == 8
      && U64.compare(duplicate.inbound_revision, received.inbound_revision) == 0
      && Bytes.secure_equals(duplicate.inbound_transition, received.inbound_transition)
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_raw_duplicate_readonly_original_disposition")?
  let replacement = b1_prepare(f, false, "replacement")?
  let rows = row_set(f.accounts.bob_path)?
  b1_check(Result.is_err(recover_braid_spqr_fragment(f.accounts.bob_path,
      f.bob_profile,
      f.bob_scope,
      rev,
      source_tr,
      b1_intent("peer-first-14")))
      && equal_rows(rows, row_set(f.accounts.bob_path)?)
      && !Bytes.secure_equals(replacement.envelope_id, original.envelope_id),
    "b1_replaced_attempt_refused_independent_outbox_retained")
end

fn b1_failures_inner(f :: B1Accounts) -> Unit!String do
  let peer = b1_peer(f)?
  let (peer, raw) = b1_peer_send(peer, BraidVectorFragment, 0, false)?
  let msg = case decode_triple_message(b1_unwrap(f, raw, false)?) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_tamper_decode")
  end
  let broken = case encode_triple_message(%{msg | ciphertext: b1_mutate(msg.ciphertext)?}) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_tamper_encode")
  end
  let rows = row_set(f.accounts.bob_path)?
  b1_check(Result.is_err(b1_receive(f, b1_wrap(f, broken, true)?))
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_combined_body_failure_exact_rollback")?
  b1_receive(f, raw)?
  let m = b1_meta(f.accounts.bob_path, f.bob_scope)?
  let rows = row_set(f.accounts.bob_path)?
  b1_check(Result.is_err(receive_braid_spqr_control(f.accounts.bob_path,
      f.bob_profile,
      f.bob_scope,
      raw))
      && Result.is_err(prepare_braid_spqr_ct1_once(f.accounts.bob_path,
        f.bob_profile,
        f.bob_scope,
        m.revision,
        b1_intent("legacy")))
      && Result.is_err(recover_braid_spqr_pending(f.accounts.bob_path,
        f.bob_profile,
        f.bob_scope,
        m.revision,
        b1_intent("legacy")))
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_no_legacy_RAT4_fallback")?
  let name = "c1/bootstrap/v1/#{Bytes.to_hex(b1_config())}/#{Bytes.to_hex(f.bob_scope.peer_account_id)}/#{Bytes.to_hex(f.bob_scope.peer_device_id)}"
  let key = platform_key()?
  let corrupt = seal_local(repeated(0, 262)?, key, local_context(name)?)?
  store_updated_blobs(f.accounts.bob_path, [name], [corrupt])?
  let rows = row_set(f.accounts.bob_path)?
  let (_peer, next) = b1_peer_send(peer, BraidVectorFragment, 1, false)?
  b1_check(Result.is_err(b1_receive(f, next)) && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_bootstrap_provenance_corruption_refused")
end

pub fn b1_header_and_output() -> Unit!String do
  b1_with(b1_header_output_inner)
end

pub fn b1_no_ack_then_ack() -> Unit!String do
  b1_with(b1_no_ack_inner)
end

pub fn b1_reordered_ack_conflict() -> Unit!String do
  b1_with(b1_reordered_inner)
end

pub fn b1_pending_provenance() -> Unit!String do
  b1_with(b1_pending_inner)
end

pub fn b1_body_and_mode_refusals() -> Unit!String do
  b1_with(b1_failures_inner)?
  b1_with(b1_fatal_inner)
end

pub fn b1_report(value :: Unit!String) -> Bool do
  case value do
    Ok(_) -> true
    Err(reason) -> do
      println(reason)
      false
    end
  end
end

fn b1_seal(f :: B1Accounts,
  he :: consume RatchetState,
  pq :: consume SpqrState,
  fragment :: BraidFragment) -> (RatchetState, SpqrState, Bytes)!String do
  let (he, pq, message) = case he_encrypt_hybrid(he,
    pq,
    Bytes.empty(),
    fragment,
    session_aad(f.alice_scope.session_id)?) do
    HybridSealed(h, q, v) -> (h, q, v)
    _ -> return Err("b1_fixture_real_header_seal")
  end
  let raw = case encode_triple_message(message) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_real_header_wire")
  end
  Ok((he, pq, b1_wrap(f, raw, true)?))
end

fn b1_fatal_inner(f :: B1Accounts) -> Unit!String do
  let m = b1_meta(f.accounts.alice_path, f.alice_scope)?
  let key = platform_key()?
  let saved = b1_kernel(f.accounts.alice_path, m)?
  let idle = case restore_alice_idle(saved, saved, key) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_actual_idle_for_malicious_peer")
  end
  let (_owner, header) = case send_header(idle) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_actual_malicious_header")
  end
  let bad_mac = b1_mutate(header)?
  let fragment = case emit_braid_fragment(BraidHeaderFragment,
    f.alice_scope.configuration,
    f.alice_scope.session_id,
    b1_num("1")?,
    bad_mac,
    0) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_actual_bad_inner_MAC_word")
  end
  let he = restore_session(load_session_record(f.accounts.alice_path,
      key,
      f.alice_scope.session_id)?,
    key)?
  let (he, pq, first) = b1_seal(f, he, b1_pq(f.accounts.alice_path, m)?, fragment)?
  b1_receive(f, first)?
  let fragment = case emit_braid_fragment(BraidHeaderFragment,
    f.alice_scope.configuration,
    f.alice_scope.session_id,
    b1_num("1")?,
    bad_mac,
    1) do
    Ok(v) -> v
    _ -> return Err("b1_fixture_actual_bad_inner_MAC_second")
  end
  let (_he, _pq, second) = b1_seal(f, he, pq, fragment)?
  b1_check(case b1_receive(f, second) do
      Err("c1_spqr_terminal_generation") -> true
      _ -> false
    end,
    "b1_only_actual_authenticated_HeaderFatal_terminal")?
  let terminal = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(terminal.phase == 10 && List.length(terminal.slots) == 0,
    "b1_terminal_metadata_no_owner_resurrection")?
  for name in List.drop(braid_spqr_labels(f.bob_scope), 1) do
    b1_check(case load_blob(f.accounts.bob_path, name) do
        Err("local_state_not_found") -> true
        _ -> false
      end,
      "b1_terminal_typed_components_deleted")?
  end
  let rows = row_set(f.accounts.bob_path)?
  b1_check(Result.is_err(b1_prepare(f, false, "terminal"))
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_terminal_cannot_reinitialize")
end

fn b1_literal_hex(name :: String) -> Bytes!String do
  case Bytes.from_hex(Env.get(name, "")) do
    Ok(v)
    _ -> Err("b1_fixture_literal_environment")
  end
end

fn b1_literal_scope() -> BraidScope!String do
  let c = repeated(1, 32)?
  let h = repeated(2, 32)?
  Ok(BraidScope {
    protocol_info: mobile_join([Bytes.from_utf8("mesh-msg/braid/v1"), repeated(0, 1)?, c, h],
      0,
      Bytes.empty())?,
    configuration: c,
    session_id: h,
    account_id: repeated(3, 32)?,
    device_id: repeated(4, 16)?,
    peer_account_id: repeated(5, 32)?,
    peer_device_id: repeated(6, 16)?
  })
end

pub fn b1_schema_and_bounds() -> Unit!String do
  let scope = b1_literal_scope()?
  let first = b1_literal_hex("MORSE_C1_B1_LITERAL_V1")?
  let second = b1_literal_hex("MORSE_C1_B1_LITERAL_V2")?
  let v1 = decode_braid_spqr_metadata(first, scope)?
  b1_check(Bytes.get(first, 4)? == 1
      && Bytes.length(v1.local_attempt) == 73
      && Bytes.secure_equals(braid_spqr_metadata_bytes(v1)?, first),
    "b1_v1_independent_literal_preserved")?
  let v2 = decode_braid_spqr_metadata(second, scope)?
  b1_check(Bytes.get(second, 4)? == 2
      && Bytes.length(v2.local_attempt) == 105
      && v2.phase == 7
      && v2.kernel_tag == 6
      && List.get(v2.partial_indices, 0) == 3
      && List.get(v2.partial_indices, 1) == 17
      && U64.compare(mobile_read_u64(Bytes.slice(v2.local_attempt, 1, 8)?)?, b1_num("10")?) == 0
      && Bytes.secure_equals(Bytes.slice(v2.local_attempt, 9, 32)?, repeated(18, 32)?)
      && Bytes.secure_equals(Bytes.slice(v2.pending_identity, 48, 32)?, repeated(19, 32)?)
      && !Bytes.secure_equals(v2.transition, Bytes.slice(v2.pending_identity, 48, 32)?)
      && Bytes.secure_equals(braid_spqr_metadata_bytes(v2)?, second),
    "b1_v2_independent_schema_provenance")?
  for cursor in [65535, 65536] do
    let boundary = %{v2 | cursors: [0, 0, cursor, 0]}
    let encoded = braid_spqr_metadata_bytes(boundary)?
    b1_check(List.get(decode_braid_spqr_metadata(encoded, scope)?.cursors, 2) == cursor,
      "b1_finite_u32_exhaustion_marker_not_wrap")?
  end
  b1_check(Result.is_err(braid_spqr_metadata_bytes(%{v2 | cursors: [0, 0, 65537, 0]}))
      && Result.is_err(braid_spqr_metadata_bytes(%{v2 | local_attempt: repeated(0, 104)?}))
      && Result.is_err(braid_spqr_metadata_bytes(%{v2 | partial_indices: [17, 3]}))
      && Result.is_err(braid_spqr_metadata_bytes(%{v2 | partial_indices: [3, 3]}))
      && Result.is_err(braid_spqr_metadata_bytes(%{v2 | pending_identity: repeated(0, 79)?})),
    "b1_exact_malformed_canonical_bounds")
end

pub fn b1_actual_api_preflight() -> Unit!String do
  # This independently executes adopted B0; future compiler also typechecks all
  # B1 callers above. It does not call a refusing B1 action and call that RED.
  let f = b1_bootstrap_initial()?
  let a = b1_meta(f.accounts.alice_path, f.alice_scope)?
  let b = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(a.kernel_tag == 2
      && a.phase == 0
      && b.phase == 4
      && U64.compare(a.local_epoch, b1_num("0")?) == 0
      && U64.compare(b.knowledge, b1_num("0")?) == 0,
    "b1_actual_bootstrap_preflight")?
  let key = platform_key()?
  let saved = b1_kernel(f.accounts.alice_path, a)?
  let idle = case restore_alice_idle(saved, saved, key) do
    Ok(v) -> v
    _ -> return Err("b1_preflight_saved_actual_idle")
  end
  let (_header_owner, complete) = case send_header(idle) do
    Ok(v) -> v
    _ -> return Err("b1_preflight_actual_send_header")
  end
  let fragment = case emit_braid_fragment(BraidHeaderFragment,
    f.alice_scope.configuration,
    f.alice_scope.session_id,
    b1_num("1")?,
    complete,
    0) do
    Ok(v) -> v
    _ -> return Err("b1_preflight_actual_fragment")
  end
  let alice_he = restore_session(load_session_record(f.accounts.alice_path,
      key,
      f.alice_scope.session_id)?,
    key)?
  let (_a, _aq, envelope) = b1_seal(f, alice_he, b1_pq(f.accounts.alice_path, a)?, fragment)?
  let message = case decode_triple_message(b1_unwrap(f, envelope, false)?) do
    Ok(v) -> v
    _ -> return Err("b1_preflight_actual_CHF1")
  end
  let bob_he = restore_session(load_session_record(f.accounts.bob_path,
      key,
      f.bob_scope.session_id)?,
    key)?
  let result = case he_decrypt_hybrid(bob_he,
    b1_pq(f.accounts.bob_path, b)?,
    message,
    session_aad(f.bob_scope.session_id)?) do
    HybridOpened(_b, _bq, header, _clear) -> b1_check(Bytes.secure_equals(header.fragment.word,
        fragment.word),
      "b1_preflight_actual_combined_peer")
    _ -> Err("b1_preflight_actual_combined_authentication")
  end
  b1_cleanup(f)?
  println("B1_ACTUAL_BOOTSTRAP_API_PREFLIGHT_EXECUTED")
  result
end

## TEST ONLY explicit acceptance controls; original six assertions stay intact.
fn b1_accept_maybe(path :: String, name :: String) -> Bytes!String do
  case load_blob(path, name) do
    Ok(v)
    Err("local_state_not_found") -> Ok(Bytes.empty())
    Err(error)
  end
end

fn b1_accept_saved(f :: B1Accounts, m :: BraidSpqrMetadata) -> SpqrSaved!String do
  let labels = braid_spqr_labels(m.scope)
  Ok(SpqrSaved {
    scope: m.scope,
    direction: m.direction,
    epoch: m.local_epoch,
    knowledge: m.knowledge,
    slots: m.slots,
    skipped_index: m.skipped_index,
    revision: m.revision,
    transition: m.transition,
    descriptor: braid_spqr_descriptor(m)?,
    chains: load_blob(f.accounts.bob_path, List.get(labels, 4))?,
    skipped: load_blob(f.accounts.bob_path, List.get(labels, 5))?
  })
end

fn b1_accept_coherent_inner(f :: B1Accounts) -> Unit!String do
  let key = platform_key()?
  let alice = load_session_record(f.accounts.alice_path, key, f.alice_scope.session_id)?
  let before = load_session_record(f.accounts.bob_path, key, f.bob_scope.session_id)?
  let old = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(alice.record.request_state == 1
      && before.record.request_state == 0
      && !before.record.blocked
      && !before.record.key_changed
      && before.record.strongest_suite == 2,
    "b1_accept_actual_B0_policy")?
  let saved = b1_accept_saved(f, old)?
  let old_pq = b1_pq(f.accounts.bob_path, old)?
  let tag = b1_root_tag(old_pq)?
  let labels = braid_spqr_labels(f.bob_scope)
  let old_auth = load_blob(f.accounts.bob_path, List.get(labels, 1))?
  let bootstrap_name = "c1/bootstrap/v1/#{Bytes.to_hex(f.bob_scope.configuration)}/#{Bytes.to_hex(f.bob_scope.peer_account_id)}/#{Bytes.to_hex(f.bob_scope.peer_device_id)}"
  let history_name = "history/v1/#{Bytes.to_hex(before.record.conversation_id)}"
  let unchanged = [
    "sessions/v1",
    "header-routing/v1",
    "outbox/v1",
    "postage-queue/v1",
    "delivery/v1",
    "device-identity-key/v1",
    bootstrap_name,
    history_name
  ]
  let protected_before = for name in unchanged do
    b1_accept_maybe(f.accounts.bob_path, name)?
  end
  let held = b1_prepare(f, true, "accept-held-header")?
  let rows = row_set(f.accounts.bob_path)?
  b1_check(case b1_receive(f, held.envelope) do
      Err("c1_spqr_session_changed") -> true
      _ -> false
    end
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_accept_pending_cannot_receive")?
  let custody = load_account_basis(f.accounts.bob_path, [])?
  let basis = capture_fanout_snapshot(f.accounts.bob_path,
    custody.profile,
    [
      "sessions/v1",
      before.label,
      "header-routing/v1",
      "device-identity-key/v1",
      "outbox/v1",
      "postage-queue/v1",
      "delivery/v1"
    ]
      ++ labels
      ++ braid_labels(f.bob_scope)
      ++ alice_header_labels(f.bob_scope)
      ++ [history_name, bootstrap_name])?
  let accepted = accept_braid_spqr_request(f.accounts.bob_path, f.bob_profile, f.bob_scope)?
  let current = b1_meta(f.accounts.bob_path, f.bob_scope)?
  let loaded = load_session_record(f.accounts.bob_path, key, f.bob_scope.session_id)?
  let candidate = %{old |
    revision: U64.add(old.revision, b1_num("1")?)?,
    transition: repeated(0, 32)?,
    local_attempt: repeated(0, 105)?
  }
  let expected_transition = braid_spqr_transition(candidate,
    basis,
    4,
    b1_accept_input(f.bob_scope, old.transition, old.revision)?)?
  b1_check(accepted.kind == 1
      && current.phase == 4
      && current.kernel_tag == 0
      && current.direction == 1
      && U64.compare(current.revision, U64.add(old.revision, b1_num("1")?)?) == 0
      && U64.compare(accepted.current_revision, current.revision) == 0
      && Bytes.secure_equals(accepted.current_transition, current.transition)
      && Bytes.secure_equals(current.transition, expected_transition)
      && !Bytes.secure_equals(current.transition, old.transition)
      && Bytes.length(current.local_attempt) == 105
      && Bytes.secure_equals(current.local_attempt, repeated(0, 105)?)
      && Bytes.get(braid_spqr_metadata_bytes(current)?, 4)? == 2
      && U64.compare(current.local_epoch, b1_num("0")?) == 0
      && U64.compare(current.knowledge, b1_num("0")?) == 0
      && List.length(current.partial_indices) == 0
      && List.length(current.slots) == 1
      && List.length(current.cursors) == 4
      && List.all(current.cursors, fn(n) -> n == 0 end)
      && Bytes.length(current.skipped_index) == 0
      && Bytes.secure_equals(current.pending_identity, repeated(0, 80)?)
      && Bytes.secure_equals(current.inbound_result, repeated(0, 82)?),
    "b1_accept_canonical_v2_transition")?
  b1_check(loaded.record.request_state == 1
      && Bytes.secure_equals(loaded.record.snapshot, before.record.snapshot)
      && Bytes.secure_equals(updated_session_record(loaded.record.snapshot,
          %{loaded.record | request_state: 0})?,
        updated_session_record(before.record.snapshot, before.record)?)
      && Bytes.secure_equals(List.get(current.hashes, 5),
        Crypto.sha256(load_blob(f.accounts.bob_path, loaded.label)?)),
    "b1_accept_only_session_policy_changed")?
  let restored = b1_pq(f.accounts.bob_path, current)?
  b1_check(Bytes.secure_equals(b1_root_tag(restored)?, tag)
      && U64.compare(List.head(current.slots).send_count, b1_num("0")?) == 0
      && U64.compare(List.head(current.slots).receive_count, b1_num("0")?) == 0,
    "b1_accept_no_fake_key_use")?
  let current_saved = b1_accept_saved(f, current)?
  b1_check((case restore_spqr(%{current_saved | chains: saved.chains}, current_saved, key) do
      Err(_) -> true
      Ok(_unexpected_chain_owner) -> false
    end)
      && (case restore_spqr(%{current_saved | skipped: saved.skipped}, current_saved, key) do
        Err(_) -> true
        Ok(_unexpected_skipped_owner) -> false
      end),
    "b1_accept_both_maps_resealed")?
  let kernel = BraidSaved {
    scope: current.scope,
    epoch: current.epoch,
    revision: current.revision,
    transition: current.transition,
    phase: 0,
    header: Bytes.empty(),
    first: Bytes.empty(),
    secrets: load_blob(f.accounts.bob_path, List.get(labels, 1))?,
    continuation: Bytes.empty()
  }
  let _actual = case restore_await(kernel, key) do
    Ok(v) -> v
    Err(_) -> return Err("b1_accept_actual_new_kernel_restore")
  end
  b1_check(case restore_await(%{kernel | secrets: old_auth}, key) do
      Err(_) -> true
      Ok(_unexpected_kernel_owner) -> false
    end,
    "b1_accept_kernel_resealed")?
  let protected_after = for name in unchanged do
    b1_accept_maybe(f.accounts.bob_path, name)?
  end
  b1_check(equal_rows(protected_before, protected_after)
      && Bytes.length(b1_accept_maybe(f.accounts.bob_path, List.get(labels, 6))?) == 0
      && Bytes.length(b1_accept_maybe(f.accounts.bob_path, List.get(labels, 7))?) == 0,
    "b1_accept_no_queue_or_index_effect")?
  let admitted = b1_receive(f, held.envelope)?
  let admitted_metadata = b1_meta(f.accounts.bob_path, f.bob_scope)?
  b1_check(admitted.phase == 4
      && List.length(admitted_metadata.partial_indices) == 1
      && U64.compare(admitted_metadata.revision, current.revision) > 0,
    "b1_accept_same_real_hybrid_header_now_admitted")
end

pub fn b1_accept_coherent() -> Unit!String do
  let f = b1_bootstrap_initial()?
  let result = b1_accept_coherent_inner(f)
  b1_cleanup(f)?
  result
end

fn b1_accept_reply_inner(f :: B1Accounts) -> Unit!String do
  let accepted = accept_braid_spqr_request(f.accounts.bob_path, f.bob_profile, f.bob_scope)?
  let rows = row_set(f.accounts.bob_path)?
  let recovered = accept_braid_spqr_request(f.accounts.bob_path, f.bob_profile, f.bob_scope)?
  b1_check(accepted.kind == 1
      && recovered.kind == 2
      && U64.compare(accepted.current_revision, recovered.current_revision) == 0
      && Bytes.secure_equals(accepted.current_transition, recovered.current_transition)
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_accept_fresh_readonly_reply")?
  let held = b1_prepare(f, true, "accept-reply-header")?
  let received = b1_receive(f, held.envelope)?
  let rows = row_set(f.accounts.bob_path)?
  let later = accept_braid_spqr_request(f.accounts.bob_path, f.bob_profile, f.bob_scope)?
  b1_check(later.kind == 2
      && U64.compare(later.current_revision, received.current_revision) == 0
      && Bytes.secure_equals(later.current_transition, received.current_transition)
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_accept_later_current_state_not_old_receipt")?
  b1_check(Result.is_err(accept_braid_spqr_request(f.accounts.bob_path,
      f.alice_profile,
      f.bob_scope))
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_accept_wrong_profile_refused")?
  let alice_rows = row_set(f.accounts.alice_path)?
  b1_check(Result.is_err(accept_braid_spqr_request(f.accounts.alice_path,
      f.alice_profile,
      f.alice_scope))
      && equal_rows(alice_rows, row_set(f.accounts.alice_path)?),
    "b1_accept_wrong_role_refused")
end

fn b1_accept_guard_inner(f :: B1Accounts, variant :: Int) -> Unit!String do
  let key = platform_key()?
  let loaded = load_session_record(f.accounts.bob_path, key, f.bob_scope.session_id)?
  if variant == 0 || variant == 1 do
    let record = if variant == 0 do
      %{loaded.record | blocked: true}
    else
      %{loaded.record | key_changed: true}
    end
    store_updated_blobs(f.accounts.bob_path,
      [loaded.label],
      [
        seal_local(updated_session_record(record.snapshot, record)?,
          key,
          local_context(loaded.label)?)?
      ])?
  else if variant == 2 do
    let name = "c1/bootstrap/v1/#{Bytes.to_hex(f.bob_scope.configuration)}/#{Bytes.to_hex(f.bob_scope.peer_account_id)}/#{Bytes.to_hex(f.bob_scope.peer_device_id)}"
    store_updated_blobs(f.accounts.bob_path,
      [name],
      [seal_local(repeated(0, 262)?, key, local_context(name)?)?])?
  else if variant == 3 do
    let m = b1_meta(f.accounts.bob_path, f.bob_scope)?
    let name = List.get(braid_spqr_labels(f.bob_scope), 0)
    let bytes = braid_spqr_metadata_bytes(%{m | revision: U64.add(m.revision, b1_num("1")?)?})?
    store_updated_blobs(f.accounts.bob_path,
      [name],
      [seal_local(bytes, key, local_context(name)?)?])?
  else if variant == 4 do
    let prepared = prepare_conversation_policy(f.accounts.bob_path,
      key,
      f.bob_scope.peer_account_id,
      1,
      0)?
    commit_conversation_policy(f.accounts.bob_path, prepared)?
    b1_check(load_session_record(f.accounts.bob_path,
        key,
        f.bob_scope.session_id)?.record.request_state == 1,
      "b1_accept_actual_plain_policy_changed_session")?
  else
    nil
  end
  let c = Crypto.sha256(Bytes.from_utf8("TEST ONLY foreign acceptance configuration"))
  let scope = if variant == 5 do
    %{f.bob_scope |
      configuration: c,
      protocol_info: mobile_join([
          Bytes.from_utf8("mesh-msg/braid/v1"),
          repeated(0, 1)?,
          c,
          f.bob_scope.session_id
        ],
        0,
        Bytes.empty())?
    }
  else
    f.bob_scope
  end
  let rows = row_set(f.accounts.bob_path)?
  b1_check(Result.is_err(accept_braid_spqr_request(f.accounts.bob_path, f.bob_profile, scope))
      && equal_rows(rows, row_set(f.accounts.bob_path)?),
    "b1_accept_guard_refusal_preserves_complete_rows")
end

pub fn b1_accept_recovery_and_guards() -> Unit!String do
  let f = b1_bootstrap_initial()?
  let result = b1_accept_reply_inner(f)
  b1_cleanup(f)?
  result?
  for variant in 0..6 do
    let f = b1_bootstrap_initial()?
    let result = b1_accept_guard_inner(f, variant)
    b1_cleanup(f)?
    result?
  end
  Ok(nil)
end

fn b1_accept_input(scope :: BraidScope,
  old_transition :: Bytes,
  old_revision :: U64) -> Bytes!String do
  Ok(Crypto.sha256(mobile_join([
      Bytes.from_utf8("morse/c1/braid-spqr/request-accept/v1"),
      repeated(0, 1)?,
      scope.protocol_info,
      old_transition,
      mobile_write_u64(old_revision)?
    ],
    0,
    Bytes.empty())?))
end

pub fn b1_accept_transition_literals() -> Unit!String do
  let scope = b1_literal_scope()?
  let value = decode_braid_spqr_metadata(b1_literal_hex("MORSE_C1_ACCEPTANCE_CANDIDATE")?, scope)?
  let profile = Bytes.from_utf8("TEST ONLY acceptance profile ciphertext")
  let z = Bytes.from_utf8("TEST ONLY z ciphertext")
  let a = Bytes.from_utf8("TEST ONLY a ciphertext")
  let basis = AccountBasis { profile: profile, labels: ["z/source", "a/source"], records: [z, a] }
  let before = FanoutSnapshot { bases: [basis] }
  let commitment = b1_accept_input(scope, repeated(21, 32)?, b1_num("1")?)?
  b1_check(Bytes.secure_equals(commitment, b1_literal_hex("MORSE_C1_ACCEPTANCE_COMMITMENT")?),
    "b1_accept_independent_input_commitment")?
  for operation in 1..4 do
    b1_check(Bytes.secure_equals(braid_spqr_transition(value, before, operation, commitment)?,
        b1_literal_hex("MORSE_C1_ACCEPTANCE_OP#{operation}")?),
      "b1_accept_old_transition_ops_unchanged")?
  end
  let transition = braid_spqr_transition(value, before, 4, commitment)?
  b1_check(Bytes.secure_equals(transition, b1_literal_hex("MORSE_C1_ACCEPTANCE_OP4")?),
    "b1_accept_independent_operation4")?
  let partitioned = FanoutSnapshot {
    bases: [
      AccountBasis { profile: profile, labels: ["a/source"], records: [a] },
      AccountBasis { profile: profile, labels: ["z/source"], records: [z] }
    ]
  }
  b1_check(Bytes.secure_equals(braid_spqr_transition(value, partitioned, 4, commitment)?,
      transition),
    "b1_accept_source_partition_is_canonical")?
  let changed = FanoutSnapshot {
    bases: [%{basis | records: [z, Bytes.from_utf8("TEST ONLY a ciphertext!")]}]
  }
  let source_transition = braid_spqr_transition(value, changed, 4, commitment)?
  b1_check(Bytes.secure_equals(source_transition,
      b1_literal_hex("MORSE_C1_ACCEPTANCE_SOURCE_CHANGED")?)
      && !Bytes.secure_equals(source_transition, transition),
    "b1_accept_source_commitment_binding")?
  let c = repeated(7, 32)?
  let changed_scope = %{scope |
    configuration: c,
    protocol_info: mobile_join([
        Bytes.from_utf8("mesh-msg/braid/v1"),
        repeated(0, 1)?,
        c,
        scope.session_id
      ],
      0,
      Bytes.empty())?
  }
  let changed_transition = braid_spqr_transition(%{value | scope: changed_scope},
    before,
    4,
    b1_accept_input(changed_scope, repeated(21, 32)?, b1_num("1")?)?)?
  b1_check(Bytes.secure_equals(changed_transition,
      b1_literal_hex("MORSE_C1_ACCEPTANCE_SCOPE_CHANGED")?)
      && !Bytes.secure_equals(changed_transition, transition),
    "b1_accept_scope_commitment_binding")?
  let slot = List.head(value.slots)
  b1_check(Result.is_err(braid_spqr_transition(%{value | revision: b1_num("3")?},
      before,
      4,
      commitment))
      && Result.is_err(braid_spqr_transition(%{value | local_attempt: repeated(0, 73)?},
        before,
        4,
        commitment))
      && Result.is_err(braid_spqr_transition(%{value | slots: [%{slot | send_count: b1_num("1")?}]},
        before,
        4,
        commitment)),
    "b1_accept_opcode4_exact_pending_candidate_only")
end
