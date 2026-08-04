import File
from MobileCore import authorize_device_link_export, complete_device_link_export, create_account_export, create_link_request_export, directory_entry_export, fanout_prekey_claims_export, install_group_transparency_for_test, load_history_export, outbox_ack_export, outbox_list_export, prepare_fanout_prekeys_export, receive_initial_export, receive_message_export, replenish_prekeys_export, reserve_fanout_prekey_export, safety_number_export, send_fanout_export, start_conversation_export, test_ratchet_jump_envelope, test_ratchet_tamper_envelope, update_conversation_export
from Prekeys.Bundle import normalize_prekey_bundle
from Prekeys.Pool import decode_prekey_claim, decode_prekey_publish
from Protocol.V1 import DeviceCredential, DeviceSet, DirectoryEntry, OuterEnvelope, PrekeyBundle, decode_device_credential, decode_directory_entry, decode_outer_envelope, decode_prekey_bundle, encode_device_set, encode_prekey_bundle
from Tests.GroupConsistencyCrypto import checkpoint
from Tests.GroupConsistencySupport import signed_transparency_view, signing_pair
from Tests.Support import append, database_path, repeated, vector, write_u32
from Transparency.Merkle import TransparencyCheckpoint, consistency_proof, leaf_hash
from Transparency.Wire import encode_checkpoint, encode_consistency_proof

fn encode_vectors(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

fn request(values :: List < Bytes >) -> Bytes ! String do
  encode_vectors(values, 0, Bytes.empty())
end

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( _) -> Err("test integer conversion failed")
    Ok( parsed) -> Ok(parsed)
  end
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("test byte encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn entry(input :: Bytes) -> DirectoryEntry ! String do
  case decode_directory_entry(input) do
    Err( _) -> Err("directory entry decode failed")
    Ok( value) -> Ok(value)
  end
end

fn bundle(input :: Bytes) -> PrekeyBundle ! String do
  case decode_prekey_bundle(input) do
    Err( _) -> Err("prekey bundle decode failed")
    Ok( value) -> Ok(value)
  end
end

fn credential(input :: Bytes) -> DeviceCredential ! String do
  case decode_device_credential(input) do
    Err( _) -> Err("device credential decode failed")
    Ok( value) -> Ok(value)
  end
end

fn outer(input :: Bytes) -> OuterEnvelope ! String do
  case decode_outer_envelope(input) do
    Err( _) -> Err("outer envelope decode failed")
    Ok( value) -> Ok(value)
  end
end

fn bundle_wire(value :: PrekeyBundle) -> Bytes ! String do
  case encode_prekey_bundle(value) do
    Err( _) -> Err("prekey bundle encode failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn base_bundle(value :: PrekeyBundle) -> PrekeyBundle ! String do
  case normalize_prekey_bundle(value) do
    Err( _) -> Err("prekey bundle normalization failed")
    Ok( normalized) -> Ok(normalized)
  end
end

fn device_set_wire(value :: DeviceSet) -> Bytes ! String do
  case encode_device_set(value) do
    Err( _) -> Err("device set encode failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn read_u32_at(input :: Bytes, offset :: Int) -> Int ! String do
  case Bytes.read_u32_be(input, offset) do
    Err( _) -> Err("output list decode failed")
    Ok( value) -> case U64.to_int(value) do
      Err( _) -> Err("output list decode failed")
      Ok( parsed) -> Ok(parsed)
    end
  end
end

fn slice(input :: Bytes, offset :: Int, length :: Int) -> Bytes ! String do
  case Bytes.slice(input, offset, length) do
    Err( _) -> Err("output list decode failed")
    Ok( value) -> Ok(value)
  end
end

fn output_items(input :: Bytes, count :: Int, index :: Int, offset :: Int, items :: List < Bytes >) -> List < Bytes > ! String do
  if index >= count do
    if offset == Bytes.length(input) do
      Ok(items)
    else
      Err("output list decode failed")
    end
  else
    let length = read_u32_at(input, offset) ?
    if length <= 0 do
      Err("output list decode failed")
    else
      let item = slice(input, offset + 4, length) ?
      output_items(input, count, index + 1, offset + 4 + length, List.append(items, item))
    end
  end
end

fn output_list(input :: Bytes) -> List < Bytes > ! String do
  if Bytes.length(input) < 8 || read_u32_at(input, 0) ? != 4 do
    Err("output list decode failed")
  else
    let count = read_u32_at(input, 4) ?
    if count < 0 || count > 64 do
      Err("output list decode failed")
    else
      output_items(input, count, 0, 8, List.new())
    end
  end
end

fn history_body(input :: Bytes) -> Bytes ! String do
  if read_u32_at(input, 0) ? != 1 do
    Err("history summary decode failed")
  else
    let client_offset = 5
    let client_length = read_u32_at(input, client_offset) ?
    let timestamp_offset = client_offset + 4 + client_length
    let timestamp_length = read_u32_at(input, timestamp_offset) ?
    let body_offset = timestamp_offset + 4 + timestamp_length
    if client_length != 16 || timestamp_length != 8 do
      Err("history summary decode failed")
    else
      slice(input, body_offset + 4, read_u32_at(input, body_offset) ?)
    end
  end
end

fn row_text(row :: Map < String, DbValue >, key :: String) -> String ! String do
  case Map.get(row, key) do
    Text( value) -> Ok(value)
    Binary( _) -> Err("expected text database value")
    Null -> Err("expected text database value")
  end
end

fn fingerprint_rows(rows :: List < Map < String, DbValue > >, index :: Int, output :: String) -> String ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    let row = List.get(rows, index)
    let separator = if index == 0 do
      ""
    else
      "|"
    end
    fingerprint_rows(rows,
    index + 1,
    output <> separator <> row_text(row, "record_hash") ? <> ":" <> row_text(row, "ciphertext_hex") ?)
  end
end

fn database_fingerprint(path :: String) -> String ! String do
  let database = Sqlite.open(path) ?
  case Sqlite.query_values(database,
  "SELECT record_hash, hex(ciphertext) AS ciphertext_hex FROM encrypted_blobs ORDER BY record_hash",
  []) do
    Err( error) -> do
      Sqlite.close(database)
      Err(error)
    end
    Ok( rows) -> do
      Sqlite.close(database)
      fingerprint_rows(rows, 0, "")
    end
  end
end

fn set_outbox_failure(path :: String, enabled :: Bool) -> Result <(), String > do
  let database = Sqlite.open(path) ?
  let statement = if enabled do
    "CREATE TRIGGER mesh_test_fail_fanout BEFORE INSERT ON encrypted_blobs WHEN NEW.record_hash = '2e18a8aa47e3428a0c87b2dd84049e85da6950238b82128496e6c35bd760b220' BEGIN SELECT RAISE(ABORT, 'forced fanout outbox write failure'); END"
  else
    "DROP TRIGGER mesh_test_fail_fanout"
  end
  case Sqlite.execute(database, statement, []) do
    Err( error) -> do
      Sqlite.close(database)
      Err(error)
    end
    Ok( _) -> do
      Sqlite.close(database)
      Ok(nil)
    end
  end
end

fn acknowledge(path :: String, envelope :: Bytes) -> Bool ! String do
  assert(Bytes.length(outbox_ack_export(request([Bytes.from_utf8(path), envelope]) ?) ?) == 0)
  Ok(true)
end

fn oversized_prekey_response(_request :: Request) -> Response do
  case Bytes.repeat(7, 19313) do
    Err( _) -> HTTP.response(500, "")
    Ok( body) -> HTTP.response_bytes_with_headers(200,
    body,
    Map.put(Map.new(), "Cache-Control", "no-store"))
  end
end

actor oversized_prekey_server() do
  HTTP.router()
    |> HTTP.on_post("/v1/prekeys/bundle", oversized_prekey_response)
    |> HTTP.serve(18996)
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("fanout-alice") ?
  let linked_path = database_path("fanout-linked") ?
  let bob_path = database_path("fanout-bob") ?
  let alice_profile = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")]) ?) ?
  let bob_profile = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")]) ?) ?
  let link_request = create_link_request_export(Bytes.from_utf8(linked_path)) ?
  let authorization = authorize_device_link_export(request([Bytes.from_utf8(alice_path), link_request]) ?) ?
  let linked_profile = complete_device_link_export(request([Bytes.from_utf8(linked_path), authorization]) ?) ?
  assert(Bytes.length(linked_profile) > 0)
  let claimed_alice_entry = entry(directory_entry_export(Bytes.from_utf8(alice_path)) ?) ?
  let claimed_linked_entry = entry(directory_entry_export(Bytes.from_utf8(linked_path)) ?) ?
  let claimed_bob_entry = entry(directory_entry_export(Bytes.from_utf8(bob_path)) ?) ?
  let claimed_alice_bundle = bundle(claimed_alice_entry.prekey_bundle) ?
  let claimed_linked_bundle = bundle(claimed_linked_entry.prekey_bundle) ?
  let claimed_bob_bundle = bundle(claimed_bob_entry.prekey_bundle) ?
  let alice_entry = % { claimed_alice_entry | prekey_bundle : bundle_wire(base_bundle(claimed_alice_bundle) ?) ? }
  let linked_entry = % { claimed_linked_entry | prekey_bundle : bundle_wire(base_bundle(claimed_linked_bundle) ?) ? }
  let bob_entry = % { claimed_bob_entry | prekey_bundle : bundle_wire(base_bundle(claimed_bob_bundle) ?) ? }
  let linked_publication = decode_prekey_publish(replenish_prekeys_export(request([Bytes.from_utf8(linked_path), write_u32(1) ?]) ?) ?) ?
  assert(List.length(linked_publication.prekeys) == 1)
  let linked_prekey = List.head(linked_publication.prekeys)
  let next_claimed_linked_bundle = % { claimed_linked_bundle | one_time_prekey_id : linked_prekey.id, one_time_prekey : linked_prekey.public_key }
  let alice_credential = credential(claimed_alice_bundle.device_credential) ?
  let linked_credential = credential(claimed_linked_bundle.device_credential) ?
  let alice_set = device_set_wire(DeviceSet {
    version : 1,
    username : "alice",
    account_identity : alice_entry.account_identity,
    sequence : wide("2") ?,
    devices : [alice_entry, linked_entry],
    revoked_device_ids : List.new()
  }) ?
  let bob_set = device_set_wire(DeviceSet {
    version : 1,
    username : "bob",
    account_identity : bob_entry.account_identity,
    sequence : wide("1") ?,
    devices : [bob_entry],
    revoked_device_ids : List.new()
  }) ?
  let greeting = Bytes.from_utf8("hello bob")
  let initial = start_conversation_export(request([Bytes.from_utf8(alice_path), bob_profile, greeting]) ?) ?
  assert(acknowledge(alice_path, initial) ?)
  assert(Bytes.secure_equals(receive_initial_export(request([Bytes.from_utf8(bob_path), initial]) ?) ?,
  greeting))
  assert(Bytes.secure_equals(update_conversation_export(request([Bytes.from_utf8(bob_path), alice_profile, byte(1) ?, write_u32(0) ?]) ?) ?,
  Bytes.from_utf8("ok")))
  let safety = safety_number_export(request([Bytes.from_utf8(alice_path), bob_profile]) ?) ?
  assert(Bytes.secure_equals(safety,
  safety_number_export(request([Bytes.from_utf8(bob_path), alice_profile]) ?) ?))
  let synced = Bytes.from_utf8("synced hello")
  let claim_targets_request = request([Bytes.from_utf8(alice_path), bob_set, alice_set]) ?
  let fanout_request = request([Bytes.from_utf8(alice_path), bob_set, alice_set, synced]) ?
  case fanout_prekey_claims_export(claim_targets_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  case send_fanout_export(fanout_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  let peer_leaf = leaf_hash(bob_set) ?
  let local_leaf = leaf_hash(alice_set) ?
  let service_pair = signing_pair() ?
  let witness_a_pair = signing_pair() ?
  let witness_b_pair = signing_pair() ?
  let empty_checkpoint = TransparencyCheckpoint {
    version : 1,
    sequence : wide("0") ?,
    tree_size : wide("0") ?,
    tree_root : repeated(0, 32) ?,
    previous_checkpoint_hash : repeated(0, 32) ?,
    timestamp : wide("0") ?,
    service_public_key : service_pair.public_key.bytes,
    signature : repeated(0, 64) ?
  }
  let peer_checkpoint = checkpoint(service_pair.private_key,
  service_pair.public_key.bytes,
  1,
  [peer_leaf],
  empty_checkpoint,
  false) ?
  assert(install_group_transparency_for_test(alice_path,
  encode_checkpoint(peer_checkpoint) ?,
  encode_consistency_proof(consistency_proof(List.new(), [peer_leaf]) ?) ?,
  service_pair.public_key.bytes,
  witness_a_pair.public_key.bytes,
  witness_b_pair.public_key.bytes,
  bob_set) ?)
  let current_leaves = [peer_leaf, local_leaf]
  let current_checkpoint = checkpoint(service_pair.private_key,
  service_pair.public_key.bytes,
  2,
  current_leaves,
  peer_checkpoint,
  true) ?
  assert(install_group_transparency_for_test(alice_path,
  encode_checkpoint(current_checkpoint) ?,
  encode_consistency_proof(consistency_proof(List.new(), current_leaves) ?) ?,
  service_pair.public_key.bytes,
  witness_a_pair.public_key.bytes,
  witness_b_pair.public_key.bytes,
  alice_set) ?)
  let claims = output_list(fanout_prekey_claims_export(claim_targets_request) ?) ?
  assert(List.length(claims) == 1)
  let claim = decode_prekey_claim(List.head(claims)) ?
  assert(Bytes.length(List.head(claims)) == 100)
  assert(Bytes.length(claim.reservation_id) == 16)
  assert(Bytes.secure_equals(claim.account_id, alice_credential.account_id))
  assert(Bytes.secure_equals(claim.device_id, linked_credential.device_id))
  assert(Bytes.secure_equals(claim.base_bundle_hash, Crypto.sha256(linked_entry.prekey_bundle)))
  let retried_claims = output_list(fanout_prekey_claims_export(claim_targets_request) ?) ?
  assert(List.length(retried_claims) == 1)
  assert(Bytes.secure_equals(List.head(retried_claims), List.head(claims)))
  let _server = spawn(oversized_prekey_server)
  Timer.sleep(100)
  let before_oversized_response = database_fingerprint(alice_path) ?
  case prepare_fanout_prekeys_export(request([Bytes.from_utf8(alice_path), bob_set, alice_set, Bytes.from_utf8("http://127.0.0.1:18996")]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "prekey_claim_too_large")
  end
  assert(database_fingerprint(alice_path) ? == before_oversized_response)
  let before_failure = database_fingerprint(alice_path) ?
  case send_fanout_export(fanout_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_fanout_prekeys")
  end
  let changed_static_bundle = % { claimed_linked_bundle | signed_prekey : repeated(99, 32) ? }
  case reserve_fanout_prekey_export(request([Bytes.from_utf8(alice_path), bob_set, alice_set, bundle_wire(changed_static_bundle) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_fanout_prekeys")
  end
  assert(database_fingerprint(alice_path) ? == before_failure)
  let reserve_request = request([Bytes.from_utf8(alice_path), bob_set, alice_set, bundle_wire(claimed_linked_bundle) ?]) ?
  assert(Bytes.length(reserve_fanout_prekey_export(reserve_request) ?) == 0)
  assert(Bytes.length(reserve_fanout_prekey_export(reserve_request) ?) == 0)
  assert(List.length(output_list(fanout_prekey_claims_export(claim_targets_request) ?) ?) == 0)
  let reserved_fingerprint = database_fingerprint(alice_path) ?
  assert(reserved_fingerprint != before_failure)
  set_outbox_failure(alice_path, true) ?
  case send_fanout_export(fanout_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "database_write_failed")
  end
  set_outbox_failure(alice_path, false) ?
  assert(database_fingerprint(alice_path) ? == reserved_fingerprint)
  assert(List.length(output_list(fanout_prekey_claims_export(claim_targets_request) ?) ?) == 0)
  let encoded_fanout = send_fanout_export(fanout_request) ?
  let fanout = output_list(encoded_fanout) ?
  assert(List.length(fanout) == 2)
  assert(Bytes.secure_equals(outbox_list_export(Bytes.from_utf8(alice_path)) ?, encoded_fanout))
  let first_fanout = List.get(fanout, 0)
  let second_fanout = List.get(fanout, 1)
  assert(acknowledge(alice_path, first_fanout) ?)
  assert(acknowledge(alice_path, second_fanout) ?)
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(alice_path)) ?) ?) == 0)
  let first_outer = outer(first_fanout) ?
  let bob_fanout = if Bytes.secure_equals(first_outer.mailbox_token, bob_entry.mailbox_token) do
    first_fanout
  else
    second_fanout
  end
  let self_fanout = if Bytes.secure_equals(first_outer.mailbox_token, linked_entry.mailbox_token) do
    first_fanout
  else
    second_fanout
  end
  assert(Bytes.secure_equals(outer(bob_fanout) ?.mailbox_token, bob_entry.mailbox_token))
  assert(Bytes.secure_equals(outer(self_fanout) ?.mailbox_token, linked_entry.mailbox_token))
  assert(Bytes.secure_equals(receive_message_export(request([Bytes.from_utf8(bob_path), bob_fanout]) ?) ?,
  synced))
  assert(Bytes.secure_equals(receive_initial_export(request([Bytes.from_utf8(linked_path), self_fanout]) ?) ?,
  synced))
  assert(Bytes.secure_equals(safety,
  safety_number_export(request([Bytes.from_utf8(linked_path), bob_profile]) ?) ?))
  let reply = Bytes.from_utf8("all alice devices")
  let reply_claim_targets = request([Bytes.from_utf8(bob_path), alice_set, bob_set]) ?
  let reply_request = request([Bytes.from_utf8(bob_path), alice_set, bob_set, reply]) ?
  case fanout_prekey_claims_export(reply_claim_targets) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  case send_fanout_export(reply_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  let bob_view = signed_transparency_view([leaf_hash(alice_set) ?, leaf_hash(bob_set) ?]) ?
  assert(install_group_transparency_for_test(bob_path,
  bob_view.checkpoint,
  bob_view.consistency,
  bob_view.service_public_key,
  bob_view.witness_a_public_key,
  bob_view.witness_b_public_key,
  alice_set) ?)
  assert(install_group_transparency_for_test(bob_path,
  bob_view.checkpoint,
  bob_view.consistency,
  bob_view.service_public_key,
  bob_view.witness_a_public_key,
  bob_view.witness_b_public_key,
  bob_set) ?)
  let reply_claims = output_list(fanout_prekey_claims_export(reply_claim_targets) ?) ?
  assert(List.length(reply_claims) == 1)
  let reply_claim = decode_prekey_claim(List.head(reply_claims)) ?
  assert(Bytes.secure_equals(reply_claim.account_id, alice_credential.account_id))
  assert(Bytes.secure_equals(reply_claim.device_id, linked_credential.device_id))
  assert(Bytes.secure_equals(reply_claim.base_bundle_hash,
  Crypto.sha256(linked_entry.prekey_bundle)))
  assert(Bytes.length(reserve_fanout_prekey_export(request([Bytes.from_utf8(bob_path), alice_set, bob_set, bundle_wire(next_claimed_linked_bundle) ?]) ?) ?) == 0)
  let encoded_reply = send_fanout_export(reply_request) ?
  let replies = output_list(encoded_reply) ?
  assert(List.length(replies) == 2)
  assert(Bytes.secure_equals(outbox_list_export(Bytes.from_utf8(bob_path)) ?, encoded_reply))
  let first_reply = List.get(replies, 0)
  let second_reply = List.get(replies, 1)
  assert(acknowledge(bob_path, first_reply) ?)
  assert(acknowledge(bob_path, second_reply) ?)
  let root_reply = if Bytes.secure_equals(outer(first_reply) ?.mailbox_token,
  alice_entry.mailbox_token) do
    first_reply
  else
    second_reply
  end
  let linked_reply = if Bytes.secure_equals(outer(first_reply) ?.mailbox_token,
  linked_entry.mailbox_token) do
    first_reply
  else
    second_reply
  end
  case receive_message_export(request([Bytes.from_utf8(alice_path), test_ratchet_jump_envelope(root_reply) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "ratchet_retryable")
  end
  case receive_message_export(request([Bytes.from_utf8(alice_path), test_ratchet_tamper_envelope(root_reply) ?]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "message_rejected")
  end
  assert(Bytes.secure_equals(receive_message_export(request([Bytes.from_utf8(alice_path), root_reply]) ?) ?,
  reply))
  case receive_message_export(request([Bytes.from_utf8(alice_path), root_reply]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "message_rejected")
  end
  assert(Bytes.secure_equals(receive_initial_export(request([Bytes.from_utf8(linked_path), linked_reply]) ?) ?,
  reply))
  assert(Bytes.secure_equals(safety,
  safety_number_export(request([Bytes.from_utf8(linked_path), bob_profile]) ?) ?))
  let linked_history = output_list(load_history_export(request([Bytes.from_utf8(linked_path), bob_profile]) ?) ?) ?
  assert(List.length(linked_history) == 2)
  assert(Bytes.secure_equals(history_body(List.get(linked_history, 0)) ?, synced))
  assert(Bytes.secure_equals(history_body(List.get(linked_history, 1)) ?, reply))
  let revoked_set = device_set_wire(DeviceSet {
    version : 1,
    username : "alice",
    account_identity : alice_entry.account_identity,
    sequence : wide("3") ?,
    devices : [alice_entry],
    revoked_device_ids : [linked_credential.device_id]
  }) ?
  let revoked_claim_targets = request([Bytes.from_utf8(bob_path), revoked_set, bob_set]) ?
  let revoked_request = request([Bytes.from_utf8(bob_path), revoked_set, bob_set, Bytes.from_utf8("root only")]) ?
  case fanout_prekey_claims_export(revoked_claim_targets) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  case send_fanout_export(revoked_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  let revoked_view = signed_transparency_view([leaf_hash(revoked_set) ?, leaf_hash(bob_set) ?]) ?
  assert(install_group_transparency_for_test(bob_path,
  revoked_view.checkpoint,
  revoked_view.consistency,
  revoked_view.service_public_key,
  revoked_view.witness_a_public_key,
  revoked_view.witness_b_public_key,
  revoked_set) ?)
  assert(install_group_transparency_for_test(bob_path,
  revoked_view.checkpoint,
  revoked_view.consistency,
  revoked_view.service_public_key,
  revoked_view.witness_a_public_key,
  revoked_view.witness_b_public_key,
  bob_set) ?)
  assert(List.length(output_list(fanout_prekey_claims_export(revoked_claim_targets) ?) ?) == 0)
  let revoked_fanout = output_list(send_fanout_export(revoked_request) ?) ?
  assert(List.length(revoked_fanout) == 1)
  let only_active = List.head(revoked_fanout)
  assert(Bytes.secure_equals(outer(only_active) ?.mailbox_token, alice_entry.mailbox_token))
  assert(acknowledge(bob_path, only_active) ?)
  assert(List.length(output_list(outbox_list_export(Bytes.from_utf8(bob_path)) ?) ?) == 0)
  File.delete(alice_path) ?
  File.delete(linked_path) ?
  File.delete(bob_path) ?
  Ok(true)
end

test("mobile multi-device fanout and revocation are proved in Mesh") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
