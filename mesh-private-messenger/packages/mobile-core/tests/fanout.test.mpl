import File
from MobileCore import authorize_device_link_export, complete_device_link_export, create_account_export, create_link_request_export, directory_entry_export, load_history_export, outbox_ack_export, outbox_list_export, receive_initial_export, receive_message_export, replenish_prekeys_export, safety_number_export, send_fanout_export, start_conversation_export, test_ratchet_jump_envelope, test_ratchet_tamper_envelope, update_conversation_export
from Prekeys.Pool import decode_prekey_publish
from Protocol.V1 import DeviceCredential, DeviceSet, DirectoryEntry, OuterEnvelope, PrekeyBundle, decode_device_credential, decode_directory_entry, decode_outer_envelope, decode_prekey_bundle, encode_device_set, encode_prekey_bundle
from Tests.Support import append, database_path, vector, write_u32

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
  let alice_entry = entry(directory_entry_export(Bytes.from_utf8(alice_path)) ?) ?
  let linked_entry = entry(directory_entry_export(Bytes.from_utf8(linked_path)) ?) ?
  let bob_entry = entry(directory_entry_export(Bytes.from_utf8(bob_path)) ?) ?
  let linked_publication = decode_prekey_publish(replenish_prekeys_export(request([Bytes.from_utf8(linked_path), write_u32(1) ?]) ?) ?) ?
  assert(List.length(linked_publication.prekeys) == 1)
  let linked_prekey = List.head(linked_publication.prekeys)
  let claimed_linked_bundle = % { bundle(linked_entry.prekey_bundle) ? | one_time_prekey_id : linked_prekey.id, one_time_prekey : linked_prekey.public_key }
  let claimed_linked_entry = % { linked_entry | prekey_bundle : bundle_wire(claimed_linked_bundle) ? }
  let linked_credential = credential(claimed_linked_bundle.device_credential) ?
  let alice_set = device_set_wire(DeviceSet {
    version : 1,
    username : "alice",
    account_identity : alice_entry.account_identity,
    sequence : wide("2") ?,
    devices : [alice_entry, linked_entry],
    revoked_device_ids : List.new()
  }) ?
  let claimed_alice_set = device_set_wire(DeviceSet {
    version : 1,
    username : "alice",
    account_identity : alice_entry.account_identity,
    sequence : wide("2") ?,
    devices : [alice_entry, claimed_linked_entry],
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
  let fanout_request = request([Bytes.from_utf8(alice_path), bob_set, alice_set, synced]) ?
  let before_failure = database_fingerprint(alice_path) ?
  set_outbox_failure(alice_path, true) ?
  case send_fanout_export(fanout_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "database_write_failed")
  end
  set_outbox_failure(alice_path, false) ?
  assert(database_fingerprint(alice_path) ? == before_failure)
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
  let encoded_reply = send_fanout_export(request([Bytes.from_utf8(bob_path), claimed_alice_set, bob_set, reply]) ?) ?
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
    Err( error) -> assert(error == "message_rejected")
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
  let revoked_fanout = output_list(send_fanout_export(request([Bytes.from_utf8(bob_path), revoked_set, bob_set, Bytes.from_utf8("root only")]) ?) ?) ?
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
