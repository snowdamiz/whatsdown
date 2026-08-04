import File
from MobileCore import create_account_export, outbox_ack_export, outbox_list_export, receive_initial_export, reconcile_prekeys_export, replenish_prekeys_export, start_conversation_export
from Prekeys.Pool import PrekeyPublishResponse, decode_prekey_publish, encode_prekey_publish_response
from Tests.Support import append, database_path, read_u32, vector, write_u32

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

fn set_receive_failure(path :: String, enabled :: Bool) -> Result <(), String > do
  let database = Sqlite.open(path) ?
  let statement = if enabled do
    "CREATE TRIGGER mesh_test_fail_receive BEFORE UPDATE ON encrypted_blobs WHEN NEW.record_hash = '1157310c10370fde0a5d9bd24a1963b3d14362f1d666addd33e692f9bc246a63' BEGIN SELECT RAISE(ABORT, 'forced late receive write failure'); END"
  else
    "DROP TRIGGER mesh_test_fail_receive"
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

fn assert_single_outbox(path :: String, envelope :: Bytes) -> Bool ! String do
  let expected = append(vector(write_u32(1) ?) ?, vector(envelope) ?) ?
  assert(Bytes.secure_equals(outbox_list_export(Bytes.from_utf8(path)) ?, expected))
  assert(Bytes.length(outbox_ack_export(request([Bytes.from_utf8(path), envelope]) ?) ?) == 0)
  assert(Bytes.secure_equals(outbox_list_export(Bytes.from_utf8(path)) ?, vector(write_u32(0) ?) ?))
  Ok(true)
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("initial-session-alice") ?
  let bob_path = database_path("initial-session-bob") ?
  let alice_profile = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")]) ?) ?
  let bob_profile_id2 = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")]) ?) ?
  assert(Bytes.length(alice_profile) > 0)
  assert(Bytes.length(bob_profile_id2) > 0)
  let publication = decode_prekey_publish(replenish_prekeys_export(request([Bytes.from_utf8(bob_path), write_u32(1) ?]) ?) ?) ?
  assert(List.length(publication.prekeys) == 1)
  let generated = List.head(publication.prekeys)
  assert(U64.compare(generated.id, U64.parse("3") ?) == 0)
  let greeting = Bytes.from_utf8("hello bob")
  let start_request = request([Bytes.from_utf8(alice_path), bob_profile_id2, greeting]) ?
  let initial_outer = start_conversation_export(start_request) ?
  assert(Bytes.length(initial_outer) > 0)
  assert(assert_single_outbox(alice_path, initial_outer) ?)
  let acknowledgement = encode_prekey_publish_response(PrekeyPublishResponse {
    account_id : publication.account_id,
    device_id : publication.device_id,
    active_ids : [generated.id]
  }) ?
  let reconciled = reconcile_prekeys_export(request([Bytes.from_utf8(bob_path), acknowledgement]) ?) ?
  assert(Bytes.length(reconciled) == 4)
  assert(read_u32(reconciled) ? == 1)
  let receive_request = request([Bytes.from_utf8(bob_path), initial_outer]) ?
  let before_failure = database_fingerprint(bob_path) ?
  set_receive_failure(bob_path, true) ?
  case receive_initial_export(receive_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "database_write_failed")
  end
  set_receive_failure(bob_path, false) ?
  assert(database_fingerprint(bob_path) ? == before_failure)
  assert(Bytes.secure_equals(receive_initial_export(receive_request) ?, greeting))
  case receive_initial_export(receive_request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "one_time_prekey_not_found")
  end
  let stale_outer = start_conversation_export(start_request) ?
  assert(Bytes.length(stale_outer) > 0)
  assert(assert_single_outbox(alice_path, stale_outer) ?)
  case receive_initial_export(request([Bytes.from_utf8(bob_path), stale_outer]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "one_time_prekey_not_found")
  end
  File.delete(alice_path) ?
  File.delete(bob_path) ?
  Ok(true)
end

test("mobile initial sessions reconcile prekeys and commit atomically in Mesh") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
