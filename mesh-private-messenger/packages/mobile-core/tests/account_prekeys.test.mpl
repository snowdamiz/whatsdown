import File
from MobileCore import create_account_export, load_profile_export, reconcile_prekeys_export, replenish_prekeys_export
from Prekeys.Pool import OneTimePrekeyPublic, PrekeyPublishRequest, PrekeyPublishResponse, decode_prekey_publish, encode_prekey_publish_response
from Tests.Support import append, database_path, read_u32, vector, write_u32

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn account_request(path :: String, username :: String) -> Bytes ! String do
  join([vector(Bytes.from_utf8(path)) ?, vector(Bytes.from_utf8(username)) ?], 0, Bytes.empty())
end

fn replenish_request(path :: String, count :: Int) -> Bytes ! String do
  join([vector(Bytes.from_utf8(path)) ?, vector(write_u32(count) ?) ?], 0, Bytes.empty())
end

fn reconcile_request(path :: String, acknowledgement :: Bytes) -> Bytes ! String do
  join([vector(Bytes.from_utf8(path)) ?, vector(acknowledgement) ?], 0, Bytes.empty())
end

fn wide(value :: Int) -> U64 ! String do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err("test integer conversion failed")
    Ok( parsed) -> Ok(parsed)
  end
end

fn consecutive_ids(start :: Int, count :: Int, index :: Int, output :: List < U64 >) -> List < U64 > ! String do
  if index >= count do
    Ok(output)
  else
    consecutive_ids(start, count, index + 1, List.append(output, wide(start + index) ?))
  end
end

fn ids(start :: Int, count :: Int) -> List < U64 > ! String do
  consecutive_ids(start, count, 0, List.new())
end

fn publication(path :: String, count :: Int) -> PrekeyPublishRequest ! String do
  decode_prekey_publish(replenish_prekeys_export(replenish_request(path, count) ?) ?)
end

fn assert_wide_ids(values :: List < U64 >, start :: Int, index :: Int) -> Bool ! String do
  if index >= List.length(values) do
    Ok(true)
  else
    assert(U64.compare(List.get(values, index), wide(start + index) ?) == 0)
    assert_wide_ids(values, start, index + 1)
  end
end

fn assert_ids(values :: List < OneTimePrekeyPublic >, start :: Int, index :: Int) -> Bool ! String do
  assert_wide_ids(List.map(values, fn (prekey) do prekey.id end), start, index)
end

fn reconcile(path :: String, account_id :: Bytes, device_id :: Bytes, active_ids :: List < U64 >) -> Int ! String do
  let acknowledgement = encode_prekey_publish_response(PrekeyPublishResponse {
    account_id : account_id,
    device_id : device_id,
    active_ids : active_ids
  }) ?
  read_u32(reconcile_prekeys_export(reconcile_request(path, acknowledgement) ?) ?)
end

fn row_text(row :: Map < String, DbValue >, key :: String) -> String ! String do
  case Map.get(row, key) do
    Text( value) -> Ok(value)
    Binary( _) -> Err("expected text database value")
    Null -> Err("expected text database value")
  end
end

fn row_binary(row :: Map < String, DbValue >, key :: String) -> Bytes ! String do
  case Map.get(row, key) do
    Binary( value) -> Ok(value)
    Text( _) -> Err("expected binary database value")
    Null -> Err("expected binary database value")
  end
end

fn database_state_rows(rows :: List < Map < String, DbValue > >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    let row = List.get(rows, index)
    database_state_rows(rows,
    index + 1,
    append(append(output, vector(Bytes.from_utf8(row_text(row, "record_hash") ?)) ?) ?,
    vector(row_binary(row, "ciphertext") ?) ?) ?)
  end
end

fn database_state(path :: String) -> Bytes ! String do
  let database = Sqlite.open(path) ?
  case Sqlite.query_values(database,
  "SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash",
  []) do
    Err( error) -> do
      Sqlite.close(database)
      Err(error)
    end
    Ok( rows) -> do
      Sqlite.close(database)
      database_state_rows(rows, 0, Bytes.empty())
    end
  end
end

fn set_reconcile_failure(path :: String, enabled :: Bool) -> Result <(), String > do
  let database = Sqlite.open(path) ?
  let statement = if enabled do
    "CREATE TRIGGER mesh_test_fail_prekey_reconcile BEFORE UPDATE ON encrypted_blobs WHEN NEW.record_hash = '1157310c10370fde0a5d9bd24a1963b3d14362f1d666addd33e692f9bc246a63' BEGIN SELECT RAISE(ABORT, 'forced reconciliation failure'); END"
  else
    "DROP TRIGGER mesh_test_fail_prekey_reconcile"
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

fn capacity_proof() -> Bool ! String do
  let configured_path = Env.get("MESSENGER_M10_CAPACITY_PATH", "")
  let path = if String.length(configured_path) > 0 do
    configured_path
  else
    database_path("prekey-capacity") ?
  end
  let profile = create_account_export(account_request(path, "capacity") ?) ?
  assert(Bytes.length(profile) > 0)
  let first_batch = publication(path, 63) ?
  assert(List.length(first_batch.prekeys) == 63)
  assert(assert_ids(first_batch.prekeys, 3, 0) ?)
  assert(reconcile(path, first_batch.account_id, first_batch.device_id, ids(2, 64) ?) ? == 64)
  assert(List.length(publication(path, 0) ?.prekeys) == 0)
  assert(reconcile(path, first_batch.account_id, first_batch.device_id, ids(33, 33) ?) ? == 33)
  let rollover = publication(path, 31) ?
  assert(List.length(rollover.prekeys) == 31)
  assert(assert_ids(rollover.prekeys, 66, 0) ?)
  assert(reconcile(path, first_batch.account_id, first_batch.device_id, ids(33, 64) ?) ? == 64)
  let full_state = database_state(path) ?
  case publication(path, 1) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "prekey_pool_full")
  end
  case publication(path, 65) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "invalid_prekey_request")
  end
  assert(Bytes.secure_equals(database_state(path) ?, full_state))
  case reconcile(path, first_batch.account_id, first_batch.device_id, ids(999, 1) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "unknown_active_prekey")
  end
  assert(Bytes.secure_equals(database_state(path) ?, full_state))
  set_reconcile_failure(path, true) ?
  case reconcile(path, first_batch.account_id, first_batch.device_id, List.new()) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "database_write_failed")
  end
  set_reconcile_failure(path, false) ?
  assert(Bytes.secure_equals(database_state(path) ?, full_state))
  assert(reconcile(path, first_batch.account_id, first_batch.device_id, List.new()) ? == 0)
  let retired = publication(path, 0) ?
  assert(List.length(retired.prekeys) == 64)
  assert(assert_ids(retired.prekeys, 33, 0) ?)
  let replacements = publication(path, 64) ?
  assert(List.length(replacements.prekeys) == 64)
  assert(assert_ids(replacements.prekeys, 97, 0) ?)
  assert(reconcile(path, first_batch.account_id, first_batch.device_id, ids(97, 64) ?) ? == 64)
  assert(List.length(publication(path, 0) ?.prekeys) == 0)
  if String.length(configured_path) == 0 do
    File.delete(path) ?
  else
    nil
  end
  Ok(true)
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account") ?
  let request = account_request(path, "alice") ?
  let profile = create_account_export(request) ?
  assert(Bytes.length(profile) > 0)
  assert(Bytes.secure_equals(load_profile_export(Bytes.from_utf8(path)) ?, profile))
  case create_account_export(request) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "account_already_exists")
  end
  let publication = decode_prekey_publish(replenish_prekeys_export(replenish_request(path, 1) ?) ?) ?
  assert(List.length(publication.prekeys) == 1)
  let active_id = List.head(publication.prekeys).id
  let acknowledgement = encode_prekey_publish_response(PrekeyPublishResponse {
    account_id : publication.account_id,
    device_id : publication.device_id,
    active_ids : [active_id]
  }) ?
  let reconciled = reconcile_prekeys_export(reconcile_request(path, acknowledgement) ?) ?
  assert(Bytes.length(reconciled) == 4)
  assert(read_u32(reconciled) ? == 1)
  let retired = decode_prekey_publish(replenish_prekeys_export(replenish_request(path, 0) ?) ?) ?
  assert(List.length(retired.prekeys) == 1)
  assert(U64.compare(List.head(retired.prekeys).id, active_id) < 0)
  assert(Bytes.secure_equals(retired.account_id, publication.account_id))
  assert(Bytes.secure_equals(retired.device_id, publication.device_id))
  File.delete(path) ?
  assert(capacity_proof() ?)
  Ok(true)
end

test("mobile accounts persist and reconcile bounded one-time prekeys in Mesh") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
