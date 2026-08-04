import File
from MobileCore import create_account_export, load_profile_export, reconcile_prekeys_export, replenish_prekeys_export
from Prekeys.Pool import PrekeyPublishResponse, decode_prekey_publish, encode_prekey_publish_response
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
