import File
from MobileCore import create_account_export, receive_initial_export, replenish_prekeys_export, start_conversation_export
from Mobile.Inbox import permanent_direct_delivery_error
from Prekeys.Pool import OneTimePrekeyPublic, PrekeyPublishRequest, decode_prekey_publish
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DirectoryEntry, PrekeyBundle
from Tests.Support import append, database_path, vector, write_u32
from Transport.Packet import ClientProfile, decode_client_profile, encode_client_profile

fn request(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    request(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

fn published_last_resort(path :: String) -> OneTimePrekeyPublic ! String do
  let publication = decode_prekey_publish(replenish_prekeys_export(request([Bytes.from_utf8(path), write_u32(0) ?],
  0,
  Bytes.empty()) ?) ?) ?
  case publication.last_resort do
    None -> Err("publication carries no last-resort prekey")
    Some( value) -> Ok(value)
  end
end

# What the directory returns once the one-time pool is empty: the base bundle
# with the reusable key in the one-time slot.

fn exhausted_profile(encoded :: Bytes, reusable :: OneTimePrekeyPublic) -> Bytes ! String do
  let profile = decode_client_profile(encoded) ?
  let bundle = case encode_prekey_bundle(% { profile.bundle | one_time_prekey_id : reusable.id, one_time_prekey : reusable.public_key }) do
    Err( _) -> Err("bundle encode failed")
    Ok( value) -> Ok(value)
  end ?
  encode_client_profile(% { profile.entry | prekey_bundle : bundle },
  profile.account_id,
  profile.device_id)
end

fn start(path :: String, peer :: Bytes, body :: String) -> Bytes ! String do
  start_conversation_export(request([Bytes.from_utf8(path), peer, Bytes.from_utf8(body)],
  0,
  Bytes.empty()) ?)
end

fn deliver(path :: String, outer :: Bytes) -> Bytes ! String do
  receive_initial_export(request([Bytes.from_utf8(path), outer], 0, Bytes.empty()) ?)
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("last-resort-alice") ?
  let carol_path = database_path("last-resort-carol") ?
  let bob_path = database_path("last-resort-bob") ?
  let _ = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")],
  0,
  Bytes.empty()) ?) ?
  let _ = create_account_export(request([Bytes.from_utf8(carol_path), Bytes.from_utf8("carol")],
  0,
  Bytes.empty()) ?) ?
  let bob_profile = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")],
  0,
  Bytes.empty()) ?) ?
  # Every publication carries the same reusable key until it is rotated.
  let reusable = published_last_resort(bob_path) ?
  let again = published_last_resort(bob_path) ?
  assert(U64.compare(reusable.id, again.id) == 0)
  assert(Bytes.secure_equals(reusable.public_key, again.public_key))
  let exhausted = exhausted_profile(bob_profile, reusable) ?
  # Two strangers reach Bob through the same key: it is not consumed.
  let first = start(alice_path, exhausted, "hello from alice") ?
  assert(Bytes.secure_equals(deliver(bob_path, first) ?, Bytes.from_utf8("hello from alice")))
  assert(Bytes.secure_equals(deliver(bob_path, start(carol_path, exhausted, "hello from carol") ?) ?,
  Bytes.from_utf8("hello from carol")))
  # One-time prekeys cannot be replayed because their secret is deleted. This
  # key stays, so delivery replaying a first message must be refused for good
  # rather than rebuilding (and so rolling back) that session.
  case deliver(bob_path, first) do
    Ok( _) -> assert(false)
    Err( error) -> do
      assert(error == "replayed_initial_message")
      assert(permanent_direct_delivery_error(error))
    end
  end
  File.delete(alice_path) ?
  File.delete(carol_path) ?
  File.delete(bob_path) ?
  Ok(true)
end

test("an exhausted prekey pool still opens sessions through the last-resort key") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
