import File
from MobileCore import age_last_resort_for_test, create_account_export, receive_initial_export, reconcile_prekeys_export, replenish_prekeys_export, start_conversation_export
from Mobile.Inbox import permanent_direct_delivery_error
from Prekeys.Pool import OneTimePrekeyPublic, PrekeyPublishRequest, PrekeyPublishResponse, decode_prekey_publish, encode_prekey_publish_response
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

# The directory's answer to a publication, which is when a device learns that
# what it published is what is being handed out.

fn directory_answered(path :: String, encoded_profile :: Bytes) -> Result <(), String > do
  let profile = decode_client_profile(encoded_profile) ?
  let acknowledgement = encode_prekey_publish_response(PrekeyPublishResponse {
    account_id : profile.account_id,
    device_id : profile.device_id,
    active_ids : List.new()
  }) ?
  let _ = reconcile_prekeys_export(request([Bytes.from_utf8(path), acknowledgement],
  0,
  Bytes.empty()) ?) ?
  Ok(nil)
end

fn rotation() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("last-resort-rotation-alice") ?
  let carol_path = database_path("last-resort-rotation-carol") ?
  let dave_path = database_path("last-resort-rotation-dave") ?
  let erin_path = database_path("last-resort-rotation-erin") ?
  let bob_path = database_path("last-resort-rotation-bob") ?
  let _ = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")],
  0,
  Bytes.empty()) ?) ?
  let _ = create_account_export(request([Bytes.from_utf8(carol_path), Bytes.from_utf8("carol")],
  0,
  Bytes.empty()) ?) ?
  let _ = create_account_export(request([Bytes.from_utf8(dave_path), Bytes.from_utf8("dave")],
  0,
  Bytes.empty()) ?) ?
  let _ = create_account_export(request([Bytes.from_utf8(erin_path), Bytes.from_utf8("erin")],
  0,
  Bytes.empty()) ?) ?
  let bob_profile = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")],
  0,
  Bytes.empty()) ?) ?
  let first = published_last_resort(bob_path) ?
  # Six days on it is still the same key; a week on the next publication names
  # a new one, and goes on naming it.
  age_last_resort_for_test(bob_path, 518400000) ?
  let unchanged = published_last_resort(bob_path) ?
  assert(U64.compare(unchanged.id, first.id) == 0)
  age_last_resort_for_test(bob_path, 86400000) ?
  let second = published_last_resort(bob_path) ?
  assert(U64.compare(second.id, first.id) > 0)
  assert(!Bytes.secure_equals(second.public_key, first.public_key))
  let again = published_last_resort(bob_path) ?
  assert(U64.compare(again.id, second.id) == 0)
  # Someone who was handed the old key just before still gets through: until
  # the directory has answered, it may still be handing the old key out.
  let replaced = exhausted_profile(bob_profile, first) ?
  assert(Bytes.secure_equals(deliver(bob_path, start(alice_path, replaced, "in flight") ?) ?,
  Bytes.from_utf8("in flight")))
  # However long the device then stays offline, the old secret is kept, because
  # the directory has not said it stopped handing the old key out.
  age_last_resort_for_test(bob_path, 3456000000) ?
  let _ = published_last_resort(bob_path) ?
  assert(Bytes.secure_equals(deliver(bob_path, start(carol_path, replaced, "still in flight") ?) ?,
  Bytes.from_utf8("still in flight")))
  # Once it has, a message sealed to the old key can be at most 31 days from
  # arriving. Thirty-five days later the secret is destroyed.
  directory_answered(bob_path, bob_profile) ?
  # The old key may have been handed out a moment before that answer.
  assert(Bytes.secure_equals(deliver(bob_path, start(erin_path, replaced, "just before") ?) ?,
  Bytes.from_utf8("just before")))
  age_last_resort_for_test(bob_path, 3024000000) ?
  directory_answered(bob_path, bob_profile) ?
  case deliver(bob_path, start(dave_path, replaced, "too late") ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "one_time_prekey_not_found")
  end
  File.delete(alice_path) ?
  File.delete(carol_path) ?
  File.delete(dave_path) ?
  File.delete(erin_path) ?
  File.delete(bob_path) ?
  Ok(true)
end

test("the last-resort key is replaced every week and its secret destroyed once no message can need it") do
  case rotation() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
