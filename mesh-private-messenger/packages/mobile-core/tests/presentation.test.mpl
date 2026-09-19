import File
from MobileCore import create_account_export, presentation_load_export, presentation_save_export
from Mobile.Presentation import encode_presented_message, consume_presented_message
from Storage.Keys import platform_key
from Transport.Packet import decode_client_profile
from Tests.GroupLifecycleWire import group_vectors
from Tests.Support import database_path, repeated

fn exercise() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("presentation") ?
  let profile = decode_client_profile(create_account_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("alice")]) ?) ?) ?
  let key = Bytes.from_utf8("user/" <> Bytes.to_hex(profile.account_id))
  let data = group_vectors([Bytes.from_utf8("alice"), Bytes.from_utf8("data:image/jpeg;base64,/9j/2Q==")]) ?
  presentation_save_export(group_vectors([Bytes.from_utf8(path), key, data]) ?) ?
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([Bytes.from_utf8(path), key]) ?) ?, data))
  let group_id = repeated(7, 32) ?
  let group_key = Bytes.from_utf8("group/" <> Bytes.to_hex(group_id))
  let group_data = group_vectors([Bytes.from_utf8("Weekend walks"), Bytes.empty()]) ?
  presentation_save_export(group_vectors([Bytes.from_utf8(path), group_key, group_data]) ?) ?
  let packet = encode_presented_message(Bytes.from_utf8("hello"), data, group_data) ?
  let wrapping_key = platform_key() ?
  assert(Bytes.secure_equals(consume_presented_message(path, wrapping_key, profile.account_id, group_id, packet) ?, Bytes.from_utf8("hello")))
  assert(Bytes.secure_equals(consume_presented_message(path, wrapping_key, profile.account_id, group_id, Bytes.from_utf8("old client")) ?, Bytes.from_utf8("old client")))
  let oversized = group_vectors([Bytes.from_utf8("alice"), repeated(97, 12289) ?]) ?
  case presentation_save_export(group_vectors([Bytes.from_utf8(path), key, oversized]) ?) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let removed = group_vectors([Bytes.from_utf8("alice"), Bytes.empty()]) ?
  presentation_save_export(group_vectors([Bytes.from_utf8(path), key, removed]) ?) ?
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([Bytes.from_utf8(path), key]) ?) ?, removed))
  File.delete(path) ?
  Ok(true)
end

test("presentation persists encrypted names and avatars, strips message metadata and supports removing photos") do
  case exercise() do
    Ok(value) -> assert(value)
    Err(error) -> do println(error) assert(false) end
  end
end
