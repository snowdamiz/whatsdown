import File
from Mobile.Codec import mobile_wide, mobile_write_u64
from MobileCore import create_account_export, presentation_load_export, presentation_save_export
from Mobile.Presentation import encode_presented_message, presented_message_writes, present_message
from Storage.Blobs import load_blob
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs
from Transport.Packet import decode_client_profile
from Tests.GroupLifecycleWire import group_vectors
from Tests.Support import database_path, repeated

fn consume_presented_message(path :: String,
  key :: borrow StorageKey,
  sender :: Bytes,
  group :: Bytes,
  creator :: Bytes,
  input :: Bytes) -> Bytes!String do
  let (body, attachment, labels, blobs) = presented_message_writes(path,
    key,
    sender,
    group,
    creator,
    input)?
  store_updated_blobs(path, labels, blobs)?
  Ok(body)
end

fn exercise() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("presentation")?
  let profile = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("alice")
  ])?)?)?
  let key = Bytes.from_utf8("user/" <> Bytes.to_hex(profile.account_id))
  let data = group_vectors([
    Bytes.from_utf8("alice"),
    Bytes.from_utf8("data:image/jpeg;base64,/9j/2Q==")
  ])?
  presentation_save_export(group_vectors([Bytes.from_utf8(path), key, data])?)?
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([Bytes.from_utf8(path), key])?)?,
    data))
  let group_id = repeated(7, 32)?
  let group_key = Bytes.from_utf8("group/" <> Bytes.to_hex(group_id))
  let group_data = group_vectors([Bytes.from_utf8("Weekend walks"), Bytes.empty()])?
  let packet = encode_presented_message(Bytes.from_utf8("hello"), data, group_data)?
  let wrapping_key = platform_key()?
  assert(Bytes.secure_equals(consume_presented_message(path,
      wrapping_key,
      profile.account_id,
      group_id,
      profile.account_id,
      packet)?,
    Bytes.from_utf8("hello")))
  assert(Bytes.secure_equals(consume_presented_message(path,
      wrapping_key,
      profile.account_id,
      group_id,
      profile.account_id,
      Bytes.from_utf8("old client"))?,
    Bytes.from_utf8("old client")))
  let updated_group = group_vectors([
    Bytes.from_utf8("Weekend walks"),
    Bytes.from_utf8("data:image/jpeg;base64,/9j/2Q=="),
    mobile_write_u64(mobile_wide("2")?)?
  ])?
  consume_presented_message(path,
    wrapping_key,
    profile.account_id,
    group_id,
    profile.account_id,
    encode_presented_message(Bytes.empty(), data, updated_group)?)?
  consume_presented_message(path,
    wrapping_key,
    profile.account_id,
    group_id,
    profile.account_id,
    packet)?
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([
      Bytes.from_utf8(path),
      group_key
    ])?)?,
    updated_group))
  let forged = group_vectors([
    Bytes.from_utf8("Not the creator"),
    Bytes.empty(),
    mobile_write_u64(mobile_wide("3")?)?
  ])?
  consume_presented_message(path,
    wrapping_key,
    repeated(8, 32)?,
    group_id,
    profile.account_id,
    encode_presented_message(Bytes.empty(), data, forged)?)?
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([
      Bytes.from_utf8(path),
      group_key
    ])?)?,
    updated_group))
  let oversized = group_vectors([Bytes.from_utf8("alice"), repeated(97, 12289)?])?
  case presentation_save_export(group_vectors([Bytes.from_utf8(path), key, oversized])?) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let invalid_avatar = group_vectors([
    Bytes.from_utf8("alice"),
    Bytes.from_utf8("data:image/jpeg;base64,not-an-image?")
  ])?
  case presentation_save_export(group_vectors([Bytes.from_utf8(path), key, invalid_avatar])?) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let removed = group_vectors([Bytes.from_utf8("alice"), Bytes.empty()])?
  presentation_save_export(group_vectors([Bytes.from_utf8(path), key, removed])?)?
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([Bytes.from_utf8(path), key])?)?,
    removed))
  File.delete(path)?
  Ok(true)
end

test("presentation persists encrypted names and avatars, strips message metadata and supports removing photos") do
  case exercise() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn exercise_nicknames() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("private-nickname")?
  create_account_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let peer = repeated(8, 32)?
  let key = Bytes.from_utf8("nickname/" <> Bytes.to_hex(peer))
  let nickname = group_vectors([
    Bytes.from_utf8("Dad"),
    Bytes.empty(),
    mobile_write_u64(mobile_wide("2")?)?
  ])?
  let before = present_message(path, Bytes.empty(), Bytes.from_utf8("hello"))?
  presentation_save_export(group_vectors([Bytes.from_utf8(path), key, nickname])?)?
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([Bytes.from_utf8(path), key])?)?,
    nickname))
  assert(!Bytes.secure_equals(load_blob(path, "presentation/v1/nickname/" <> Bytes.to_hex(peer))?,
    nickname))
  assert(Bytes.secure_equals(present_message(path, Bytes.empty(), Bytes.from_utf8("hello"))?,
    before))
  let shared = group_vectors([Bytes.from_utf8("Alex Chen"), Bytes.empty()])?
  let wrapping_key = platform_key()?
  consume_presented_message(path,
    wrapping_key,
    peer,
    Bytes.empty(),
    Bytes.empty(),
    encode_presented_message(Bytes.from_utf8("hi"), shared, Bytes.empty())?)?
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([Bytes.from_utf8(path), key])?)?,
    nickname))
  presentation_save_export(group_vectors([Bytes.from_utf8(path), key, Bytes.from_hex("00")?])?)?
  assert(Bytes.length(presentation_load_export(group_vectors([Bytes.from_utf8(path), key])?)?) == 0)
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([
      Bytes.from_utf8(path),
      Bytes.from_utf8("user/" <> Bytes.to_hex(peer))
    ])?)?,
    shared))
  File.delete(path)?
  Ok(true)
end

test("contact nicknames persist encrypted, stay off the wire and clear without changing shared profiles") do
  case exercise_nicknames() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
