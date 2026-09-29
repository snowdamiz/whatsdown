import File
from Mobile.Codec import mobile_wide, mobile_write_u64
from MobileCore import create_account_export, presentation_load_export, presentation_save_export
from Mobile.Presentation import (
  community_change_allowed,
  encode_presented_message,
  presented_message_writes,
  present_message,
  store_group_anchor
)
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
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([
      Bytes.from_utf8(path),
      key
    ])?)?,
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
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([
      Bytes.from_utf8(path),
      key
    ])?)?,
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
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([
      Bytes.from_utf8(path),
      key
    ])?)?,
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
  assert(Bytes.secure_equals(presentation_load_export(group_vectors([
      Bytes.from_utf8(path),
      key
    ])?)?,
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

# A community's record adds its details and roles: the owner, then admins in ascending order.
fn community_record(name :: String,
  revision :: Int,
  details :: Bytes,
  roles :: List<Bytes>) -> Bytes!String do
  group_vectors([
    Bytes.from_utf8(name),
    Bytes.empty(),
    mobile_write_u64(mobile_wide("#{revision}")?)?,
    details,
    List.reduce(roles,
      Bytes.empty(),
      fn(joined, id) do
        case Bytes.concat(joined, id) do
          Ok(value) -> value
          Err(_) -> Bytes.empty()
        end
      end)
  ])
end

fn stored_record(path :: String, group_key :: Bytes) -> Bytes!String do
  presentation_load_export(group_vectors([Bytes.from_utf8(path), group_key])?)
end

fn ascending_roles(joined :: Bytes, next :: Int, end_at :: Int) -> Bytes!String do
  if next >= end_at do
    Ok(joined)
  else
    ascending_roles(Bytes.concat(joined, repeated(next, 32)?)?, next + 1, end_at)
  end
end

# With a full-size photo and details a community outgrows the plain record's bound.
fn exercise_community_bounds() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let sender = group_vectors([Bytes.from_utf8("alice"), Bytes.empty()])?
  let owner = repeated(1, 32)?
  let avatar = Bytes.concat(Bytes.from_utf8("data:image/jpeg;base64,"), repeated(65, 12264)?)?
  let largest = group_vectors([
    Bytes.from_utf8("Solana builders"),
    avatar,
    mobile_write_u64(mobile_wide("5")?)?,
    repeated(97, 16384)?,
    ascending_roles(owner, 2, 18)?
  ])?
  assert(Bytes.length(largest) > 29000)
  encode_presented_message(Bytes.empty(), sender, largest)?
  let rejected = [
    community_record("Solana builders", 5, repeated(97, 16385)?, [owner])?,
    community_record("Solana builders", 5, Bytes.empty(), [owner])?,
    community_record("Solana builders", 5, Bytes.from_hex("0a")?, [owner])?,
    community_record("Solana builders", 5, Bytes.from_utf8("x"), [])?,
    community_record("Solana builders", 5, Bytes.from_utf8("x"), [owner, owner])?,
    community_record("Solana builders",
      5,
      Bytes.from_utf8("x"),
      [owner, repeated(3, 32)?, repeated(2, 32)?])?,
    community_record("Solana builders", 5, Bytes.from_utf8("x"), [repeated(1, 31)?])?,
    group_vectors([
      Bytes.from_utf8("Solana builders"),
      Bytes.empty(),
      mobile_write_u64(mobile_wide("5")?)?,
      Bytes.from_utf8("x")
    ])?
  ]
  List.map(rejected,
    fn(value) -> case encode_presented_message(Bytes.empty(), sender, value) do
      Ok(_) -> assert(false)
      Err(_) -> assert(true)
    end end)
  Ok(true)
end

test("community records hold details and roles beside a full-size photo and reject malformed roles") do
  case exercise_community_bounds() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn deliver_record(path :: String,
  key :: borrow StorageKey,
  group_id :: Bytes,
  creator :: Bytes,
  sender :: Bytes,
  from :: Bytes,
  record :: Bytes) -> Bytes!String do
  consume_presented_message(path,
    key,
    from,
    group_id,
    creator,
    encode_presented_message(Bytes.empty(), sender, record)?)
end

# A member first learns a community from whoever added them, then only from its
# owner, or from an admin who leaves the roles as they were.
fn exercise_community_authority() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("community-authority")?
  create_account_export(group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("alice")])?)?
  let sender = group_vectors([Bytes.from_utf8("alice"), Bytes.empty()])?
  let key = platform_key()?
  let group_id = repeated(9, 32)?
  let group_key = Bytes.from_utf8("group/" <> Bytes.to_hex(group_id))
  let creator = repeated(1, 32)?
  let inviter = repeated(2, 32)?
  let admin = repeated(3, 32)?
  let stranger = repeated(4, 32)?
  let first = community_record("Solana builders", 1, Bytes.from_utf8("[]"), [inviter])?
  deliver_record(path, key, group_id, creator, sender, creator, first)?
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    stranger,
    community_record("Fake", 2, Bytes.from_utf8("[]"), [stranger])?)?
  assert(Bytes.length(stored_record(path, group_key)?) == 0)
  store_group_anchor(path, key, group_id, inviter)?
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    inviter,
    community_record("Solana builders", 1, Bytes.from_utf8("[]"), [creator])?)?
  assert(Bytes.length(stored_record(path, group_key)?) == 0)
  deliver_record(path, key, group_id, creator, sender, inviter, first)?
  assert(Bytes.secure_equals(stored_record(path, group_key)?, first))
  let promoted = community_record("Solana builders", 2, Bytes.from_utf8("[]"), [inviter, admin])?
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    admin,
    community_record("Solana builders", 3, Bytes.from_utf8("[1]"), [inviter, admin])?)?
  deliver_record(path, key, group_id, creator, sender, inviter, promoted)?
  assert(Bytes.secure_equals(stored_record(path, group_key)?, promoted))
  let edited = community_record("Solana builders", 3, Bytes.from_utf8("[1]"), [inviter, admin])?
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    admin,
    community_record("Solana builders", 3, Bytes.from_utf8("[2]"), [admin, inviter])?)?
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    admin,
    community_record("Solana builders", 3, Bytes.from_utf8("[2]"), [inviter])?)?
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    stranger,
    community_record("Solana builders", 3, Bytes.from_utf8("[2]"), [inviter, admin])?)?
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    creator,
    community_record("Solana builders", 3, Bytes.from_utf8("[2]"), [inviter, admin])?)?
  assert(Bytes.secure_equals(stored_record(path, group_key)?, promoted))
  deliver_record(path, key, group_id, creator, sender, admin, edited)?
  assert(Bytes.secure_equals(stored_record(path, group_key)?, edited))
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    admin,
    group_vectors([
      Bytes.from_utf8("Plain now"),
      Bytes.empty(),
      mobile_write_u64(mobile_wide("4")?)?
    ])?)?
  assert(Bytes.secure_equals(stored_record(path, group_key)?, edited))
  let handed = community_record("Solana builders", 4, Bytes.from_utf8("[1]"), [admin, inviter])?
  deliver_record(path, key, group_id, creator, sender, inviter, handed)?
  assert(Bytes.secure_equals(stored_record(path, group_key)?, handed))
  deliver_record(path,
    key,
    group_id,
    creator,
    sender,
    inviter,
    community_record("Solana builders", 5, Bytes.from_utf8("[1]"), [inviter])?)?
  assert(Bytes.secure_equals(stored_record(path, group_key)?, handed))
  assert(community_change_allowed(path, key, group_id, admin, stranger)?)
  assert(community_change_allowed(path, key, group_id, inviter, Bytes.empty())?)
  assert(!community_change_allowed(path, key, group_id, stranger, Bytes.empty())?)
  assert(!community_change_allowed(path, key, group_id, inviter, admin)?)
  assert(community_change_allowed(path, key, group_id, admin, inviter)?)
  assert(community_change_allowed(path, key, group_id, inviter, inviter)?)
  assert(community_change_allowed(path, key, repeated(10, 32)?, stranger, admin)?)
  File.delete(path)?
  Ok(true)
end

test("community records come first from whoever added this device, then only from the owner or admins") do
  case exercise_community_authority() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
