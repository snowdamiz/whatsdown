from Tests.PresentationFixture import fixture_load_presentation, fixture_save_presentation
import File
from Mobile.Codec import mobile_wide, mobile_write_u64
from MobileCore import create_account_export
from Mobile.Presentation import (
  community_change_allowed,
  encode_presented_message,
  presented_message_writes,
  present_message,
  store_group_anchor
)
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import local_context, platform_key, seal_local
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
  fixture_save_presentation(group_vectors([Bytes.from_utf8(path), key, data])?)?
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
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
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
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
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
      Bytes.from_utf8(path),
      group_key
    ])?)?,
    updated_group))
  let oversized = group_vectors([Bytes.from_utf8("alice"), repeated(97, 12289)?])?
  case fixture_save_presentation(group_vectors([Bytes.from_utf8(path), key, oversized])?) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let invalid_avatar = group_vectors([
    Bytes.from_utf8("alice"),
    Bytes.from_utf8("data:image/jpeg;base64,not-an-image?")
  ])?
  case fixture_save_presentation(group_vectors([Bytes.from_utf8(path), key, invalid_avatar])?) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let removed = group_vectors([Bytes.from_utf8("alice"), Bytes.empty()])?
  fixture_save_presentation(group_vectors([Bytes.from_utf8(path), key, removed])?)?
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
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
  fixture_save_presentation(group_vectors([Bytes.from_utf8(path), key, nickname])?)?
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
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
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
      Bytes.from_utf8(path),
      key
    ])?)?,
    nickname))
  fixture_save_presentation(group_vectors([Bytes.from_utf8(path), key, Bytes.from_hex("00")?])?)?
  assert(Bytes.length(fixture_load_presentation(group_vectors([
    Bytes.from_utf8(path),
    key
  ])?)?) == 0)
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
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
  fixture_load_presentation(group_vectors([Bytes.from_utf8(path), group_key])?)
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

fn reject_authenticated_presentation(path :: String,
  wrapping_key :: borrow StorageKey,
  label :: String,
  request :: Bytes,
  raw :: Bytes) -> Bool!String do
  store_updated_blobs(path, [label], [seal_local(raw, wrapping_key, local_context(label)?)?])?
  case fixture_load_presentation(request) do
    Ok(_) -> do
      assert(false)
      Ok(false)
    end
    Err(error) -> do
      assert(error == "invalid_presentation")
      Ok(true)
    end
  end
end

fn exercise_authenticated_load_validation() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("presentation-authenticated-load")?
  let profile = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("alice")
  ])?)?)?
  let key = Bytes.from_utf8("user/" <> Bytes.to_hex(profile.account_id))
  let label = "presentation/v1/user/" <> Bytes.to_hex(profile.account_id)
  let request = group_vectors([Bytes.from_utf8(path), key])?
  let wrapping_key = platform_key()?
  let value_context = local_context(label)?
  assert(Bytes.length(fixture_load_presentation(request)?) == 0)
  let valid = group_vectors([Bytes.from_utf8("Alice"), Bytes.empty()])?
  store_updated_blobs(path, [label], [seal_local(valid, wrapping_key, value_context)?])?
  assert(Bytes.secure_equals(fixture_load_presentation(request)?, valid))
  # Authentication alone cannot make a truncated or invalid presentation canonical.
  assert(reject_authenticated_presentation(path,
    wrapping_key,
    label,
    request,
    Bytes.from_hex("00000001")?)?)
  assert(reject_authenticated_presentation(path,
    wrapping_key,
    label,
    request,
    group_vectors([Bytes.empty(), Bytes.empty()])?)?)
  store_updated_blobs(path, [label], [seal_local(Bytes.empty(), wrapping_key, value_context)?])?
  assert(Bytes.length(fixture_load_presentation(request)?) == 0)
  store_updated_blobs(path, [label], [repeated(9, 64)?])?
  case fixture_load_presentation(request) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "local_state_open_failed")
  end
  store_updated_blobs(path, [label], [seal_local(valid, wrapping_key, value_context)?])?
  assert(Bytes.secure_equals(fixture_load_presentation(request)?, valid))
  File.delete(path)?
  Ok(true)
end

test("presentation loads reject authenticated malformed records while preserving empty, valid and authentication-error results") do
  case exercise_authenticated_load_validation() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn exercise_error_priority() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("private_presentation_error_priority")?
  ensure_schema(path)?
  let owner = repeated(1, 32)?
  let group = repeated(4, 32)?
  let user_label = "presentation/v1/user/" <> Bytes.to_hex(owner)
  let group_label = "presentation/v1/group/" <> Bytes.to_hex(group)
  let anchor_label = "group-anchor/v1/" <> Bytes.to_hex(group)
  let profile = group_vectors([Bytes.from_utf8("Sender"), Bytes.empty()])?
  let established = community_record("Owner group", 1, Bytes.from_utf8("[1]"), [owner])?
  let framed = encode_presented_message(Bytes.from_utf8("body"), profile, established)?
  consume_presented_message(path, wrapping, owner, group, owner, framed)?
  let user_before = load_blob(path, user_label)?
  let group_before = load_blob(path, group_label)?
  let malformed_user = seal_local(Bytes.from_hex("00000001")?,
    wrapping,
    local_context(user_label)?)?
  store_updated_blobs(path,
    [user_label, anchor_label],
    [malformed_user, Bytes.from_utf8("corrupt")])?
  case presented_message_writes(path, wrapping, owner, group, owner, framed) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "invalid_presentation")
  end
  assert(Bytes.secure_equals(load_blob(path, user_label)?, malformed_user))
  assert(Bytes.secure_equals(load_blob(path, group_label)?, group_before))
  store_updated_blobs(path, [user_label], [user_before])?
  case presented_message_writes(path, wrapping, owner, group, owner, framed) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "local_state_open_failed")
  end
  # Preparing a new user ciphertext does not install it when the group fails.
  assert(Bytes.secure_equals(load_blob(path, user_label)?, user_before))
  assert(Bytes.secure_equals(load_blob(path, group_label)?, group_before))
  store_group_anchor(path, wrapping, group, owner)?
  let fresh = presented_message_writes(path, wrapping, owner, group, owner, framed)?
  let (_, _, labels, blobs) = fresh
  assert(List.length(labels) == 2 && List.length(blobs) == 2)
  assert(Bytes.secure_equals(load_blob(path, user_label)?, user_before))
  assert(Bytes.secure_equals(load_blob(path, group_label)?, group_before))
  store_updated_blobs(path, labels, blobs)?
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
      Bytes.from_utf8(path),
      Bytes.from_utf8("user/" <> Bytes.to_hex(owner))
    ])?)?,
    profile))
  assert(Bytes.secure_equals(fixture_load_presentation(group_vectors([
      Bytes.from_utf8(path),
      Bytes.from_utf8("group/" <> Bytes.to_hex(group))
    ])?)?,
    established))
  File.delete(path)?
  Ok(true)
end

test("independent presentation preparation preserves first error and never commits partial plans") do
  case exercise_error_priority() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn creation_personal_record(name :: Bytes, avatar :: Bytes) -> Bytes!String do
  group_vectors([name, avatar, mobile_write_u64(mobile_wide("123456789")?)?])
end

fn creation_load(path :: String, account_id :: Bytes) -> Bytes!String do
  fixture_load_presentation(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("user/" <> Bytes.to_hex(account_id))
  ])?)
end

fn creation_row_count(path :: String) -> String!String do
  let database = Sqlite.open(path)?
  let rows = Sqlite.query(database,
    "SELECT CAST(count(*) AS TEXT) AS value FROM encrypted_blobs",
    [])?
  Sqlite.close(database)
  Ok(Map.get(List.head(rows), "value"))
end

fn exercise_created_personal() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account_creation_personal")?
  let personal = creation_personal_record(Bytes.from_utf8("Owned name"),
    Bytes.from_utf8("data:image/jpeg;base64,/9j/2Q=="))?
  let profile = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("account-name"),
    personal
  ])?)?)?
  assert(Bytes.secure_equals(creation_load(path, profile.account_id)?, personal))
  let sealed = load_blob(path, "presentation/v1/user/" <> Bytes.to_hex(profile.account_id))?
  assert(Bytes.length(sealed) > Bytes.length(personal))
  assert(!Bytes.secure_equals(sealed, personal))
  let old_personal = group_vectors([Bytes.from_utf8("No revision"), Bytes.empty()])?
  let old_path = database_path("account_creation_personal_legacy_inner")?
  let old_profile = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(old_path),
    Bytes.from_utf8("old-inner"),
    old_personal
  ])?)?)?
  assert(Bytes.secure_equals(creation_load(old_path, old_profile.account_id)?, old_personal))
  File.delete(old_path)?
  File.delete(path)?
  Ok(true)
end

test("account creation atomically persists the supplied personal name avatar and revision") do
  case exercise_created_personal() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn exercise_created_personal_maximum() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account_creation_personal_maximum")?
  let avatar = Bytes.concat(Bytes.from_utf8("data:image/jpeg;base64,"), repeated(65, 12265)?)?
  assert(Bytes.length(avatar) == 12288)
  let personal = creation_personal_record(repeated(78, 96)?, avatar)?
  assert(Bytes.length(personal) == 12404)
  let profile = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("maximum"),
    personal
  ])?)?)?
  assert(Bytes.secure_equals(creation_load(path, profile.account_id)?, personal))
  File.delete(path)?
  Ok(true)
end

test("account creation accepts the inclusive maximum personal record") do
  case exercise_created_personal_maximum() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn creation_rejected(path :: String, wire :: Bytes) -> Bool!String do
  assert(Result.is_err(create_account_export(wire)))
  assert(Result.is_err(load_blob(path, "profile/v1")))
  assert(Result.is_err(load_blob(path, "account-signing-key/v1")))
  File.delete(path)?
  Ok(true)
end

fn exercise_creation_frame_refusal() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("account_creation_personal_invalid")?
  let base = [Bytes.from_utf8(path), Bytes.from_utf8("invalid")]
  creation_rejected(path, group_vectors(base ++ [Bytes.empty()])?)?
  let personal = creation_personal_record(Bytes.from_utf8("valid"), Bytes.empty())?
  let wire = group_vectors(base ++ [personal])?
  creation_rejected(path, Bytes.slice(wire, 0, Bytes.length(wire) - 1)?)?
  creation_rejected(path, group_vectors(base ++ [personal, Bytes.empty()])?)?
  creation_rejected(path, group_vectors(base ++ [repeated(65, 12405)?])?)?
  creation_rejected(path, repeated(0, 16577)?)?
  # A present malformed record may not be mistaken for absent legacy data.
  creation_rejected(path, group_vectors(base ++ [Bytes.from_hex("00000000")?])?)?
  Ok(true)
end

test("account creation rejects empty truncated trailing and oversized optional presentation frames") do
  case exercise_creation_frame_refusal() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn exercise_creation_personal_only() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let ordinary = database_path("account_creation_personal_general_control")?
  let profile = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(ordinary),
    Bytes.from_utf8("general")
  ])?)?)?
  let key = Bytes.from_utf8("user/" <> Bytes.to_hex(profile.account_id))
  let owner = repeated(1, 32)?
  let admin = repeated(2, 32)?
  let role62 = group_vectors([
    Bytes.from_utf8("A"),
    Bytes.empty(),
    mobile_write_u64(mobile_wide("0")?)?,
    Bytes.from_utf8("x"),
    owner
  ])?
  let role94 = group_vectors([
    Bytes.from_utf8("A"),
    Bytes.empty(),
    mobile_write_u64(mobile_wide("0")?)?,
    Bytes.from_utf8("x"),
    Bytes.concat(owner, admin)?
  ])?
  assert(Bytes.length(role62) == 62 && Bytes.length(role94) == 94)
  # Existing generic presentation storage deliberately still accepts communities.
  fixture_save_presentation(group_vectors([Bytes.from_utf8(ordinary), key, role62])?)?
  assert(Bytes.secure_equals(creation_load(ordinary, profile.account_id)?, role62))
  fixture_save_presentation(group_vectors([Bytes.from_utf8(ordinary), key, role94])?)?
  assert(Bytes.secure_equals(creation_load(ordinary, profile.account_id)?, role94))
  let path = database_path("account_creation_personal_roles")?
  creation_rejected(path,
    group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("personal"), role62])?)?
  creation_rejected(path,
    group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("personal"), role94])?)?
  File.delete(ordinary)?
  Ok(true)
end

test("personal signup refuses community roles while generic presentation records retain them") do
  case exercise_creation_personal_only() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn exercise_creation_personal_rollback() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let control = database_path("account_creation_personal_count")?
  let legacy = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(control),
    Bytes.from_utf8("legacy")
  ])?)?)?
  assert(Bytes.length(creation_load(control, legacy.account_id)?) == 0)
  let count = creation_row_count(control)?
  let path = database_path("account_creation_personal_rollback")?
  ensure_schema(path)?
  let database = Sqlite.open(path)?
  Sqlite.execute(database,
    "CREATE TRIGGER fail_extra_account_record BEFORE INSERT ON encrypted_blobs WHEN (SELECT count(*) FROM encrypted_blobs) >= "
      <> count
      <> " BEGIN SELECT RAISE(ABORT, 'synthetic additional account record failure'); END",
    [])?
  Sqlite.close(database)
  let personal = creation_personal_record(Bytes.from_utf8("Atomic"), Bytes.empty())?
  let request = group_vectors([Bytes.from_utf8(path), Bytes.from_utf8("atomic"), personal])?
  assert(Result.is_err(create_account_export(request)))
  assert(creation_row_count(path)? == "0")
  assert(Result.is_err(load_blob(path, "profile/v1")))
  assert(Result.is_err(load_blob(path, "account-signing-key/v1")))
  let reopened = Sqlite.open(path)?
  Sqlite.execute(reopened, "DROP TRIGGER fail_extra_account_record", [])?
  Sqlite.close(reopened)
  let profile = decode_client_profile(create_account_export(request)?)?
  assert(Bytes.secure_equals(creation_load(path, profile.account_id)?, personal))
  File.delete(path)?
  File.delete(control)?
  Ok(true)
end

test("optional personal record failure rolls back the whole account and permits a clean retry") do
  case exercise_creation_personal_rollback() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
