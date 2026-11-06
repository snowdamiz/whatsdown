from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  generate_account,
  generate_device,
  issue_device_credential
)
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DirectoryEntry, ProtocolExtension
from Credits.PostagePolicy import (
  postage_policy_from_device_set,
  sign_postage_policy,
  encode_postage_policy
)
from Storage.CreditPostagePolicy import publish_postage_policy
from Storage.Delivery import enqueue_envelope, DeliveryInsert
from Storage.ContactAddress import publish_contact_address, ContactAddressWrite
from Protocol.V1 import OuterEnvelope
from Storage.Devices import register_device, resolve_devices, DeviceWrite

fn bytes(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test bytes failed")
    Ok(value)
  end
end

fn now() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn entry(owner :: borrow AccountKeys,
  identity :: AccountIdentity,
  device :: borrow DeviceKeys,
  sequence :: String,
  token :: Int) -> DirectoryEntry!String do
  let created = now()?
  let expires = U64.add(created, U64.parse("86400000")?)?
  let credential = case issue_device_credential(owner,
    device,
    U64.parse("1")?,
    created,
    expires,
    U64.parse(sequence)?) do
    Err(_) -> return Err("test credential failed")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device, credential, U64.parse("1")?, expires) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  let once = case generate_one_time_prekey(U64.parse("1")?) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  let bundle = case build_prekey_bundle(credential, signed, once) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  let account_bytes = case encode_account_identity(identity) do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  let bundle_bytes = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  Ok(DirectoryEntry {
    version: 1,
    username: "postage-owner",
    account_identity: account_bytes,
    prekey_bundle: bundle_bytes,
    mailbox_token: bytes(token, 32)?
  })
end

fn current(pool :: PoolHandle) -> DeviceSet!String do
  case resolve_devices(pool, "postage-owner")? do
    None -> Err("missing test devices")
    Some(value) -> Ok(value)
  end
end

fn current_price(pool :: PoolHandle) -> Int!String do
  case postage_policy_from_device_set(current(pool)?)? do
    None -> Ok(0)
    Some(value) -> Ok(value.credits)
  end
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 4, 5000)?
  let (owner, identity) = case generate_account(now()?, U64.parse("1")?) do
    Err(_) -> return Err("test account failed")
    Ok(value) -> value
  end
  let device = case generate_device() do
    Err(_) -> return Err("test device failed")
    Ok(value) -> value
  end
  let first = entry(owner, identity, device, "1", 31)?
  let bundle = case decode_prekey_bundle(first.prekey_bundle) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  let forged = %{bundle |
    extensions: [ProtocolExtension { id: 3, mandatory: false, value: bytes(71, 141)? }]
  }
  let forged_bytes = case encode_prekey_bundle(forged) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  assert(register_device(pool, %{first | prekey_bundle: forged_bytes})? == DeviceAccepted)
  # An authenticated device registration does not authenticate arbitrary
  # account policy bytes carried in unsigned prekey extensions.
  assert(postage_policy_from_device_set(current(pool)?)? == None)
  let first_policy = sign_postage_policy(owner,
    device.device_id,
    U64.parse("1")?,
    U64.parse("1")?,
    5,
    now()?)?
  let accepted = publish_postage_policy(pool, first_policy)?
  assert(accepted.created && accepted.device_set_revision == U64.parse("2")?)
  let stored = case postage_policy_from_device_set(current(pool)?)? do
    None -> return Err("policy not mirrored")
    Some(value) -> value
  end
  assert(Bytes.secure_equals(encode_postage_policy(stored)?, encode_postage_policy(first_policy)?))
  assert(!publish_postage_policy(pool, first_policy)?.created)
  assert(Result.is_err(publish_postage_policy(pool, %{first_policy | credits: 25})))
  assert(Result.is_err(publish_postage_policy(pool,
    sign_postage_policy(owner, device.device_id, U64.parse("3")?, U64.parse("2")?, 25, now()?)?)))
  let second_device = case generate_device() do
    Err(_) -> return Err("test device failed")
    Ok(value) -> value
  end
  let second = entry(owner, identity, second_device, "3", 32)?
  assert(register_device(pool, second)? == DeviceAccepted)
  let after_link = current(pool)?
  assert(List.length(after_link.devices) == 2 && after_link.sequence == U64.parse("3")?)
  assert(current_price(pool)? == 5)
  # A new registration and exact replay of an old entry cannot clear policy3.
  assert(register_device(pool, first)? == DeviceUnchanged)
  let next_policy = sign_postage_policy(owner,
    device.device_id,
    U64.parse("2")?,
    U64.parse("3")?,
    25,
    now()?)?
  Pool.execute(pool,
    "CREATE FUNCTION pg_temp.fail_postage_log() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced postage log failure'; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER fail_postage_log BEFORE INSERT ON transparency_entries FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_postage_log()",
    [])?
  assert(Result.is_err(publish_postage_policy(pool, next_policy)))
  Pool.execute(pool, "DROP TRIGGER fail_postage_log ON transparency_entries", [])?
  assert(current(pool)?.sequence == U64.parse("3")?)
  assert(current_price(pool)? == 5)
  assert(publish_postage_policy(pool, next_policy)?.created)
  assert(current(pool)?.sequence == U64.parse("4")?)
  assert(current_price(pool)? == 25)
  # The old signed request remains an exact no-op after subsequent device and
  # policy changes, without reapplying its lower price or incrementing the log.
  assert(!publish_postage_policy(pool, first_policy)?.created)
  assert(current(pool)?.sequence == U64.parse("4")?)
  let prices = Pool.query(pool,
    "SELECT DISTINCT postage_credits::text AS price FROM messenger_mailboxes WHERE active",
    [])?
  assert(List.length(prices) == 1 && Map.get(List.head(prices), "price") == "25")
  let outer = OuterEnvelope {
    version: 1,
    envelope_id: bytes(91, 16)?,
    mailbox_token: first.mailbox_token,
    suite: 1,
    expiration: U64.add(now()?, U64.parse("86400000")?)?,
    padding_bucket: 512,
    ciphertext: bytes(72, 512)?
  }
  assert(enqueue_envelope(pool, outer)? == PostageRequired)
  assert(publish_contact_address(pool,
    Crypto.sha256(first.mailbox_token),
    Crypto.sha256(bytes(81, 32)?))? == ContactAddressPublished)
  let contact_outer = %{outer | mailbox_token: bytes(81, 32)?}
  assert(enqueue_envelope(pool, contact_outer)? == Accepted)
  assert(enqueue_envelope(pool, contact_outer)? == Duplicate)
  assert(publish_contact_address(pool,
    Crypto.sha256(first.mailbox_token),
    Crypto.sha256(bytes(82, 32)?))? == ContactAddressPublished)
  assert(enqueue_envelope(pool, %{contact_outer | envelope_id: bytes(92, 16)?})? == PostageRequired)
  println("CREDITS_POSTAGE_POLICY")
  Ok(true)
end

test("unsigned registration cannot publish account postage policy") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
