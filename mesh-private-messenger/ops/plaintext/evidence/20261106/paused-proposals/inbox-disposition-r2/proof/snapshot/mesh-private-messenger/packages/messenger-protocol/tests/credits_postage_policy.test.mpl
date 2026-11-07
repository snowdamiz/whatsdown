from Credits.PostagePolicy import (
  sign_postage_policy,
  verify_postage_policy,
  encode_postage_policy,
  decode_postage_policy,
  bundle_with_postage_policy,
  strip_postage_policy_extension,
  postage_policy_from_device_set
)
from Identity.Device import AccountKeys, DeviceKeys, generate_device, issue_device_credential
from Prekeys.Bundle import generate_signed_prekey, generate_one_time_prekey, build_prekey_bundle
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry, PrekeyBundle, ProtocolExtension
from Identity.Device import generate_account

fn proof() -> Bool!String do
  let (owner, account) = case generate_account(U64.parse("1000")?, U64.parse("1")?) do
    Err(_) -> return Err("test account failed")
    Ok(value) -> value
  end
  let device = case Bytes.repeat(11, 16) do
    Err(_) -> return Err("test bytes failed")
    Ok(value) -> value
  end
  let policy = sign_postage_policy(owner,
    device,
    U64.parse("1")?,
    U64.parse("2")?,
    25,
    U64.parse("1000000")?)?
  let encoded = encode_postage_policy(policy)?
  assert(Bytes.length(encoded) == 141)
  assert(verify_postage_policy(policy, account)?)
  assert(!verify_postage_policy(%{policy | credits: 0}, account)?)
  assert(!verify_postage_policy(%{policy | expected_device_set_revision: U64.parse("3")?},
    account)?)
  assert(!verify_postage_policy(%{policy | issued_at_ms: U64.parse("1000001")?}, account)?)
  let maximum = sign_postage_policy(owner,
    device,
    U64.parse("18446744073709551615")?,
    U64.parse("18446744073709551614")?,
    1,
    U64.parse("18446744073709551615")?)?
  let decoded = decode_postage_policy(encode_postage_policy(maximum)?)?
  assert(decoded.revision == maximum.revision && decoded.issued_at_ms == maximum.issued_at_ms)
  assert(verify_postage_policy(decoded, account)?)
  assert(Result.is_err(decode_postage_policy(Bytes.concat(encoded, Bytes.from_hex("00")?)?)))
  assert(Result.is_err(encode_postage_policy(%{policy | credits: 2})))
  assert(Result.is_err(encode_postage_policy(%{policy | revision: U64.parse("0")?})))
  Ok(true)
end

test("account-signed postage policy binds owner, level and complete monotonic publication") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn bundle(owner :: borrow AccountKeys, device :: borrow DeviceKeys) -> PrekeyBundle!String do
  let credential = case issue_device_credential(owner,
    device,
    U64.parse("1")?,
    U64.parse("1000")?,
    U64.parse("2000000")?,
    U64.parse("1")?) do
    Err(_) -> return Err("test credential failed")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device,
    credential,
    U64.parse("1")?,
    U64.parse("2000000")?) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  let once = case generate_one_time_prekey(U64.parse("1")?) do
    Err(_) -> return Err("test prekey failed")
    Ok(value) -> value
  end
  case build_prekey_bundle(credential, signed, once) do
    Err(_) -> Err("test bundle failed")
    Ok(value)
  end
end

fn bundle_wire(value :: PrekeyBundle) -> Bytes!String do
  case encode_prekey_bundle(value) do
    Err(_) -> Err("test bundle codec failed")
    Ok(value)
  end
end

fn mirrors() -> Bool!String do
  let (owner, account) = case generate_account(U64.parse("1000")?, U64.parse("1")?) do
    Err(_) -> return Err("test account failed")
    Ok(value) -> value
  end
  let device = case generate_device() do
    Err(_) -> return Err("test device failed")
    Ok(value) -> value
  end
  let policy = sign_postage_policy(owner,
    device.device_id,
    U64.parse("1")?,
    U64.parse("2")?,
    5,
    U64.parse("1000000")?)?
  let base = bundle(owner, device)?
  let extended = %{base |
    extensions: [
      ProtocolExtension { id: 1, mandatory: false, value: Bytes.from_utf8("renewal-part-a") },
      ProtocolExtension { id: 2, mandatory: false, value: Bytes.from_utf8("renewal-part-b") },
      ProtocolExtension { id: 4, mandatory: false, value: Bytes.from_utf8("future") }
    ]
  }
  let mirrored = bundle_with_postage_policy(extended, policy)?
  assert(Bytes.secure_equals(bundle_wire(strip_postage_policy_extension(mirrored))?,
    bundle_wire(extended)?))
  let identity = case encode_account_identity(account) do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  let token = case Bytes.repeat(44, 32) do
    Err(_) -> return Err("test token failed")
    Ok(value) -> value
  end
  let entry = DirectoryEntry {
    version: 1,
    username: "postage-owner",
    account_identity: identity,
    prekey_bundle: bundle_wire(mirrored)?,
    mailbox_token: token
  }
  let snapshot = DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: identity,
    sequence: U64.parse("3")?,
    devices: [entry],
    revoked_device_ids: []
  }
  assert(case postage_policy_from_device_set(snapshot)? do
    None -> false
    Some(value) -> value.credits == 5 && value.revision == U64.parse("1")?
  end)
  let empty_extension = %{base |
    extensions: [ProtocolExtension { id: 3, mandatory: false, value: Bytes.empty() }]
  }
  assert(Result.is_err(postage_policy_from_device_set(%{snapshot |
    devices: [%{entry | prekey_bundle: bundle_wire(empty_extension)?}]
  })))
  assert(Result.is_err(postage_policy_from_device_set(%{snapshot | sequence: U64.parse("2")?})))
  let forged = bundle_with_postage_policy(base, %{policy | credits: 0})?
  assert(Result.is_err(postage_policy_from_device_set(%{snapshot |
    devices: [%{entry | prekey_bundle: bundle_wire(forged)?}]
  })))
  let no_policy = %{entry | prekey_bundle: bundle_wire(base)?}
  assert(case postage_policy_from_device_set(%{snapshot | devices: [no_policy]})? do
    None -> true
    Some(_) -> false
  end)
  let second = %{no_policy | mailbox_token: Crypto.sha256(token)}
  assert(Result.is_err(postage_policy_from_device_set(%{snapshot | devices: [entry, second]})))
  Ok(true)
end

test("postage policy extension preserves renewal bytes and rejects missing or forged mirrors") do
  case mirrors() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
