from Api.Binary import fetch_request, register_device_request, resolve_devices_request, revoke_device_request, submit_request
from Identity.Device import AccountKeys, DeviceKeys, generate_account, generate_device, issue_device_credential, issue_device_revocation
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, MailboxFetch, OuterEnvelope, ProtocolError, decode_delivery_batch, decode_device_set, encode_account_identity, encode_directory_entry, encode_directory_lookup, encode_mailbox_fetch, encode_outer_envelope, encode_prekey_bundle, encode_device_revocation

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn wide(value :: String) -> U64 ! String do
  U64.parse(value)
end

fn now() -> U64 ! String do
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn account(created_at :: U64) -> Result <( AccountKeys, AccountIdentity), String > do
  case generate_account(created_at, wide("1") ?) do
    Err( _) -> Err("account generation failed")
    Ok( value) -> Ok(value)
  end
end

fn device() -> DeviceKeys ! String do
  case generate_device() do
    Err( _) -> Err("device generation failed")
    Ok( value) -> Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
device_keys :: borrow DeviceKeys,
created_at :: U64,
expires_at :: U64,
sequence :: U64) -> DeviceCredential ! String do
  case issue_device_credential(account_keys,
  device_keys,
  wide("1") ?,
  created_at,
  expires_at,
  sequence) do
    Err( _) -> Err("credential generation failed")
    Ok( value) -> Ok(value)
  end
end

fn protocol(value :: Result < Bytes, ProtocolError >) -> Bytes ! String do
  case value do
    Err( _) -> Err("protocol encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn entry(identity :: AccountIdentity,
device_keys :: borrow DeviceKeys,
device_credential :: DeviceCredential,
mailbox_token :: Bytes,
expires_at :: U64) -> DirectoryEntry ! String do
  let signed = case generate_signed_prekey(device_keys, device_credential, wide("1") ?, expires_at) do
    Err( _) -> Err("signed prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let one_time = case generate_one_time_prekey(wide("2") ?) do
    Err( _) -> Err("one-time prekey generation failed")
    Ok( value) -> Ok(value)
  end ?
  let bundle = case build_prekey_bundle(device_credential, signed, one_time) do
    Err( _) -> Err("bundle generation failed")
    Ok( value) -> Ok(value)
  end ?
  Ok(DirectoryEntry {
    version : 1,
    username : "alice",
    account_identity : protocol(encode_account_identity(identity)) ?,
    prekey_bundle : protocol(encode_prekey_bundle(bundle)) ?,
    mailbox_token : mailbox_token
  })
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = Pool.execute(pool,
  "TRUNCATE messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_directory, messenger_mailboxes RESTART IDENTITY",
  []) ?
  let created_at = now() ?
  let expires_at = U64.add(created_at, wide("31536000000") ?) ?
  let ( account_keys, identity) = account(created_at) ?
  let first_device = device() ?
  let second_device = device() ?
  let first = entry(identity,
  first_device,
  credential(account_keys, first_device, created_at, expires_at, wide("1") ?) ?,
  repeated(31, 32),
  expires_at) ?
  let second = entry(identity,
  second_device,
  credential(account_keys, second_device, created_at, expires_at, wide("2") ?) ?,
  repeated(32, 32),
  expires_at) ?
  assert(register_device_request(pool, protocol(encode_directory_entry(second)) ?).status == 409)
  assert(resolve_devices_request(pool, protocol(encode_directory_lookup("alice")) ?).status == 404)
  assert(register_device_request(pool, protocol(encode_directory_entry(first)) ?).status == 201)
  assert(register_device_request(pool, protocol(encode_directory_entry(second)) ?).status == 201)
  let resolved = resolve_devices_request(pool, protocol(encode_directory_lookup("alice")) ?)
  assert(resolved.status == 200)
  let device_set = case decode_device_set(resolved.body) do
    Err( _) -> Err("invalid device set")
    Ok( value) -> Ok(value)
  end ?
  assert(List.length(device_set.devices) == 2)
  assert(U64.compare(device_set.sequence, wide("2") ?) == 0)
  let queued_delivery = protocol(encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : repeated(33, 16),
    mailbox_token : second.mailbox_token,
    suite : 1,
    expiration : expires_at,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("queued")
  })) ?
  assert(submit_request(pool, queued_delivery).status == 202)
  let revocation = case issue_device_revocation(account_keys, second_device.device_id, wide("3") ?) do
    Err( _) -> Err("revocation signing failed")
    Ok( value) -> Ok(value)
  end ?
  assert(revoke_device_request(pool, protocol(encode_device_revocation(revocation)) ?).status == 200)
  let updated = resolve_devices_request(pool, protocol(encode_directory_lookup("alice")) ?)
  let updated_set = case decode_device_set(updated.body) do
    Err( _) -> Err("invalid updated device set")
    Ok( value) -> Ok(value)
  end ?
  assert(List.length(updated_set.devices) == 1)
  assert(List.length(updated_set.revoked_device_ids) == 1)
  assert(U64.compare(updated_set.sequence, wide("3") ?) == 0)
  assert(register_device_request(pool, protocol(encode_directory_entry(second)) ?).status == 409)
  let revoked_fetch = fetch_request(pool,
  protocol(encode_mailbox_fetch(MailboxFetch {
    version : 1,
    mailbox_token : second.mailbox_token,
    after_sequence : wide("0") ?
  })) ?)
  let revoked_deliveries = case decode_delivery_batch(revoked_fetch.body) do
    Err( _) -> Err("invalid revoked mailbox response")
    Ok( values) -> Ok(values)
  end ?
  assert(List.length(revoked_deliveries) == 0)
  let revoked_delivery = protocol(encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : repeated(34, 16),
    mailbox_token : second.mailbox_token,
    suite : 1,
    expiration : expires_at,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("opaque")
  })) ?
  assert(submit_request(pool, revoked_delivery).status == 410)
  Pool.close(pool)
  Ok(true)
end

test("device registration, resolution, revocation, and mailbox disabling are atomic") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
