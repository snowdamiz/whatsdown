from Api.Binary import claim_prekey_request, publish_prekeys_request, revoke_device_request
from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  generate_account,
  generate_device,
  issue_device_credential,
  issue_device_revocation
)
from Prekeys.Bundle import (
  build_prekey_bundle,
  generate_one_time_prekey,
  generate_signed_prekey,
  verify_prekey_bundle
)
from Prekeys.Pool import (
  OneTimePrekeyPublic,
  PrekeyClaimRequest,
  PrekeyPublishRequest,
  decode_prekey_publish_response,
  encode_prekey_claim,
  encode_prekey_publish,
  prekey_publish_signing_bytes
)
from Protocol.DirectoryWire import encode_device_revocation
from Protocol.IdentityWire import (
  encode_account_identity,
  decode_device_credential,
  encode_device_credential
)
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DirectoryEntry, PrekeyBundle, ProtocolError
from Storage.Devices import DeviceWrite, register_device, resolve_devices
from Storage.Prekeys import publish_prekeys, prune_consumed_prekeys
from Runtime.Workers import next_work_at, run_scheduled

fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test allocation failed")
    Ok(output)
  end
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn now() -> U64!String do
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn protocol(value :: Result<Bytes, ProtocolError>) -> Bytes!String do
  case value do
    Err(_) -> Err("protocol encoding failed")
    Ok(output)
  end
end

fn registration(account :: borrow AccountKeys,
  identity :: AccountIdentity,
  device :: borrow DeviceKeys,
  mailbox_token :: Bytes,
  sequence :: String,
  created_at :: U64,
  expires_at :: U64) -> DirectoryEntry!String do
  let credential = case issue_device_credential(account,
    device,
    wide("1")?,
    created_at,
    expires_at,
    wide(sequence)?) do
    Err(_) -> Err("credential generation failed")
    Ok(output)
  end?
  let signed = case generate_signed_prekey(device, credential, wide("1")?, expires_at) do
    Err(_) -> Err("signed prekey generation failed")
    Ok(output)
  end?
  let one_time = case generate_one_time_prekey(wide("2")?) do
    Err(_) -> Err("one-time prekey generation failed")
    Ok(output)
  end?
  let bundle = case build_prekey_bundle(credential, signed, one_time) do
    Err(_) -> Err("prekey bundle generation failed")
    Ok(output)
  end?
  Ok(DirectoryEntry {
    version: 1,
    username: "prekey-account",
    account_identity: protocol(encode_account_identity(identity))?,
    prekey_bundle: protocol(encode_prekey_bundle(bundle))?,
    mailbox_token: mailbox_token
  })
end

fn sign_publish(key :: borrow SigningPrivateKey,
  request :: PrekeyPublishRequest) -> PrekeyPublishRequest!String do
  let signature = case Crypto.sign(key, prekey_publish_signing_bytes(request)?) do
    Err(_) -> Err("prekey publication signing failed")
    Ok(output)
  end?
  Ok(PrekeyPublishRequest {
    account_id: request.account_id,
    device_id: request.device_id,
    prekeys: request.prekeys,
    last_resort: request.last_resort,
    contact_address_hash: request.contact_address_hash,
    signature: signature.bytes
  })
end

fn unsigned_publish(identity :: AccountIdentity,
  device :: borrow DeviceKeys,
  prekeys :: List<OneTimePrekeyPublic>) -> PrekeyPublishRequest!String do
  Ok(PrekeyPublishRequest {
    account_id: identity.account_id,
    device_id: device.device_id,
    prekeys: prekeys,
    last_resort: None,
    contact_address_hash: None,
    signature: repeated(0, 64)?
  })
end

fn unsigned_claim(identity :: AccountIdentity,
  target :: borrow DeviceKeys,
  base_bundle_hash :: Bytes,
  reservation_id :: Bytes) -> PrekeyClaimRequest do
  PrekeyClaimRequest {
    account_id: identity.account_id,
    device_id: target.device_id,
    base_bundle_hash: base_bundle_hash,
    reservation_id: reservation_id
  }
end

fn find_bundle(entries :: List<DirectoryEntry>,
  mailbox_token :: Bytes,
  index :: Int) -> Bytes!String do
  if index >= List.length(entries) do
    Err("target base bundle missing")
  else
    let entry = List.get(entries, index)
    if Bytes.secure_equals(entry.mailbox_token, mailbox_token) do
      Ok(entry.prekey_bundle)
    else
      find_bundle(entries, mailbox_token, index + 1)
    end
  end
end

fn target_base_bundle(pool :: PoolHandle, mailbox_token :: Bytes) -> Bytes!String do
  case resolve_devices(pool, "prekey-account")? do
    None -> Err("device set missing")
    Some(value) -> find_bundle(value.devices, mailbox_token, 0)
  end
end

fn claim_request(identity :: AccountIdentity,
  target :: borrow DeviceKeys,
  base_bundle :: Bytes,
  reservation_id :: Bytes) -> PrekeyClaimRequest do
  unsigned_claim(identity, target, Crypto.sha256(base_bundle), reservation_id)
end

fn decoded_bundle(input :: Bytes) -> PrekeyBundle!String do
  case decode_prekey_bundle(input) do
    Err(_) -> Err("claimed bundle did not decode")
    Ok(output)
  end
end

fn await_claim_id(job :: Pid<Int>, normal_exits :: Int) -> Int!String do
  case Job.await(job) do
    Ok(output)
    Err(error) -> if error == "normal" && normal_exits < 2 do
      await_claim_id(job, normal_exits + 1)
    else
      Err("concurrent prekey claim failed: #{error}")
    end
  end
end

fn target_key_count(pool :: PoolHandle, account_id :: Bytes, device_id :: Bytes) -> Int!String do
  let rows = Pool.query_values(pool,
    "SELECT count(*)::text AS key_count FROM messenger_one_time_prekeys WHERE account_id = $1 AND device_id = $2",
    [Binary(account_id), Binary(device_id)])?
  if List.length(rows) != 1 do
    Err("prekey count failed")
  else
    case Map.get(List.head(rows), "key_count") do
      Text(value) -> case String.to_int(value) do
        None -> Err("invalid prekey count")
        Some(output) -> Ok(output)
      end
      _ -> Err("invalid prekey count")
    end
  end
end

fn target_consumed_key_count(pool :: PoolHandle,
  account_id :: Bytes,
  device_id :: Bytes) -> Int!String do
  let rows = Pool.query_values(pool,
    "SELECT count(*)::text AS key_count FROM messenger_one_time_prekeys WHERE account_id = $1 AND device_id = $2 AND consumed_at IS NOT NULL",
    [Binary(account_id), Binary(device_id)])?
  if List.length(rows) != 1 do
    Err("consumed prekey count failed")
  else
    case Map.get(List.head(rows), "key_count") do
      Text(value) -> case String.to_int(value) do
        None -> Err("invalid consumed prekey count")
        Some(output) -> Ok(output)
      end
      _ -> Err("invalid consumed prekey count")
    end
  end
end

fn last_resort(id :: String, fill :: Int) -> Option<OneTimePrekeyPublic>!String do
  Ok(Some(OneTimePrekeyPublic { id: wide(id)?, public_key: repeated(fill, 32)? }))
end

fn publish_status(pool :: PoolHandle,
  identity :: AccountIdentity,
  device :: borrow DeviceKeys,
  prekeys :: List<OneTimePrekeyPublic>,
  reusable :: Option<OneTimePrekeyPublic>) -> Int!String do
  let unsigned = unsigned_publish(identity, device, prekeys)?
  let signed = sign_publish(device.signing_private_key, %{unsigned | last_resort: reusable})?
  Ok(publish_prekeys_request(pool, encode_prekey_publish(signed)?).status)
end

fn cleanup_for_probe(pool :: PoolHandle) -> Int!String do
  prune_consumed_prekeys(pool, 128)
end

fn reset_retention_probe(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE messenger_retired_prekeys, credit_postage_policies, credit_issuer_announcements, transparency_entry_devices, transparency_device_records, transparency_anchors, transparency_maintenance, messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  Pool.execute(pool,
    "UPDATE messenger_prekey_retention_clock SET expired_before_ms = 0 WHERE singleton",
    [])?
  Pool.execute(pool, "UPDATE credit_issuer_cursor SET checkpoint = ''::bytea WHERE singleton", [])?
  Ok(nil)
end

fn retention_probe(mode :: Int) -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 4, 5000)?
  reset_retention_probe(pool)?
  let created = now()?
  let expiry = U64.add(created,
    wide(if mode == 2 do
      "3000"
    else
      "31536000000"
    end)?)?
  let (account, identity) = case generate_account(created, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(output)
  end?
  let device = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(output)
  end?
  let entry = registration(account, identity, device, repeated(21, 32)?, "1", created, expiry)?
  let original_key = decoded_bundle(entry.prekey_bundle)?
  case register_device(pool, entry)? do
    DeviceAccepted -> Ok(nil)
    _ -> Err("retention registration failed")
  end?
  let base = target_base_bundle(pool, repeated(21, 32)?)?
  let request = claim_request(identity, device, base, repeated(44, 16)?)
  let wire = encode_prekey_claim(request)?
  let first = claim_prekey_request(pool, wire)
  assert(first.status == 200)
  let initial = decoded_bundle(first.body)?
  assert(U64.compare(initial.one_time_prekey_id, wide("2")?) == 0)
  let newer = sign_publish(device.signing_private_key,
    unsigned_publish(identity,
      device,
      [OneTimePrekeyPublic { id: wide("100")?, public_key: repeated(45, 32)? }])?)?
  assert(publish_prekeys_request(pool, encode_prekey_publish(newer)?).status == 201)
  if mode == 2 do
    let remaining = U64.to_int(expiry)? - DateTime.to_unix_ms(DateTime.utc_now())
    if remaining >= 0 do
      Timer.sleep(remaining + 20)
    end
    let late = claim_prekey_request(pool,
      encode_prekey_claim(%{request | reservation_id: repeated(46, 16)?})?)
    # An expired base must not allocate a fresh one-time key.
    assert(late.status == 404)
    assert(target_consumed_key_count(pool, identity.account_id, device.device_id)? == 1)
  else
    Pool.execute(pool,
      "UPDATE messenger_one_time_prekeys SET consumed_at = clock_timestamp() - interval '2 years' WHERE consumed_at IS NOT NULL",
      [])?
    cleanup_for_probe(pool)?
    if mode == 0 do
      let replay = claim_prekey_request(pool, wire)
      assert(replay.status == 200)
      # Existing signed bundle remains usable, regardless of consumed_at age.
      assert(Bytes.secure_equals(replay.body, first.body))
      assert(target_consumed_key_count(pool, identity.account_id, device.device_id)? == 1)
    else
      let stale_publication = sign_publish(device.signing_private_key,
        unsigned_publish(identity,
          device,
          [
            OneTimePrekeyPublic {
              id: original_key.one_time_prekey_id,
              public_key: original_key.one_time_prekey
            }
          ])?)?
      let answer = publish_prekeys_request(pool, encode_prekey_publish(stale_publication)?)
      assert(answer.status == 200)
      let active = decode_prekey_publish_response(answer.body)?.active_ids
      assert(List.length(active) == 1)
      assert(U64.compare(List.head(active), wide("100")?) == 0)
    end
  end
  Pool.close(pool)
  Ok(true)
end

fn signed_horizon_probe() -> Bool!String do
  let created = now()?
  let early = U64.add(created, wide("300000")?)?
  let late = U64.add(created, wide("600000")?)?
  let (account, identity) = case generate_account(created, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(output)
  end?
  let device = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(output)
  end?
  for credential_expiry in [early, late] do
    let signed_expiry = if U64.compare(credential_expiry, early) == 0 do
      late
    else
      early
    end
    let credential = case issue_device_credential(account,
      device,
      wide("1")?,
      created,
      credential_expiry,
      wide("1")?) do
      Err(_) -> Err("credential generation failed")
      Ok(output)
    end?
    let signed = case generate_signed_prekey(device, credential, wide("1")?, signed_expiry) do
      Err(_) -> Err("signed prekey generation failed")
      Ok(output)
    end?
    let once = case generate_one_time_prekey(wide("2")?) do
      Err(_) -> Err("one-time key generation failed")
      Ok(output)
    end?
    let bundle = case build_prekey_bundle(credential, signed, once) do
      Err(_) -> Err("bundle generation failed")
      Ok(output)
    end?
    assert(case verify_prekey_bundle(identity, bundle, 1, early, wide("1")?) do
      Err(_) -> false
      Ok(value) -> value
    end)
    assert(case verify_prekey_bundle(identity,
      bundle,
      1,
      U64.add(early, wide("1")?)?,
      wide("1")?) do
      Err(_) -> true
      Ok(value) -> !value
    end)
  end
  Ok(true)
end

fn sql_count(pool :: PoolHandle, query :: String) -> Int!String do
  let rows = Pool.query(pool, query, [])?
  case String.to_int(Map.get(List.head(rows), "n")) do
    None -> Err("invalid count")
    Some(value) -> Ok(value)
  end
end

fn expire_wait(expiry :: U64) -> Result<(), String> do
  let remaining = U64.to_int(expiry)? - DateTime.to_unix_ms(DateTime.utc_now())
  if remaining >= 0 do
    Timer.sleep(remaining + 20)
  end
  Ok(nil)
end

fn retired_compatibility_probe() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 4, 5000)?
  reset_retention_probe(pool)?
  let created = now()?
  let expiry = U64.add(created, wide("3000")?)?
  let (account, identity) = case generate_account(created, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end?
  let device = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end?
  let entry = registration(account, identity, device, repeated(25, 32)?, "1", created, expiry)?
  let original_key = decoded_bundle(entry.prekey_bundle)?
  assert(case register_device(pool, entry)? do
    DeviceAccepted -> true
    _ -> false
  end)
  let base = target_base_bundle(pool, repeated(25, 32)?)?
  let request = claim_request(identity, device, base, repeated(48, 16)?)
  let first = claim_prekey_request(pool, encode_prekey_claim(request)?)
  assert(first.status == 200)
  # Simulate a pre-030 exact-response row and a too-small cached deadline.
  Pool.execute(pool,
    "UPDATE messenger_one_time_prekeys SET claim_retry_until_ms = NULL, claim_retention_checked = false WHERE consumed_at IS NOT NULL",
    [])?
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM messenger_one_time_prekeys WHERE consumed_at IS NOT NULL AND claim_retention_checked AND claim_retry_until_ms IS NOT NULL")? == 1)
  Pool.execute(pool,
    "UPDATE messenger_one_time_prekeys SET claim_retry_until_ms = 0 WHERE consumed_at IS NOT NULL",
    [])?
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(Bytes.secure_equals(claim_prekey_request(pool, encode_prekey_claim(request)?).body,
    first.body))
  # A saved migration009 base marker is also verified/promoted without losing
  # the exact claimed one-time slot.
  Pool.execute_values(pool,
    "UPDATE messenger_one_time_prekeys SET claim_response = $1, claim_retry_until_ms = NULL, claim_retention_checked = false WHERE consumed_at IS NOT NULL",
    [Binary(base)])?
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(Bytes.secure_equals(claim_prekey_request(pool, encode_prekey_claim(request)?).body,
    first.body))
  expire_wait(expiry)?
  assert(prune_consumed_prekeys(pool, 128)? == 1)
  let floor_rows = Pool.query(pool,
    "SELECT expired_before_ms::text AS value FROM messenger_prekey_retention_clock WHERE singleton",
    [])?
  assert(Map.get(List.head(floor_rows), "value") == U64.to_string(U64.add(expiry, wide("1")?)?))
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(target_consumed_key_count(pool, identity.account_id, device.device_id)? == 0)
  assert(sql_count(pool, "SELECT count(*)::text AS n FROM messenger_retired_prekeys")? == 1)
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM information_schema.columns WHERE table_name = 'messenger_retired_prekeys' AND column_name IN ('consumed_at', 'created_at', 'claim_id_hash', 'claim_base_bundle_hash', 'claim_response', 'claim_retry_until_ms')")? == 0)
  assert(claim_prekey_request(pool, encode_prekey_claim(request)?).status == 404)
  assert(claim_prekey_request(pool,
    encode_prekey_claim(%{request | reservation_id: repeated(49, 16)?})?).status == 404)
  let old = sign_publish(device.signing_private_key,
    unsigned_publish(identity,
      device,
      [
        OneTimePrekeyPublic {
          id: original_key.one_time_prekey_id,
          public_key: original_key.one_time_prekey
        }
      ])?)?
  let exact = publish_prekeys_request(pool, encode_prekey_publish(old)?)
  assert(exact.status == 200)
  assert(List.length(decode_prekey_publish_response(exact.body)?.active_ids) == 0)
  let changed = sign_publish(device.signing_private_key,
    unsigned_publish(identity,
      device,
      [
        OneTimePrekeyPublic { id: original_key.one_time_prekey_id, public_key: repeated(91, 32)? }
      ])?)?
  assert(publish_prekeys_request(pool, encode_prekey_publish(changed)?).status == 409)
  # No max-ID floor: unrelated lower holes remain publishable.
  assert(publish_status(pool,
    identity,
    device,
    [OneTimePrekeyPublic { id: wide("1")?, public_key: repeated(92, 32)? }],
    None)? == 201)
  Pool.close(pool)
  Ok(true)
end

fn malformed_and_bounded_probe() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 4, 5000)?
  reset_retention_probe(pool)?
  let created = now()?
  let expiry = U64.add(created, wide("31536000000")?)?
  let (account, identity) = case generate_account(created, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end?
  let device = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end?
  assert(case register_device(pool,
    registration(account, identity, device, repeated(27, 32)?, "1", created, expiry)?)? do
    DeviceAccepted -> true
    _ -> false
  end)
  let base = target_base_bundle(pool, repeated(27, 32)?)?
  let request = claim_request(identity, device, base, repeated(50, 16)?)
  let original = claim_prekey_request(pool, encode_prekey_claim(request)?)
  assert(original.status == 200)
  Pool.execute_values(pool,
    "UPDATE messenger_one_time_prekeys SET claim_response = $1, claim_retry_until_ms = NULL, claim_retention_checked = false WHERE consumed_at IS NOT NULL",
    [Binary(Bytes.from_utf8("malformed historical response"))])?
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM messenger_one_time_prekeys WHERE consumed_at IS NOT NULL AND claim_retention_checked AND claim_retry_until_ms IS NULL")? == 1)
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(claim_prekey_request(pool, encode_prekey_claim(request)?).status == 500)
  let saved = decoded_bundle(original.body)?
  let credential = case decode_device_credential(saved.device_credential) do
    Err(_) -> Err("fixture credential decode failed")
    Ok(value)
  end?
  let bad_credential = case encode_device_credential(%{credential | signature: repeated(0, 64)?}) do
    Err(_) -> Err("fixture credential encode failed")
    Ok(value)
  end?
  let invalid = %{saved | device_credential: bad_credential}
  let invalid_wire = case encode_prekey_bundle(invalid) do
    Err(_) -> Err("fixture bundle encode failed")
    Ok(value)
  end?
  let invalid_base = case encode_prekey_bundle(%{invalid |
    one_time_prekey_id: wide("0")?,
    one_time_prekey: Bytes.empty()
  }) do
    Err(_) -> Err("fixture base encode failed")
    Ok(value)
  end?
  # Canonical and self-consistent bytes with a forged credential signature are
  # still not a verified expiry authority and must never authorize cleanup.
  Pool.execute_values(pool,
    "UPDATE messenger_one_time_prekeys SET claim_response = $1, claim_base_bundle_hash = $2, claim_retry_until_ms = NULL, claim_retention_checked = false WHERE consumed_at IS NOT NULL",
    [Binary(invalid_wire), Binary(Crypto.sha256(invalid_base))])?
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM messenger_one_time_prekeys WHERE consumed_at IS NOT NULL AND claim_retention_checked AND claim_retry_until_ms IS NULL")? == 1)
  # Genuine legacy schema shape: consumed before reservation hashes existed.
  # These fixture-only rows contain no replay material to retain.
  Pool.execute_values(pool,
    "INSERT INTO messenger_one_time_prekeys (account_id, device_id, prekey_id, public_key, consumed_at) SELECT $1, $2, id, $3, clock_timestamp() FROM generate_series(500, 628) AS id",
    [Binary(identity.account_id), Binary(device.device_id), Binary(repeated(93, 32)?)])?
  assert(prune_consumed_prekeys(pool, 128)? == 128)
  assert(prune_consumed_prekeys(pool, 128)? == 1)
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(sql_count(pool, "SELECT count(*)::text AS n FROM messenger_retired_prekeys")? == 129)
  assert(target_consumed_key_count(pool, identity.account_id, device.device_id)? == 1)
  assert(case prune_consumed_prekeys(pool, 0) do
    Err(_) -> true
    _ -> false
  end)
  assert(case prune_consumed_prekeys(pool, 129) do
    Err(_) -> true
    _ -> false
  end)
  Pool.close(pool)
  Ok(true)
end

fn last_resort_retention_probe() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 4, 5000)?
  reset_retention_probe(pool)?
  let created = now()?
  let expiry = U64.add(created, wide("31536000000")?)?
  let (account, identity) = case generate_account(created, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end?
  let device = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end?
  assert(case register_device(pool,
    registration(account, identity, device, repeated(29, 32)?, "1", created, expiry)?)? do
    DeviceAccepted -> true
    _ -> false
  end)
  assert(publish_status(pool, identity, device, [], last_resort("9", 90)?)? == 201)
  assert(publish_status(pool, identity, device, [], last_resort("12", 120)?)? == 201)
  assert(prune_consumed_prekeys(pool, 128)? == 1)
  assert(publish_status(pool, identity, device, [], last_resort("9", 90)?)? == 200)
  assert(publish_status(pool, identity, device, [], last_resort("9", 91)?)? == 409)
  assert(publish_status(pool, identity, device, [], last_resort("11", 110)?)? == 409)
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM messenger_one_time_prekeys WHERE last_resort AND consumed_at IS NULL AND prekey_id = 12")? == 1)
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM messenger_retired_prekeys WHERE last_resort AND prekey_id = 9")? == 1)
  # Physical deletion is an FK cascade, not just an application cleanup promise.
  Pool.execute_values(pool,
    "DELETE FROM messenger_devices WHERE account_id = $1 AND device_id = $2",
    [Binary(identity.account_id), Binary(device.device_id)])?
  assert(sql_count(pool, "SELECT count(*)::text AS n FROM messenger_retired_prekeys")? == 0)
  Pool.close(pool)
  Ok(true)
end

fn wait_prekey_pause(pool :: PoolHandle,
  query_part :: String,
  attempts :: Int) -> Result<(), String> do
  let rows = Pool.query_values(pool,
    "SELECT count(*)::text AS n FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND wait_event = 'PgSleep' AND position($1 in query) > 0",
    [Text(query_part)])?
  let count = case Map.get(List.head(rows), "n") do
    Text(value) -> value
    _ -> "0"
  end
  if count != "0" do
    Ok(nil)
  else if attempts >= 100 do
    Err("prekey concurrency barrier not reached")
  else
    Timer.sleep(5)
    wait_prekey_pause(pool, query_part, attempts + 1)
  end
end

fn concurrent_cleanup(pool :: PoolHandle) -> Int do
  case prune_consumed_prekeys(pool, 128) do
    Err(_) -> -1
    Ok(value) -> value
  end
end

fn pause_retirement(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "CREATE OR REPLACE FUNCTION mesh_test_pause_retirement() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER mesh_test_pause_retirement BEFORE INSERT ON messenger_retired_prekeys FOR EACH ROW EXECUTE FUNCTION mesh_test_pause_retirement()",
    [])?
  Ok(nil)
end

fn concurrent_retention_probe() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 6, 5000)?
  reset_retention_probe(pool)?
  let created = now()?
  let expiry = U64.add(created, wide("31536000000")?)?
  let (account, identity) = case generate_account(created, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end?
  let primary = case generate_device() do
    Err(_) -> Err("primary generation failed")
    Ok(value)
  end?
  let target = case generate_device() do
    Err(_) -> Err("target generation failed")
    Ok(value)
  end?
  assert(case register_device(pool,
    registration(account, identity, primary, repeated(30, 32)?, "1", created, expiry)?)? do
    DeviceAccepted -> true
    _ -> false
  end)
  assert(case register_device(pool,
    registration(account, identity, target, repeated(31, 32)?, "2", created, expiry)?)? do
    DeviceAccepted -> true
    _ -> false
  end)
  let base = target_base_bundle(pool, repeated(31, 32)?)?
  assert(publish_status(pool, identity, target, [], last_resort("9", 90)?)? == 201)
  assert(publish_status(pool, identity, target, [], last_resort("12", 120)?)? == 201)
  Pool.execute(pool,
    "CREATE FUNCTION mesh_test_pause_retention_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.4); RETURN NEW; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER mesh_test_pause_retention_claim BEFORE UPDATE OF claim_id_hash ON messenger_one_time_prekeys FOR EACH ROW WHEN (OLD.claim_id_hash IS NULL AND NEW.claim_id_hash IS NOT NULL) EXECUTE FUNCTION mesh_test_pause_retention_claim()",
    [])?
  let claim = encode_prekey_claim(claim_request(identity, target, base, repeated(54, 16)?))?
  let job = Job.async(fn() -> claim_prekey_request(pool, claim).status end)
  wait_prekey_pause(pool, "UPDATE messenger_one_time_prekeys SET consumed_at", 0)?
  # The device share lock held by claim makes cleanup skip, never delete its
  # replay state or wait on an inverted row-lock order.
  assert(prune_consumed_prekeys(pool, 128)? == 0)
  assert(await_claim_id(job, 0)? == 200)
  Pool.execute(pool,
    "DROP TRIGGER mesh_test_pause_retention_claim ON messenger_one_time_prekeys",
    [])?
  Pool.execute(pool, "DROP FUNCTION mesh_test_pause_retention_claim()", [])?
  assert(prune_consumed_prekeys(pool, 128)? == 1)
  let exact = claim_prekey_request(pool, claim)
  assert(exact.status == 200)
  assert(Bytes.secure_equals(claim_prekey_request(pool, claim).body, exact.body))
  # Publication waits for the exclusive cleanup lock, then consults the retired
  # record rather than reinserting the old ID.
  assert(publish_status(pool, identity, target, [], last_resort("15", 150)?)? == 201)
  pause_retirement(pool)?
  let cleanup = Job.async(fn() -> concurrent_cleanup(pool) end)
  wait_prekey_pause(pool, "INSERT INTO messenger_retired_prekeys", 0)?
  let publication = sign_publish(target.signing_private_key,
    %{unsigned_publish(identity, target, [])? | last_resort: last_resort("12", 120)?})?
  let publication_bytes = encode_prekey_publish(publication)?
  let published = Job.async(fn() -> publish_prekeys_request(pool, publication_bytes).status end)
  assert(await_claim_id(cleanup, 0)? == 1)
  assert(await_claim_id(published, 0)? == 200)
  Pool.execute(pool, "DROP TRIGGER mesh_test_pause_retirement ON messenger_retired_prekeys", [])?
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM messenger_one_time_prekeys WHERE last_resort AND consumed_at IS NULL AND prekey_id = 15")? == 1)
  # Revocation serializes after cleanup and removes BOTH tables atomically.
  assert(publish_status(pool, identity, target, [], last_resort("18", 180)?)? == 201)
  pause_retirement(pool)?
  let cleanup = Job.async(fn() -> concurrent_cleanup(pool) end)
  wait_prekey_pause(pool, "INSERT INTO messenger_retired_prekeys", 0)?
  let revocation = case issue_device_revocation(account, target.device_id, wide("3")?) do
    Err(_) -> Err("revocation signing failed")
    Ok(value)
  end?
  let revoked_bytes = protocol(encode_device_revocation(revocation))?
  let revoked = Job.async(fn() -> revoke_device_request(pool, revoked_bytes).status end)
  assert(await_claim_id(cleanup, 0)? == 1)
  assert(await_claim_id(revoked, 0)? == 200)
  Pool.execute(pool, "DROP TRIGGER mesh_test_pause_retirement ON messenger_retired_prekeys", [])?
  Pool.execute(pool, "DROP FUNCTION mesh_test_pause_retirement()", [])?
  assert(sql_count(pool, "SELECT count(*)::text AS n FROM messenger_retired_prekeys")? == 0)
  assert(target_key_count(pool, identity.account_id, target.device_id)? == 0)
  assert(claim_prekey_request(pool, claim).status == 404)
  assert(publish_prekeys_request(pool, publication_bytes).status == 403)
  Pool.close(pool)
  Ok(true)
end

test("wall-age cleanup cannot change a still-usable reservation replay") do
  case retention_probe(0) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("wall-age cleanup cannot reactivate an identical old signed publication") do
  case retention_probe(1) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("expired signed base cannot allocate a new claim") do
  case retention_probe(2) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("actual PKB verification accepts inclusive min expiry and rejects its successor") do
  case signed_horizon_probe() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("signed expiry retirement preserves legacy exact replay and OTB key equality") do
  case retired_compatibility_probe() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("malformed history stays unpruned and each cleanup handles at most 128 rows") do
  case malformed_and_bounded_probe() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("retired reusable IDs retain exact equality and ordering until FK removal") do
  case last_resort_retention_probe() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("claim publication cleanup and revocation use the same device lock order") do
  case concurrent_retention_probe() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn clock_boundary_probe(maximum :: Bool) -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 4, 5000)?
  reset_retention_probe(pool)?
  let created = now()?
  let expiry = if maximum do
    wide("18446744073709551615")?
  else
    U64.add(created, wide("600000")?)?
  end
  let (account, identity) = case generate_account(created, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end?
  let device = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end?
  assert(case register_device(pool,
    registration(account, identity, device, repeated(33, 32)?, "1", created, expiry)?)? do
    DeviceAccepted -> true
    _ -> false
  end)
  let base = target_base_bundle(pool, repeated(33, 32)?)?
  let claim = encode_prekey_claim(claim_request(identity, device, base, repeated(58, 16)?))?
  assert(claim_prekey_request(pool, claim).status == 200)
  if maximum do
    assert(prune_consumed_prekeys(pool, 128)? == 0)
    let before = DateTime.to_unix_ms(DateTime.utc_now())
    let due = next_work_at(pool)?
    assert(due >= before && due <= DateTime.to_unix_ms(DateTime.utc_now()) + 3600000)
    let rows = Pool.query(pool,
      "SELECT claim_retry_until_ms::text AS value FROM messenger_one_time_prekeys WHERE consumed_at IS NOT NULL",
      [])?
    assert(Map.get(List.head(rows), "value") == "18446744073709551615")
  else
    let floor = U64.add(expiry, wide("1")?)?
    # Simulate a persisted earlier retirement floor with the OS/DB wall clock
    # now behind it; no system clock is changed by this fixture.
    Pool.execute_values(pool,
      "UPDATE messenger_prekey_retention_clock SET expired_before_ms = $1::numeric WHERE singleton",
      [Text(U64.to_string(floor))])?
    assert(claim_prekey_request(pool, claim).status == 404)
    assert(next_work_at(pool)? <= DateTime.to_unix_ms(DateTime.utc_now()))
    assert(prune_consumed_prekeys(pool, 128)? == 1)
    Pool.close(pool)
    let reopened = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 4, 5000)?
    assert(claim_prekey_request(reopened, claim).status == 404)
    assert(claim_prekey_request(reopened,
      encode_prekey_claim(claim_request(identity, device, base, repeated(59, 16)?))?).status == 404)
    let rows = Pool.query(reopened,
      "SELECT expired_before_ms::text AS value FROM messenger_prekey_retention_clock WHERE singleton",
      [])?
    assert(Map.get(List.head(rows), "value") == U64.to_string(floor))
    assert(sql_count(reopened, "SELECT count(*)::text AS n FROM messenger_retired_prekeys")? == 1)
    # An older uncorrelated tombstone cannot lower the global floor.
    assert(publish_status(reopened, identity, device, [], last_resort("9", 90)?)? == 201)
    assert(publish_status(reopened, identity, device, [], last_resort("12", 120)?)? == 201)
    assert(prune_consumed_prekeys(reopened, 128)? == 1)
    let later = Pool.query(reopened,
      "SELECT expired_before_ms::text AS value FROM messenger_prekey_retention_clock WHERE singleton",
      [])?
    assert(Map.get(List.head(later), "value") == U64.to_string(floor))
    # Test-only reset after removing its entire device namespace; real code
    # never decreases the persisted floor.
    reset_retention_probe(reopened)?
    Pool.close(reopened)
    return Ok(true)
  end
  Pool.close(pool)
  Ok(true)
end

test("retired signed horizon survives clock rollback and restart without resurrection") do
  case clock_boundary_probe(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("maximum U64 expiry stays unpruned and produces a bounded scheduler deadline") do
  case clock_boundary_probe(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn fill_publication_range(first :: Int,
  count :: Int,
  offset :: Int,
  output :: List<OneTimePrekeyPublic>) -> List<OneTimePrekeyPublic>!String do
  if offset >= count do
    Ok(output)
  else
    fill_publication_range(first,
      count,
      offset + 1,
      List.append(output,
        OneTimePrekeyPublic {
          id: wide(Int.to_string(first + offset))?,
          public_key: repeated(80 + offset, 32)?
        }))
  end
end

fn mixed_publication_probe(near_capacity :: Bool) -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 4, 5000)?
  reset_retention_probe(pool)?
  let created = now()?
  let expiry = U64.add(created, wide("31536000000")?)?
  let (account, identity) = case generate_account(created, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end?
  let device = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end?
  let entry = registration(account, identity, device, repeated(35, 32)?, "1", created, expiry)?
  let once = decoded_bundle(entry.prekey_bundle)?
  assert(case register_device(pool, entry)? do
    DeviceAccepted -> true
    _ -> false
  end)
  let base = target_base_bundle(pool, repeated(35, 32)?)?
  let claim = claim_request(identity, device, base, repeated(60, 16)?)
  assert(claim_prekey_request(pool, encode_prekey_claim(claim)?).status == 200)
  # Convert the genuinely published+consumed row to the exact pre008 shape;
  # this historical shape has no claim-response retry material to keep.
  Pool.execute(pool,
    "UPDATE messenger_one_time_prekeys SET claim_id_hash = NULL, claim_base_bundle_hash = NULL, claim_response = NULL, claim_retry_until_ms = NULL, claim_retention_checked = false WHERE consumed_at IS NOT NULL",
    [])?
  assert(prune_consumed_prekeys(pool, 128)? == 1)
  let existing = if near_capacity do
    63
  else
    0
  end
  if existing > 0 do
    assert(publish_status(pool,
      identity,
      device,
      fill_publication_range(100, existing, 0, [])?,
      None)? == 201)
  end
  let fresh_id = wide(Int.to_string(100 + existing))?
  let mixed = sign_publish(device.signing_private_key,
    unsigned_publish(identity,
      device,
      [
        OneTimePrekeyPublic { id: once.one_time_prekey_id, public_key: once.one_time_prekey },
        OneTimePrekeyPublic { id: fresh_id, public_key: repeated(190, 32)? }
      ])?)?
  let response = publish_prekeys_request(pool, encode_prekey_publish(mixed)?)
  assert(response.status == 201)
  let active = decode_prekey_publish_response(response.body)?.active_ids
  assert(List.length(active) == existing + 1)
  assert(U64.compare(List.head(active), wide("100")?) == 0)
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM messenger_one_time_prekeys WHERE prekey_id = 2")? == 0)
  assert(sql_count(pool,
    "SELECT count(*)::text AS n FROM messenger_retired_prekeys WHERE prekey_id = 2")? == 1)
  assert(publish_prekeys_request(pool, encode_prekey_publish(mixed)?).status == 200)
  let next = claim_prekey_request(pool,
    encode_prekey_claim(%{claim | reservation_id: repeated(61, 16)?})?)
  assert(next.status == 200)
  assert(U64.compare(decoded_bundle(next.body)?.one_time_prekey_id, wide("100")?) == 0)
  Pool.close(pool)
  Ok(true)
end

test("mixed retired and fresh OTB inserts only fresh IDs and never reclaims the retired key") do
  case mixed_publication_probe(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("mixed retired and fresh OTB preserves the 64-active capacity boundary") do
  case mixed_publication_probe(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
