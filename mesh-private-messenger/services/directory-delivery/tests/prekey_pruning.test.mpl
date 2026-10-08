from Api.Binary import claim_prekey_request, publish_prekeys_request
from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  generate_account,
  generate_device,
  issue_device_credential
)
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Prekeys.Pool import (
  OneTimePrekeyPublic,
  PrekeyClaimRequest,
  PrekeyPublishRequest,
  decode_prekey_publish_response,
  encode_prekey_claim,
  encode_prekey_publish,
  prekey_publish_signing_bytes
)
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DirectoryEntry, ProtocolError
from Runtime.Workers import next_work_at, run_scheduled
from Storage.Devices import DeviceWrite, register_device, resolve_devices
from Storage.PrekeyPruning import prekeys_pruning_due

# A consumed one-time prekey keeps its claim for a day, so a retried claim still
# gets its exact answer; then the scheduled job deletes the row and its claim
# hashes, and nothing can bring the key back.

fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test allocation failed")
    Ok(output)
  end
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn protocol(value :: Result<Bytes, ProtocolError>) -> Bytes!String do
  case value do
    Err(_) -> Err("protocol encoding failed")
    Ok(output)
  end
end

fn check(value :: Bool, message :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(message)
  end
end

fn scalar(pool :: PoolHandle, sql :: String) -> String!String do
  case Pool.query_values(pool, sql, [])? do
    [row] -> case Map.get(row, "value") do
      Text(value) -> Ok(value)
      _ -> Err("scalar was not text")
    end
    _ -> Err("scalar query returned no single row")
  end
end

fn entry(account :: borrow AccountKeys,
  identity :: AccountIdentity,
  device :: borrow DeviceKeys,
  now :: U64) -> DirectoryEntry!String do
  let expires_at = U64.add(now, wide("31536000000")?)?
  let credential = case issue_device_credential(account,
    device,
    wide("1")?,
    now,
    expires_at,
    wide("1")?) do
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
    username: "pruned-account",
    account_identity: protocol(encode_account_identity(identity))?,
    prekey_bundle: protocol(encode_prekey_bundle(bundle))?,
    mailbox_token: repeated(33, 32)?
  })
end

fn publication(identity :: AccountIdentity, device :: borrow DeviceKeys) -> Bytes!String do
  let unsigned = PrekeyPublishRequest {
    account_id: identity.account_id,
    device_id: device.device_id,
    prekeys: [
      OneTimePrekeyPublic { id: wide("100")?, public_key: repeated(41, 32)? },
      OneTimePrekeyPublic { id: wide("101")?, public_key: repeated(42, 32)? }
    ],
    last_resort: None,
    contact_address_hash: None,
    signature: repeated(0, 64)?
  }
  let signature = case Crypto.sign(device.signing_private_key,
    prekey_publish_signing_bytes(unsigned)?) do
    Err(_) -> Err("prekey publication signing failed")
    Ok(output)
  end?
  encode_prekey_publish(%{unsigned | signature: signature.bytes})
end

fn claimed_id(body :: Bytes) -> String!String do
  case decode_prekey_bundle(body) do
    Err(_) -> Err("claimed bundle did not decode")
    Ok(bundle) -> Ok(U64.to_string(bundle.one_time_prekey_id))
  end
end

fn active_ids(body :: Bytes) -> String!String do
  let response = decode_prekey_publish_response(body)?
  Ok(String.join(List.map(response.active_ids, fn(id) -> U64.to_string(id) end), ","))
end

fn claim(pool :: PoolHandle, request :: PrekeyClaimRequest, reservation :: Int) -> Bytes!String do
  let response = claim_prekey_request(pool,
    encode_prekey_claim(%{request | reservation_id: repeated(reservation, 16)?})?)
  check(response.status == 200, "claim #{reservation} answered #{response.status}")?
  Ok(response.body)
end

fn consumed(pool :: PoolHandle) -> String!String do
  scalar(pool,
    "SELECT concat(count(*) FILTER (WHERE consumed_at IS NOT NULL), ':', count(*) FILTER (WHERE claim_id_hash IS NOT NULL), ':', count(*)) AS value FROM messenger_one_time_prekeys WHERE NOT last_resort")
end

fn proof() -> Result<(), String> do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 2, 5000)?
  Pool.execute(pool,
    "TRUNCATE messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  let now = wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?
  let (account, identity) = case generate_account(now, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(output)
  end?
  let device = case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(output)
  end?
  case register_device(pool, entry(account, identity, device, now)?)? do
    DeviceAccepted -> Ok(nil)
    _ -> Err("registration failed")
  end?
  let published = publication(identity, device)?
  check(publish_prekeys_request(pool, published).status == 201, "publication failed")?
  let base = case resolve_devices(pool, "pruned-account")? do
    Some(set) -> Ok(List.head(set.devices).prekey_bundle)
    None -> Err("device set missing")
  end?
  let request = PrekeyClaimRequest {
    account_id: identity.account_id,
    device_id: device.device_id,
    base_bundle_hash: Crypto.sha256(base),
    reservation_id: repeated(0, 16)?
  }
  check(claimed_id(claim(pool, request, 1)?)? == "2", "first claim did not take key 2")?
  let answer = claim(pool, request, 2)?
  check(claimed_id(answer)? == "100", "second claim did not take key 100")?
  let due = prekeys_pruning_due(pool)?
  let later = DateTime.to_unix_ms(DateTime.utc_now()) + 86400000
  check(due > later - 60000 && due <= later, "pruning is not due a day after the claims")?
  check(next_work_at(pool)? <= due, "the scheduler would sleep past the pruning")?
  # Inside the window the scheduled job keeps both claims, so a retried claim
  # still gets its exact answer.
  run_scheduled(pool)?
  check(consumed(pool)? == "2:2:3", "a claim inside its retry window was deleted")?
  check(Bytes.secure_equals(claim(pool, request, 2)?, answer),
    "a retried claim lost its exact answer")?
  Pool.execute(pool,
    "UPDATE messenger_one_time_prekeys SET consumed_at = consumed_at - interval '25 hours' WHERE consumed_at IS NOT NULL",
    [])?
  run_scheduled(pool)?
  check(consumed(pool)? == "0:0:1", "consumed prekeys outlived their retry window")?
  check(prekeys_pruning_due(pool)? == 0, "pruning still due with nothing consumed")?
  # Replaying the publication that named key 100 cannot bring it back.
  let replayed = publish_prekeys_request(pool, published)
  check(replayed.status == 200 && active_ids(replayed.body)? == "101",
    "a replayed publication brought a deleted key back")?
  check(consumed(pool)? == "0:0:1", "a replayed publication stored a deleted key")?
  # After the window a retried reservation is a new claim.
  check(claimed_id(claim(pool, request, 2)?)? == "101", "a late retry was not a new claim")?
  Pool.close(pool)
  Ok(nil)
end

test("consumed one-time prekeys are deleted after the claim retry window") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
