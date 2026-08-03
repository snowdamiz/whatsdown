from Api.Binary import claim_prekey_request, publish_prekeys_request, revoke_device_request
from Identity.Device import AccountKeys, DeviceKeys, generate_account, generate_device, issue_device_credential, issue_device_revocation
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Prekeys.Pool import OneTimePrekeyPublic, PrekeyClaimRequest, PrekeyPublishRequest, encode_prekey_claim, encode_prekey_publish, prekey_publish_signing_bytes
from Protocol.V1 import AccountIdentity, DirectoryEntry, PrekeyBundle, ProtocolError, decode_prekey_bundle, encode_account_identity, encode_device_revocation, encode_directory_entry, encode_prekey_bundle
from Storage.Devices import DeviceWrite, register_device, resolve_devices

fn repeated(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn append_bytes(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn wide(value :: String) -> U64 ! String do
  U64.parse(value)
end

fn now() -> U64 ! String do
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn protocol(value :: Result < Bytes, ProtocolError >) -> Bytes ! String do
  case value do
    Err( _) -> Err("protocol encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn registration(account :: borrow AccountKeys,
identity :: AccountIdentity,
device :: borrow DeviceKeys,
mailbox_token :: Bytes,
sequence :: String,
created_at :: U64,
expires_at :: U64) -> DirectoryEntry ! String do
  let credential = case issue_device_credential(account,
  device,
  wide("1") ?,
  created_at,
  expires_at,
  wide(sequence) ?) do
    Err( _) -> Err("credential generation failed")
    Ok( output) -> Ok(output)
  end ?
  let signed = case generate_signed_prekey(device, credential, wide("1") ?, expires_at) do
    Err( _) -> Err("signed prekey generation failed")
    Ok( output) -> Ok(output)
  end ?
  let one_time = case generate_one_time_prekey(wide("2") ?) do
    Err( _) -> Err("one-time prekey generation failed")
    Ok( output) -> Ok(output)
  end ?
  let bundle = case build_prekey_bundle(credential, signed, one_time) do
    Err( _) -> Err("prekey bundle generation failed")
    Ok( output) -> Ok(output)
  end ?
  Ok(DirectoryEntry {
    version : 1,
    username : "prekey-account",
    account_identity : protocol(encode_account_identity(identity)) ?,
    prekey_bundle : protocol(encode_prekey_bundle(bundle)) ?,
    mailbox_token : mailbox_token
  })
end

fn sign_publish(key :: borrow SigningPrivateKey, request :: PrekeyPublishRequest) -> PrekeyPublishRequest ! String do
  let signature = case Crypto.sign(key, prekey_publish_signing_bytes(request) ?) do
    Err( _) -> Err("prekey publication signing failed")
    Ok( output) -> Ok(output)
  end ?
  Ok(PrekeyPublishRequest {
    account_id : request.account_id,
    device_id : request.device_id,
    prekeys : request.prekeys,
    signature : signature.bytes
  })
end

fn unsigned_publish(identity :: AccountIdentity,
device :: borrow DeviceKeys,
prekeys :: List < OneTimePrekeyPublic >) -> PrekeyPublishRequest ! String do
  Ok(PrekeyPublishRequest {
    account_id : identity.account_id,
    device_id : device.device_id,
    prekeys : prekeys,
    signature : repeated(0, 64) ?
  })
end

fn unsigned_claim(identity :: AccountIdentity,
target :: borrow DeviceKeys,
base_bundle_hash :: Bytes) -> PrekeyClaimRequest do
  PrekeyClaimRequest {
    account_id : identity.account_id,
    device_id : target.device_id,
    base_bundle_hash : base_bundle_hash
  }
end

fn find_bundle(entries :: List < DirectoryEntry >, mailbox_token :: Bytes, index :: Int) -> Bytes ! String do
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

fn target_base_bundle(pool :: PoolHandle, mailbox_token :: Bytes) -> Bytes ! String do
  case resolve_devices(pool, "prekey-account") ? do
    None -> Err("device set missing")
    Some( value) -> find_bundle(value.devices, mailbox_token, 0)
  end
end

fn claim_request(identity :: AccountIdentity, target :: borrow DeviceKeys, base_bundle :: Bytes) -> PrekeyClaimRequest do
  unsigned_claim(identity, target, Crypto.sha256(base_bundle))
end

fn decoded_bundle(input :: Bytes) -> PrekeyBundle ! String do
  case decode_prekey_bundle(input) do
    Err( _) -> Err("claimed bundle did not decode")
    Ok( output) -> Ok(output)
  end
end

fn claimed_id(pool :: PoolHandle, body :: Bytes) -> Int do
  let response = claim_prekey_request(pool, body)
  if response.status != 200 do
    0
  else
    case decode_prekey_bundle(response.body) do
      Err( _) -> 0
      Ok( bundle) -> case U64.to_int(bundle.one_time_prekey_id) do
        Err( _) -> 0
        Ok( output) -> output
      end
    end
  end
end

fn await_claim_id(job :: Pid < Int >, normal_exits :: Int) -> Int ! String do
  case Job.await(job) do
    Ok( output) -> Ok(output)
    Err( error) -> if error == "normal" && normal_exits < 2 do
      await_claim_id(job, normal_exits + 1)
    else
      Err("concurrent prekey claim failed: #{error}")
    end
  end
end

fn prekey_range(start_id :: Int, count :: Int, index :: Int, output :: List < OneTimePrekeyPublic >) -> List < OneTimePrekeyPublic > ! String do
  if index >= count do
    Ok(output)
  else
    prekey_range(start_id,
    count,
    index + 1,
    List.append(output,
    OneTimePrekeyPublic {
      id : wide(Int.to_string(start_id + index)) ?,
      public_key : repeated(80 + index, 32) ?
    }))
  end
end

fn target_key_count(pool :: PoolHandle, account_id :: Bytes, device_id :: Bytes) -> Int ! String do
  let rows = Pool.query_values(pool,
  "SELECT count(*)::text AS key_count FROM messenger_one_time_prekeys WHERE account_id = $1 AND device_id = $2",
  [Binary(account_id), Binary(device_id)]) ?
  if List.length(rows) != 1 do
    Err("prekey count failed")
  else
    case Map.get(List.head(rows), "key_count") do
      Text( value) -> case String.to_int(value) do
        None -> Err("invalid prekey count")
        Some( output) -> Ok(output)
      end
      _ -> Err("invalid prekey count")
    end
  end
end

fn happy_path() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = Pool.execute(pool,
  "TRUNCATE messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_directory, messenger_mailboxes RESTART IDENTITY",
  []) ?
  let created_at = now() ?
  let expires_at = U64.add(created_at, wide("31536000000") ?) ?
  let ( account, identity) = case generate_account(created_at, wide("1") ?) do
    Err( _) -> Err("account generation failed")
    Ok( output) -> Ok(output)
  end ?
  let requester = case generate_device() do
    Err( _) -> Err("requester generation failed")
    Ok( output) -> Ok(output)
  end ?
  let target = case generate_device() do
    Err( _) -> Err("target generation failed")
    Ok( output) -> Ok(output)
  end ?
  case register_device(pool,
  registration(account, identity, requester, repeated(31, 32) ?, "1", created_at, expires_at) ?) ? do
    DeviceAccepted -> Ok(nil)
    _ -> Err("requester registration failed")
  end ?
  case register_device(pool,
  registration(account, identity, target, repeated(32, 32) ?, "2", created_at, expires_at) ?) ? do
    DeviceAccepted -> Ok(nil)
    _ -> Err("target registration failed")
  end ?
  let target_base = target_base_bundle(pool, repeated(32, 32) ?) ?
  let stored = decoded_bundle(target_base) ?
  assert(U64.compare(stored.one_time_prekey_id, wide("0") ?) == 0)
  assert(Bytes.length(stored.one_time_prekey) == 0)
  let claim = claim_request(identity, target, target_base)
  let stale_claim = PrekeyClaimRequest {
    account_id : claim.account_id,
    device_id : claim.device_id,
    base_bundle_hash : repeated(99, 32) ?
  }
  assert(claim_prekey_request(pool, encode_prekey_claim(stale_claim) ?).status == 404)
  assert(claim_prekey_request(pool, append_bytes(encode_prekey_claim(claim) ?, repeated(0, 1) ?) ?).status == 400)
  let initial_response = claim_prekey_request(pool, encode_prekey_claim(claim) ?)
  assert(initial_response.status == 200)
  let initial_bundle = decoded_bundle(initial_response.body) ?
  assert(U64.compare(initial_bundle.one_time_prekey_id, wide("2") ?) == 0)
  let unsigned = unsigned_publish(identity,
  target,
  [OneTimePrekeyPublic {
    id : wide("100") ?,
    public_key : repeated(41, 32) ?
  }, OneTimePrekeyPublic {
    id : wide("101") ?,
    public_key : repeated(42, 32) ?
  }]) ?
  let forged = sign_publish(requester.signing_private_key, unsigned) ?
  assert(publish_prekeys_request(pool, encode_prekey_publish(forged) ?).status == 403)
  let published = sign_publish(target.signing_private_key, unsigned) ?
  assert(publish_prekeys_request(pool, encode_prekey_publish(published) ?).status == 201)
  assert(publish_prekeys_request(pool, encode_prekey_publish(published) ?).status == 200)
  assert(publish_prekeys_request(pool,
  append_bytes(encode_prekey_publish(published) ?, repeated(0, 1) ?) ?).status == 400)
  let tampered = PrekeyPublishRequest {
    account_id : published.account_id,
    device_id : published.device_id,
    prekeys : [OneTimePrekeyPublic {
      id : wide("100") ?,
      public_key : repeated(44, 32) ?
    }],
    signature : published.signature
  }
  assert(publish_prekeys_request(pool, encode_prekey_publish(tampered) ?).status == 403)
  let conflicting = sign_publish(target.signing_private_key,
  unsigned_publish(identity,
  target,
  [OneTimePrekeyPublic {
    id : wide("100") ?,
    public_key : repeated(43, 32) ?
  }]) ?) ?
  assert(publish_prekeys_request(pool, encode_prekey_publish(conflicting) ?).status == 409)
  let claim_body = encode_prekey_claim(claim) ?
  let first_job = Job.async(fn () -> claimed_id(pool, claim_body) end)
  let second_job = Job.async(fn () -> claimed_id(pool, claim_body) end)
  let first_claim_id = await_claim_id(first_job, 0) ?
  let second_claim_id = await_claim_id(second_job, 0) ?
  assert(first_claim_id != second_claim_id)
  let ids_match = (first_claim_id == 100 && second_claim_id == 101) || (first_claim_id == 101 && second_claim_id == 100)
  assert(ids_match)
  assert(claim_prekey_request(pool, claim_body).status == 409)
  let replenished = sign_publish(target.signing_private_key,
  unsigned_publish(identity,
  target,
  [OneTimePrekeyPublic {
    id : wide("102") ?,
    public_key : repeated(45, 32) ?
  }]) ?) ?
  assert(publish_prekeys_request(pool, encode_prekey_publish(replenished) ?).status == 201)
  let replenished_claim = claim_prekey_request(pool, claim_body)
  assert(replenished_claim.status == 200)
  assert(U64.compare(decoded_bundle(replenished_claim.body) ?.one_time_prekey_id, wide("102") ?) == 0)
  assert(claim_prekey_request(pool, claim_body).status == 409)
  let bounded_values = prekey_range(200, 64, 0, List.new()) ?
  let bounded = sign_publish(target.signing_private_key,
  unsigned_publish(identity, target, bounded_values) ?) ?
  assert(publish_prekeys_request(pool, encode_prekey_publish(bounded) ?).status == 201)
  assert(publish_prekeys_request(pool, encode_prekey_publish(bounded) ?).status == 200)
  let overflow = sign_publish(target.signing_private_key,
  unsigned_publish(identity,
  target,
  [OneTimePrekeyPublic {
    id : wide("400") ?,
    public_key : repeated(46, 32) ?
  }]) ?) ?
  assert(publish_prekeys_request(pool, encode_prekey_publish(overflow) ?).status == 429)
  let oversized = unsigned_publish(identity, target, prekey_range(500, 65, 0, List.new()) ?) ?
  case encode_prekey_publish(oversized) do
    Err( _) -> Ok(nil)
    Ok( _) -> Err("oversized prekey batch encoded")
  end ?
  let revocation = case issue_device_revocation(account, target.device_id, wide("3") ?) do
    Err( _) -> Err("revocation signing failed")
    Ok( output) -> Ok(output)
  end ?
  assert(revoke_device_request(pool, protocol(encode_device_revocation(revocation)) ?).status == 200)
  assert(target_key_count(pool, identity.account_id, target.device_id) ? == 0)
  assert(publish_prekeys_request(pool, encode_prekey_publish(bounded) ?).status == 403)
  assert(claim_prekey_request(pool, claim_body).status == 404)
  Pool.close(pool)
  Ok(true)
end

test("authenticated publication feeds one atomic bundle claim") do
  case happy_path() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
