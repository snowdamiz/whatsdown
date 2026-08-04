from Api.Binary import bind_push_request, unbind_push_request
from Identity.Device import AccountKeys, DeviceKeys, generate_account, generate_device, issue_device_credential
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.V1 import AccountIdentity, DirectoryEntry, OuterEnvelope, ProtocolError, encode_account_identity, encode_prekey_bundle
from Push.Binding import PushBindRequest, PushUnbindRequest, encode_push_bind, encode_push_unbind, push_bind_signing_bytes, push_unbind_signing_bytes
from Push.Token import seal_provider_token
from Runtime.FakePushProvider import generic_push_payload
from Runtime.PushDispatch import broker_status, dispatch_push
from Storage.Delivery import DeliveryInsert, enqueue_envelope
from Storage.Devices import DeviceWrite, register_device
from Storage.Outbox import PushResult, finish_outbox, lease_outbox
from Storage.Push import find_push_binding_for_mailbox

fn repeated(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn random_hash() -> Bytes ! String do
  case Crypto.random_bytes(32) do
    Err( _) -> Err("test randomness failed")
    Ok( output) -> Ok(output)
  end
end

fn append_bytes(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn protocol(value :: Result < Bytes, ProtocolError >) -> Bytes ! String do
  case value do
    Err( _) -> Err("protocol encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn current_time() -> U64 ! String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn registration(account :: borrow AccountKeys,
identity :: AccountIdentity,
device :: borrow DeviceKeys,
mailbox_token :: Bytes,
created_at :: U64,
expires_at :: U64) -> DirectoryEntry ! String do
  let credential = case issue_device_credential(account,
  device,
  U64.parse("1") ?,
  created_at,
  expires_at,
  U64.parse("1") ?) do
    Err( _) -> Err("credential generation failed")
    Ok( output) -> Ok(output)
  end ?
  let signed = case generate_signed_prekey(device, credential, U64.parse("1") ?, expires_at) do
    Err( _) -> Err("signed prekey generation failed")
    Ok( output) -> Ok(output)
  end ?
  let one_time = case generate_one_time_prekey(U64.parse("2") ?) do
    Err( _) -> Err("one-time prekey generation failed")
    Ok( output) -> Ok(output)
  end ?
  let bundle = case build_prekey_bundle(credential, signed, one_time) do
    Err( _) -> Err("prekey bundle generation failed")
    Ok( output) -> Ok(output)
  end ?
  Ok(DirectoryEntry {
    version : 1,
    username : "push-device",
    account_identity : protocol(encode_account_identity(identity)) ?,
    prekey_bundle : protocol(encode_prekey_bundle(bundle)) ?,
    mailbox_token : mailbox_token
  })
end

fn sign_bind(key :: borrow SigningPrivateKey, request :: PushBindRequest) -> PushBindRequest ! String do
  let signature = case Crypto.sign(key, push_bind_signing_bytes(request) ?) do
    Err( _) -> Err("push bind signing failed")
    Ok( output) -> Ok(output)
  end ?
  Ok(PushBindRequest {
    mailbox_token_hash : request.mailbox_token_hash,
    wake_token_hash : request.wake_token_hash,
    revision : request.revision,
    provider : request.provider,
    provider_token_ciphertext : request.provider_token_ciphertext,
    signature : signature.bytes
  })
end

fn sign_unbind(key :: borrow SigningPrivateKey, request :: PushUnbindRequest) -> PushUnbindRequest ! String do
  let signature = case Crypto.sign(key, push_unbind_signing_bytes(request) ?) do
    Err( _) -> Err("push unbind signing failed")
    Ok( output) -> Ok(output)
  end ?
  Ok(PushUnbindRequest {
    mailbox_token_hash : request.mailbox_token_hash,
    revision : request.revision,
    signature : signature.bytes
  })
end

fn unsigned_bind(mailbox_token_hash :: Bytes,
wake_token_hash :: Bytes,
revision :: String,
provider_token_ciphertext :: Bytes) -> PushBindRequest ! String do
  Ok(PushBindRequest {
    mailbox_token_hash : mailbox_token_hash,
    wake_token_hash : wake_token_hash,
    revision : U64.parse(revision) ?,
    provider : 1,
    provider_token_ciphertext : provider_token_ciphertext,
    signature : repeated(0, 64) ?
  })
end

fn unsigned_unbind(mailbox_token_hash :: Bytes, revision :: String) -> PushUnbindRequest ! String do
  Ok(PushUnbindRequest {
    mailbox_token_hash : mailbox_token_hash,
    revision : U64.parse(revision) ?,
    signature : repeated(0, 64) ?
  })
end

test("push broker statuses preserve retry semantics") do
  case broker_status(204) do
    PushDelivered -> assert(true)
    _ -> assert(false)
  end
  case broker_status(422) do
    PushPermanent( code) -> assert(code == "provider_rejected")
    _ -> assert(false)
  end
  case broker_status(503) do
    PushRetryable( code) -> assert(code == "provider_retryable")
    _ -> assert(false)
  end
  case broker_status(500) do
    PushRetryable( code) -> assert(code == "broker_invalid_response")
    _ -> assert(false)
  end
end

fn text(value :: DbValue) -> String ! String do
  case value do
    Text( output) -> Ok(output)
    _ -> Err("invalid test row")
  end
end

fn scalar(pool :: PoolHandle, sql :: String) -> String ! String do
  let rows = Pool.query_values(pool, sql, []) ?
  if List.length(rows) == 1 do
    text(Map.get(List.head(rows), "value"))
  else
    Err("expected one row")
  end
end

fn enqueue(pool :: PoolHandle, mailbox_token :: Bytes, id :: Int) -> Result <(), String > do
  case enqueue_envelope(pool,
  OuterEnvelope {
    version : 1,
    envelope_id : repeated(id, 16) ?,
    mailbox_token : mailbox_token,
    suite : 1,
    expiration : U64.parse("4102444800000") ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("opaque")
  }) ? do
    Accepted -> Ok(nil)
    _ -> Err("envelope was not accepted")
  end
end

fn finish_next(pool :: PoolHandle, owner :: String, available :: Bool) -> Result <(), String > do
  let events = lease_outbox(pool, owner, 1, 60) ?
  if List.length(events) != 1 do
    Err("outbox event missing")
  else
    let event = List.head(events)
    finish_outbox(pool, event, owner, dispatch_push(pool, event, available) ?)
  end
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = Pool.execute(pool,
  "TRUNCATE messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_directory, messenger_mailboxes RESTART IDENTITY",
  []) ?
  let created_at = current_time() ?
  let expires_at = U64.add(created_at, U64.parse("31536000000") ?) ?
  let ( account, identity) = case generate_account(created_at, U64.parse("1") ?) do
    Err( _) -> Err("account generation failed")
    Ok( output) -> Ok(output)
  end ?
  let device = case generate_device() do
    Err( _) -> Err("device generation failed")
    Ok( output) -> Ok(output)
  end ?
  let attacker = case generate_device() do
    Err( _) -> Err("attacker generation failed")
    Ok( output) -> Ok(output)
  end ?
  let mailbox_token = repeated(7, 32) ?
  let mailbox_token_hash = Crypto.sha256(mailbox_token)
  let first_wake_token_hash = random_hash() ?
  let second_wake_token_hash = random_hash() ?
  let broker = case Crypto.x25519_from_seed(repeated(12, 32) ?) do
    Err( _) -> Err("broker key generation failed")
    Ok( output) -> Ok(output)
  end ?
  let first_provider_token = seal_provider_token(Bytes.from_utf8("ExpoPushToken[first-test-device]"),
  broker.public_key) ?
  let second_provider_token = seal_provider_token(Bytes.from_utf8("ExpoPushToken[second-test-device]"),
  broker.public_key) ?
  assert(!Bytes.secure_equals(mailbox_token_hash, first_wake_token_hash))
  case register_device(pool,
  registration(account, identity, device, mailbox_token, created_at, expires_at) ?) ? do
    DeviceAccepted -> Ok(nil)
    _ -> Err("device registration failed")
  end ?
  enqueue(pool, mailbox_token, 1) ?
  finish_next(pool, "no-binding", false) ?
  assert(scalar(pool,
  "SELECT concat(status, ':', (SELECT count(*) FROM messenger_envelopes)) AS value FROM messenger_outbox_events") ? == "delivered:1")
  let first_unsigned = unsigned_bind(mailbox_token_hash,
  first_wake_token_hash,
  "1",
  first_provider_token) ?
  let unauthorized = sign_bind(attacker.signing_private_key, first_unsigned) ?
  assert(bind_push_request(pool, encode_push_bind(unauthorized) ?).status == 403)
  let first = sign_bind(device.signing_private_key, first_unsigned) ?
  let encoded_first = encode_push_bind(first) ?
  assert(bind_push_request(pool, append_bytes(encoded_first, repeated(0, 1) ?) ?).status == 400)
  assert(bind_push_request(pool, encoded_first).status == 201)
  assert(bind_push_request(pool, encode_push_bind(first) ?).status == 201)
  let conflicting_first = sign_bind(device.signing_private_key,
  unsigned_bind(mailbox_token_hash, second_wake_token_hash, "1", second_provider_token) ?) ?
  assert(bind_push_request(pool, encode_push_bind(conflicting_first) ?).status == 409)
  let tampered = PushBindRequest {
    mailbox_token_hash : first.mailbox_token_hash,
    wake_token_hash : second_wake_token_hash,
    revision : first.revision,
    provider : first.provider,
    provider_token_ciphertext : first.provider_token_ciphertext,
    signature : first.signature
  }
  assert(bind_push_request(pool, encode_push_bind(tampered) ?).status == 403)
  case encode_push_bind(unsigned_bind(mailbox_token_hash,
  mailbox_token_hash,
  "2",
  first_provider_token) ?) do
    Err( _) -> Ok(nil)
    Ok( _) -> Err("mailbox and wake hashes were allowed to alias")
  end ?
  enqueue(pool, mailbox_token, 2) ?
  finish_next(pool, "provider-outage", false) ?
  assert(scalar(pool,
  "SELECT concat((SELECT count(*) FROM messenger_outbox_events WHERE status = 'retryable_failure'), ':', (SELECT count(*) FROM messenger_envelopes), ':', (SELECT completed_at IS NULL FROM messenger_outbox_events WHERE status = 'retryable_failure')) AS value") ? == "1:2:t")
  let second = sign_bind(device.signing_private_key,
  unsigned_bind(mailbox_token_hash, second_wake_token_hash, "2", second_provider_token) ?) ?
  assert(bind_push_request(pool, encode_push_bind(second) ?).status == 201)
  assert(bind_push_request(pool, encode_push_bind(first) ?).status == 409)
  let stored = find_push_binding_for_mailbox(pool, mailbox_token_hash) ?
  case stored do
    None -> Err("push binding missing")
    Some( binding) -> if Bytes.secure_equals(binding.wake_token_hash, second_wake_token_hash) && binding.provider == 1 && Bytes.secure_equals(binding.provider_token_ciphertext,
    second.provider_token_ciphertext) do
      Ok(nil)
    else
      Err("stale push binding replaced newer state")
    end
  end ?
  let invalid_unbind = PushUnbindRequest {
    mailbox_token_hash : mailbox_token_hash,
    revision : U64.parse("3") ?,
    signature : second.signature
  }
  assert(unbind_push_request(pool, encode_push_unbind(invalid_unbind) ?).status == 403)
  let unbind = sign_unbind(device.signing_private_key, unsigned_unbind(mailbox_token_hash, "3") ?) ?
  assert(unbind_push_request(pool, encode_push_unbind(unbind) ?).status == 200)
  assert(unbind_push_request(pool, encode_push_unbind(unbind) ?).status == 200)
  let stale_unbind = sign_unbind(device.signing_private_key,
  unsigned_unbind(mailbox_token_hash, "2") ?) ?
  assert(unbind_push_request(pool, encode_push_unbind(stale_unbind) ?).status == 409)
  assert(bind_push_request(pool, encode_push_bind(second) ?).status == 409)
  case find_push_binding_for_mailbox(pool, mailbox_token_hash) ? do
    None -> Ok(nil)
    Some( _) -> Err("push binding remained active")
  end ?
  let final_binding = sign_bind(device.signing_private_key,
  unsigned_bind(mailbox_token_hash, first_wake_token_hash, "4", first_provider_token) ?) ?
  assert(bind_push_request(pool, encode_push_bind(final_binding) ?).status == 201)
  let _ = Pool.execute_values(pool,
  "UPDATE messenger_mailboxes SET active = false WHERE mailbox_token_hash = $1",
  [Binary(mailbox_token_hash)]) ?
  assert(scalar(pool, "SELECT count(*)::text AS value FROM messenger_push_bindings") ? == "0")
  let payload = generic_push_payload()
  assert(payload.body == "New encrypted activity")
  assert(payload.kind == "encrypted-wakeup")
  Pool.close(pool)
  Ok(true)
end

test("signed push binding replays are idempotent without weakening durable delivery") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
