from Api.Binary import acknowledge_request, fetch_request, submit_request, submit_sealed_request
from Privacy.Edge import encode_sealed_delivery, seal_delivery
from Protocol.EnvelopeWire import decode_outer_envelope, encode_outer_envelope
from Protocol.MailboxWire import decode_delivery_batch
from Protocol.V1 import OuterEnvelope
from Tests.MailboxSupport import mailbox_test_now, register_test_mailbox, signed_ack, signed_ack_at, signed_fetch, signed_fetch_at

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(error)
    Ok(parsed)
  end
end

fn wire(value :: Result<Bytes, ProtocolError>) -> Bytes!String do
  case value do
    Err(_) -> Err("protocol encoding failed")
    Ok(encoded)
  end
end

fn soon() -> U64!String do
  U64.add(mailbox_test_now()?, wide("3600000")?)
end

fn after_days(days :: String) -> U64!String do
  U64.add(mailbox_test_now()?, U64.multiply(wide(days)?, wide("86400000")?)?)
end

fn delivery_count(value :: Bytes) -> Int!String do
  case decode_delivery_batch(value) do
    Err(_) -> Err("invalid delivery response")
    Ok(deliveries) -> Ok(List.length(deliveries))
  end
end

fn outer(value :: Bytes) -> OuterEnvelope!String do
  case decode_outer_envelope(value) do
    Err(_) -> Err("invalid delivered envelope")
    Ok(envelope)
  end
end

fn database_rejects_suite(pool :: PoolHandle, token :: Bytes, envelope_id :: Bytes, suite :: Int) -> Bool do
  case Pool.execute_values(pool,
    "INSERT INTO messenger_envelopes (mailbox_token_hash, envelope_id, suite, expiration_ms, padding_bucket, ciphertext) VALUES ($1, $2, $3::smallint, $4::bigint, $5::integer, $6)",
    [
      Binary(Crypto.sha256(token)),
      Binary(envelope_id),
      Text(Int.to_string(suite)),
      Text("4102444800000"),
      Text("256"),
      Binary(Bytes.from_utf8("opaque"))
    ]) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn frame_header(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Err(_) -> Err("test frame construction failed")
    Ok(output)
  end
end

fn legacy_fetch(token :: Bytes) -> Bytes!String do
  let addressed = Bytes.concat(frame_header([1, 70, 69, 84])?, token)?
  Bytes.concat(addressed, frame_header([0, 0, 0, 0, 0, 0, 0, 0])?)
end

fn legacy_ack(token :: Bytes, envelope_id :: Bytes) -> Bytes!String do
  let addressed = Bytes.concat(frame_header([1, 65, 67, 75])?, token)?
  let counted = Bytes.concat(addressed, frame_header([1])?)?
  Bytes.concat(counted, envelope_id)
end

fn reset(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  Ok(nil)
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  reset(pool)?
  let token = repeated(3, 32)
  let owner = register_test_mailbox(pool, "device-b", token)?
  let envelope_id = repeated(4, 16)
  let envelope = wire(encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: envelope_id,
    mailbox_token: token,
    suite: 2,
    expiration: soon()?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("opaque ciphertext")
  }))?
  assert(submit_request(pool, envelope).status == 202)
  assert(submit_request(pool, envelope).status == 200)
  let delivery_seed = Bytes.from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?
  let delivery_key = case Crypto.x25519_from_seed(delivery_seed) do
    Err(_) -> Err("delivery key failed")
    Ok(value)
  end?
  let sealed_id = repeated(5, 16)
  let sealed = wire(encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: sealed_id,
    mailbox_token: token,
    suite: 1,
    expiration: soon()?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("sealed ciphertext")
  }))?
  assert(submit_sealed_request(pool,
    encode_sealed_delivery(seal_delivery(sealed, delivery_key.public_key)?)?,
    delivery_seed).status == 202)
  let fetched = fetch_request(pool, signed_fetch(owner, token)?)
  assert(fetched.status == 200)
  let deliveries = case decode_delivery_batch(fetched.body) do
    Err(_) -> Err("invalid delivery response")
    Ok(values)
  end?
  assert(List.length(deliveries) == 2)
  assert(outer(List.head(deliveries).envelope)?.suite == 2)
  let acknowledged = acknowledge_request(pool, signed_ack(owner, token, [envelope_id, sealed_id])?)
  assert(acknowledged.status == 200)
  assert(delivery_count(fetch_request(pool, signed_fetch(owner, token)?).body)? == 0)
  assert(database_rejects_suite(pool, token, repeated(6, 16), 0))
  assert(database_rejects_suite(pool, token, repeated(7, 16), 5))
  # Suite 4 is the recipient-sealed transport: delivery stores it without
  # learning the protocol suite or the packet kind.
  let sealed_transport = wire(encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(8, 16),
    mailbox_token: token,
    suite: 4,
    expiration: soon()?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("recipient-sealed")
  }))?
  assert(submit_request(pool, sealed_transport).status == 202)
  let hostile = Bytes.from_utf8("not-a-canonical-frame")
  assert(submit_request(pool, hostile).status == 400)
  assert(fetch_request(pool, hostile).status == 400)
  assert(acknowledge_request(pool, hostile).status == 400)
  Pool.close(pool)
  Ok(true)
end

# The mailbox address is public. Everything below is what a third party who
# resolved the victim's username can attempt; none of it may read or remove mail.

fn mailbox_takeover_proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  reset(pool)?
  let victim_token = repeated(21, 32)
  let attacker_token = repeated(22, 32)
  let victim = register_test_mailbox(pool, "victim", victim_token)?
  let attacker = register_test_mailbox(pool, "attacker", attacker_token)?
  let envelope_id = repeated(23, 16)
  let envelope = wire(encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: envelope_id,
    mailbox_token: victim_token,
    suite: 1,
    expiration: soon()?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("for the victim only")
  }))?
  assert(submit_request(pool, envelope).status == 202)
  # 1. The pre-hardening request: the public address as a bearer credential.
  assert(fetch_request(pool, legacy_fetch(victim_token)?).status == 400)
  assert(acknowledge_request(pool, legacy_ack(victim_token, envelope_id)?).status == 400)
  # 2. A validly registered device signing for somebody else's mailbox.
  assert(fetch_request(pool, signed_fetch(attacker, victim_token)?).status == 403)
  assert(acknowledge_request(pool, signed_ack(attacker, victim_token, [envelope_id])?).status == 403)
  # 3. An unregistered mailbox is indistinguishable from an unauthorized one.
  assert(fetch_request(pool, signed_fetch(attacker, repeated(24, 32))?).status == 403)
  # 4. A captured request stops working outside its signed time window.
  let now = mailbox_test_now()?
  let expired = U64.subtract(now, wide("301000")?)?
  let premature = U64.add(now, wide("120000")?)?
  assert(fetch_request(pool, signed_fetch_at(victim, victim_token, wide("0")?, expired)?).status == 403)
  assert(fetch_request(pool, signed_fetch_at(victim, victim_token, wide("0")?, premature)?).status == 403)
  assert(acknowledge_request(pool, signed_ack_at(victim, victim_token, [envelope_id], expired)?).status == 403)
  # 4b. An envelope cannot be parked forever. The client's own lifetime is 30
  # days; anything that would outlast it, or has already expired, is refused,
  # so a full mailbox always drains by itself.
  let parked = wire(encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(25, 16),
    mailbox_token: victim_token,
    suite: 4,
    expiration: after_days("400")?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("never expires")
  }))?
  assert(submit_request(pool, parked).status == 400)
  let stale = wire(encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(26, 16),
    mailbox_token: victim_token,
    suite: 4,
    expiration: wide("1")?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("already expired")
  }))?
  assert(submit_request(pool, stale).status == 400)
  let month = wire(encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(27, 16),
    mailbox_token: attacker_token,
    suite: 4,
    expiration: after_days("30")?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("a client's normal lifetime")
  }))?
  assert(submit_request(pool, month).status == 202)
  # 5. None of the attempts removed the victim's envelope.
  let survived = fetch_request(pool, signed_fetch(victim, victim_token)?)
  assert(survived.status == 200)
  assert(delivery_count(survived.body)? == 1)
  # 6. The attacker still reads and acknowledges only its own mailbox.
  assert(delivery_count(fetch_request(pool, signed_fetch(attacker, attacker_token)?).body)? == 1)
  assert(acknowledge_request(pool, signed_ack(victim, victim_token, [envelope_id])?).status == 200)
  assert(delivery_count(fetch_request(pool, signed_fetch(victim, victim_token)?).body)? == 0)
  Pool.close(pool)
  Ok(true)
end

test("binary API accepts canonical records and rejects hostile frames") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("a public mailbox address cannot read, subscribe to, or acknowledge another device's mail") do
  case mailbox_takeover_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
