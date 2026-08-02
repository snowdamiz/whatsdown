from Api.Binary import acknowledge_request, fetch_request, register_request, resolve_request, submit_request
from Protocol.V1 import DirectoryEntry, MailboxAck, MailboxFetch, OuterEnvelope, decode_delivery_batch, encode_directory_entry, encode_directory_lookup, encode_mailbox_ack, encode_mailbox_fetch, encode_outer_envelope

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( error) -> Err(error)
    Ok( parsed) -> Ok(parsed)
  end
end

fn wire(value :: Result < Bytes, ProtocolError >) -> Bytes ! String do
  case value do
    Err( _) -> Err("protocol encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn delivery_count(value :: Bytes) -> Int ! String do
  case decode_delivery_batch(value) do
    Err( _) -> Err("invalid delivery response")
    Ok( deliveries) -> Ok(List.length(deliveries))
  end
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_envelopes", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_directory", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_mailboxes", []) ?
  let token = repeated(3, 32)
  let entry = DirectoryEntry {
    version : 1,
    username : "device-b",
    account_identity : Bytes.from_utf8("public-account"),
    prekey_bundle : Bytes.from_utf8("public-prekey"),
    mailbox_token : token
  }
  let registered = register_request(pool, wire(encode_directory_entry(entry)) ?)
  assert(registered.status == 201)
  let resolved = resolve_request(pool, wire(encode_directory_lookup("device-b")) ?)
  assert(resolved.status == 200)
  assert(Bytes.secure_equals(resolved.body, wire(encode_directory_entry(entry)) ?))
  let envelope_id = repeated(4, 16)
  let envelope = wire(encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : envelope_id,
    mailbox_token : token,
    suite : 1,
    expiration : wide("2000000000") ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("opaque ciphertext")
  })) ?
  assert(submit_request(pool, envelope).status == 202)
  assert(submit_request(pool, envelope).status == 200)
  let fetched = fetch_request(pool,
  wire(encode_mailbox_fetch(MailboxFetch {
    version : 1,
    mailbox_token : token,
    after_sequence : wide("0") ?
  })) ?)
  assert(fetched.status == 200)
  let deliveries = case decode_delivery_batch(fetched.body) do
    Err( _) -> Err("invalid delivery response")
    Ok( values) -> Ok(values)
  end ?
  assert(List.length(deliveries) == 1)
  let acknowledged = acknowledge_request(pool,
  wire(encode_mailbox_ack(MailboxAck {
    version : 1,
    mailbox_token : token,
    envelope_ids : [envelope_id]
  })) ?)
  assert(acknowledged.status == 200)
  assert(delivery_count(fetch_request(pool,
  wire(encode_mailbox_fetch(MailboxFetch {
    version : 1,
    mailbox_token : token,
    after_sequence : wide("0") ?
  })) ?).body) ? == 0)
  let hostile = Bytes.from_utf8("not-a-canonical-frame")
  assert(register_request(pool, hostile).status == 400)
  assert(resolve_request(pool, hostile).status == 400)
  assert(submit_request(pool, hostile).status == 400)
  assert(fetch_request(pool, hostile).status == 400)
  assert(acknowledge_request(pool, hostile).status == 400)
  Pool.close(pool)
  Ok(true)
end

test("binary API accepts canonical records and rejects hostile frames") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
