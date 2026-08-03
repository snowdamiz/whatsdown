from Protocol.V1 import DirectoryEntry, MailboxAck, MailboxFetch, OuterEnvelope
from Storage.Directory import register_directory, resolve_directory
from Storage.Delivery import DeliveryInsert, acknowledge_mailbox, enqueue_envelope, fetch_mailbox

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

fn expect(condition :: Bool, message :: String) -> Result <(), String > do
  if condition do
    Ok(nil)
  else
    Err(message)
  end
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_envelopes", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_rate_limits", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_directory", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_mailboxes", []) ?
  let token = repeated(7, 32)
  let entry = DirectoryEntry {
    version : 1,
    username : "device-b",
    account_identity : Bytes.from_utf8("public-account"),
    prekey_bundle : Bytes.from_utf8("public-prekey"),
    mailbox_token : token
  }
  let _ = register_directory(pool, entry) ?
  case resolve_directory(pool, "device-b") ? do
    None -> Err("directory entry missing")
    Some( resolved) -> expect(Bytes.secure_equals(resolved.mailbox_token, token),
    "directory token changed")
  end ?
  let first_id = repeated(1, 16)
  let second_id = repeated(2, 16)
  let first = OuterEnvelope {
    version : 1,
    envelope_id : first_id,
    mailbox_token : token,
    suite : 1,
    expiration : wide("4102444800000") ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("cipher-one")
  }
  let second = OuterEnvelope {
    version : 1,
    envelope_id : second_id,
    mailbox_token : token,
    suite : 1,
    expiration : wide("4102444800000") ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("cipher-two")
  }
  case enqueue_envelope(pool, first) ? do
    Accepted -> Ok(nil)
    _ -> Err("first envelope not accepted")
  end ?
  case enqueue_envelope(pool, first) ? do
    Duplicate -> Ok(nil)
    _ -> Err("duplicate envelope not detected")
  end ?
  case enqueue_envelope(pool, second) ? do
    Accepted -> Ok(nil)
    _ -> Err("second envelope not accepted")
  end ?
  let fetched = fetch_mailbox(pool,
  MailboxFetch {
    version : 1,
    mailbox_token : token,
    after_sequence : wide("0") ?
  }) ?
  expect(List.length(fetched) == 2, "unexpected fetch count") ?
  let acknowledged = acknowledge_mailbox(pool,
  MailboxAck {
    version : 1,
    mailbox_token : token,
    envelope_ids : [first_id, second_id]
  }) ?
  expect(acknowledged == 2, "unexpected acknowledgement count") ?
  let empty = fetch_mailbox(pool,
  MailboxFetch {
    version : 1,
    mailbox_token : token,
    after_sequence : wide("0") ?
  }) ?
  expect(List.length(empty) == 0, "acknowledged envelopes fetched again") ?
  let full_token = repeated(8, 32)
  let full_hash = Crypto.sha256(full_token)
  let _ = Pool.execute_values(pool,
  "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($1)",
  [Binary(full_hash)]) ?
  let _ = Pool.execute_values(pool,
  "INSERT INTO messenger_envelopes (mailbox_token_hash, envelope_id, suite, expiration_ms, padding_bucket, ciphertext) SELECT $1, decode(lpad(to_hex(n), 32, '0'), 'hex'), 1, 2000000000, 256, decode('00', 'hex') FROM generate_series(1, 64) AS n",
  [Binary(full_hash)]) ?
  case enqueue_envelope(pool,
  OuterEnvelope {
    version : 1,
    envelope_id : repeated(9, 16),
    mailbox_token : full_token,
    suite : 1,
    expiration : wide("4102444800000") ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("over-capacity")
  }) ? do
    MailboxFull -> Ok(nil)
    _ -> Err("mailbox capacity not enforced")
  end ?
  Pool.close(pool)
  Ok(true)
end

test("PostgreSQL directory and delivery storage is durable and bounded") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
