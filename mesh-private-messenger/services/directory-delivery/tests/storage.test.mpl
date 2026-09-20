from Protocol.V1 import OuterEnvelope
from Storage.Delivery import DeliveryInsert, acknowledge_mailbox, enqueue_envelope, fetch_mailbox
from Storage.MailboxAuth import MailboxOwner

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

fn soon() -> U64 ! String do
  U64.add(U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) ?, wide("3600000") ?)
end

fn expect(condition :: Bool, message :: String) -> Result <(), String > do
  if condition do
    Ok(nil)
  else
    Err(message)
  end
end

fn scalar(pool :: PoolHandle, sql :: String) -> String ! String do
  let rows = Pool.query_values(pool, sql, []) ?
  if List.length(rows) != 1 do
    Err("expected one row")
  else
    case Map.get(List.head(rows), "value") do
      Text( value) -> Ok(value)
      _ -> Err("expected text")
    end
  end
end

# 0 accepted, 1 refused because the mailbox is full, 2 anything else.

fn deposit(pool :: PoolHandle, token :: Bytes, id_byte :: Int) -> Int ! String do
  let _ = Pool.execute(pool, "DELETE FROM messenger_rate_limits", []) ?
  case enqueue_envelope(pool,
  OuterEnvelope {
    version : 1,
    envelope_id : repeated(id_byte, 16),
    mailbox_token : token,
    suite : 1,
    expiration : soon() ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("small")
  }) ? do
    Accepted -> Ok(0)
    MailboxFull -> Ok(1)
    _ -> Ok(2)
  end
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_envelopes", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_rate_limits", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_devices", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_revoked_devices", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_accounts", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_mailboxes", []) ?
  let token = repeated(7, 32)
  let _ = Pool.execute_values(pool,
  "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($1)",
  [Binary(Crypto.sha256(token))]) ?
  # Storage is exercised below the authorization boundary; Api tests cover it.
  let owner = MailboxOwner {
    mailbox_token : token,
    signing_public_key : repeated(0, 32)
  }
  let first_id = repeated(1, 16)
  let second_id = repeated(2, 16)
  let first = OuterEnvelope {
    version : 1,
    envelope_id : first_id,
    mailbox_token : token,
    suite : 1,
    expiration : soon() ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("cipher-one")
  }
  let second = OuterEnvelope {
    version : 1,
    envelope_id : second_id,
    mailbox_token : token,
    suite : 1,
    expiration : soon() ?,
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
  let fetched = fetch_mailbox(pool, owner, wide("0") ?) ?
  expect(List.length(fetched) == 2, "unexpected fetch count") ?
  let acknowledged = acknowledge_mailbox(pool, owner, [first_id, second_id]) ?
  expect(acknowledged == 2, "unexpected acknowledgement count") ?
  let empty = fetch_mailbox(pool, owner, wide("0") ?) ?
  expect(List.length(empty) == 0, "acknowledged envelopes fetched again") ?
  # Nothing was ever registered under this address: final, like a revoked one,
  # so a sender gives up instead of retrying forever.
  case enqueue_envelope(pool,
  OuterEnvelope {
    version : 1,
    envelope_id : repeated(13, 16),
    mailbox_token : repeated(77, 32),
    suite : 1,
    expiration : soon() ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("nowhere")
  }) ? do
    MailboxRevoked -> Ok(nil)
    _ -> Err("an unknown address was not refused for good")
  end ?
  # A mailbox is bounded by what it costs to keep, 4 MiB, not by a count of 64.
  # These fills arrive through the contact address, which may use all of it; what
  # the public address may use is proved in contact_address.test.
  # Sixty-four envelopes of the largest size fill it...
  let full_token = repeated(8, 32)
  let full_hash = Crypto.sha256(full_token)
  let _ = Pool.execute_values(pool,
  "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($1)",
  [Binary(full_hash)]) ?
  let _ = Pool.execute_values(pool,
  "INSERT INTO messenger_envelopes (mailbox_token_hash, envelope_id, suite, expiration_ms, padding_bucket, ciphertext, contact) SELECT $1, decode(lpad(to_hex(n), 32, '0'), 'hex'), 1, 2000000000, 65536, decode('00', 'hex'), true FROM generate_series(1, 64) AS n",
  [Binary(full_hash)]) ?
  expect(deposit(pool, full_token, 9) ? == 1, "a full mailbox took another envelope") ?
  # ...and acknowledging one makes room again.
  let _ = Pool.execute_values(pool,
  "UPDATE messenger_envelopes SET acknowledged_at = clock_timestamp() WHERE mailbox_token_hash = $1 AND envelope_id = decode(lpad(to_hex(1), 32, '0'), 'hex')",
  [Binary(full_hash)]) ?
  expect(deposit(pool, full_token, 9) ? == 0, "acknowledging did not make room") ?
  # Ordinary messages are small, so far more than 64 of them fit: a device that
  # is offline for a while no longer turns its senders away.
  let busy_token = repeated(10, 32)
  let busy_hash = Crypto.sha256(busy_token)
  let _ = Pool.execute_values(pool,
  "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($1)",
  [Binary(busy_hash)]) ?
  let _ = Pool.execute_values(pool,
  "INSERT INTO messenger_envelopes (mailbox_token_hash, envelope_id, suite, expiration_ms, padding_bucket, ciphertext, contact) SELECT $1, decode(lpad(to_hex(n), 32, '0'), 'hex'), 1, 2000000000, 256, decode('00', 'hex'), true FROM generate_series(1, 4095) AS n",
  [Binary(busy_hash)]) ?
  expect(deposit(pool, busy_token, 11) ? == 0,
  "an ordinary message was refused well inside the budget") ?
  # The number of rows is bounded as well, at 4,096.
  expect(deposit(pool, busy_token, 12) ? == 1, "the envelope count is not bounded") ?
  expect(scalar(pool,
  "SELECT concat(pending_count, ':', pending_bytes) AS value FROM messenger_mailboxes WHERE mailbox_token_hash = decode('" <> Bytes.to_hex(busy_hash) <> "', 'hex')") ? == "4096:1048576",
  "the mailbox did not account for what it holds") ?
  Pool.close(pool)
  Ok(true)
end

test("PostgreSQL delivery storage is durable and bounded") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
