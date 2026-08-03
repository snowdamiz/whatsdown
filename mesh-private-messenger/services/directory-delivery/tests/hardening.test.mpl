from Protocol.V1 import DirectoryEntry, MailboxFetch, OuterEnvelope
from Storage.Delivery import DeliveryInsert, enqueue_envelope, fetch_mailbox
from Storage.Directory import register_directory
from Storage.Outbox import OutboxEvent, PushResult, finish_outbox, lease_outbox
from Storage.RateLimit import allow_request
from Storage.Retention import purge_envelopes

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn wide(value :: String) -> U64 ! String do
  U64.parse(value)
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

fn expect(condition :: Bool, message :: String) -> Result <(), String > do
  if condition do
    Ok(nil)
  else
    Err(message)
  end
end

fn crash_after_envelope(conn :: borrow PgConn) -> Int ! String do
  let _ = Pg.execute(conn,
  "INSERT INTO messenger_envelopes (mailbox_token_hash, envelope_id, suite, expiration_ms, padding_bucket, ciphertext) SELECT mailbox_token_hash, decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex'), 1, 4102444800000, 256, decode('00', 'hex') FROM messenger_mailboxes LIMIT 1",
  []) ?
  Err("simulated crash after envelope insert")
end

fn push_unavailable(_event :: OutboxEvent) -> PushResult do
  PushRetryable("provider_unavailable")
end

fn push_delivered(_event :: OutboxEvent) -> PushResult do
  PushDelivered
end

fn envelope(token :: Bytes, id_byte :: Int, expiration :: String) -> OuterEnvelope ! String do
  Ok(OuterEnvelope {
    version : 1,
    envelope_id : repeated(id_byte, 16),
    mailbox_token : token,
    suite : 1,
    expiration : wide(expiration) ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("opaque")
  })
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 4, 5000) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_outbox_events", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_rate_limits", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_envelopes", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_directory", []) ?
  let _ = Pool.execute(pool, "DELETE FROM messenger_mailboxes", []) ?
  let token = repeated(7, 32)
  let _ = register_directory(pool,
  DirectoryEntry {
    version : 1,
    username : "hardening-device",
    account_identity : Bytes.from_utf8("public-account"),
    prekey_bundle : Bytes.from_utf8("public-prekey"),
    mailbox_token : token
  }) ?
  case Repo.transaction(pool, crash_after_envelope) do
    Ok( _) -> Err("simulated crash committed")
    Err( _) -> Ok(nil)
  end ?
  expect(scalar(pool,
  "SELECT count(*)::text AS value FROM messenger_envelopes WHERE envelope_id = decode('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'hex')") ? == "0",
  "rollback left a partial envelope") ?
  let durable = envelope(token, 1, "4102444800000") ?
  case enqueue_envelope(pool, durable) ? do
    Accepted -> Ok(nil)
    _ -> Err("durable envelope was not accepted")
  end ?
  Pool.close(pool)
  let reopened = Pool.open(url, 1, 4, 5000) ?
  expect(scalar(reopened,
  "SELECT concat((SELECT count(*) FROM messenger_envelopes), ':', (SELECT count(*) FROM messenger_outbox_events)) AS value") ? == "1:1",
  "envelope and outbox were not committed together") ?
  case enqueue_envelope(reopened, durable) ? do
    Duplicate -> Ok(nil)
    _ -> Err("duplicate submission was not idempotent")
  end ?
  expect(scalar(reopened,
  "SELECT concat((SELECT count(*) FROM messenger_envelopes), ':', (SELECT count(*) FROM messenger_outbox_events), ':', (SELECT pending_count FROM messenger_mailboxes LIMIT 1)) AS value") ? == "1:1:1",
  "duplicate submission corrupted durable state") ?
  let first_lease = lease_outbox(reopened, "worker-a", 1, 60) ?
  expect(List.length(first_lease) == 1, "first worker did not acquire outbox event") ?
  expect(List.length(lease_outbox(reopened, "worker-b", 1, 60) ?) == 0,
  "two workers leased the same event") ?
  let _ = Pool.execute(reopened,
  "UPDATE messenger_outbox_events SET lease_expires_at = now() - interval '1 second'",
  []) ?
  let recovered = lease_outbox(reopened, "worker-b", 1, 60) ?
  expect(List.length(recovered) == 1, "expired outbox lease was not recovered") ?
  let recovered_event = List.head(recovered)
  finish_outbox(reopened, recovered_event, "worker-b", push_unavailable(recovered_event)) ?
  expect(scalar(reopened,
  "SELECT concat(status, ':', attempts::text, ':', completed_at IS NULL, ':', (SELECT count(*) FROM messenger_envelopes)) AS value FROM messenger_outbox_events") ? == "retryable_failure:2:t:1",
  "failed push lost or completed the message") ?
  let _ = Pool.execute(reopened,
  "UPDATE messenger_outbox_events SET attempts = 4, available_at = now() WHERE completed_at IS NULL",
  []) ?
  let final_attempt = lease_outbox(reopened, "worker-c", 1, 60) ?
  expect(List.length(final_attempt) == 1, "retryable event was not processed") ?
  let final_event = List.head(final_attempt)
  finish_outbox(reopened, final_event, "worker-c", push_unavailable(final_event)) ?
  expect(scalar(reopened,
  "SELECT concat(status, ':', attempts::text, ':', completed_at IS NOT NULL, ':', (SELECT count(*) FROM messenger_envelopes)) AS value FROM messenger_outbox_events") ? == "permanent_failure:5:t:1",
  "retry bound or message retention failed") ?
  let delivered = envelope(token, 2, "4102444800000") ?
  let _ = enqueue_envelope(reopened, delivered) ?
  let delivery_attempt = lease_outbox(reopened, "worker-d", 1, 60) ?
  expect(List.length(delivery_attempt) == 1, "successful push event was not processed") ?
  let delivery_event = List.head(delivery_attempt)
  finish_outbox(reopened, delivery_event, "worker-d", push_delivered(delivery_event)) ?
  expect(scalar(reopened,
  "SELECT count(*)::text AS value FROM messenger_outbox_events WHERE status = 'delivered'") ? == "1",
  "successful push was not completed") ?
  let expired = envelope(token, 3, "1") ?
  let _ = enqueue_envelope(reopened, expired) ?
  let fetched = fetch_mailbox(reopened,
  MailboxFetch {
    version : 1,
    mailbox_token : token,
    after_sequence : wide("0") ?
  }) ?
  expect(List.length(fetched) == 2, "expired envelope was returned") ?
  expect(purge_envelopes(reopened, 3600, 128) ? == 1, "expired envelope was not purged") ?
  let _ = Pool.execute_values(reopened,
  "UPDATE messenger_rate_limits SET request_count = 32, window_started_at = clock_timestamp() WHERE bucket_key = $1",
  [Binary(Crypto.sha256(token))]) ?
  case enqueue_envelope(reopened, envelope(token, 4, "4102444800000") ?) ? do
    RateLimited -> Ok(nil)
    _ -> Err("delivery rate limit was not enforced")
  end ?
  expect(scalar(reopened,
  "SELECT concat((SELECT count(*) FROM messenger_envelopes WHERE envelope_id = decode('04040404040404040404040404040404', 'hex')), ':', (SELECT count(*) FROM messenger_outbox_events WHERE envelope_id = decode('04040404040404040404040404040404', 'hex'))) AS value") ? == "0:0",
  "rate-limited delivery left partial state") ?
  let rate_key = Crypto.sha256(repeated(9, 32))
  expect(allow_request(reopened, rate_key, 2, 60) ?, "first request was limited") ?
  expect(allow_request(reopened, rate_key, 2, 60) ?, "second request was limited") ?
  expect(!allow_request(reopened, rate_key, 2, 60) ?, "rate limit was not enforced") ?
  Pool.close(reopened)
  Ok(true)
end

test("durable backend survives transaction, worker, push, expiry, and abuse failures") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
