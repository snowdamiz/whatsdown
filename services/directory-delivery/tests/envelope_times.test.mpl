from Protocol.V1 import OuterEnvelope
from Storage.Delivery import DeliveryInsert, acknowledge_mailbox, enqueue_envelope
from Storage.MailboxAuth import MailboxOwner
from Storage.Outbox import PushResult, finish_outbox, lease_outbox

# Delivery keeps an envelope's times to the minute: when it arrived, when it was
# acknowledged, when its push wake was queued and finished, and when the
# mailbox's rate window opened. The database rounds an envelope's own times
# whatever the writer sends.

fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test allocation failed")
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

# How many of the named times are not on a whole minute, and how many are set.

fn exact_times(pool :: PoolHandle) -> String!String do
  scalar(pool,
    "SELECT concat((SELECT count(*) FILTER (WHERE received_at <> date_trunc('minute', received_at, 'UTC') OR acknowledged_at <> date_trunc('minute', acknowledged_at, 'UTC')) FROM messenger_envelopes), ':', (SELECT count(acknowledged_at) FROM messenger_envelopes), ':', (SELECT count(*) FILTER (WHERE created_at <> date_trunc('minute', created_at, 'UTC') OR completed_at <> date_trunc('minute', completed_at, 'UTC') OR (completed_at IS NOT NULL AND available_at <> date_trunc('minute', available_at, 'UTC'))) FROM messenger_outbox_events), ':', (SELECT count(completed_at) FROM messenger_outbox_events), ':', (SELECT count(*) FILTER (WHERE window_started_at <> date_trunc('minute', window_started_at, 'UTC')) FROM messenger_rate_limits), ':', (SELECT count(*) FROM messenger_rate_limits)) AS value")
end

fn proof() -> Result<(), String> do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", ""), 1, 2, 5000)?
  Pool.execute(pool,
    "TRUNCATE messenger_mailbox_aliases, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_mailboxes RESTART IDENTITY CASCADE",
    [])?
  let token = repeated(21, 32)?
  Pool.execute_values(pool,
    "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($1)",
    [Binary(Crypto.sha256(token))])?
  let expiration = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()) + 3600000))?
  case enqueue_envelope(pool,
    OuterEnvelope {
      version: 1,
      envelope_id: repeated(1, 16)?,
      mailbox_token: token,
      suite: 4,
      expiration: expiration,
      padding_bucket: 256,
      ciphertext: Bytes.from_utf8("sealed")
    })? do
    Accepted -> Ok(nil)
    _ -> Err("envelope was refused")
  end?
  check(exact_times(pool)? == "0:0:0:0:0:1", "an arrival time was stored exactly")?
  let events = lease_outbox(pool, "times-test", 1, 30)?
  check(List.length(events) == 1, "the push wake was not queued")?
  finish_outbox(pool, List.head(events), "times-test", PushDelivered)?
  let owner = MailboxOwner { mailbox_token: token, signing_public_key: repeated(0, 32)? }
  check(acknowledge_mailbox(pool, owner, [repeated(1, 16)?])? == 1, "acknowledgement failed")?
  check(exact_times(pool)? == "0:1:0:1:0:1", "an acknowledgement or push time was stored exactly")?
  # Whatever a writer sends, an older directory's included, the minute is stored.
  Pool.execute(pool,
    "UPDATE messenger_envelopes SET received_at = received_at + interval '17 seconds', acknowledged_at = clock_timestamp()",
    [])?
  check(exact_times(pool)? == "0:1:0:1:0:1", "the database stored an exact envelope time")?
  Pool.execute(pool,
    "TRUNCATE messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_mailboxes RESTART IDENTITY CASCADE",
    [])?
  Pool.close(pool)
  Ok(nil)
end

test("delivery keeps envelope times to the minute") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
