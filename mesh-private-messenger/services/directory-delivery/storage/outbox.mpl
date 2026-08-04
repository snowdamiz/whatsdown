pub struct OutboxEvent do
  event_id :: String
  mailbox_token_hash :: Bytes
  attempts :: Int
end

pub type PushResult do
  PushDelivered

  PushRetryable( String)

  PushPermanent( String)
end

fn binary(value :: DbValue) -> Bytes ! String do
  case value do
    Binary( bytes) -> Ok(bytes)
    _ -> Err("invalid outbox row")
  end
end

fn text(value :: DbValue) -> String ! String do
  case value do
    Text( output) -> Ok(output)
    _ -> Err("invalid outbox row")
  end
end

fn integer(value :: DbValue) -> Int ! String do
  case String.to_int(text(value) ?) do
    None -> Err("invalid outbox integer")
    Some( output) -> Ok(output)
  end
end

fn decode_events(rows :: List < Map < String, DbValue > >,
index :: Int,
events :: List < OutboxEvent >) -> List < OutboxEvent > ! String do
  if index >= List.length(rows) do
    Ok(events)
  else
    let row = List.get(rows, index)
    decode_events(rows,
    index + 1,
    List.append(events,
    OutboxEvent {
      event_id : text(Map.get(row, "event_id")) ?,
      mailbox_token_hash : binary(Map.get(row, "mailbox_token_hash")) ?,
      attempts : integer(Map.get(row, "attempts")) ?
    }))
  end
end

fn valid_lease(owner :: String, limit :: Int, lease_seconds :: Int) -> Result <(), String > do
  if String.length(owner) == 0 || String.length(owner) > 128 || limit <= 0 || limit > 32 || lease_seconds <= 0 || lease_seconds > 300 do
    Err("invalid outbox lease")
  else
    Ok(nil)
  end
end

pub fn lease_outbox(pool :: PoolHandle, owner :: String, limit :: Int, lease_seconds :: Int) -> List < OutboxEvent > ! String do
  valid_lease(owner, limit, lease_seconds) ?
  let rows = Pool.query_values(pool,
  "WITH exhausted AS (UPDATE messenger_outbox_events SET status = 'permanent_failure', completed_at = clock_timestamp(), lease_owner = NULL, lease_expires_at = NULL, last_error_code = 'lease_attempts_exhausted' WHERE status = 'leased' AND attempts >= 5 AND lease_expires_at <= clock_timestamp()), candidates AS (SELECT event_id FROM messenger_outbox_events WHERE completed_at IS NULL AND attempts < 5 AND available_at <= clock_timestamp() AND (status IN ('pending', 'retryable_failure') OR (status = 'leased' AND lease_expires_at <= clock_timestamp())) ORDER BY created_at, event_id FOR UPDATE SKIP LOCKED LIMIT $2::integer) UPDATE messenger_outbox_events AS event SET status = 'leased', lease_owner = $1, lease_expires_at = clock_timestamp() + ($3::integer * interval '1 second'), attempts = event.attempts + 1, last_error_code = NULL FROM candidates WHERE event.event_id = candidates.event_id RETURNING event.event_id::text, event.mailbox_token_hash, event.attempts::text",
  [Text(owner), Text(Int.to_string(limit)), Text(Int.to_string(lease_seconds))]) ?
  decode_events(rows, 0, List.new())
end

fn expect_fenced_update(changed :: Int) -> Result <(), String > do
  if changed == 1 do
    Ok(nil)
  else
    Err("outbox lease lost")
  end
end

fn complete(pool :: PoolHandle,
event :: OutboxEvent,
owner :: String,
status :: String,
error_code :: String) -> Result <(), String > do
  let changed = Pool.execute_values(pool,
  "UPDATE messenger_outbox_events SET status = $3, completed_at = clock_timestamp(), lease_owner = NULL, lease_expires_at = NULL, last_error_code = NULLIF(left($4, 64), '') WHERE event_id = $1::uuid AND status = 'leased' AND lease_owner = $2 AND lease_expires_at > clock_timestamp()",
  [Text(event.event_id), Text(owner), Text(status), Text(error_code)]) ?
  expect_fenced_update(changed)
end

fn retry(pool :: PoolHandle, event :: OutboxEvent, owner :: String, error_code :: String) -> Result <(), String > do
  let changed = Pool.execute_values(pool,
  "UPDATE messenger_outbox_events SET status = CASE WHEN attempts >= 5 THEN 'permanent_failure' ELSE 'retryable_failure' END, completed_at = CASE WHEN attempts >= 5 THEN clock_timestamp() ELSE NULL END, available_at = CASE WHEN attempts >= 5 THEN available_at ELSE clock_timestamp() + (LEAST(60, (1 << LEAST(attempts - 1, 5))) * interval '1 second') END, lease_owner = NULL, lease_expires_at = NULL, last_error_code = left($3, 64) WHERE event_id = $1::uuid AND status = 'leased' AND lease_owner = $2 AND lease_expires_at > clock_timestamp()",
  [Text(event.event_id), Text(owner), Text(error_code)]) ?
  expect_fenced_update(changed)
end

pub fn finish_outbox(pool :: PoolHandle,
event :: OutboxEvent,
owner :: String,
result :: PushResult) -> Result <(), String > do
  case result do
    PushDelivered -> complete(pool, event, owner, "delivered", "")
    PushRetryable( error_code) -> retry(pool, event, owner, error_code)
    PushPermanent( error_code) -> complete(pool, event, owner, "permanent_failure", error_code)
  end
end
