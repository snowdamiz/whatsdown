from Protocol.V1 import DeliveredEnvelope, MailboxAck, MailboxFetch, OuterEnvelope, encode_mailbox_ack, encode_mailbox_fetch, encode_outer_envelope
from Storage.RateLimit import allow_request_on_connection

pub type DeliveryInsert do
  Accepted

  Duplicate

  MailboxFull

  MailboxRevoked

  RateLimited
end deriving(Eq, Debug)

fn binary(value :: DbValue) -> Bytes ! String do
  case value do
    Binary( bytes) -> Ok(bytes)
    _ -> Err("invalid delivery row")
  end
end

fn text(value :: DbValue) -> String ! String do
  case value do
    Text( output) -> Ok(output)
    _ -> Err("invalid delivery row")
  end
end

fn integer(value :: DbValue) -> Int ! String do
  case String.to_int(text(value) ?) do
    None -> Err("invalid delivery integer")
    Some( output) -> Ok(output)
  end
end

fn wide(value :: DbValue) -> U64 ! String do
  U64.parse(text(value) ?)
end

fn valid_outer(value :: OuterEnvelope) -> Result <(), String > do
  case encode_outer_envelope(value) do
    Err( _) -> Err("invalid outer envelope")
    Ok( _) -> Ok(nil)
  end
end

fn insert_envelope(conn :: borrow PgConn, value :: OuterEnvelope) -> DeliveryInsert ! String do
  let token_hash = Crypto.sha256(value.mailbox_token)
  let existing = Pg.query_values(conn,
  "SELECT sequence::text FROM messenger_envelopes WHERE mailbox_token_hash = $1 AND envelope_id = $2",
  [Binary(token_hash), Binary(value.envelope_id)]) ?
  if List.length(existing) > 0 do
    Ok(Duplicate)
  else
    let _ = Pg.execute_values(conn,
    "INSERT INTO messenger_envelopes (mailbox_token_hash, envelope_id, suite, expiration_ms, padding_bucket, ciphertext) VALUES ($1, $2, $3::smallint, $4::bigint, $5::integer, $6)",
    [Binary(token_hash), Binary(value.envelope_id), Text(Int.to_string(value.suite)), Text(U64.to_string(value.expiration)), Text(Int.to_string(value.padding_bucket)), Binary(value.ciphertext)]) ?
    if allow_request_on_connection(conn, token_hash, 32, 60) ? do
      let _ = Pg.execute_values(conn,
      "INSERT INTO messenger_outbox_events (mailbox_token_hash, envelope_id) VALUES ($1, $2)",
      [Binary(token_hash), Binary(value.envelope_id)]) ?
      Ok(Accepted)
    else
      Err("messenger_rate_limited")
    end
  end
end

pub fn enqueue_envelope(pool :: PoolHandle, value :: OuterEnvelope) -> DeliveryInsert ! String do
  valid_outer(value) ?
  case Repo.transaction(pool, fn (conn :: borrow PgConn) -> insert_envelope(conn, value) end) do
    Ok( result) -> Ok(result)
    Err( error) -> if String.contains(error, "messenger_envelopes_mailbox_envelope_key") do
      Ok(Duplicate)
    else
      if String.contains(error, "messenger_mailbox_capacity") do
        Ok(MailboxFull)
      else
        if String.contains(error, "messenger_mailbox_inactive") do
          Ok(MailboxRevoked)
        else
          if String.contains(error, "messenger_rate_limited") do
            Ok(RateLimited)
          else
            Err(error)
          end
        end
      end
    end
  end
end

fn deliveries(rows :: List < Map < String, DbValue > >,
token :: Bytes,
index :: Int,
output :: List < DeliveredEnvelope >) -> List < DeliveredEnvelope > ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    let row = List.get(rows, index)
    let envelope = OuterEnvelope {
      version : 1,
      envelope_id : binary(Map.get(row, "envelope_id")) ?,
      mailbox_token : token,
      suite : integer(Map.get(row, "suite")) ?,
      expiration : wide(Map.get(row, "expiration_ms")) ?,
      padding_bucket : integer(Map.get(row, "padding_bucket")) ?,
      ciphertext : binary(Map.get(row, "ciphertext")) ?
    }
    let encoded = case encode_outer_envelope(envelope) do
      Err( _) -> Err("invalid stored envelope")
      Ok( value) -> Ok(value)
    end ?
    deliveries(rows,
    token,
    index + 1,
    List.append(output,
    DeliveredEnvelope {
      sequence : wide(Map.get(row, "sequence")) ?,
      envelope : encoded
    }))
  end
end

pub fn fetch_mailbox(pool :: PoolHandle, request :: MailboxFetch) -> List < DeliveredEnvelope > ! String do
  case encode_mailbox_fetch(request) do
    Err( _) -> Err("invalid mailbox fetch")
    Ok( _) -> Ok(nil)
  end ?
  let rows = Pool.query_values(pool,
  "SELECT envelope.sequence::text, envelope.envelope_id, envelope.suite::text, envelope.expiration_ms::text, envelope.padding_bucket::text, envelope.ciphertext FROM messenger_envelopes AS envelope JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = envelope.mailbox_token_hash AND mailbox.active WHERE envelope.mailbox_token_hash = $1 AND envelope.sequence > $2::bigint AND envelope.acknowledged_at IS NULL AND envelope.expiration_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint ORDER BY envelope.sequence LIMIT 8",
  [Binary(Crypto.sha256(request.mailbox_token)), Text(U64.to_string(request.after_sequence))]) ?
  deliveries(rows, request.mailbox_token, 0, List.new())
end

fn acknowledge_ids(pool :: PoolHandle,
token_hash :: Bytes,
ids :: List < Bytes >,
index :: Int,
count :: Int) -> Int ! String do
  if index >= List.length(ids) do
    Ok(count)
  else
    let changed = Pool.execute_values(pool,
    "UPDATE messenger_envelopes SET acknowledged_at = now() WHERE mailbox_token_hash = $1 AND envelope_id = $2 AND acknowledged_at IS NULL",
    [Binary(token_hash), Binary(List.get(ids, index))]) ?
    acknowledge_ids(pool, token_hash, ids, index + 1, count + changed)
  end
end

pub fn acknowledge_mailbox(pool :: PoolHandle, ack :: MailboxAck) -> Int ! String do
  case encode_mailbox_ack(ack) do
    Err( _) -> Err("invalid mailbox acknowledgement")
    Ok( _) -> Ok(nil)
  end ?
  acknowledge_ids(pool, Crypto.sha256(ack.mailbox_token), ack.envelope_ids, 0, 0)
end
