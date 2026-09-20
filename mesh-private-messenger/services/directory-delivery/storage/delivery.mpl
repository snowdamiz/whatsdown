from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import DeliveredEnvelope, OuterEnvelope
from Storage.MailboxAuth import MailboxOwner
from Storage.ContactAddress import resolve_deposit_address
from Storage.RateLimit import allow_request_on_connection
import RuntimeJobs

pub type DeliveryInsert do
  Accepted

  Duplicate

  MailboxFull

  MailboxRevoked

  RateLimited

  ExpiryRejected
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

# Contacts and strangers are limited separately, so a stranger who exhausts the
# deposit rate cannot stop a contact's envelope getting through.

fn deposit_rate_allowed(conn :: borrow PgConn, mailbox_hash :: Bytes, contact :: Bool) -> Bool ! String do
  if contact do
    allow_request_on_connection(conn, mailbox_hash, 32, 60)
  else
    let bucket = case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/stranger-deposits"), mailbox_hash) do
      Err( _) -> Err("rate bucket allocation failed")
      Ok( joined) -> Ok(Crypto.sha256(joined))
    end ?
    allow_request_on_connection(conn, bucket, 24, 60)
  end
end

# An envelope addressed to a device's contact address belongs to the same
# mailbox, so it is stored under the mailbox's own hash: fetch, acknowledgement,
# deduplication and the delivered envelope are all unchanged.

fn insert_envelope(conn :: borrow PgConn, value :: OuterEnvelope) -> DeliveryInsert ! String do
  let ( token_hash, contact) = resolve_deposit_address(conn, Crypto.sha256(value.mailbox_token)) ?
  let existing = Pg.query_values(conn,
  "SELECT sequence::text FROM messenger_envelopes WHERE mailbox_token_hash = $1 AND envelope_id = $2",
  [Binary(token_hash), Binary(value.envelope_id)]) ?
  if List.length(existing) > 0 do
    Ok(Duplicate)
  else
    let _ = Pg.execute_values(conn,
    "INSERT INTO messenger_envelopes (mailbox_token_hash, envelope_id, suite, expiration_ms, padding_bucket, ciphertext, contact) VALUES ($1, $2, $3::smallint, $4::bigint, $5::integer, $6, $7::boolean)",
    [Binary(token_hash), Binary(value.envelope_id), Text(Int.to_string(value.suite)), Text(U64.to_string(value.expiration)), Text(Int.to_string(value.padding_bucket)), Binary(value.ciphertext), Text(if contact do
      "true"
    else
      "false"
    end)]) ?
    if deposit_rate_allowed(conn, token_hash, contact) ? do
      let _ = Pg.execute_values(conn,
      "INSERT INTO messenger_outbox_events (mailbox_token_hash, envelope_id) VALUES ($1, $2)",
      [Binary(token_hash), Binary(value.envelope_id)]) ?
      RuntimeJobs.notify(conn, "directory") ?
      Ok(Accepted)
    else
      Err("messenger_rate_limited")
    end
  end
end

# A mailbox holds a bounded amount and anyone may deposit into it, so an
# envelope that never expires would hold its space until the owner next comes
# online. A client gives its envelopes 30 days; delivery accepts that plus a day
# of clock skew, and nothing already expired, so a full mailbox always drains by
# itself.

fn expiry_acceptable(expiration :: U64) -> Bool ! String do
  let now = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) ?
  let latest = U64.add(now, U64.parse("2678400000") ?) ?
  Ok(U64.compare(expiration, now) > 0 && U64.compare(expiration, latest) <= 0)
end

pub fn enqueue_envelope(pool :: PoolHandle, value :: OuterEnvelope) -> DeliveryInsert ! String do
  valid_outer(value) ?
  if !(expiry_acceptable(value.expiration) ?) do
    return Ok(ExpiryRejected)
  end
  case Repo.transaction(pool, fn (conn :: borrow PgConn) -> insert_envelope(conn, value) end) do
    Ok( result) -> Ok(result)
    Err( error) -> if String.contains(error, "messenger_envelopes_mailbox_envelope_key") do
      Ok(Duplicate)
    else if String.contains(error, "messenger_mailbox_capacity") do
      Ok(MailboxFull)
    else if String.contains(error, "messenger_mailbox_inactive") do
      Ok(MailboxRevoked)
    else if String.contains(error, "messenger_mailbox_registration") do
      # An address nothing was ever registered under is as final as a revoked
      # one. Answering both alike tells nobody which addresses ever existed, and
      # a sender must be able to give up: a server error would make it retry
      # forever, holding up everything it has queued.
      Ok(MailboxRevoked)
    else if String.contains(error, "messenger_rate_limited") do
      Ok(RateLimited)
    else
      Err(error)
    end
  end
end

fn deliveries(rows :: List < Map < String, DbValue > >, token :: Bytes) -> List < DeliveredEnvelope > ! String do
  let values = for row in rows do
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
    DeliveredEnvelope {
      sequence : wide(Map.get(row, "sequence")) ?,
      envelope : encoded
    }
  end
  Ok(values)
end

## Reads require the `MailboxOwner` produced by `Storage.MailboxAuth`: knowing a
## mailbox address is never enough to read or acknowledge its envelopes.

pub fn fetch_mailbox(pool :: PoolHandle, owner :: MailboxOwner, after_sequence :: U64) -> List < DeliveredEnvelope > ! String do
  let rows = Pool.query_values(pool,
  "SELECT envelope.sequence::text, envelope.envelope_id, envelope.suite::text, envelope.expiration_ms::text, envelope.padding_bucket::text, envelope.ciphertext FROM messenger_envelopes AS envelope JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = envelope.mailbox_token_hash AND mailbox.active WHERE envelope.mailbox_token_hash = $1 AND envelope.sequence > $2::bigint AND envelope.acknowledged_at IS NULL AND envelope.expiration_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint ORDER BY envelope.sequence LIMIT 8",
  [Binary(Crypto.sha256(owner.mailbox_token)), Text(U64.to_string(after_sequence))]) ?
  deliveries(rows, owner.mailbox_token)
end

fn acknowledge_one(conn :: borrow PgConn, token_hash :: Bytes, id :: Bytes) -> Int ! String do
  let changed = Pg.execute_values(conn,
  "UPDATE messenger_envelopes SET acknowledged_at = now() WHERE mailbox_token_hash = $1 AND envelope_id = $2 AND acknowledged_at IS NULL",
  [Binary(token_hash), Binary(id)]) ?
  if changed > 0 do
    RuntimeJobs.notify(conn, "directory") ?
  end
  Ok(changed)
end

fn acknowledge_ids(pool :: PoolHandle,
token_hash :: Bytes,
ids :: List < Bytes >,
index :: Int,
count :: Int) -> Int ! String do
  if index >= List.length(ids) do
    Ok(count)
  else
    let changed = Repo.transaction(pool,
    fn (conn :: borrow PgConn) -> acknowledge_one(conn, token_hash, List.get(ids, index)) end) ?
    acknowledge_ids(pool, token_hash, ids, index + 1, count + changed)
  end
end

pub fn acknowledge_mailbox(pool :: PoolHandle,
owner :: MailboxOwner,
envelope_ids :: List < Bytes >) -> Int ! String do
  acknowledge_ids(pool, Crypto.sha256(owner.mailbox_token), envelope_ids, 0, 0)
end
