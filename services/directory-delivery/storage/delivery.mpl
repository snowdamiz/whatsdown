from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import DeliveredEnvelope, OuterEnvelope
from Storage.MailboxAuth import MailboxOwner
from Storage.ContactAddress import resolve_deposit_address
from Storage.RateLimit import allow_request_on_connection
from Storage.Credits import credits_take_hold_on_connection
from Storage.PaidMailboxes import mailbox_policy_on_connection, mailbox_retention_on_connection
import RuntimeJobs

pub type DeliveryInsert do
  Accepted
  Duplicate
  MailboxFull
  MailboxRevoked
  RateLimited
  ExpiryRejected
  PostageRequired(policy :: Bytes)
end deriving(Eq, Debug)

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid delivery row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid delivery row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    None -> Err("invalid delivery integer")
    Some(output) -> Ok(output)
  end
end

fn wide(value :: DbValue) -> U64!String do
  U64.parse(text(value)?)
end

fn valid_outer(value :: OuterEnvelope) -> Result<(), String> do
  case encode_outer_envelope(value) do
    Err(_) -> Err("invalid outer envelope")
    Ok(_) -> Ok(nil)
  end
end

# Contacts and strangers are limited separately, so a stranger who exhausts the
# deposit rate cannot stop a contact's envelope getting through.

fn deposit_rate_allowed(conn :: borrow PgConn,
  mailbox_hash :: Bytes,
  contact :: Bool) -> Bool!String do
  if contact do
    allow_request_on_connection(conn, mailbox_hash, 32, 60)
  else
    let bucket = case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/stranger-deposits"),
      mailbox_hash) do
      Err(_) -> Err("rate bucket allocation failed")
      Ok(joined) -> Ok(Crypto.sha256(joined))
    end?
    allow_request_on_connection(conn, bucket, 24, 60)
  end
end

# An envelope addressed to a device's contact address belongs to the same
# mailbox, so it is stored under the mailbox's own hash: fetch, acknowledgement,
# deduplication and the delivered envelope are all unchanged.

# What a public-address envelope must still pay: the mailbox's signed policy
# when its postage exceeds `paid` credits. A contact-address envelope never
# pays.

fn postage_due(conn :: borrow PgConn,
  token_hash :: Bytes,
  contact :: Bool,
  paid :: Int) -> Option<Bytes>!String do
  if contact do
    Ok(None)
  else
    case mailbox_policy_on_connection(conn, token_hash)? do
      Some((postage, policy)) -> if postage > paid do
        Ok(Some(policy))
      else
        Ok(None)
      end
      None -> Ok(None)
    end
  end
end

# An entitled mailbox accepts envelopes up to its retention (plus the day of
# skew) and keeps each at least that long from its arrival; any other keeps
# the sender's expiry, at most 31 days ahead.

fn stored_expiration(conn :: borrow PgConn,
  token_hash :: Bytes,
  expiration :: U64) -> Option<U64>!String do
  let now = DateTime.to_unix_ms(DateTime.utc_now())
  let days = case mailbox_retention_on_connection(conn, token_hash)? do
    Some(value) -> value
    None -> 30
  end
  let requested = U64.to_int(expiration)?
  if requested > now + (days + 1) * 86400000 do
    Ok(None)
  else if days > 30 && requested < now + days * 86400000 do
    Ok(Some(U64.parse(Int.to_string(now + days * 86400000))?))
  else
    Ok(Some(expiration))
  end
end

fn insert_envelope(conn :: borrow PgConn, value :: OuterEnvelope) -> DeliveryInsert!String do
  insert_paid_envelope(conn, value, 0)
end

fn insert_paid_envelope(conn :: borrow PgConn,
  value :: OuterEnvelope,
  paid :: Int) -> DeliveryInsert!String do
  let (token_hash, contact) = resolve_deposit_address(conn, Crypto.sha256(value.mailbox_token))?
  let existing = Pg.query_values(conn,
    "SELECT sequence::text FROM messenger_envelopes WHERE mailbox_token_hash = $1 AND envelope_id = $2",
    [Binary(token_hash), Binary(value.envelope_id)])?
  if List.length(existing) > 0 do
    return Ok(Duplicate)
  end
  case postage_due(conn, token_hash, contact, paid)? do
    Some(policy) -> return Ok(PostageRequired(policy))
    None -> nil
  end
  case stored_expiration(conn, token_hash, value.expiration)? do
    None -> Ok(ExpiryRejected)
    Some(expiration) -> store_envelope(conn, %{value | expiration: expiration}, token_hash, contact)
  end
end

fn store_envelope(conn :: borrow PgConn,
  value :: OuterEnvelope,
  token_hash :: Bytes,
  contact :: Bool) -> DeliveryInsert!String do
  Pg.execute_values(conn,
    "INSERT INTO messenger_envelopes (mailbox_token_hash, envelope_id, suite, expiration_ms, padding_bucket, ciphertext, contact) VALUES ($1, $2, $3::smallint, $4::bigint, $5::integer, $6, $7::boolean)",
    [
      Binary(token_hash),
      Binary(value.envelope_id),
      Text(Int.to_string(value.suite)),
      Text(U64.to_string(value.expiration)),
      Text(Int.to_string(value.padding_bucket)),
      Binary(value.ciphertext),
      Text(if contact do
        "true"
      else
        "false"
      end)
    ])?
  if deposit_rate_allowed(conn, token_hash, contact)? do
    Pg.execute_values(conn,
      "INSERT INTO messenger_outbox_events (mailbox_token_hash, envelope_id) VALUES ($1, $2)",
      [Binary(token_hash), Binary(value.envelope_id)])?
    RuntimeJobs.notify(conn, "directory")?
    Ok(Accepted)
  else
    Err("messenger_rate_limited")
  end
end

# A mailbox holds a bounded amount and anyone may deposit into it, so an
# envelope that never expires would hold its space until the owner next comes
# online. A client gives its envelopes 30 days; delivery accepts that plus a day
# of clock skew, and nothing already expired, so a full mailbox always drains by
# itself.

# Checked before the database: nothing already expired, and nothing past the
# longest storage any mailbox can have (180 days plus the day). The mailbox's
# own limit is checked in the insert (stored_expiration).

fn expiry_acceptable(expiration :: U64) -> Bool!String do
  let now = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?
  let latest = U64.add(now, U64.parse("15638400000")?)?
  Ok(U64.compare(expiration, now) > 0 && U64.compare(expiration, latest) <= 0)
end

pub fn enqueue_envelope(pool :: PoolHandle, value :: OuterEnvelope) -> DeliveryInsert!String do
  valid_outer(value)?
  if !(expiry_acceptable(value.expiration)?) do
    return Ok(ExpiryRejected)
  end
  delivery_outcome(Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> insert_envelope(conn, value) end))
end

fn delivery_outcome(result :: DeliveryInsert!String) -> DeliveryInsert!String do
  case result do
    Ok(inserted)
    Err(error) -> if String.contains(error, "messenger_envelopes_mailbox_envelope_key") do
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

# The hold goes with the envelope: taken in the envelope's own transaction, so
# a rolled-back insert leaves it, and one hold delivers one envelope.

fn insert_held_envelope(conn :: borrow PgConn,
  value :: OuterEnvelope,
  redemption_id :: Bytes) -> DeliveryInsert!String do
  case credits_take_hold_on_connection(conn, redemption_id, 1)? do
    None -> Err("credit_hold_missing")
    Some((credits, _binding)) -> insert_paid_envelope(conn, value, credits)
  end
end

## As enqueue_envelope, for an envelope the privacy edge was paid for in
## credits: it takes the envelope hold `redemption_id` names in the same
## transaction. Err "credit_hold_missing" when there is none to take.

pub fn enqueue_held_envelope(pool :: PoolHandle,
  value :: OuterEnvelope,
  redemption_id :: Bytes) -> DeliveryInsert!String do
  valid_outer(value)?
  if !(expiry_acceptable(value.expiration)?) do
    return Ok(ExpiryRejected)
  end
  delivery_outcome(Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> insert_held_envelope(conn, value, redemption_id) end))
end

fn deliveries(rows :: List<Map<String, DbValue>>,
  token :: Bytes) -> List<DeliveredEnvelope>!String do
  let values = for row in rows do
    let envelope = OuterEnvelope {
      version: 1,
      envelope_id: binary(Map.get(row, "envelope_id"))?,
      mailbox_token: token,
      suite: integer(Map.get(row, "suite"))?,
      expiration: wide(Map.get(row, "expiration_ms"))?,
      padding_bucket: integer(Map.get(row, "padding_bucket"))?,
      ciphertext: binary(Map.get(row, "ciphertext"))?
    }
    let encoded = case encode_outer_envelope(envelope) do
      Err(_) -> Err("invalid stored envelope")
      Ok(value)
    end?
    DeliveredEnvelope { sequence: wide(Map.get(row, "sequence"))?, envelope: encoded }
  end
  Ok(values)
end

## Reads require the `MailboxOwner` produced by `Storage.MailboxAuth`: knowing a
## mailbox address is never enough to read or acknowledge its envelopes.

pub fn fetch_mailbox(pool :: PoolHandle,
  owner :: MailboxOwner,
  after_sequence :: U64) -> List<DeliveredEnvelope>!String do
  let rows = Pool.query_values(pool,
    "SELECT envelope.sequence::text, envelope.envelope_id, envelope.suite::text, envelope.expiration_ms::text, envelope.padding_bucket::text, envelope.ciphertext FROM messenger_envelopes AS envelope JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = envelope.mailbox_token_hash AND mailbox.active WHERE envelope.mailbox_token_hash = $1 AND envelope.sequence > $2::bigint AND envelope.acknowledged_at IS NULL AND envelope.expiration_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint ORDER BY envelope.sequence LIMIT 8",
    [Binary(Crypto.sha256(owner.mailbox_token)), Text(U64.to_string(after_sequence))])?
  deliveries(rows, owner.mailbox_token)
end

fn acknowledge_one(conn :: borrow PgConn, token_hash :: Bytes, id :: Bytes) -> Int!String do
  let changed = Pg.execute_values(conn,
    "UPDATE messenger_envelopes SET acknowledged_at = now() WHERE mailbox_token_hash = $1 AND envelope_id = $2 AND acknowledged_at IS NULL",
    [Binary(token_hash), Binary(id)])?
  if changed > 0 do
    RuntimeJobs.notify(conn, "directory")?
  end
  Ok(changed)
end

fn acknowledge_ids(pool :: PoolHandle,
  token_hash :: Bytes,
  ids :: List<Bytes>,
  index :: Int,
  count :: Int) -> Int!String do
  if index >= List.length(ids) do
    Ok(count)
  else
    let changed = Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> acknowledge_one(conn, token_hash, List.get(ids, index)) end)?
    acknowledge_ids(pool, token_hash, ids, index + 1, count + changed)
  end
end

pub fn acknowledge_mailbox(pool :: PoolHandle,
  owner :: MailboxOwner,
  envelope_ids :: List<Bytes>) -> Int!String do
  acknowledge_ids(pool, Crypto.sha256(owner.mailbox_token), envelope_ids, 0, 0)
end
