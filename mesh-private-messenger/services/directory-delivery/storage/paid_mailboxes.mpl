##! Mailbox extras paid in credits: the postage a device asks for message
##! requests at its public address, and longer storage (protocol/credits-v1.md
##! "Extras").

from Credits.MailboxExtras import (
  credits_decode_policy,
  credits_retention_days,
  credits_retention_price,
  credits_verify_policy,
  credits_verify_retention,
  MailboxRetention
)
from Protocol.MailboxWire import mailbox_request_is_fresh
from Storage.Credits import credits_take_hold_on_connection
from Storage.MailboxAuth import bundle_signing_public_key

pub type PolicyWrite do
  PolicyStored
  PolicyUnchanged
  PolicyStale
  PolicyUnauthorized
  PolicyInvalid
end

pub type RetentionWrite do
  RetentionGranted(days :: Int, until_ms :: Int)
  RetentionUnpaid
  RetentionUnauthorized
  RetentionHoldMissing
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid mailbox extras row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case value do
    Text(text) -> case String.to_int(text) do
      Some(parsed) -> Ok(parsed)
      None -> Err("invalid mailbox extras integer")
    end
    _ -> Err("invalid mailbox extras row")
  end
end

# The signing key of the one active, unrevoked device that owns a mailbox.

fn owner_key(conn :: borrow PgConn, mailbox_hash :: Bytes) -> Option<Bytes>!String do
  let rows = Pg.query_values(conn,
    "SELECT device.prekey_bundle FROM messenger_devices AS device JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = device.mailbox_token_hash WHERE device.mailbox_token_hash = $1 AND device.revoked_at IS NULL AND mailbox.active",
    [Binary(mailbox_hash)])?
  case rows do
    [row] -> Ok(Some(bundle_signing_public_key(binary(Map.get(row, "prekey_bundle"))?)?))
    _ -> Ok(None)
  end
end

fn publish_on_connection(conn :: borrow PgConn, frame :: Bytes) -> PolicyWrite!String do
  let policy = case credits_decode_policy(frame) do
    Err(_) -> return Ok(PolicyInvalid)
    Ok(value) -> value
  end
  let key = case owner_key(conn, policy.mailbox_hash)? do
    None -> return Ok(PolicyUnauthorized)
    Some(value) -> value
  end
  if !credits_verify_policy(policy, key) do
    return Ok(PolicyUnauthorized)
  end
  let changed = Pg.execute_values(conn,
    "INSERT INTO messenger_mailbox_policies (mailbox_token_hash, policy, sequence, postage) VALUES ($1, $2, $3::bigint, $4::smallint) ON CONFLICT (mailbox_token_hash) DO UPDATE SET policy = EXCLUDED.policy, sequence = EXCLUDED.sequence, postage = EXCLUDED.postage, updated_at = date_trunc('minute', now(), 'UTC') WHERE messenger_mailbox_policies.sequence < EXCLUDED.sequence",
    [
      Binary(policy.mailbox_hash),
      Binary(frame),
      Text(Int.to_string(policy.sequence)),
      Text(Int.to_string(policy.postage))
    ])?
  if changed == 1 do
    Ok(PolicyStored)
  else
    let same = Pg.query_values(conn,
      "SELECT 1 FROM messenger_mailbox_policies WHERE mailbox_token_hash = $1 AND policy = $2",
      [Binary(policy.mailbox_hash), Binary(frame)])?
    if List.length(same) == 1 do
      Ok(PolicyUnchanged)
    else
      Ok(PolicyStale)
    end
  end
end

## Stores a device's signed policy for its own mailbox. A policy only replaces
## one with a lower sequence, so an old one cannot come back.

pub fn mailbox_policy_publish(pool :: PoolHandle, frame :: Bytes) -> PolicyWrite!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> publish_on_connection(conn, frame) end)
end

## (postage, the signed MBP) of a mailbox, or None: no price.

pub fn mailbox_policy_on_connection(conn :: borrow PgConn,
  mailbox_hash :: Bytes) -> Option<(Int, Bytes)>!String do
  let rows = Pg.query_values(conn,
    "SELECT postage::text AS postage, policy FROM messenger_mailbox_policies WHERE mailbox_token_hash = $1",
    [Binary(mailbox_hash)])?
  case rows do
    [row] -> Ok(Some((integer(Map.get(row, "postage"))?, binary(Map.get(row, "policy"))?)))
    _ -> Ok(None)
  end
end

## The signed policy of an account's device, for a version 2 prekey claim.

pub fn mailbox_policy_for_device(pool :: PoolHandle,
  account_id :: Bytes,
  device_id :: Bytes) -> Option<Bytes>!String do
  let rows = Pool.query_values(pool,
    "SELECT policy.policy FROM messenger_devices AS device JOIN messenger_mailbox_policies AS policy ON policy.mailbox_token_hash = device.mailbox_token_hash WHERE device.account_id = $1 AND device.device_id = $2 AND device.revoked_at IS NULL",
    [Binary(account_id), Binary(device_id)])?
  case rows do
    [row] -> Ok(Some(binary(Map.get(row, "policy"))?))
    _ -> Ok(None)
  end
end

## The days a mailbox keeps what arrives now: its entitlement, or None.

pub fn mailbox_retention_on_connection(conn :: borrow PgConn,
  mailbox_hash :: Bytes) -> Option<Int>!String do
  let rows = Pg.query_values(conn,
    "SELECT retention_days::text AS days FROM messenger_mailbox_retention WHERE mailbox_token_hash = $1 AND entitled_until > now()",
    [Binary(mailbox_hash)])?
  case rows do
    [row] -> Ok(Some(integer(Map.get(row, "days"))?))
    _ -> Ok(None)
  end
end

fn grant_on_connection(conn :: borrow PgConn,
  request :: MailboxRetention,
  credits :: Int) -> RetentionWrite!String do
  # A refusal rolls back, leaving the hold untaken.
  let key = case owner_key(conn, request.mailbox_hash)? do
    None -> return Err("retention_unauthorized")
    Some(value) -> value
  end
  if !credits_verify_retention(request, key) do
    return Err("retention_unauthorized")
  end
  if credits < credits_retention_price(request.periods) do
    return Err("retention_unpaid")
  end
  let days = credits_retention_days(request.periods)
  # A purchase never shortens what the mailbox already has.
  let rows = Pg.query_values(conn,
    "INSERT INTO messenger_mailbox_retention (mailbox_token_hash, retention_days, entitled_until) VALUES ($1, $2::smallint, now() + $2::integer * interval '1 day') ON CONFLICT (mailbox_token_hash) DO UPDATE SET retention_days = CASE WHEN messenger_mailbox_retention.entitled_until > now() THEN GREATEST(messenger_mailbox_retention.retention_days, EXCLUDED.retention_days) ELSE EXCLUDED.retention_days END, entitled_until = GREATEST(messenger_mailbox_retention.entitled_until, EXCLUDED.entitled_until) RETURNING retention_days::text AS days, floor(extract(epoch FROM entitled_until) * 1000)::bigint::text AS until_ms",
    [Binary(request.mailbox_hash), Text(Int.to_string(days))])?
  case rows do
    [row] -> Ok(RetentionGranted(integer(Map.get(row, "days"))?,
      integer(Map.get(row, "until_ms"))?))
    _ -> Err("storage entitlement failed")
  end
end

fn retention_on_connection(conn :: borrow PgConn,
  redemption_id :: Bytes,
  request :: MailboxRetention) -> RetentionWrite!String do
  case credits_take_hold_on_connection(conn, redemption_id, 2)? do
    None -> Ok(RetentionHoldMissing)
    Some((credits, _binding)) -> grant_on_connection(conn, request, credits)
  end
end

## Longer storage for a mailbox, paid by the storage hold `redemption_id`,
## taken in the same transaction. The request must be fresh (5 minutes) and
## signed by the device that owns the mailbox.

pub fn mailbox_retention_purchase(pool :: PoolHandle,
  redemption_id :: Bytes,
  request :: MailboxRetention,
  now_ms :: Int) -> RetentionWrite!String do
  let fresh = case (U64.parse(Int.to_string(request.issued_at)),
    U64.parse(Int.to_string(now_ms))) do
    (Ok(issued), Ok(now)) -> mailbox_request_is_fresh(issued, now)
    _ -> false
  end
  if !fresh do
    Ok(RetentionUnauthorized)
  else
    let outcome = Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> retention_on_connection(conn, redemption_id, request) end)
    case outcome do
      Err(error) -> if String.contains(error, "retention_unpaid") do
        Ok(RetentionUnpaid)
      else if String.contains(error, "retention_unauthorized") do
        Ok(RetentionUnauthorized)
      else
        Err(error)
      end
      Ok(value)
    end
  end
end
