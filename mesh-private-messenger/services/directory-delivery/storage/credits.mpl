from Credits.Action import (
  CreditAction,
  encode_credit_action,
  credit_action_id,
  validate_credit_action,
  credit_action_price
)
from Credits.Token import CreditSpend, verify_credit_frame
from Credits.Wire import CreditFrame, encode_credit_frame
from Storage.PostagePolicyState import postage_price_on_connection
from Storage.CreditOperation import lock_credit_operation, ensure_credit_operation_active
from Storage.CreditIssuers import (
  credit_now,
  configured_credit_purpose,
  core_credit_service_key,
  admitted_credit_keys_on_connection
)
import RuntimeJobs
from Runtime.WorkPolicy import configured_signup_difficulty

pub struct CreditHold do
  id :: Bytes
  action :: Bytes
  credits :: Int
  expires_at :: U64
  retain_until :: U64
  state :: String
  effect_id :: Bytes
end

pub struct CreditRedemption do
  created :: Bool
  hold :: CreditHold
end

pub type CreditHoldUse do
  HoldApplied
  HoldAlreadyApplied
end deriving(Eq, Debug)

pub struct CreditPruneResult do
  spent :: Int
  holds :: Int
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_credit_row")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_credit_row")
  end
end

fn number(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    None -> Err("invalid_credit_row")
    Some(output) -> Ok(output)
  end
end

fn read_hold(row :: Map<String, DbValue>) -> CreditHold!String do
  Ok(CreditHold {
    id: binary(Map.get(row, "hold_id"))?,
    action: binary(Map.get(row, "action"))?,
    credits: number(Map.get(row, "credits"))?,
    expires_at: U64.parse(text(Map.get(row, "expires_at"))?)?,
    retain_until: U64.parse(text(Map.get(row, "retain_until"))?)?,
    state: text(Map.get(row, "state"))?,
    effect_id: binary(Map.get(row, "effect_id"))?
  })
end

fn hold_rows(conn :: borrow PgConn, id :: Bytes) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT hold_id, action, frame_hash, credits::text, expires_at::text, retain_until::text, COALESCE(effect_id, ''::bytea) AS effect_id, CASE WHEN consumed_at IS NOT NULL THEN 'consumed' WHEN expires_at <= floor(extract(epoch FROM clock_timestamp()))::bigint THEN 'expired' ELSE 'held' END AS state FROM credit_holds WHERE hold_id = $1 FOR UPDATE",
    [Binary(id)])
end

fn retry(row :: Map<String, DbValue>,
  action :: Bytes,
  frame_hash :: Bytes) -> CreditRedemption!String do
  if !Bytes.secure_equals(binary(Map.get(row, "action"))?, action)
    || !Bytes.secure_equals(binary(Map.get(row, "frame_hash"))?, frame_hash) do
    return Err("credit_operation_conflict")
  end
  Ok(CreditRedemption { created: false, hold: read_hold(row)? })
end

fn price(conn :: borrow PgConn, action :: CreditAction) -> Int!String do
  let postage = if action.kind == 3 do
    postage_price_on_connection(conn, action.target)?
  else
    0
  end
  if action.kind == 2 do
    if List.length(Pg.query_values(conn,
      "SELECT mailbox_token_hash FROM messenger_mailboxes WHERE mailbox_token_hash = $1 AND active FOR SHARE",
      [Binary(action.target)])?) != 1 do
      return Err("unknown_credit_mailbox")
    end
  else
    nil
  end
  credit_action_price(action,
    postage,
    Env.get_int("MESSENGER_ABUSE_BASE_DIFFICULTY", 16),
    configured_signup_difficulty())
end

fn spend_json(spends :: List<CreditSpend>) -> String do
  let rows = for spend in spends do
    "{\"n\":"
      <> Json.encode_string(Bytes.to_hex(spend.nullifier))
      <> ",\"e\":"
      <> Json.encode_string(U64.to_string(spend.epoch))
      <> ",\"r\":"
      <> Json.encode_string(U64.to_string(spend.retain_until))
      <> "}"
  end
  "[" <> String.join(rows, ",") <> "]"
end

fn redeem(conn :: borrow PgConn,
  action :: CreditAction,
  request_body :: Bytes,
  frame :: CreditFrame) -> CreditRedemption!String do
  let encoded = encode_credit_action(action)?
  let frame_hash = Crypto.sha256(encode_credit_frame(frame)?)
  let id = credit_action_id(action)?
  lock_credit_operation(conn, id)?
  ensure_credit_operation_active(conn, id)?
  # Look up durable identity before expiry/key-window checks: a lost response
  # retries the original hold, including after it was applied or expired.
  let existing = hold_rows(conn, id)?
  if List.length(existing) == 1 do
    if !Bytes.secure_equals(action.request_sha256, Crypto.sha256(request_body)) do
      return Err("credit_action_request_mismatch")
    end
    return retry(List.head(existing), encoded, frame_hash)
  end
  let now = credit_now(conn)?
  validate_credit_action(action, request_body, now)?
  let amount = price(conn, action)?
  if amount < 1 do
    return Err("credit_not_required")
  end
  let purpose = configured_credit_purpose()?
  let keys = admitted_credit_keys_on_connection(conn, now, purpose)?
  let service_key = core_credit_service_key()?
  let spends = verify_credit_frame(frame,
    request_body,
    amount,
    keys,
    service_key.bytes,
    now,
    purpose)?
  let retain_until = List.reduce(spends,
    U64.parse("0")?,
    fn(maximum, spend) do
      if U64.compare(spend.retain_until, maximum) > 0 do
        spend.retain_until
      else
        maximum
      end
    end)
  let inserted = Pg.query_values(conn,
    "INSERT INTO credit_holds (hold_id, action, action_kind, target, request_hash, frame_hash, credits, expires_at, retain_until) VALUES ($1, $2, $3::smallint, $4, $5, $6, $7::smallint, $8::bigint, $9::bigint) ON CONFLICT DO NOTHING RETURNING hold_id",
    [
      Binary(id),
      Binary(encoded),
      Text(Int.to_string(action.kind)),
      Binary(action.target),
      Binary(action.request_sha256),
      Binary(frame_hash),
      Text(Int.to_string(amount)),
      Text(U64.to_string(action.expires_at)),
      Text(U64.to_string(retain_until))
    ])?
  if List.length(inserted) == 0 do
    let won = hold_rows(conn, id)?
    if List.length(won) != 1 do
      return Err("credit_operation_conflict")
    end
    return retry(List.head(won), encoded, frame_hash)
  end
  # Sorted insertion prevents cycles when different frames overlap in several
  # tokens. Partial ON CONFLICT success is an ERROR for Repo.transaction, so
  # every fresh insert and the new hold roll back if even one token was spent.
  let counts = Pg.query_values(conn,
    "WITH proposed AS (SELECT decode(n, 'hex') AS nullifier, e::bigint AS epoch, r::bigint AS retention FROM jsonb_to_recordset($1::jsonb) AS j(n text, e text, r text)), inserted AS (INSERT INTO credit_spent (nullifier, issuer_epoch, retain_until, hold_id) SELECT nullifier, epoch, retention, $2 FROM proposed ORDER BY nullifier ON CONFLICT DO NOTHING RETURNING nullifier) SELECT count(*)::text AS count FROM inserted",
    [Text(spend_json(spends)), Binary(id)])?
  if number(Map.get(List.head(counts), "count"))? != amount do
    return Err("credit_already_spent")
  end
  # The wakeup must become durable before spending commits. A registrar outage
  # aborts this transaction, leaving every token available for the exact retry.
  RuntimeJobs.notify(conn, "directory")?
  let rows = hold_rows(conn, id)?
  Ok(CreditRedemption { created: true, hold: read_hold(List.head(rows))? })
end

pub fn redeem_credits(pool :: PoolHandle,
  action :: CreditAction,
  request_body :: Bytes,
  frame :: CreditFrame) -> CreditRedemption!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> redeem_credits_on_connection(conn,
      action,
      request_body,
      frame) end)
end

# Action adapters authenticate actual inputs first, then call this in the SAME
# transaction as hold consumption, effect and immutable completion receipt.
pub fn redeem_credits_on_connection(conn :: borrow PgConn,
  action :: CreditAction,
  request_body :: Bytes,
  frame :: CreditFrame) -> CreditRedemption!String do
  if Bytes.length(request_body) > 65536 do
    return Err("credit_request_too_large")
  end
  encode_credit_action(action)?
  encode_credit_frame(frame)?
  redeem(conn, action, request_body, frame)
end

# This MUST run inside the same Repo.transaction as the actual DB action or a
# durable service-effect record. On HoldApplied perform that effect; on
# HoldAlreadyApplied recover its stored result. There is deliberately no
# one-shot HTTP consume endpoint whose lost response could lose the action.
pub fn consume_credit_hold_on_connection(conn :: borrow PgConn,
  action :: CreditAction,
  effect_id :: Bytes) -> CreditHoldUse!String do
  if Bytes.length(effect_id) != 32
    || Bytes.secure_equals(effect_id, Bytes.from_hex(String.repeat("00", 32))?) do
    return Err("invalid_credit_effect")
  end
  let id = credit_action_id(action)?
  lock_credit_operation(conn, id)?
  ensure_credit_operation_active(conn, id)?
  let rows = hold_rows(conn, id)?
  if List.length(rows) != 1 do
    return Err("unknown_credit_hold")
  end
  let hold = read_hold(List.head(rows))?
  if !Bytes.secure_equals(hold.action, encode_credit_action(action)?) do
    return Err("credit_operation_conflict")
  end
  if hold.state == "consumed" do
    if Bytes.secure_equals(hold.effect_id, effect_id) do
      return Ok(HoldAlreadyApplied)
    end
    return Err("credit_effect_conflict")
  end
  if hold.state == "expired" do
    return Err("expired_credit_action")
  end
  Pg.execute_values(conn,
    "UPDATE credit_holds SET effect_id = $2, consumed_at = clock_timestamp() WHERE hold_id = $1",
    [Binary(id), Binary(effect_id)])?
  Ok(HoldApplied)
end

fn prune(conn :: borrow PgConn, limit :: Int) -> CreditPruneResult!String do
  let now = U64.to_string(credit_now(conn)?)
  Pg.execute_values(conn,
    "WITH expired AS (SELECT hold_id FROM credit_cancellations WHERE retain_until < $1::bigint ORDER BY retain_until, hold_id LIMIT $2::integer FOR UPDATE SKIP LOCKED) DELETE FROM credit_cancellations c USING expired e WHERE c.hold_id = e.hold_id",
    [Text(now), Text(Int.to_string(limit))])?
  let spent = Pg.execute_values(conn,
    "WITH expired AS (SELECT nullifier FROM credit_spent WHERE retain_until < $1::bigint ORDER BY retain_until, nullifier LIMIT $2::integer FOR UPDATE SKIP LOCKED) DELETE FROM credit_spent s USING expired e WHERE s.nullifier = e.nullifier",
    [Text(now), Text(Int.to_string(limit))])?
  let holds = Pg.execute_values(conn,
    "WITH expired AS (SELECT hold_id FROM credit_holds h WHERE retain_until < $1::bigint AND NOT EXISTS (SELECT 1 FROM credit_spent s WHERE s.hold_id = h.hold_id) ORDER BY retain_until, hold_id LIMIT $2::integer FOR UPDATE SKIP LOCKED) DELETE FROM credit_holds h USING expired e WHERE h.hold_id = e.hold_id",
    [Text(now), Text(Int.to_string(limit))])?
  Ok(CreditPruneResult { spent: spent, holds: holds })
end

pub fn prune_credit_ledger(pool :: PoolHandle, limit :: Int) -> CreditPruneResult!String do
  if limit < 1 || limit > 1000 do
    return Err("invalid_credit_prune_limit")
  end
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> prune(conn, limit) end)
end
