from Credits.Action import credit_action_id, encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  encode_credit_action_submission,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Cancellation import (
  sign_credit_cancellation,
  encode_credit_cancellation,
  decode_credit_cancellation,
  verify_credit_cancellation
)
from Credits.Token import verify_credit_frame
from Credits.Wire import encode_credit_frame
from Storage.CreditOperation import lock_credit_operation
from Storage.CreditIssuers import (
  credit_now,
  core_credit_service_key,
  configured_credit_purpose,
  admitted_credit_keys_on_connection
)

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_credit_recovery_row")
  end
end

fn recover(conn :: borrow PgConn, input :: CreditActionSubmission) -> Bytes!String do
  let id = credit_action_id(input.action)?
  lock_credit_operation(conn, id)?
  let core = core_credit_service_key()?
  let effects = Pg.query_values(conn,
    "SELECT receipt FROM credit_action_effects WHERE hold_id = $1",
    [Binary(id)])?
  if List.length(effects) == 1 do
    let receipt = binary(Map.get(List.head(effects), "receipt"))?
    if !verify_credit_action_receipt(decode_credit_action_receipt(receipt)?, core, input)? do
      return Err("credit_operation_conflict")
    end
    return Ok(receipt)
  end
  let cancellations = Pg.query_values(conn,
    "SELECT receipt FROM credit_cancellations WHERE hold_id = $1",
    [Binary(id)])?
  if List.length(cancellations) == 1 do
    let receipt = binary(Map.get(List.head(cancellations), "receipt"))?
    if !verify_credit_cancellation(decode_credit_cancellation(receipt)?, core, input)? do
      return Err("credit_operation_conflict")
    end
    return Ok(receipt)
  end
  # Clock is read only after the lock. A prior in-flight consume may have
  # committed a receipt while we waited, and must win over cancellation.
  let now = credit_now(conn)?
  if U64.compare(now, input.action.expires_at) < 0 do
    return Err("credit_action_not_expired")
  end
  let action = encode_credit_action(input.action)?
  let frame_hash = Crypto.sha256(encode_credit_frame(input.frame)?)
  let holds = Pg.query_values(conn,
    "SELECT action, frame_hash, effect_id FROM credit_holds WHERE hold_id = $1 FOR UPDATE",
    [Binary(id)])?
  if List.length(holds) == 1 do
    let hold = List.head(holds)
    if !Bytes.secure_equals(binary(Map.get(hold, "action"))?, action)
      || !Bytes.secure_equals(binary(Map.get(hold, "frame_hash"))?, frame_hash) do
      return Err("credit_operation_conflict")
    end
    case Map.get(hold, "effect_id") do
      Null -> nil
      _ -> return Err("credit_effect_receipt_missing")
    end
  end
  # Valid bearer tokens authorize recovery; malformed or arbitrary requests
  # cannot create cancellation rows. Current pricing is irrelevant to release.
  let purpose = configured_credit_purpose()?
  let spends = verify_credit_frame(input.frame,
    input.request_body,
    List.length(input.frame.tokens),
    admitted_credit_keys_on_connection(conn, now, purpose)?,
    core.bytes,
    now,
    purpose)?
  let nullifiers = "["
    <> String.join(for spend in spends do
        Json.encode_string(Bytes.to_hex(spend.nullifier))
      end,
      ",")
    <> "]"
  let other = Pg.query_values(conn,
    "SELECT nullifier FROM credit_spent WHERE nullifier IN (SELECT decode(value, 'hex') FROM jsonb_array_elements_text($1::jsonb)) AND hold_id <> $2 LIMIT 1",
    [Text(nullifiers), Binary(id)])?
  if List.length(other) != 0 do
    return Err("credit_already_spent")
  end
  let retain_until = List.reduce(spends,
    input.action.expires_at,
    fn(maximum, spend) do
      if U64.compare(spend.retain_until, maximum) > 0 do
        spend.retain_until
      else
        maximum
      end
    end)
  let seed = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> return Err("credit_receipt_signer_unavailable")
    Ok(value) -> value
  end
  let key = case Crypto.signing_from_secret(seed) do
    Err(_) -> return Err("credit_receipt_signer_unavailable")
    Ok(value) -> value
  end
  # Absent actions are already permanently expired. Their exact signed proof
  # is deterministic and stateless: a bearer cannot grow the database by
  # inventing arbitrarily many old nonces using one set of valid tokens.
  # Only an existing hold needs a durable cancellation fence replacing it.
  let cancelled_at = if List.length(holds) == 0 do
    input.action.expires_at
  else
    now
  end
  let receipt = encode_credit_cancellation(sign_credit_cancellation(key.private_key,
    input,
    cancelled_at)?)?
  if List.length(holds) == 1 do
    Pg.execute_values(conn, "DELETE FROM credit_spent WHERE hold_id = $1", [Binary(id)])?
    Pg.execute_values(conn, "DELETE FROM credit_holds WHERE hold_id = $1", [Binary(id)])?
    Pg.execute_values(conn,
      "INSERT INTO credit_cancellations (hold_id, action, frame_hash, receipt, retain_until) VALUES ($1, $2, $3, $4, $5::bigint)",
      [
        Binary(id),
        Binary(action),
        Binary(frame_hash),
        Binary(receipt),
        Text(U64.to_string(retain_until))
      ])?
    nil
  else
    nil
  end
  Ok(receipt)
end

pub fn reconcile_credit_action(pool :: PoolHandle,
  input :: CreditActionSubmission) -> Bytes!String do
  encode_credit_action_submission(input)?
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> recover(conn, input) end)
end
