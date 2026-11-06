from Credits.Action import credit_action_id, encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  encode_credit_action_receipt,
  sign_credit_action_receipt
)
from Credits.Attachment import (
  decode_credit_attachment_grant,
  credit_attachment_action,
  validate_credit_attachment_grant,
  credit_attachment_result,
  encode_credit_attachment_result,
  credit_attachment_effect_id,
  verify_credit_attachment_receipt
)
from Storage.Credits import (
  redeem_credits_on_connection,
  consume_credit_hold_on_connection,
  CreditHoldUse
)
from Storage.CreditIssuers import credit_now, core_credit_service_key
import RuntimeJobs

pub struct CreditAttachmentCompletion do
  created :: Bool
  receipt :: Bytes
end

fn completed(conn :: borrow PgConn, submission :: CreditActionSubmission) -> Option<Bytes>!String do
  let rows = Pg.query_values(conn,
    "SELECT receipt FROM credit_action_effects WHERE hold_id = $1",
    [Binary(credit_action_id(submission.action)?)])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  let receipt = case Map.get(List.head(rows), "receipt") do
    Binary(value) -> value
    _ -> return Err("invalid_credit_attachment_row")
  end
  case verify_credit_attachment_receipt(submission, core_credit_service_key()?, receipt) do
    Err(_) -> return Err("credit_operation_conflict")
    Ok(_) -> nil
  end
  Ok(Some(receipt))
end

fn signer() -> SigningKeyPair!String do
  let seed = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> return Err("credit_receipt_signer_unavailable")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(seed) do
    Err(_) -> Err("credit_receipt_signer_unavailable")
    Ok(value)
  end
end

fn apply(conn :: borrow PgConn,
  submission :: CreditActionSubmission) -> CreditAttachmentCompletion!String do
  let grant = decode_credit_attachment_grant(submission.request_body)?
  if !Bytes.secure_equals(encode_credit_action(submission.action)?,
    encode_credit_action(credit_attachment_action(grant)?)?) do
    return Err("credit_action_request_mismatch")
  end
  # A stored exact authorization survives request/key expiry. The object store
  # can recover its idempotent external effect after an uncertain HTTP response.
  case completed(conn, submission)? do
    Some(receipt) -> return Ok(CreditAttachmentCompletion { created: false, receipt: receipt })
    None -> nil
  end
  let now = credit_now(conn)?
  validate_credit_attachment_grant(grant, now)?
  let hold = redeem_credits_on_connection(conn,
    submission.action,
    submission.request_body,
    submission.frame)?
  # The unique hold insert serializes concurrent first submissions. Re-read
  # the effect AFTER it, since another transaction may have just committed it.
  case completed(conn, submission)? do
    Some(receipt) -> return Ok(CreditAttachmentCompletion { created: false, receipt: receipt })
    None -> nil
  end
  let id = credit_action_id(submission.action)?
  Pg.execute_values(conn,
    "INSERT INTO credit_attachment_objects(object_id,hold_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
    [Binary(grant.object_id), Binary(id)])?
  let bindings = Pg.query_values(conn,
    "SELECT hold_id FROM credit_attachment_objects WHERE object_id=$1",
    [Binary(grant.object_id)])?
  if List.length(bindings) != 1 do
    return Err("credit_operation_conflict")
  end
  let bound = case Map.get(List.head(bindings), "hold_id") do
    Binary(value) -> value
    _ -> return Err("invalid_credit_attachment_row")
  end
  if !Bytes.secure_equals(bound, id) do
    return Err("credit_operation_conflict")
  end
  let applied = credit_now(conn)?
  if U64.compare(applied, submission.action.expires_at) >= 0 do
    return Err("expired_credit_action")
  end
  validate_credit_attachment_grant(grant, applied)?
  let effect = credit_attachment_effect_id(submission.action)?
  case consume_credit_hold_on_connection(conn, submission.action, effect)? do
    HoldAlreadyApplied -> return Err("credit_effect_receipt_missing")
    HoldApplied -> nil
  end
  let recovery = U64.add(U64.divide(U64.add(grant.expires_at_ms, U64.parse("999")?)?,
      U64.parse("1000")?)?,
    U64.parse("604800")?)?
  Pg.execute_values(conn,
    "UPDATE credit_holds SET retain_until = GREATEST(retain_until, $2::bigint) WHERE hold_id = $1",
    [Binary(id), Text(U64.to_string(recovery))])?
  let pair = signer()?
  let receipt = encode_credit_action_receipt(sign_credit_action_receipt(pair.private_key,
    submission,
    effect,
    applied,
    encode_credit_attachment_result(credit_attachment_result(grant)?)?)?)?
  Pg.execute_values(conn,
    "INSERT INTO credit_action_effects (hold_id, effect_id, action_kind, receipt) VALUES ($1, $2, 1, $3)",
    [Binary(id), Binary(effect), Binary(receipt)])?
  if !hold.created do
    RuntimeJobs.notify(conn, "directory")?
  end
  Ok(CreditAttachmentCompletion { created: true, receipt: receipt })
end

pub fn apply_credit_attachment_grant(pool :: PoolHandle,
  submission :: CreditActionSubmission) -> CreditAttachmentCompletion!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) do apply(conn, submission) end)
end
