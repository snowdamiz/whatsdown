from Storage.CreditOperation import lock_credit_operation
from Credits.Action import credit_action_id, encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  decode_credit_action_receipt,
  encode_credit_action_receipt,
  sign_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Retention import (
  CreditRetentionRequest,
  CreditRetentionResult,
  decode_credit_retention_request,
  credit_retention_action,
  verify_credit_retention_request,
  encode_credit_retention_result
)
from Storage.Credits import (
  redeem_credits_on_connection,
  consume_credit_hold_on_connection,
  CreditHoldUse
)
from Storage.CreditIssuers import credit_now, core_credit_service_key
from Storage.MailboxAuth import bundle_signing_public_key
import RuntimeJobs

pub struct CreditRetentionCompletion do
  created :: Bool
  receipt :: Bytes
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_credit_effect_row")
  end
end

fn wide(value :: DbValue) -> U64!String do
  case value do
    Text(output) -> U64.parse(output)
    _ -> Err("invalid_credit_effect_row")
  end
end

fn maximum(left :: U64, right :: U64) -> U64 do
  if U64.compare(left, right) >= 0 do
    left
  else
    right
  end
end

fn completed(conn :: borrow PgConn, submission :: CreditActionSubmission) -> Option<Bytes>!String do
  let rows = Pg.query_values(conn,
    "SELECT receipt FROM credit_action_effects WHERE hold_id = $1",
    [Binary(credit_action_id(submission.action)?)])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  let receipt = binary(Map.get(List.head(rows), "receipt"))?
  if !verify_credit_action_receipt(decode_credit_action_receipt(receipt)?,
    core_credit_service_key()?,
    submission)? do
    return Err("credit_operation_conflict")
  end
  Ok(Some(receipt))
end

fn signer() -> SigningKeyPair!String do
  let material = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> return Err("credit_receipt_signer_unavailable")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(material) do
    Err(_) -> Err("credit_receipt_signer_unavailable")
    Ok(value)
  end
end

fn apply(conn :: borrow PgConn,
  submission :: CreditActionSubmission,
  request :: CreditRetentionRequest) -> CreditRetentionCompletion!String do
  # Bare redemption and recovery take the operation lock first. Retention
  # must follow the same order before locking the mailbox, or a concurrent
  # redeemer can own the operation while waiting for this mailbox row.
  lock_credit_operation(conn, credit_action_id(submission.action)?)?
  # Completed exact requests recover even after expiry or owner revocation.
  # They cannot authorize another effect or replace the original payment.
  case completed(conn, submission)? do
    Some(receipt) -> return Ok(CreditRetentionCompletion { created: false, receipt: receipt })
    None -> nil
  end
  let owners = Pg.query_values(conn,
    "SELECT d.prekey_bundle, m.credit_retention_until_ms::text FROM messenger_devices d JOIN messenger_mailboxes m ON m.mailbox_token_hash = d.mailbox_token_hash WHERE d.mailbox_token_hash = $1 AND d.revoked_at IS NULL AND m.active FOR UPDATE OF m FOR SHARE OF d",
    [Binary(request.mailbox_hash)])?
  # The mailbox lock serializes two first submissions; read the receipt again
  # after waiting so exactly one payment/effect is ever applied.
  case completed(conn, submission)? do
    Some(receipt) -> return Ok(CreditRetentionCompletion { created: false, receipt: receipt })
    None -> nil
  end
  if List.length(owners) != 1 do
    return Err("credit_retention_unauthorized")
  end
  let owner = List.head(owners)
  let clock = Pg.query_values(conn,
    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint::text AS now",
    [])?
  let now_ms = wide(Map.get(List.head(clock), "now"))?
  if !verify_credit_retention_request(request,
    SigningPublicKey {
      bytes: bundle_signing_public_key(binary(Map.get(owner, "prekey_bundle"))?)?
    },
    now_ms)? do
    return Err("credit_retention_unauthorized")
  end
  let hold = redeem_credits_on_connection(conn,
    submission.action,
    submission.request_body,
    submission.frame)?
  let applied_at = credit_now(conn)?
  if U64.compare(applied_at, submission.action.expires_at) >= 0 do
    return Err("expired_credit_action")
  end
  let id = credit_action_id(submission.action)?
  let effect = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-credit-retention-effect-v1"), id)?)
  case consume_credit_hold_on_connection(conn, submission.action, effect)? do
    HoldAlreadyApplied -> return Err("credit_effect_receipt_missing")
    HoldApplied -> nil
  end
  let epoch_ms = U64.multiply(applied_at, U64.parse("1000")?)?
  let requested = U64.add(epoch_ms, U64.parse(Int.to_string(request.days * 86400000))?)?
  let until = maximum(wide(Map.get(owner, "credit_retention_until_ms"))?, requested)
  if U64.compare(until, U64.add(epoch_ms, U64.parse("15552000000")?)?) > 0 do
    return Err("invalid_credit_effect_row")
  end
  Pg.execute_values(conn,
    "UPDATE messenger_mailboxes SET credit_retention_until_ms = $2::bigint WHERE mailbox_token_hash = $1",
    [Binary(request.mailbox_hash), Text(U64.to_string(until))])?
  # Expired rows are never resurrected. Already parked, live rows may renew;
  # acknowledgements keep their existing short deletion policy.
  Pg.execute_values(conn,
    "UPDATE messenger_envelopes SET storage_until_ms = GREATEST(storage_until_ms, $2::bigint) WHERE mailbox_token_hash = $1 AND acknowledged_at IS NULL AND GREATEST(expiration_ms, storage_until_ms) > $3::bigint",
    [Binary(request.mailbox_hash), Text(U64.to_string(until)), Text(U64.to_string(now_ms))])?
  let recovery_until = U64.add(U64.divide(U64.add(until, U64.parse("999")?)?, U64.parse("1000")?)?,
    U64.parse("604800")?)?
  Pg.execute_values(conn,
    "UPDATE credit_holds SET retain_until = GREATEST(retain_until, $2::bigint) WHERE hold_id = $1",
    [Binary(id), Text(U64.to_string(recovery_until))])?
  let result = encode_credit_retention_result(CreditRetentionResult {
    mailbox_hash: request.mailbox_hash,
    days: request.days,
    effective_until_ms: until
  })?
  let core_pair = signer()?
  let receipt = encode_credit_action_receipt(sign_credit_action_receipt(core_pair.private_key,
    submission,
    effect,
    applied_at,
    result)?)?
  Pg.execute_values(conn,
    "INSERT INTO credit_action_effects (hold_id, effect_id, action_kind, receipt) VALUES ($1, $2, 2, $3)",
    [Binary(id), Binary(effect), Binary(receipt)])?
  if !hold.created do
    RuntimeJobs.notify(conn, "directory")?
  else
    nil
  end
  Ok(CreditRetentionCompletion { created: true, receipt: receipt })
end

pub fn apply_credit_retention(pool :: PoolHandle,
  submission :: CreditActionSubmission) -> CreditRetentionCompletion!String do
  let request = decode_credit_retention_request(submission.request_body)?
  if !Bytes.secure_equals(encode_credit_action(submission.action)?,
    encode_credit_action(credit_retention_action(request)?)?) do
    return Err("credit_action_request_mismatch")
  end
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> apply(conn, submission, request) end)
end
