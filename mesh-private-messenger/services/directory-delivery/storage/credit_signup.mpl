from Credits.Action import credit_action_id, encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  decode_credit_action_receipt,
  encode_credit_action_receipt,
  sign_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Signup import (
  CreditSignupRequest,
  CreditSignupResult,
  decode_credit_signup_request,
  credit_signup_action,
  encode_credit_signup_result
)
from Storage.Credits import (
  redeem_credits_on_connection,
  consume_credit_hold_on_connection,
  CreditHoldUse
)
from Storage.CreditIssuers import credit_now, core_credit_service_key
from Storage.Devices import register_fresh_device_on_connection, DeviceWrite
from Protocol.DirectoryWire import decode_directory_entry

pub struct CreditSignupCompletion do
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
    _ -> return Err("invalid_credit_effect_row")
  end
  if !verify_credit_action_receipt(decode_credit_action_receipt(receipt)?,
    core_credit_service_key()?,
    submission)? do
    return Err("credit_operation_conflict")
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
  submission :: CreditActionSubmission,
  request :: CreditSignupRequest) -> CreditSignupCompletion!String do
  case completed(conn, submission)? do
    Some(receipt) -> return Ok(CreditSignupCompletion { created: false, receipt: receipt })
    None -> nil
  end
  # The hold serializes identical concurrent requests. A competing free or
  # independently paid signup is serialized by the account lock in Devices.
  redeem_credits_on_connection(conn, submission.action, submission.request_body, submission.frame)?
  case completed(conn, submission)? do
    Some(receipt) -> return Ok(CreditSignupCompletion { created: false, receipt: receipt })
    None -> nil
  end
  let applied_at = credit_now(conn)?
  if U64.compare(applied_at, submission.action.expires_at) >= 0 do
    return Err("expired_credit_action")
  end
  let id = credit_action_id(submission.action)?
  let effect = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-credit-signup-effect-v1"), id)?)
  case consume_credit_hold_on_connection(conn, submission.action, effect)? do
    HoldAlreadyApplied -> return Err("credit_effect_receipt_missing")
    HoldApplied -> nil
  end
  let entry = case decode_directory_entry(request.entry) do
    Err(_) -> return Err("invalid_credit_signup_request")
    Ok(value) -> value
  end
  case register_fresh_device_on_connection(conn, entry)? do
    DeviceAccepted -> nil
    _ -> return Err("credit_signup_already_registered")
  end
  let result = encode_credit_signup_result(CreditSignupResult {
    account_id: submission.action.target,
    entry_sha256: Crypto.sha256(request.entry)
  })?
  let key = signer()?
  let receipt = encode_credit_action_receipt(sign_credit_action_receipt(key.private_key,
    submission,
    effect,
    applied_at,
    result)?)?
  Pg.execute_values(conn,
    "INSERT INTO credit_action_effects (hold_id, effect_id, action_kind, receipt) VALUES ($1, $2, 4, $3)",
    [Binary(id), Binary(effect), Binary(receipt)])?
  Ok(CreditSignupCompletion { created: true, receipt: receipt })
end

pub fn apply_credit_signup(pool :: PoolHandle,
  submission :: CreditActionSubmission) -> CreditSignupCompletion!String do
  let request = decode_credit_signup_request(submission.request_body)?
  if !Bytes.secure_equals(encode_credit_action(submission.action)?,
    encode_credit_action(credit_signup_action(request)?)?) do
    return Err("credit_action_request_mismatch")
  end
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> apply(conn, submission, request) end)
end
