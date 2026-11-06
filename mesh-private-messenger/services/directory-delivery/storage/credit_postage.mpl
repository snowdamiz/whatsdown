from Credits.Action import credit_action_id, encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  decode_credit_action_receipt,
  verify_credit_action_receipt,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Postage import (
  CreditPostageRequest,
  CreditPostageResult,
  decode_credit_postage_request,
  credit_postage_action,
  credit_postage_effect_id,
  encode_credit_postage_result
)
from Credits.PostageBox import SealedPostageBatch, postage_batch_digest, open_postage_credit_box
from Credits.PostageReply import seal_postage_reply
from Credits.PostagePolicy import postage_policy_from_device_set
from Privacy.Edge import decode_sealed_delivery, open_delivery_with_key
from Protocol.DirectoryWire import encode_device_set
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.V1 import OuterEnvelope
from Storage.ContactAddress import resolve_deposit_address
from Storage.CreditIssuers import credit_now, core_credit_service_key
from Storage.CreditOperation import lock_credit_operation
from Storage.CreditRecovery import reconcile_credit_action
from Storage.Credits import (
  redeem_credits_on_connection,
  consume_credit_hold_on_connection,
  CreditHoldUse
)
from Storage.Devices import resolve_account_devices_on_connection
from Storage.Delivery import enqueue_paid_envelope_on_connection, DeliveryInsert

pub struct CreditPostageCompletion do
  created :: Bool
  response :: Bytes
end

struct PreparedPostage do
  batch :: SealedPostageBatch
  submission :: CreditActionSubmission
  request :: CreditPostageRequest
  envelopes :: List<OuterEnvelope>
end

fn prepare(batch :: SealedPostageBatch,
  private :: borrow X25519PrivateKey) -> PreparedPostage!String do
  let submission = open_postage_credit_box(private, batch.deliveries, batch.credit_box)?
  let request = decode_credit_postage_request(submission.request_body)?
  if !Bytes.secure_equals(encode_credit_action(submission.action)?,
    encode_credit_action(credit_postage_action(request)?)?)
    || !Bytes.secure_equals(request.batch_digest, postage_batch_digest(batch.deliveries)?) do
    return Err("credit_action_request_mismatch")
  end
  let envelopes = for delivery in batch.deliveries do
    let raw = open_delivery_with_key(decode_sealed_delivery(delivery)?, private)?
    case decode_outer_envelope(raw) do
      Err(_) -> return Err("invalid_credit_postage_envelope")
      Ok(value) -> value
    end
  end
  Ok(PreparedPostage {
    batch: batch,
    submission: submission,
    request: request,
    envelopes: envelopes
  })
end

fn reply(input :: PreparedPostage, receipt :: Bytes) -> Bytes!String do
  seal_postage_reply(X25519PublicKey { bytes: input.request.reply_public_key },
    input.batch.deliveries,
    receipt)
end

fn completed(conn :: borrow PgConn, input :: PreparedPostage) -> Option<Bytes>!String do
  let rows = Pg.query_values(conn,
    "SELECT receipt FROM credit_action_effects WHERE hold_id = $1",
    [Binary(credit_action_id(input.submission.action)?)])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  let receipt = case Map.get(List.head(rows), "receipt") do
    Binary(value) -> value
    _ -> return Err("invalid_credit_effect_row")
  end
  if !verify_credit_action_receipt(decode_credit_action_receipt(receipt)?,
    core_credit_service_key()?,
    input.submission)? do
    return Err("credit_operation_conflict")
  end
  Ok(Some(receipt))
end

fn apply(conn :: borrow PgConn, input :: PreparedPostage) -> CreditPostageCompletion!String do
  let submission = input.submission
  let request = input.request
  lock_credit_operation(conn, credit_action_id(submission.action)?)?
  case completed(conn, input)? do
    Some(receipt) -> return Ok(CreditPostageCompletion {
      created: false,
      response: reply(input, receipt)?
    })
    None -> nil
  end
  # The account share lock pins its entire active device set and policy until
  # enqueue commits. Registration, removal and publication take its update lock.
  let devices = resolve_account_devices_on_connection(conn, request.recipient_account_id)?
  let encoded = case encode_device_set(devices) do
    Err(_) -> return Err("invalid_stored_postage_policy")
    Ok(value) -> value
  end
  let policy = case postage_policy_from_device_set(devices)? do
    None -> return Err("credit_not_required")
    Some(value) -> value
  end
  if policy.credits == 0 do
    return Err("credit_not_required")
  end
  if request.policy_revision != policy.revision
    || request.device_set_revision != devices.sequence
    || !Bytes.secure_equals(request.device_set_sha256, Crypto.sha256(encoded))
    || List.length(input.envelopes) != List.length(devices.devices) do
    return Err("credit_postage_snapshot_conflict")
  end
  let contacts = for index in 0..List.length(input.envelopes) do
    let outer = List.get(input.envelopes, index)
    let entry = List.get(devices.devices, index)
    let (mailbox_hash, contact) = resolve_deposit_address(conn, Crypto.sha256(outer.mailbox_token))?
    if !Bytes.secure_equals(mailbox_hash, Crypto.sha256(entry.mailbox_token)) do
      return Err("credit_postage_snapshot_conflict")
    end
    contact
  end
  if List.all(contacts, fn(value) -> value end) do
    return Err("credit_not_required")
  end
  # One price/frame for the account, not one for each linked device. Spending,
  # every envelope/outbox event, the hold and exact signed receipt all commit or
  # all roll back. A full later mailbox cannot spend an earlier token/enqueue.
  redeem_credits_on_connection(conn, submission.action, submission.request_body, submission.frame)?
  let applied_at = credit_now(conn)?
  if U64.compare(applied_at, submission.action.expires_at) >= 0 do
    return Err("expired_credit_action")
  end
  let effect = credit_postage_effect_id(submission.action)?
  case consume_credit_hold_on_connection(conn, submission.action, effect)? do
    HoldApplied -> nil
    HoldAlreadyApplied -> return Err("credit_effect_receipt_missing")
  end
  for outer in input.envelopes do
    case enqueue_paid_envelope_on_connection(conn, outer)? do
      Accepted -> nil
      Duplicate -> return Err("credit_postage_already_delivered")
      ExpiryRejected -> return Err("invalid_credit_postage_expiry")
      _ -> return Err("credit_postage_enqueue_failed")
    end
  end
  let result = encode_credit_postage_result(CreditPostageResult {
    recipient_account_id: request.recipient_account_id,
    batch_digest: request.batch_digest,
    policy_revision: policy.revision,
    device_set_revision: devices.sequence,
    enqueued_count: List.length(input.envelopes),
    charged_credits: policy.credits
  })?
  let seed = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> return Err("credit_receipt_signer_unavailable")
    Ok(value) -> value
  end
  let key = case Crypto.signing_from_secret(seed) do
    Err(_) -> return Err("credit_receipt_signer_unavailable")
    Ok(value) -> value
  end
  let receipt = encode_credit_action_receipt(sign_credit_action_receipt(key.private_key,
    submission,
    effect,
    applied_at,
    result)?)?
  # A malformed reply key cannot consume credits and leave an unreplyable
  # result. Response encryption must succeed before the transaction commits.
  let response = reply(input, receipt)?
  Pg.execute_values(conn,
    "INSERT INTO credit_action_effects (hold_id, effect_id, action_kind, receipt) VALUES ($1, $2, 3, $3)",
    [Binary(credit_action_id(submission.action)?), Binary(effect), Binary(receipt)])?
  Ok(CreditPostageCompletion { created: true, response: response })
end

pub fn apply_credit_postage(pool :: PoolHandle,
  batch :: SealedPostageBatch,
  private :: borrow X25519PrivateKey) -> CreditPostageCompletion!String do
  let prepared = prepare(batch, private)?
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> apply(conn, prepared) end)
end

pub fn reconcile_credit_postage(pool :: PoolHandle,
  batch :: SealedPostageBatch,
  private :: borrow X25519PrivateKey) -> Bytes!String do
  let prepared = prepare(batch, private)?
  # Generic recovery checks the exact immutable CAP against a stored effect or
  # cancellation. Only its request-bound reply key is used to seal the result.
  reply(prepared, reconcile_credit_action(pool, prepared.submission)?)
end
