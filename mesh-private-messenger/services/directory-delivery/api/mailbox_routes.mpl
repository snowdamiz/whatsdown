##! Mailbox extras routes (protocol/credits-v1.md "Extras").

from Api.Binary import BinaryResult, claim_prekey_request
from Credits.CreditFrames import credits_decode_held
from Credits.MailboxExtras import (
  credits_decode_retention,
  credits_encode_claim_answer,
  credits_encode_retention_answer
)
from Prekeys.Pool import decode_prekey_claim
from Storage.PaidMailboxes import (
  PolicyWrite,
  RetentionWrite,
  mailbox_policy_for_device,
  mailbox_policy_publish,
  mailbox_retention_purchase
)

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

## PUT /v1/mailbox/policy: a device's signed MBP for its own mailbox. 201
## stored, 200 the same policy again, 409 not newer than the stored one, 403
## not signed by the mailbox's device, 400 malformed.

pub fn mailbox_policy_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case mailbox_policy_publish(pool, body) do
    Err(_) -> empty(500)
    Ok(PolicyStored) -> empty(201)
    Ok(PolicyUnchanged) -> empty(200)
    Ok(PolicyStale) -> empty(409)
    Ok(PolicyUnauthorized) -> empty(403)
    Ok(PolicyInvalid) -> empty(400)
  end
end

fn with_version(body :: Bytes, version :: Int) -> Bytes!String do
  case (Bytes.from_list([version]), Bytes.slice(body, 1, Bytes.length(body) - 1)) do
    (Ok(head), Ok(rest)) -> Bytes.concat(head, rest)
    _ -> Err("invalid prekey claim")
  end
end

fn policy_answer(pool :: PoolHandle, claim :: Bytes, answer :: BinaryResult) -> BinaryResult do
  let request = case decode_prekey_claim(claim) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case mailbox_policy_for_device(pool, request.account_id, request.device_id) do
    Err(_) -> empty(500)
    Ok(policy) -> case credits_encode_claim_answer(answer.body, policy) do
      Err(_) -> empty(500)
      Ok(encoded) -> BinaryResult { status: 200, body: encoded }
    end
  end
end

## A version 2 OTQ is a version 1 claim whose answer is PKC: the claimed
## bundle and the device's signed mailbox policy, if it set one, so a sender
## knows the postage before its first message.

pub fn claim_with_policy_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  let claim = case with_version(body, 1) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  let answer = claim_prekey_request(pool, claim)
  if answer.status != 200 do
    answer
  else
    policy_answer(pool, claim, answer)
  end
end

## POST /internal/v1/mailbox/retention (the edge, bearer): HLD(storage hold,
## MRT). 201 MRA; 402 the hold holds fewer credits than the periods cost; 403
## not signed by the mailbox's device or not fresh; 409 no hold to take; 400
## malformed.

pub fn mailbox_retention_request(pool :: PoolHandle,
  body :: Bytes,
  now_ms :: Int) -> BinaryResult do
  let (hold, frame) = case credits_decode_held(body) do
    Ok((Some(id), inner)) -> (id, inner)
    _ -> return empty(400)
  end
  let request = case credits_decode_retention(frame) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case mailbox_retention_purchase(pool, hold, request, now_ms) do
    Err(_) -> empty(500)
    Ok(RetentionUnpaid) -> empty(402)
    Ok(RetentionUnauthorized) -> empty(403)
    Ok(RetentionHoldMissing) -> empty(409)
    Ok(RetentionGranted(days, until_ms)) -> case credits_encode_retention_answer(days, until_ms) do
      Err(_) -> empty(500)
      Ok(encoded) -> BinaryResult { status: 201, body: encoded }
    end
  end
end
