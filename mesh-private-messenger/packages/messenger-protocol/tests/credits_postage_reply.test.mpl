from Credits.PostageBox import postage_batch_digest
from Credits.Action import CreditAction
from Credits.ActionWire import (
  CreditActionSubmission,
  sign_credit_action_receipt,
  encode_credit_action_receipt,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Cancellation import sign_credit_cancellation, encode_credit_cancellation
from Credits.PostageReply import seal_postage_reply, open_postage_reply, open_postage_reply_for_digest, is_sealed_postage_reply
from Credits.Wire import CreditToken, CreditTokenInput, CreditFrame
from Privacy.Edge import SealedDelivery, encode_sealed_delivery

fn bytes(value :: Int, size :: Int) -> Bytes!String do
  case Bytes.repeat(value, size) do
    Err(_) -> Err("test bytes failed")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  let reply = case Crypto.x25519_generate() do
    Err(_) -> return Err("test key failed")
    Ok(value) -> value
  end
  let public = reply.public_key
  let private = reply.private_key
  let core = case Crypto.signing_generate() do
    Err(_) -> return Err("test signer failed")
    Ok(value) -> value
  end
  let attacker = case Crypto.signing_generate() do
    Err(_) -> return Err("test signer failed")
    Ok(value) -> value
  end
  let deliveries = for index in 1..3 do
    encode_sealed_delivery(SealedDelivery {
      ephemeral_public_key: bytes(index, 32)?,
      nonce: bytes(11, 12)?,
      ciphertext: bytes(22, 512)?
    })?
  end
  let body = Bytes.from_utf8("canonical request descriptor fixture")
  let request = CreditActionSubmission {
    action: CreditAction {
      kind: 3,
      operation_nonce: bytes(33, 32)?,
      target: bytes(44, 32)?,
      quantity: U64.parse("0")?,
      expires_at: U64.parse("1600")?,
      request_sha256: Crypto.sha256(body)
    },
    request_body: body,
    frame: CreditFrame {
      binding: Crypto.sha256(body),
      tokens: [
        CreditToken {
          input: CreditTokenInput {
            nonce: bytes(55, 32)?,
            challenge_digest: bytes(66, 32)?,
            token_key_id: bytes(77, 32)?
          },
          authenticator: bytes(88, 256)?
        }
      ]
    }
  }
  let receipt = sign_credit_action_receipt(core.private_key,
    request,
    bytes(99, 32)?,
    U64.parse("1000")?,
    Bytes.from_utf8("exact result"))?
  let raw = encode_credit_action_receipt(receipt)?
  let sealed = seal_postage_reply(public, deliveries, raw)?
  assert(is_sealed_postage_reply(sealed) && Bytes.length(sealed) == 564)
  assert(Bytes.secure_equals(open_postage_reply(private, deliveries, sealed)?, raw))
  assert(Bytes.secure_equals(open_postage_reply_for_digest(private, postage_batch_digest(deliveries)?, sealed)?, raw))
  assert(Result.is_err(open_postage_reply_for_digest(private, bytes(99, 32)?, sealed)))
  assert(Result.is_err(open_postage_reply(private, List.reverse(deliveries), sealed)))
  assert(Result.is_err(open_postage_reply(private, [List.head(deliveries)], sealed)))
  let cancelled = encode_credit_cancellation(sign_credit_cancellation(core.private_key,
    request,
    U64.parse("1600")?)?)?
  assert(Bytes.length(seal_postage_reply(public, deliveries, cancelled)?) == Bytes.length(sealed))
  assert(Bytes.secure_equals(open_postage_reply(private,
      deliveries,
      seal_postage_reply(public, deliveries, cancelled)?)?,
    cancelled))
  let forged = encode_credit_action_receipt(sign_credit_action_receipt(attacker.private_key,
    request,
    receipt.effect_id,
    U64.parse("1000")?,
    receipt.result)?)?
  let opened_forgery = open_postage_reply(private,
    deliveries,
    seal_postage_reply(public, deliveries, forged)?)?
  assert(!verify_credit_action_receipt(decode_credit_action_receipt(opened_forgery)?,
    core.public_key,
    request)?)
  assert(Result.is_err(open_postage_reply(private,
    deliveries,
    Bytes.concat(sealed, Bytes.from_hex("00")?)?)))
  assert(Result.is_err(seal_postage_reply(public, deliveries, Bytes.from_utf8("200 OK"))))
  Ok(true)
end

test("postage replies hide CAR and CCR with fixed padding and exact batch binding") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
