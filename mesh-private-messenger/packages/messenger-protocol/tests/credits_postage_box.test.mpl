from Credits.Action import CreditAction
from Credits.ActionWire import CreditActionSubmission, encode_credit_action_submission
from Credits.PostageBox import (
  SealedPostageBatch,
  postage_batch_digest,
  seal_postage_credit_box,
  open_postage_credit_box,
  encode_sealed_postage_batch,
  decode_sealed_postage_batch
)
from Credits.Wire import CreditFrame, CreditToken, CreditTokenInput
from Privacy.Edge import SealedDelivery, encode_sealed_delivery, seal_delivery
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope

fn bytes(value :: Int, size :: Int) -> Bytes!String do
  case Bytes.repeat(value, size) do
    Err(_) -> Err("test allocation failed")
    Ok(value)
  end
end

fn submission(count :: Int) -> CreditActionSubmission!String do
  let body = Bytes.from_utf8("postage descriptor fixture: semantic authentication is a separate core gate")
  let tokens = for index in 0..count do
    CreditToken {
      input: CreditTokenInput {
        nonce: bytes(index + 1, 32)?,
        challenge_digest: bytes(44, 32)?,
        token_key_id: bytes(55, 32)?
      },
      authenticator: bytes(66, 256)?
    }
  end
  Ok(CreditActionSubmission {
    action: CreditAction {
      kind: 3,
      operation_nonce: bytes(11, 32)?,
      target: bytes(22, 32)?,
      expires_at: U64.parse("1600")?,
      quantity: U64.parse("0")?,
      request_sha256: Crypto.sha256(body)
    },
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: tokens }
  })
end

fn proof() -> Bool!String do
  let core = case Crypto.x25519_generate() do
    Err(_) -> return Err("test key failed")
    Ok(value) -> value
  end
  let public = core.public_key
  let private = core.private_key
  let other = case Crypto.x25519_generate() do
    Err(_) -> return Err("test key failed")
    Ok(value) -> value
  end
  let deliveries = for marker in [11, 12] do
    let outer = case encode_outer_envelope(OuterEnvelope {
      version: 1,
      envelope_id: bytes(marker, 16)?,
      mailbox_token: bytes(marker + 1, 32)?,
      suite: 4,
      expiration: U64.parse("2000000")?,
      padding_bucket: 256,
      ciphertext: bytes(77, 256)?
    }) do
      Err(_) -> return Err("test envelope failed")
      Ok(value) -> value
    end
    encode_sealed_delivery(seal_delivery(outer, public)?)?
  end
  let expected = submission(1)?
  let box = seal_postage_credit_box(public, deliveries, expected)?
  assert(Bytes.length(box) == 16436)
  assert(Bytes.secure_equals(encode_credit_action_submission(open_postage_credit_box(private,
      deliveries,
      box)?)?,
    encode_credit_action_submission(expected)?))
  assert(!Bytes.secure_equals(postage_batch_digest(deliveries)?,
    postage_batch_digest(List.reverse(deliveries))?))
  assert(Result.is_err(open_postage_credit_box(private, List.reverse(deliveries), box)))
  assert(Result.is_err(open_postage_credit_box(private, [List.head(deliveries)], box)))
  assert(Result.is_err(open_postage_credit_box(other.private_key, deliveries, box)))
  for count in [1, 5, 25] do
    assert(Bytes.length(seal_postage_credit_box(public, deliveries, submission(count)?)?) == 16436)
  end
  assert(Result.is_err(seal_postage_credit_box(public, deliveries, submission(2)?)))
  assert(Result.is_err(postage_batch_digest([])))
  assert(Result.is_err(postage_batch_digest([List.head(deliveries), List.head(deliveries)])))
  let encoded = encode_sealed_postage_batch(SealedPostageBatch {
    deliveries: deliveries,
    credit_box: box
  })?
  assert(Bytes.secure_equals(encode_sealed_postage_batch(decode_sealed_postage_batch(encoded)?)?,
    encoded))
  assert(Result.is_err(decode_sealed_postage_batch(Bytes.concat(encoded, Bytes.from_hex("00")?)?)))
  let maximum = for index in 0..8 do
    encode_sealed_delivery(SealedDelivery {
      ephemeral_public_key: bytes(index + 1, 32)?,
      nonce: bytes(88, 12)?,
      ciphertext: bytes(99, 65622)?
    })?
  end
  let maximum_box = seal_postage_credit_box(public, maximum, submission(25)?)?
  let maximum_packet = encode_sealed_postage_batch(SealedPostageBatch {
    deliveries: maximum,
    credit_box: maximum_box
  })?
  assert(Bytes.length(maximum_packet) == 541865)
  assert(List.length(decode_sealed_postage_batch(maximum_packet)?.deliveries) == 8)
  assert(Result.is_err(postage_batch_digest(maximum ++ [List.head(deliveries)])))
  assert(Result.is_err(open_postage_credit_box(private, deliveries, Bytes.slice(box, 0, 16435)?)))
  Ok(true)
end

test("one fixed-size postage credit box binds an ordered bounded recipient fanout") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
